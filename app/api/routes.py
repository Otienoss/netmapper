"""/scan, /jobs/{id}, WS /ws/jobs/{id}, /scans, /stats, /hosts, /scans/{id}/report.

Akış: POST /scan job'ı başlatır (hemen job_id + ws_url döner) → arka planda
keşif/tarama her aşamada WebSocket abonelerine push edilir → bitince sonuçlar
DB'ye yazılır → /scans/{id}/results JSON ve /scans/{id}/report PDF hazırdır.
"""

import ipaddress
import re
from typing import Literal

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from pydantic import AliasChoices, BaseModel, Field, field_validator, model_validator

from app.core.exploit_gate import check_exploit_allowed
from app.reporting.pdf_report import build_pdf_report
from app.reporting.risk_rules import evaluate_host
from app.services.job_manager import job_manager
from app.storage import repository
from app.storage.database import async_session_factory

router = APIRouter()


class ScanRequest(BaseModel):
    subnet: str                                     # 192.168.1.10 veya 192.168.1.0/24
    profile: Literal["quick", "full", "custom"] = "full"
    ports: str | None = None                        # yalnızca profile=custom için

    @field_validator("subnet")
    @classmethod
    def validate_subnet(cls, v: str) -> str:
        # Private kısıtı KALDIRILDI: herhangi bir IP/CIDR kabul edilir.
        net = ipaddress.ip_network(v, strict=False)
        # Tarama en fazla /24 genişliğinde olmalı (/25, /32 ve tek IP dahil kabul edilir)
        if net.prefixlen < 24:
            raise ValueError(
                "Tarama aralığı en fazla /24 genişliğinde olabilir "
                "(tek IP de kabul edilir)."
            )
        return str(net)

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        if not v or len(v) > 512 or not re.fullmatch(r"[\d,\-\s]+", v):
            raise ValueError(
                "Port listesi yalnızca rakam, virgül ve tire içerebilir "
                "(örn: 21,22,80,443,8000-8100)."
            )
        return v

    @model_validator(mode="after")
    def require_ports_for_custom(self):
        if self.profile == "custom" and not self.ports:
            raise ValueError("Özel profil için port listesi zorunludur.")
        return self


@router.post("/scan")
async def start_scan(req: ScanRequest) -> dict:
    """Tarama job'ı başlatır; uzun sürdüğü için job_id + ws_url ile döner."""
    job_id = await job_manager.start_scan(
        req.subnet, profile=req.profile, ports=req.ports
    )
    return {
        "job_id": job_id,
        "status": "started",
        "ws_url": f"/api/v1/ws/jobs/{job_id}",
        "detail_url": f"/api/v1/jobs/{job_id}",
    }


@router.get("/jobs/{job_id}")
async def get_job(job_id: str) -> dict:
    """Job durumu (anlık hafıza → DB yedeği)."""
    state = await job_manager.get_state(job_id)
    if state is None:
        raise HTTPException(status_code=404, detail="Job bulunamadı")
    return job_manager.serialize(state)


@router.websocket("/ws/jobs/{job_id}")
async def job_updates(websocket: WebSocket, job_id: str):
    """Canlı job durumu: her aşama/log anında push edilir; done/error'da kapanır.

    Kimlik doğrulama (T2): API_TOKEN tanımlıysa ?token=<token> sorgu
    parametresi zorunludur; yetkisiz bağlantı 4401 ile kapatılır.
    """
    from app.core.auth import is_websocket_authorized

    if not is_websocket_authorized(websocket):
        await websocket.close(code=4401)     # policy violation: yetkisiz
        return

    state = await job_manager.get_state(job_id)   # hafıza yoksa DB'den yükler
    if state is None:
        await websocket.close(code=4404)
        return

    await websocket.accept()
    queue = await job_manager.subscribe(job_id)
    try:
        while True:
            payload = await queue.get()
            await websocket.send_json(payload)
            if job_manager.is_terminal(payload):
                break
    except WebSocketDisconnect:
        pass
    finally:
        job_manager.unsubscribe(job_id, queue)


# ---------------------------------------------------------------- dashboard
def _serialize_host(db_host, include_scan: bool = True) -> dict:
    """DB host satırı → API/JSON gövdesi (risk bulguları dahil)."""
    host_result = repository.to_host_result(db_host)
    risk = evaluate_host(host_result)
    services = [
        {
            "port": svc.port,
            "protocol": svc.protocol,
            "service_name": svc.service_name,
            "product": svc.product,
            "version": svc.version,
            # evaluate_host servisleri sırayla değerlendirir → zip güvenli
            "risk_level": finding.level,
            "reasons": finding.reasons,
        }
        for svc, finding in zip(host_result.services, risk.findings)
    ]
    payload = {
        "ip": host_result.ip,
        "hostname": host_result.hostname,
        "mac": host_result.mac,
        "vendor": host_result.vendor,
        "source_tool": host_result.source_tool,
        "scanned_at": host_result.scanned_at.isoformat(),
        "risk_level": risk.level,
        "risk_score": risk.score,
        "services": services,
        "web_findings": [
            {
                "id": f.id,
                "osvdb_id": f.osvdb_id,
                "severity": f.severity,
                "message": f.message,
                "uri": f.uri,
            }
            for f in host_result.web_findings
        ],
    }
    if include_scan:
        payload["scan_id"] = db_host.scan_id
    return payload


def _dedupe_latest(db_hosts: list) -> list:
    """Aynı IP için en yeni kaydı tut (envanter/history gösterimini sadeleştirir)."""
    seen: set[str] = set()
    unique = []
    for h in db_hosts:            # liste scanned_at, en yeniden eskiye sıralı
        if h.ip in seen:
            continue
        seen.add(h.ip)
        unique.append(h)
    return unique


@router.get("/scans")
async def list_scans(limit: int = 20) -> dict:
    """Son taramalar (dashboard 'Son Taramalar' listesi)."""
    async with async_session_factory() as session:
        jobs = await repository.list_jobs(session, limit=min(max(limit, 1), 100))
    return {
        "scans": [
            {
                "scan_id": j.id,
                "subnet": j.subnet,
                "profile": j.profile,
                "status": j.status,
                "created_at": j.created_at.isoformat(),
                "finished_at": j.finished_at.isoformat() if j.finished_at else None,
            }
            for j in jobs
        ]
    }


@router.get("/stats")
async def get_stats() -> dict:
    """Dashboard özet kartları (IP bazında tekilleştirilmiş)."""
    async with async_session_factory() as session:
        recent = await repository.list_jobs(session, limit=1)
        db_hosts = _dedupe_latest(await repository.list_all_hosts(session))

    high_risk = sum(
        1 for h in db_hosts
        if evaluate_host(repository.to_host_result(h)).level == "high"
    )
    last = recent[0] if recent else None
    return {
        "last_scan": None if last is None else {
            "scan_id": last.id,
            "subnet": last.subnet,
            "profile": last.profile,
            "status": last.status,
            "updated_at": (
                (last.finished_at or last.created_at).isoformat()
            ),
        },
        "total_hosts": len(db_hosts),
        "open_ports": sum(len(h.services) for h in db_hosts),
        "high_risk": high_risk,
    }


@router.get("/hosts")
async def list_hosts() -> dict:
    """Host envanteri: her IP için en güncel kayıt (risk + portlar + nikto)."""
    async with async_session_factory() as session:
        db_hosts = _dedupe_latest(await repository.list_all_hosts(session))
    return {"hosts": [_serialize_host(h) for h in db_hosts]}


# ------------------------------------------------------------- tarama detayı
_SCAN_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def _validate_scan_id(scan_id: str) -> None:
    """Dosya adı üretiminden ÖNCE format kontrolü (path traversal savunması).

    scan_id'ler uuid4 hex'tir; DB'den gelen değer zaten güvenlidir ama
    yol/uzantı ayıracı içeren girdiler daha DB sorgusuna bile ulaşmaz.
    """
    if not _SCAN_ID_RE.match(scan_id or ""):
        raise HTTPException(status_code=404, detail="Tarama bulunamadı")


async def _load_scan(scan_id: str, require_done: bool = False):
    async with async_session_factory() as session:
        job = await repository.get_job(session, scan_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Tarama bulunamadı")
        if require_done and job.status != "done":
            raise HTTPException(
                status_code=409,
                detail=f"Tarama henüz tamamlanmadı (durum: {job.status})",
            )
        db_hosts = await repository.get_hosts_with_services(session, scan_id)
    return job, db_hosts


@router.get("/scans/{scan_id}/results")
async def get_scan_results(scan_id: str) -> dict:
    """JSON sonuçlar (envanter/dashboard beslemesi): host + servis + risk."""
    _validate_scan_id(scan_id)              # savunma derinliği: format koruması
    job, db_hosts = await _load_scan(scan_id)
    return {
        "scan_id": scan_id,
        "subnet": job.subnet,
        "status": job.status,
        "hosts": [_serialize_host(h, include_scan=False) for h in db_hosts],
    }


@router.get("/scans/{scan_id}/report")
async def download_report(scan_id: str) -> FileResponse:
    """Tamamlanmış taramanın PDF raporu (ReportLab)."""
    _validate_scan_id(scan_id)              # savunma derinliği: format koruması
    job, db_hosts = await _load_scan(scan_id, require_done=True)

    hosts: list[tuple] = []
    for db_host in db_hosts:
        host_result = repository.to_host_result(db_host)
        hosts.append((host_result, evaluate_host(host_result)))

    pdf_path = build_pdf_report(scan_id=scan_id, subnet=job.subnet, hosts=hosts)
    return FileResponse(
        path=pdf_path,
        media_type="application/pdf",
        filename=pdf_path.name,
    )


# ----------------------------------------------------------------- AD modülü
_TARGET_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]{0,252})$")
_DOMAIN_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,252})$")


class ADScanRequest(BaseModel):
    """Active Directory keşif isteği (Impacket).

    Şifre yalnızca bu request nesnesinde yaşar: JobState'e, DB'ye ve
    loglara asla yazılmaz (ProcessRunner redact ile maskelenir).
    """

    target: str                                  # DC IP'si veya FQDN
    domain: str                                  # örn: corp.local
    username: str
    password: str = Field(min_length=1, max_length=256)
    # not: "pwn" bu Literal'da KASTEN yok — sömürü yalnızca /ad/exploit
    # (confirm="SÖMÜR" + exploit_gate kapıları) üzerinden tetiklenebilir.
    tasks: list[Literal["dcinfo", "spn", "asrep", "dcsync", "acl", "cve"]] = Field(
        default_factory=lambda: ["dcinfo", "spn", "asrep"]
    )
    privesc_start: str | None = None   # acl görevi için opsiyonel başlangıç hesabı
    dc_hostname: str | None = None     # BloodHound için DC FQDN (örn: dc01.corp.local)

    @field_validator("target")
    @classmethod
    def _valid_target(cls, v: str) -> str:
        v = v.strip()
        if not _TARGET_RE.match(v):
            raise ValueError(
                "Hedef bir DC IP'si veya hostname olmalı "
                "(örn: 10.0.0.5 veya dc.corp.local)."
            )
        return v

    @field_validator("domain")
    @classmethod
    def _valid_domain(cls, v: str) -> str:
        v = v.strip()
        if not _DOMAIN_RE.match(v):
            raise ValueError("Geçerli bir domain adı girin (örn: corp.local).")
        return v

    @field_validator("username")
    @classmethod
    def _valid_username(cls, v: str) -> str:
        v = v.strip()
        if not v or any(ch in v for ch in "/:@ \t"):
            raise ValueError(
                "Kullanıcı adı boşluk, '/', ':' ve '@' içeremez "
                "(impacket hedef sözdizimi kısıtı)."
            )
        return v

    @field_validator("privesc_start")
    @classmethod
    def _valid_privesc_start(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        if not v:
            return None
        if any(ch in v for ch in "/:@ \t"):
            raise ValueError(
                "Başlangıç hesabı boşluk, '/', ':' ve '@' içeremez."
            )
        return v

    @field_validator("dc_hostname")
    @classmethod
    def _valid_dc_hostname(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        if not v:
            return None
        if not _TARGET_RE.match(v):
            raise ValueError(
                "DC Hostname geçerli bir FQDN olmalı "
                "(örn: dc01.corp.local)."
            )
        return v

    @model_validator(mode="after")
    def _tasks_nonempty(self):
        if not self.tasks:
            raise ValueError(
                "En az bir görev seçin (spn, asrep, dcsync, acl, cve)."
            )
        self.tasks = list(dict.fromkeys(self.tasks))   # tekrarı temizle, sırayı koru
        return self


class ADProbeRequest(ADScanRequest):
    """Check-only BaseADProbe isteği; tasks alanı bu uçta kullanılmaz."""

    probe: Literal["maq"] = "maq"
    # Çoklu DC'de zorunlu seçim; dc_fqdn JSON alias'ı da kabul edilir.
    target_dc: str | None = Field(
        default=None,
        validation_alias=AliasChoices("target_dc", "dc_fqdn"),
    )


class ExploitRequest(ADScanRequest):
    """Sömürü (Auto-Pwn) isteği — NoPac zinciri.

    ADScanRequest'in tüm doğrulamaları geçerlidir (target/domain/username/
    password/shifre gizliliği). Üstüne İKİ sömürü kapısı:
      1) confirm == "SÖMÜR"  — operatör niyeti (UI da çift onay gösterir)
      2) exploit_gate        — exploit_enabled + exploit_allowlist (endpoint
         403 döner; pwn() içinde ayrıca yeniden doğrulanır)
    tasks bu istekte zorla ["pwn"] yapılır.
    """

    confirm: str = Field(default="", max_length=16, validate_default=True)
    da_user: str = "Administrator"   # S4U2self ile taklit edilecek DA hesabı

    @field_validator("confirm")
    @classmethod
    def _valid_confirm(cls, v: str) -> str:
        from app.config import settings
        if not settings.exploit_require_confirm:
            return v or "SÖMÜR"          # onay kapalı: her değer/boş kabul
        v = v.strip()
        if v.upper() != "SÖMÜR":
            raise ValueError(
                "Sömürü için onay gerekli: alan tam olarak 'SÖMÜR' içermeli."
            )
        return "SÖMÜR"

    @field_validator("da_user")
    @classmethod
    def _valid_da_user(cls, v: str) -> str:
        v = (v or "").strip()
        if not v:
            return "Administrator"
        if any(ch in v for ch in "/:@ \t"):
            raise ValueError(
                "DA hesabı boşluk, '/', ':' ve '@' içeremez."
            )
        return v

    @model_validator(mode="after")
    def _force_pwn_task(self):
        self.tasks = ["pwn"]         # bu endpoint her zaman sömürü çalıştırır
        return self


@router.post("/scan/ad")
async def start_ad_scan(req: ADScanRequest) -> dict:
    """AD keşif job'ı başlatır (arka planda Impacket görevleri koşar)."""
    job_id = await job_manager.start_scan(
        req.target,
        profile="ad",
        module="ad",
        params={
            "domain": req.domain,
            "username": req.username,
            "password": req.password,     # sadece _run'a; state/DB yok
            "tasks": req.tasks,
            "privesc_start": req.privesc_start,
            "dc_hostname": req.dc_hostname,
        },
    )
    return {
        "job_id": job_id,
        "status": "started",
        "ws_url": f"/api/v1/ws/jobs/{job_id}",
        "detail_url": f"/api/v1/jobs/{job_id}",
    }


@router.post("/ad/cve-scan")
async def start_ad_cve_scan(req: ADScanRequest) -> dict:
    """Kritik CVE taraması (ZeroLogon/PrintNightmare/NoPac) — check-only job.

    AD pipeline'ının tamamını kullanır: job_manager ile asenkron koşar,
    ilerleme WebSocket'e push edilir, bulgular ortak havuza yazılır.
    Sömürü YAPILMAZ — yalnızca zafiyetin varlığı test edilir (cve görevi).
    """
    job_id = await job_manager.start_scan(
        req.target,
        profile="ad",
        module="ad",
        params={
            "domain": req.domain,
            "username": req.username,
            "password": req.password,     # sadece _run'a; state/DB yok
            "tasks": ["cve"],             # bu endpoint her zaman cve çalıştırır
            "privesc_start": None,
            "dc_hostname": req.dc_hostname,
        },
    )
    return {
        "job_id": job_id,
        "status": "started",
        "ws_url": f"/api/v1/ws/jobs/{job_id}",
        "detail_url": f"/api/v1/jobs/{job_id}",
    }


@router.post("/ad/probe")
async def start_ad_probe(req: ADProbeRequest) -> dict:
    """Beş aşamalı, check-only AD probe job'ı başlatır.

    Pre-flight koşulları sağlanmıyorsa tetik çalışmaz; sonuç ve cleanup
    durumu WebSocket/job results üzerinden raporlanır.
    """
    job_id = await job_manager.start_scan(
        req.target,
        profile="ad",
        module="ad_probe",
        params={
            "domain": req.domain,
            "username": req.username,
            "password": req.password,
            "probe": req.probe,
            "target_dc": req.target_dc or req.dc_hostname,
        },
    )
    return {
        "job_id": job_id,
        "status": "started",
        "ws_url": f"/api/v1/ws/jobs/{job_id}",
        "detail_url": f"/api/v1/jobs/{job_id}",
    }


@router.post("/ad/exploit")
async def start_ad_exploit(req: ExploitRequest) -> dict:
    """Sömürü (Auto-Pwn) job'ı — NoPac zinciriyle DA kimlikli bilet indirir.

    ÜÇ kapı birlikte: confirm="SÖMÜR" (model) + exploit_enabled +
    exploit_allowlist (gate). Kapalıysa iş hiç başlamaz → 403.
    Zincir: sahte hesap oluştur → SPN temizle → rename (42278) → getTGT →
    rename-geri → getST (42287) → DA ccache → temizlik. Ayrıntılar:
    app/scanners/nopac_exploiter.py
    """
    allowed, reason, _verified_ips = check_exploit_allowed(req.target)
    if not allowed:
        raise HTTPException(status_code=403, detail=reason)
    # Not: doğrulanmış IP burada job'a KOPYALANMAZ; NopacExploiter.pwn()
    # içinde kapı TEKRAR doğrulanır ve doğrulanmış IP'nin kendisi LDAP/KDC
    # bağlantılarında kullanılır (TOCTOU yok: kapı ile eylem aynı fonksiyonda).

    job_id = await job_manager.start_scan(
        req.target,
        profile="ad",
        module="ad",
        params={
            "domain": req.domain,
            "username": req.username,
            "password": req.password,     # sadece _run'a; state/DB yok
            "tasks": ["pwn"],             # bu endpoint her zaman sömürü çalıştırır
            "privesc_start": None,
            "dc_hostname": req.dc_hostname,
            "da_user": req.da_user,
        },
    )
    return {
        "job_id": job_id,
        "status": "started",
        "ws_url": f"/api/v1/ws/jobs/{job_id}",
        "detail_url": f"/api/v1/jobs/{job_id}",
        "warning": (
            "SAHTE HESAP OLUŞTURULDU/YENİDEN ADLANDIRILDI — iş bitince "
            "loglardaki temizlik satırını doğrulayın; silinemediyse hesabı "
            "elle silin."
        ),
    }


@router.get("/ad/findings")
async def get_ad_findings(job_id: str | None = None, limit: int = 100) -> dict:
    """AD bulgu havuzu — tüm işlerin veya tek işin zafiyetleri (JSON)."""
    async with async_session_factory() as session:
        rows = await repository.list_ad_findings(
            session, job_id, min(max(limit, 1), 500)
        )
    return {
        "findings": [
            {
                "id": r.id,
                "job_id": r.job_id,
                "kind": r.kind,
                "principal": r.principal,
                "spn": r.spn,
                "severity": r.severity,
                "message": r.message,
                "detail": r.detail or {},
                "created_at": r.created_at.isoformat(),
            }
            for r in rows
        ]
    }


# --------------------------------------------------------------- NAC modülü
_IFACE_RE  = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]{0,31})$")
_MAC_RE    = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")


class NacScanRequest(BaseModel):
    """MAC/vendor keşif isteği (arp-scan → nmap fallback).

    Yalnızca private subnet'ler kabul edilir; tarama genişliği /24 ile sınırlı.
    interface alan adı OS kısıtlamalarına uymak zorunda (harf/rakam/nokta/tire).
    """

    interface: str = Field(min_length=1, max_length=32)
    subnet: str

    @field_validator("interface")
    @classmethod
    def _valid_iface(cls, v: str) -> str:
        v = v.strip()
        if not _IFACE_RE.match(v):
            raise ValueError(
                "Interface adı geçersiz (örn: eth0, enp3s0, wlan0)."
            )
        return v

    @field_validator("subnet")
    @classmethod
    def _valid_subnet(cls, v: str) -> str:
        net = ipaddress.ip_network(v.strip(), strict=False)
        if not net.is_private:
            raise ValueError("Yalnızca private subnet'ler taranabilir.")
        if net.prefixlen < 24:
            raise ValueError(
                "NAC taraması en fazla /24 genişliğinde olabilir."
            )
        return str(net)


class NacBypassRequest(BaseModel):
    """NAC/MAB bypass isteği — interface MAC'ini hedef cihazla eşler.

    Yalnızca kendi yönetiminizde veya yazılı izin aldığınız ağlarda
    kullanılabilir. hold_seconds süresinin bitiminde orijinal MAC otomatik
    geri yüklenir; süreç erken kesilirse restore job ayrıca tetiklenir.
    """

    interface: str = Field(min_length=1, max_length=32)
    target_ip: str                     # hangi cihazın MAC'i taklit ediliyor
    target_mac: str                    # NacScan sonucundan gelen MAC
    target_vendor: str | None = None
    hold_seconds: int = Field(default=30, ge=5, le=300)

    @field_validator("interface")
    @classmethod
    def _valid_iface(cls, v: str) -> str:
        v = v.strip()
        if not _IFACE_RE.match(v):
            raise ValueError(
                "Interface adı geçersiz (örn: eth0, enp3s0, wlan0)."
            )
        return v

    @field_validator("target_ip")
    @classmethod
    def _valid_target_ip(cls, v: str) -> str:
        v = v.strip()
        try:
            addr = ipaddress.ip_address(v)
        except ValueError:
            raise ValueError("Hedef IP geçerli bir IPv4 adresi olmalı.")
        if not addr.is_private:
            raise ValueError(
                "Hedef IP private bir adres olmalı "
                "(yalnızca kendi ağınızda NAC bypass yapabilirsiniz)."
            )
        return str(addr)

    @field_validator("target_mac")
    @classmethod
    def _valid_mac(cls, v: str) -> str:
        v = v.strip().lower()
        if not _MAC_RE.match(v):
            raise ValueError(
                "Geçersiz MAC adresi formatı (örn: aa:bb:cc:dd:ee:ff)."
            )
        # Broadcast ve multicast MAC'leri reddet
        first_octet = int(v.split(":")[0], 16)
        if first_octet & 0x01:
            raise ValueError(
                "Multicast/broadcast MAC adresi taklit edilemez."
            )
        return v


@router.post("/nac/scan")
async def nac_scan(req: NacScanRequest) -> dict:
    """Subnet'teki cihazların MAC ve vendor bilgisini toplar.

    Önce arp-scan denenir; kurulu değilse veya başarısız olursa nmap -sn
    fallback'i kullanılır. Sonuçta her cihaz için 'is_trusted_hint' alanı
    döner (printer/camera/switch gibi NAC'ın otomatik güvenlediği türler).
    """
    from app.scanners.nac_scanner import NacScanner

    scanner = NacScanner()
    try:
        devices = await scanner.collect_arp_table(req.interface, req.subnet)
    except Exception:
        # arp-scan yoksa veya hata verdiyse nmap'e düş
        devices = await scanner.collect_from_nmap(req.subnet)

    return {
        "interface": req.interface,
        "subnet": req.subnet,
        "device_count": len(devices),
        "devices": [
            {
                "ip":             d.ip,
                "mac":            d.mac,
                "vendor":         d.vendor,
                "device_type":    d.device_type,
                "is_trusted_hint": d.device_type is not None,
            }
            for d in devices
        ],
    }


@router.post("/nac/bypass")
async def nac_bypass(req: NacBypassRequest) -> dict:
    """NAC/MAB bypass: seçilen cihazın MAC'ini interface'e uygular.

    Asenkron çalışır (job_id döner); ilerleme WebSocket üzerinden
    push edilir. hold_seconds bitince MAC otomatik geri yüklenir.

    GÜVENLİK: Bu endpoint sudo/root gerektiren 'ip link' çağrısı yapar.
    Üretim ortamında /etc/sudoers.d/ ile kısıtlı NOPASSWD tanımlanmalı.
    Yalnızca izin verilen ağlarda kullanın.
    """
    job_id = await job_manager.start_scan(
        req.target_ip,
        profile="nac",
        module="nac_bypass",
        params={
            "interface":     req.interface,
            "target_ip":     req.target_ip,
            "target_mac":    req.target_mac,
            "target_vendor": req.target_vendor,
            "hold_seconds":  req.hold_seconds,
        },
    )
    return {
        "job_id":    job_id,
        "status":    "started",
        "ws_url":    f"/api/v1/ws/jobs/{job_id}",
        "detail_url": f"/api/v1/jobs/{job_id}",
        "warning": (
            f"MAC {req.hold_seconds}s sonra otomatik geri yüklenecek. "
            "İşlem erken sonlanırsa 'ip link set <iface> address <original_mac>' "
            "ile manuel geri yükleme yapın."
        ),
    }


@router.post("/nac/restore")
async def nac_restore(interface: str, original_mac: str) -> dict:
    """Acil MAC geri yükleme — bypass job erken kesilirse manuel çağrılır.

    interface ve original_mac, bypass job'ı başlatılırken dönen loglarda
    (veya /jobs/{job_id} sonucunda 'original_mac' alanında) yer alır.
    """
    if not _IFACE_RE.match(interface.strip()):
        raise HTTPException(status_code=422, detail="Geçersiz interface adı.")
    if not _MAC_RE.match(original_mac.strip().lower()):
        raise HTTPException(status_code=422, detail="Geçersiz MAC adresi.")

    from app.services.nac_bypass import NacBypassService
    svc = NacBypassService()
    success = await svc.restore_mac(interface.strip(), original_mac.strip().lower())
    return {
        "success":   success,
        "interface": interface,
        "mac":       original_mac,
        "message":   "MAC geri yüklendi." if success else "Geri yükleme başarısız — root yetkisi gerekebilir.",
    }


# --------------------------------------------------------------- MitM modülü
class MitmStartRequest(BaseModel):
    """ARP poisoning + paket yakalama oturumu.

    Çift yönlü zehirleme: kurban ↔ gateway arası tüm trafik saldırgan
    üzerinden geçer. IP forwarding otomatik açılır; oturum bitince kapatılır.
    duration_sec süresince ARP paketi interval aralıklarla yenilenir;
    süre dolunca veya /mitm/stop/{job_id} çağrılınca ARP tabloları restore edilir.
    Yalnızca private IP aralıkları ve izin verilen ağlar kabul edilir.
    """

    interface:    str = Field(min_length=1, max_length=32)
    victim_ip:    str
    gateway_ip:   str
    duration_sec: int  = Field(default=120, ge=10, le=600)
    capture:      bool = True

    @field_validator("interface")
    @classmethod
    def _valid_iface(cls, v: str) -> str:
        v = v.strip()
        if not _IFACE_RE.match(v):
            raise ValueError("Interface adı geçersiz (örn: eth0, enp3s0, vboxnet0).")
        return v

    @field_validator("victim_ip", "gateway_ip")
    @classmethod
    def _private_only(cls, v: str) -> str:
        v = v.strip()
        try:
            addr = ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"Geçersiz IP adresi: {v}")
        if not addr.is_private:
            raise ValueError(
                f"{v} private bir IP olmalı — yalnızca kendi ağınızda MitM yapabilirsiniz."
            )
        return str(addr)

    @model_validator(mode="after")
    def _victim_ne_gateway(self):
        if self.victim_ip == self.gateway_ip:
            raise ValueError("Kurban IP ve gateway IP aynı olamaz.")
        return self


@router.post("/mitm/start")
async def mitm_start(req: MitmStartRequest) -> dict:
    """ARP poisoning + paket yakalama oturumu başlatır.

    job_id anında döner; ilerleme ve log WebSocket üzerinden push edilir.
    duration_sec sonunda ARP tabloları otomatik restore edilir.
    Yalnızca izin verilen ağlarda kullanın.
    """
    import asyncio as _asyncio

    job_id = await job_manager.start_scan(
        req.victim_ip,
        profile="mitm",
        module="mitm",
        params={
            "interface":    req.interface,
            "victim_ip":    req.victim_ip,
            "gateway_ip":   req.gateway_ip,
            "duration_sec": req.duration_sec,
            "capture":      req.capture,
        },
    )
    return {
        "job_id":     job_id,
        "status":     "started",
        "ws_url":     f"/api/v1/ws/jobs/{job_id}",
        "detail_url": f"/api/v1/jobs/{job_id}",
        "warning": (
            f"ARP poisoning {req.duration_sec}s sonra otomatik durdurulur "
            "ve restore yapılır. Yalnızca izin verilen ağlarda kullanın."
        ),
    }


@router.post("/mitm/stop/{job_id}")
async def mitm_stop(job_id: str) -> dict:
    """Çalışan MitM oturumunu durdur ve ARP tablolarını restore et.

    stop() sinyali gönderilir; spoof döngüsü bir sonraki iterasyonda durur
    ve finally bloğunda cleanup (ARP restore + IP forward kapat) çalışır.
    """
    from app.services.arp_spoofer import _spoofer
    _spoofer.stop(job_id)
    return {
        "job_id":  job_id,
        "message": "Durdurma sinyali gönderildi — ARP tabloları restore ediliyor.",
    }


@router.get("/mitm/captures/{job_id}")
async def mitm_captures(job_id: str) -> dict:
    """Tamamlanan MitM oturumunun paket yakalama istatistiklerini döner.

    Oturum bitmeden çağrılırsa o ana kadar biriken istatistikler döner.
    Hassas veriler (credential_hints) yalnızca bu endpoint üzerinden erişilebilir;
    DB'ye ve loglara yazılmaz.
    """
    state = await job_manager.get_state(job_id)
    if state is None:
        raise HTTPException(status_code=404, detail="Job bulunamadı")
    serialized = job_manager.serialize(state)
    results = serialized.get("results") or []
    return {
        "job_id":  job_id,
        "status":  serialized.get("status"),
        "results": results,
    }