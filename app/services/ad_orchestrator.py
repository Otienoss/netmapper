"""Active Directory keşif orkestratörü (Impacket görevleri).

Akış (WebSocket'e job_manager üzerinden push edilir):
  DISCOVERING → SCANNING (görev başına: spn/asrep/dcsync) → NORMALIZING
  → DONE (job_manager._run)

Kalıcılık: bulgular hem ortak havuza (ad_findings tablosu) hem de
data/raw/ad_findings_{job_id}.json dosyasına yazılır (hash'ler dahil).
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from app.config import settings
from app.normalization.ad_parser import (
    parse_getnpusers,
    parse_getuserspns,
    parse_secretsdump,
)
from app.normalization.bloodhound_parser import parse_bloodhound_zip
from app.normalization.schema import ADFinding
from app.scanners.bloodhound_scanner import BloodhoundScanner
from app.scanners.cve_scanner import CveScanner
from app.scanners.impacket_scanner import ImpacketScanner
from app.scanners.ldap_discovery import query_domain_controllers
from app.scanners.nopac_exploiter import NopacExploiter
from app.services.job_manager import JobStatus, job_manager
from app.services.path_finder import PathFinder
from app.storage import repository
from app.storage.database import async_session_factory

TASK_TR = {
    "dcinfo": "Domain Controller envanteri (salt-okunur LDAP)",
    "spn": "Kerberoasting (GetUserSPNs)",
    "asrep": "AS-REP Roast (GetNPUsers)",
    "dcsync": "DCSync / NTDS dökümü (secretsdump)",
    "acl": "ACL / BloodHound keşfi (privesc yol analizi)",
    "cve": "Kritik CVE tarayıcısı (ZeroLogon/PrintNightmare/NoPac)",
    "pwn": "SÖMÜR — NoPac otomatik sömürü (CVE-2021-42278/42287)",
}
DEFAULT_TARGET_GROUP = "DOMAIN ADMINS"


class ADOchestrator:
    def __init__(self):
        self.impacket = ImpacketScanner()
        self.bloodhound = BloodhoundScanner()
        self.cve = CveScanner()
        self.exploiter = NopacExploiter()

    async def run(
        self,
        job_id: str,
        *,
        target: str,
        domain: str,
        username: str,
        password: str,
        tasks: list[str],
        privesc_start: str | None = None,
        dc_hostname: str | None = None,
        da_user: str | None = None,
    ) -> list[ADFinding]:
        await job_manager.update(job_id, status=JobStatus.DISCOVERING)
        await job_manager.log(
            job_id,
            f"AD keşif başladı: DC={target} domain={domain} "
            f"kullanıcı={domain}\\{username} görevler={','.join(tasks)}",
        )

        findings: list[ADFinding] = []
        errors: list[str] = []
        total = len(tasks)

        for i, task in enumerate(tasks, start=1):
            await job_manager.update(
                job_id, status=JobStatus.SCANNING,
                progress={"task_total": total, "task_done": i - 1},
            )
            try:
                if task == "dcinfo":
                    await job_manager.log(
                        job_id, f"{TASK_TR[task]} başlatıldı…"
                    )
                    records = await query_domain_controllers(
                        domain=domain, target=target,
                        username=username, password=password,
                    )
                    found = [self._dc_finding(record) for record in records]
                    await job_manager.log(
                        job_id,
                        f"DC envanteri: {len(found)} Domain Controller — "
                        + (", ".join(
                            f"{r['sAMAccountName']} ({r.get('dNSHostName') or 'FQDN yok'})"
                            for r in records
                        ) if records else "kayıt yok"),
                    )
                elif task == "spn":
                    await job_manager.log(
                        job_id, f"{TASK_TR[task]} başlatıldı…"
                    )
                    stdout, hash_file = await self.impacket.kerberoast(
                        target, domain, username, password
                    )
                    found = parse_getuserspns(stdout, hash_file)
                    await job_manager.log(
                        job_id, f"Kerberoast: {len(found)} SPN hesabı bulundu"
                    )
                elif task == "asrep":
                    await job_manager.log(
                        job_id, f"{TASK_TR[task]} başlatıldı…"
                    )
                    stdout, hash_file = await self.impacket.asrep(
                        target, domain, username, password
                    )
                    found = parse_getnpusers(stdout, hash_file)
                    await job_manager.log(
                        job_id, f"AS-REP: {len(found)} pre-auth kapalı hesap"
                    )
                elif task == "dcsync":
                    await job_manager.log(
                        job_id, f"{TASK_TR[task]} başlatıldı…"
                    )
                    stdout = await self.impacket.dcsync(
                        target, domain, username, password
                    )
                    found = parse_secretsdump(stdout)
                    await job_manager.log(
                        job_id, f"DCSync: {len(found)} hesap hash'i"
                    )
                elif task == "acl":
                    await job_manager.log(
                        job_id, f"{TASK_TR[task]}: veri toplanıyor…"
                    )
                    zip_path = await self.bloodhound.scan(
                        domain=domain, username=username,
                        password=password, dc_ip=target,
                        dc_hostname=dc_hostname,
                    )
                    graph = parse_bloodhound_zip(zip_path)
                    await job_manager.log(
                        job_id,
                        f"BloodHound: {len(graph.sid_to_name)} nesne, "
                        f"{len(graph.edges)} kenar, "
                        f"{len(graph.user_sids)} kullanıcı hesabı",
                    )
                    finder = PathFinder(graph)
                    if privesc_start:
                        res = finder.shortest_path_to(
                            privesc_start, DEFAULT_TARGET_GROUP
                        )
                    else:
                        res = finder.shortest_path_from_users(
                            DEFAULT_TARGET_GROUP
                        )
                    found = [self._privesc_finding(res, privesc_start)]
                    if res.get("found"):
                        path_desc = res["hops"][0]["from"] + "".join(
                            f" -[{h['right']}]-> {h['to']}" for h in res["hops"]
                        ) if res["hops"] else res.get("start", "?")
                        await job_manager.log(
                            job_id,
                            f"Privesc: {res['hop_count']} hop → "
                            f"{res['target']}: {path_desc}",
                        )
                    else:
                        await job_manager.log(
                            job_id, f"Privesc yol bulunamadı: {res.get('reason')}"
                        )
                elif task == "cve":
                    await job_manager.log(
                        job_id, f"{TASK_TR[task]} başlatıldı (check-only)…"
                    )
                    results = await self.cve.scan(
                        domain=domain, dc_ip=target,
                        username=username, password=password,
                        dc_hostname=dc_hostname,
                    )
                    found = [self._cve_finding(r, target) for r in results]
                    open_count = sum(1 for r in results if r.get("vulnerable"))
                    await job_manager.log(
                        job_id,
                        f"CVE: {len(results)} kontrol, {open_count} açık — "
                        + ", ".join(
                            f"{r['cve']}={'AÇIK' if r.get('vulnerable') else 'yok/kontrol'}"
                            for r in results
                        ),
                    )
                elif task == "pwn":
                    await job_manager.log(
                        job_id,
                        f"{TASK_TR[task]} başlatıldı — GERÇEK AD DEĞİŞİKLİĞİ "
                        "yapar (sahte hesap oluşturur/yeniden adlandırır)…",
                    )

                    async def _pwn_step(msg: str) -> None:
                        await job_manager.log(job_id, f"  · {msg}")

                    outcome = await self.exploiter.pwn(
                        domain=domain, target=target,
                        username=username, password=password,
                        da_user=da_user or "Administrator",
                        dc_hostname=dc_hostname,
                        on_step=_pwn_step,
                        job_id=job_id,
                    )
                    # temizlik durumu işlem sonucundan BAĞIMSIZ raporlanır
                    cu = outcome.get("cleanup") or {}
                    if cu.get("status") == "unknown":
                        await job_manager.log(
                            job_id,
                            "[!] HESAP VARLIĞI BELİRSİZ — temizlik gerekip "
                            f"gerekmediği bilinmiyor: {cu.get('error')} — "
                            f"{cu.get('manual_hint')}",
                        )
                    elif cu.get("attempted") and not cu.get("verified"):
                        await job_manager.log(
                            job_id,
                            f"[!] TEMİZLİK DOĞRULANAMADI ({cu.get('status')}): "
                            f"{cu.get('error')} — elle silin: {cu.get('manual_hint')}",
                        )
                    # kapı/preflight engeli → görev hatası (bulgu üretme)
                    if outcome.get("outcome") == "failed":
                        raise RuntimeError(outcome.get("error") or "sömürü engellendi")
                    found = [self._pwn_finding(outcome)]
                    verb = (
                        "tamam (DA bileti DOĞRULANDI)"
                        if outcome.get("outcome") == "exploited"
                        else f"tamam ({outcome.get('outcome')})"
                    )
                    await job_manager.log(
                        job_id,
                        f"Sömürü {verb}: {outcome.get('da_user')} → "
                        f"{outcome.get('da_ccache') or '—'} "
                        f"(temizlik: {cu.get('status', 'skipped')})",
                    )
                else:
                    found = []
                    await job_manager.log(job_id, f"Bilinmeyen görev atlandı: {task}")
                findings.extend(found)
            except Exception as e:
                errors.append(f"{task}: {e}")
                await job_manager.log(job_id, f"Görev {task} başarısız: {e}")
            finally:
                await job_manager.update(
                    job_id,
                    progress={"task_total": total, "task_done": i},
                )

        # hiçbir görev üretmediyse ve hepsi hataysa → job'ı hata olarak bitir
        if not findings and errors and len(errors) == total:
            raise RuntimeError("Tüm AD görevleri başarısız: " + "; ".join(errors))

        await job_manager.update(job_id, status=JobStatus.NORMALIZING)
        await self._persist(
            job_id, findings, target=target, domain=domain,
            username=username, tasks=tasks,
        )
        await job_manager.log(
            job_id,
            f"AD keşif tamam: {len(findings)} bulgu "
            f"(havuz + data/raw/ad_findings_{job_id[:8]}.json)",
        )
        return findings

    async def _persist(
        self, job_id: str, findings: list[ADFinding], *,
        target: str, domain: str, username: str, tasks: list[str],
    ) -> None:
        """Bulguları ortak havuza (DB) ve JSON dosyasına yazar."""
        # 1) DB havuzu
        try:
            async with async_session_factory() as session:
                await repository.save_ad_findings(session, job_id, findings)
        except Exception as e:
            # JSON her koşulda yazılsın
            await job_manager.log(job_id, f"Havuz kaydı başarısız (JSON'a yazılacak): {e}")

        # 2) JSON dosyası (hash'ler dahil — pentest kanıtı)
        out = Path(settings.raw_output_dir) / f"ad_findings_{job_id}.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(
                {
                    "job_id": job_id,
                    "target": target,
                    "domain": domain,
                    "username": username,   # şifre ASLA yazılmaz
                    "tasks": tasks,
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "findings": [f.model_dump(mode="json") for f in findings],
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

    @staticmethod
    def _dc_finding(record: dict) -> ADFinding:
        """Salt-okunur DC LDAP kaydını ortak havuz bulgusuna çevirir."""
        sam = record["sAMAccountName"]
        fqdn = record.get("dNSHostName")
        return ADFinding(
            kind="dcinfo",
            principal=sam,
            severity="info",
            message=(
                f"Domain Controller makine hesabı (sAMAccountName): {sam}"
                + (f" — dNSHostName: {fqdn}" if fqdn else "")
            ),
            detail=record,
        )

    @staticmethod
    def _privesc_finding(res: dict, privesc_start: str | None) -> ADFinding:
        """PathFinder sonucunu ortak havuz bulgusuna çevirir."""
        if res.get("found"):
            hops = res.get("hops") or []
            path_desc = (
                hops[0]["from"] + "".join(
                    f" -[{h['right']}]-> {h['to']}" for h in hops
                )
                if hops else res.get("start", "?")
            )
            return ADFinding(
                kind="privesc",
                principal=res.get("start") or privesc_start or "?",
                severity="high",
                message=(
                    f"Yetki yükseltme yolu ({res['hop_count']} hop): "
                    f"{path_desc}"
                ),
                detail={
                    "target_group": res.get("target"),
                    "hop_count": res.get("hop_count"),
                    "hops": hops,
                    "auto_selected": not privesc_start,
                },
            )
        return ADFinding(
            kind="privesc",
            principal=privesc_start or "*",
            severity="info",
            message=(
                f"BloodHound: {DEFAULT_TARGET_GROUP} yolU bulunamadı — "
                f"{res.get('reason', 'bilinmeyen')}"
            ),
            detail={"target_group": DEFAULT_TARGET_GROUP, "auto": not privesc_start},
        )

    @staticmethod
    def _cve_finding(r: dict, target: str) -> ADFinding:
        """CveScanner sonucunu ortak havuz bulgusuna çevirir."""
        cve = str(r.get("cve") or "?")
        vuln = bool(r.get("vulnerable"))
        return ADFinding(
            kind="cve",
            principal=cve,
            severity="high" if vuln else "info",
            message=(
                f"{cve}: KRİTİK ZAFİYET AÇIK"
                if vuln else f"{cve}: kontrol tamamlandı — açık kanıt yok"
            ),
            detail={
                "cve": cve,
                "vulnerable": vuln,
                "target": target,
                "description": str(r.get("detail") or ""),
            },
        )

    # Görev 6 — sonuç sınıflandırması: bilet dosyasının varlığı TEK BAŞINA
    # "DA erişimi kanıtı" DEĞİLDİR; exploiter ccache magic+boyut doğrulaması
    # yapar ve outcome alanını üretir. Burada kanıt temelli severity/özet.
    _PWN_SEVERITY = {
        "exploited": "critical",     # DA ccache doğrulandı (magic+boyut)
        "validated": "high",         # 42278 KANITLI (spoof adla TGT), ST yok
        "attempted": "medium",       # zincir başladı, TGT'ye ulaşamadı
        "inconclusive": "medium",    # getST dedi ama dosya doğrulanamadı
        "failed": "info",            # kapı/preflight — AD değişikliği olmadı
    }

    @staticmethod
    def _pwn_finding(outcome: dict) -> ADFinding:
        """NopacExploiter.pwn sonucunu ortak havuz bulgusuna çevirir (T6).

        Her outcome için AYRI bulgu üretir; severity kanıt gücüne göre
        seçilir; temizlik durumu detail'de bağımsız alan olarak taşınır.
        """
        oc = str(outcome.get("outcome") or "attempted")
        cu = outcome.get("cleanup") or {}
        cleanup_failed = bool(
            (cu.get("attempted") and not cu.get("verified"))
            or cu.get("status") == "unknown"     # hesap varlığı belirsiz → uyar
        )
        severity = ADOchestrator._PWN_SEVERITY.get(oc, "medium")
        da_user = str(outcome.get("da_user") or "?")
        spn = outcome.get("spn")

        _summary = {
            "exploited": (
                f"Sömürü BAŞARILI (NoPac): '{da_user}' kimliğiyle {spn} "
                "bileti ALINDI VE DOĞRULANDI (ccache magic+boyut) — Domain "
                f"Admin erişimi kanıtlandı. Bilet: {outcome.get('da_ccache')}"
            ),
            "validated": (
                f"Zafiyet DOĞRULANDI (CVE-2021-42278): sahte adla TGT "
                f"alınabildi ({outcome.get('computer_account')}) ancak son "
                f"servis bileti ALINAMADI — erişim KANITLANMADI. Hata: "
                f"{outcome.get('error')}"
            ),
            "attempted": (
                f"Sömürü denendi ama TGT aşamasına ulaşılamadı — zafiyet "
                f"kanıtlanmadı, erişim yok. Hata: {outcome.get('error')}"
            ),
            "inconclusive": (
                f"SONUÇ BELİRSİZ: getST bilet dosyası üretti ama DOĞRULANAMADI "
                f"(ccache magic/boyut) — erişim kanıtı SAYILMADI. Hata: "
                f"{outcome.get('error')}"
            ),
            "failed": (
                f"Sömürü ENGELLENDİ (kapı/preflight): {outcome.get('error')}"
            ),
        }.get(oc, f"Sömürü sonucu: {oc} — {outcome.get('error')}")

        return ADFinding(
            kind="pwn",
            principal=da_user,
            spn=spn,
            severity=severity,
            message=_summary,
            detail={
                "outcome": oc,
                "error_kind": outcome.get("error_kind"),
                "account_state": outcome.get("account_state"),
                "success_claim": oc == "exploited",   # tek başına kanıt eşiği
                "error": outcome.get("error"),
                "ccache_path": outcome.get("da_ccache"),   # None → kanıt yok
                "tgt_ccache_path": outcome.get("tgt_ccache"),
                "computer_account": outcome.get("computer_account"),
                "spn": spn,
                "dc_fqdn": outcome.get("dc_fqdn"),
                "cleanup_status": cu.get("status"),
                "cleanup_verified": cu.get("verified", False),
                "cleanup_error": cu.get("error"),
                "cleanup_failed": cleanup_failed,
                "manual_hint": cu.get("manual_hint"),
                "chain": "addcomputer→SPN-temizle→rename(42278)→getTGT"
                         "→rename-geri→getST(42287)→temizlik+doğrulama",
            },
        )
