import asyncio
from pathlib import Path

from fastapi.testclient import TestClient
import pytest
from pydantic import ValidationError
from starlette.websockets import WebSocketDisconnect

from app.api.routes import ScanRequest
from app.main import app
from app.normalization.schema import HostResult, ServiceInfo
from app.services.job_manager import JobStatus, job_manager
from app.storage import repository
from app.storage.database import async_session_factory, init_db


def test_health():
    with TestClient(app) as client:   # lifespan -> init_db çalışır
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}


def test_root_serves_ui():
    """/ adresi artık 3 panelli NetMapper Dashboard kabuğunu döndürür."""
    with TestClient(app) as client:
        resp = client.get("/")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "NetMapper Dashboard" in resp.text
        for panel in ("dashboard.html", "yeni_tarama.html", "host_envanteri.html"):
            assert f"/static/panels/{panel}" in resp.text


def test_panels_served():
    """Dört panel de statik dizinden sunulur (+ AD'de acl görevi)."""
    with TestClient(app) as client:
        for panel in ("dashboard", "yeni_tarama", "host_envanteri", "ad_modulu"):
            resp = client.get(f"/static/panels/{panel}.html")
            assert resp.status_code == 200, panel
            assert "NetMapper" in resp.text
        ad = client.get("/static/panels/ad_modulu.html").text
        assert 'value="acl"' in ad           # BloodHound görev checkbox'ı
        assert 'id="privesc_start"' in ad    # opsiyonel başlangıç hesabı
        assert 'value="cve"' in ad           # Kritik CVE görev checkbox'ı


def test_public_subnet_allowed():
    """Private kısıtı kaldırıldı: public aralıklar da kabul edilir
    (model düzeyinde test edilir — gerçek tarama başlatılmaz)."""
    assert ScanRequest(subnet="8.8.8.0/24").subnet == "8.8.8.0/24"
    assert ScanRequest(subnet="8.8.8.8").subnet == "8.8.8.8/32"


def test_invalid_subnet_rejected():
    with TestClient(app) as client:
        resp = client.post("/api/v1/scan", json={"subnet": "bu-bir-cidr-degil"})
        assert resp.status_code == 422


def test_unknown_job_returns_404():
    with TestClient(app) as client:
        resp = client.get("/api/v1/jobs/olmayan-job")
        assert resp.status_code == 404


def test_report_of_unknown_scan_returns_404():
    with TestClient(app) as client:
        resp = client.get("/api/v1/scans/olmayan-scan/report")
        assert resp.status_code == 404


def test_single_ip_accepted():
    """Tek IP girilebilmeli (/32'ye normalize edilir, tarama başlatılmaz)."""
    req = ScanRequest(subnet="192.168.1.10")
    assert req.subnet == "192.168.1.10/32"


def test_single_private_ip_accepted():
    assert ScanRequest(subnet="10.0.0.5").subnet == "10.0.0.5/32"


def test_wider_than_slash24_rejected():
    """/24'ten geniş aralık (ör. /8) engellenir — dev taramaları önlemek için."""
    with pytest.raises(ValidationError):
        ScanRequest(subnet="10.0.0.0/8")


def _seed_finished_scan(job_id: str, subnet: str) -> None:
    """DB'ye tamamlanmış bir tarama yazar (tarama subprocess'i çalıştırmaz)."""
    async def _inner():
        await init_db()
        async with async_session_factory() as session:
            await repository.create_job(session, job_id, subnet)
            await repository.save_scan_results(session, job_id, [
                HostResult(ip="192.168.1.50", services=[
                    ServiceInfo(port=23, protocol="tcp", state="open",
                                service_name="telnet"),
                    ServiceInfo(port=80, protocol="tcp", state="open",
                                service_name="http"),
                ]),
            ])
            await repository.set_job_status(session, job_id, "done")
    asyncio.run(_inner())


def test_job_db_fallback_and_pdf_report():
    """Regresyon: in-memory cache yokken job DB'den okunur (async lazy-load
    500 vermemeli) ve rapor endpoint'i gerçek PDF döndürür."""
    job_id = "testreportregression01"
    _seed_finished_scan(job_id, "192.168.1.0/24")

    with TestClient(app) as client:
        # job_manager önbelleğinde yok → repository DB yolu çalışır
        job = client.get(f"/api/v1/jobs/{job_id}")
        assert job.status_code == 200
        body = job.json()
        assert body["status"] == "done"
        assert body["subnet"] == "192.168.1.0/24"
        assert body["job_id"] == job_id
        assert isinstance(body["logs"], list)

        report = client.get(f"/api/v1/scans/{job_id}/report")
        assert report.status_code == 200
        assert report.headers["content-type"] == "application/pdf"
        assert report.content[:4] == b"%PDF"

    pdf_path = Path(f"data/reports/report_{job_id}.pdf")
    if pdf_path.exists():
        pdf_path.unlink()  # test artifact'ını temizle


def test_scan_results_json():
    """Arayüzün beslendiği JSON: host + servis + risk bulguları dolu gelmeli."""
    job_id = "testresultsjson01"
    _seed_finished_scan(job_id, "192.168.1.0/24")

    with TestClient(app) as client:
        resp = client.get(f"/api/v1/scans/{job_id}/results")
        assert resp.status_code == 200
        body = resp.json()
        assert body["scan_id"] == job_id
        assert body["status"] == "done"
        assert body["subnet"] == "192.168.1.0/24"

        host = body["hosts"][0]
        assert host["ip"] == "192.168.1.50"
        assert host["risk_level"] == "high"       # telnet 23 → yüksek
        assert host["risk_score"] == 75

        telnet = next(s for s in host["services"] if s["port"] == 23)
        assert telnet["risk_level"] == "high"
        assert any("Telnet" in r for r in telnet["reasons"])
        http = next(s for s in host["services"] if s["port"] == 80)
        assert http["risk_level"] == "low"


def test_scan_results_unknown_404():
    with TestClient(app) as client:
        assert client.get("/api/v1/scans/olmayan-scan/results").status_code == 404


# --------------------------------------------------------------- profiller
def test_scan_profiles_and_ports_validation():
    """quick/full/custom profilleri + port listesi doğrulaması."""
    assert ScanRequest(subnet="192.168.1.10", profile="quick").profile == "quick"
    req = ScanRequest(subnet="192.168.1.0/24", profile="custom", ports="22,80,443")
    assert req.ports == "22,80,443"

    with pytest.raises(ValidationError):        # custom'da port zorunlu
        ScanRequest(subnet="192.168.1.0/24", profile="custom")
    with pytest.raises(ValidationError):        # shell enjeksiyonu / bozuk format
        ScanRequest(subnet="192.168.1.0/24", profile="custom", ports="22; rm -rf /")
    with pytest.raises(ValidationError):        # bilinmeyen profil
        ScanRequest(subnet="192.168.1.0/24", profile="aggressive")


# ------------------------------------------------------- dashboard verileri
def test_scans_stats_hosts_endpoints():
    """/scans, /stats, /hosts dashboard'u besleyen uçlar."""
    job_id = "testdashboarddata01"
    _seed_finished_scan(job_id, "192.168.1.0/24")

    with TestClient(app) as client:
        scans = client.get("/api/v1/scans").json()["scans"]
        mine = next(s for s in scans if s["scan_id"] == job_id)
        assert mine["status"] == "done"
        assert mine["subnet"] == "192.168.1.0/24"
        assert mine["profile"] == "full"

        stats = client.get("/api/v1/stats").json()
        assert stats["last_scan"] is not None
        assert stats["total_hosts"] >= 1
        assert stats["open_ports"] >= 2
        assert stats["high_risk"] >= 1          # seeded host'ta telnet var

        hosts = client.get("/api/v1/hosts").json()["hosts"]
        h = next(x for x in hosts if x.get("scan_id") == job_id)
        assert h["ip"] == "192.168.1.50"
        assert h["risk_level"] == "high"
        assert any(s["port"] == 23 for s in h["services"])


# ------------------------------------------------------------- WebSocket
def test_ws_unknown_job_closes_with_4404():
    with TestClient(app) as client:
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect("/api/v1/ws/jobs/olmayan-job") as ws:
                ws.receive_json()


def test_ws_pushes_terminal_state():
    """Yeni abone anında mevcut durumu alır; done'da bağlantı kendiliğinden biter."""
    job_id = "testwsdone01"
    job_manager.create_job(job_id, "192.168.1.50/32", "quick")

    async def finish():
        await job_manager.update(job_id, status=JobStatus.DONE)
    asyncio.run(finish())

    with TestClient(app) as client:
        with client.websocket_connect(f"/api/v1/ws/jobs/{job_id}") as ws:
            payload = ws.receive_json()
    assert payload["job_id"] == job_id
    assert payload["status"] == "done"
    assert payload["subnet"] == "192.168.1.50/32"
    assert payload["profile"] == "quick"


# ------------------------------------------------------------- AD modülü
def test_ad_request_validation():
    from app.api.routes import ADScanRequest
    ok = ADScanRequest(
        target="10.0.0.5", domain="corp.local",
        username="alice", password="p@ss:word!",
    )
    assert ok.tasks == ["dcinfo", "spn", "asrep"]  # varsayılan görevler
    assert ok.target == "10.0.0.5"

    # FQDN hedef de geçerli
    assert ADScanRequest(
        target="dc.corp.local", domain="corp.local",
        username="a", password="x", tasks=["dcsync"],
    ).tasks == ["dcsync"]

    # --------------------------------------------------- acl / privesc_start
    req = ADScanRequest(
        target="dc.corp.local", domain="corp.local",
        username="a", password="x", tasks=["acl"],
        privesc_start="sql_svc",
    )
    assert req.tasks == ["acl"] and req.privesc_start == "sql_svc"
    # boş/None kabul (otomatik mod)
    assert ADScanRequest(
        target="dc.corp.local", domain="corp.local",
        username="a", password="x", tasks=["acl"],
        privesc_start="   ",
    ).privesc_start is None
    with pytest.raises(ValidationError):                 # geçersiz sözdizimi
        ADScanRequest(
            target="dc.corp.local", domain="corp.local",
            username="a", password="x", tasks=["acl"],
            privesc_start="sql/svc",                      # '/' yasak
        )

    # --------------------------------------------------- dc_hostname (BloodHound)
    req2 = ADScanRequest(
        target="10.0.0.5", domain="corp.local",
        username="a", password="x", tasks=["acl"],
        dc_hostname="winterfell.north.sevenkingdoms.local",
    )
    assert req2.dc_hostname == "winterfell.north.sevenkingdoms.local"
    assert req2.privesc_start is None
    # boş/None kabul → scanner fallback dc.<domain> kullanır
    assert ADScanRequest(
        target="10.0.0.5", domain="corp.local",
        username="a", password="x", tasks=["acl"], dc_hostname="  ",
    ).dc_hostname is None
    with pytest.raises(ValidationError):                 # FQDN kuralları
        ADScanRequest(
            target="10.0.0.5", domain="corp.local",
            username="a", password="x", tasks=["acl"],
            dc_hostname="geçersiz hostname!",
        )

    with pytest.raises(ValidationError):         # geçersiz hedef
        ADScanRequest(target="geçersiz hedef!", domain="corp.local",
                      username="a", password="x")
    with pytest.raises(ValidationError):         # şifre zorunlu
        ADScanRequest(target="10.0.0.5", domain="corp.local",
                      username="a", password="")
    with pytest.raises(ValidationError):         # username kısıtları
        ADScanRequest(target="10.0.0.5", domain="corp.local",
                      username="do main", password="x")
    with pytest.raises(ValidationError):         # boş görev listesi
        ADScanRequest(target="10.0.0.5", domain="corp.local",
                      username="a", password="x", tasks=[])


def test_start_ad_scan_endpoint(monkeypatch):
    """/scan/ad — job_manager.start_scan doğru argümanlarla çağrılır (tarama yok)."""
    captured = {}

    async def fake_start(subnet, **kwargs):
        captured.update({"subnet": subnet, **kwargs})
        return "fakeadjob01"

    monkeypatch.setattr(job_manager, "start_scan", fake_start)

    with TestClient(app) as client:
        resp = client.post("/api/v1/scan/ad", json={
            "target": "10.0.0.5", "domain": "corp.local",
            "username": "alice", "password": "Secret123",
            "tasks": ["spn", "dcsync"],
            "dc_hostname": "winterfell.north.sevenkingdoms.local",
        })
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["job_id"] == "fakeadjob01"
    assert body["ws_url"] == "/api/v1/ws/jobs/fakeadjob01"

    assert captured["subnet"] == "10.0.0.5"
    assert captured["module"] == "ad"
    assert captured["profile"] == "ad"
    assert captured["params"]["domain"] == "corp.local"
    assert captured["params"]["tasks"] == ["spn", "dcsync"]
    assert captured["params"]["password"] == "Secret123"
    assert captured["params"]["dc_hostname"] == "winterfell.north.sevenkingdoms.local"


def test_ad_cve_scan_endpoint(monkeypatch):
    """/ad/cve-scan — her zaman tasks=["cve"] ile asenkron job başlatır."""
    captured = {}

    async def fake_start(subnet, **kwargs):
        captured.update({"subnet": subnet, **kwargs})
        return "fakecvejob01"

    monkeypatch.setattr(job_manager, "start_scan", fake_start)

    with TestClient(app) as client:
        resp = client.post("/api/v1/ad/cve-scan", json={
            "target": "10.0.0.5", "domain": "corp.local",
            "username": "alice", "password": "Secret123",
            "tasks": ["spn"],                       # göz ardı edilir → cve zorunlu
            "dc_hostname": "dc01.corp.local",
        })
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["job_id"] == "fakecvejob01"
    assert body["ws_url"] == "/api/v1/ws/jobs/fakecvejob01"

    assert captured["subnet"] == "10.0.0.5"
    assert captured["profile"] == "ad"
    assert captured["module"] == "ad"
    assert captured["params"]["tasks"] == ["cve"]
    assert captured["params"]["dc_hostname"] == "dc01.corp.local"
    assert captured["params"]["password"] == "Secret123"

    # hedef doğrulaması endpoint için de geçerli (aynı request modeli)
    with TestClient(app) as client:
        bad = client.post("/api/v1/ad/cve-scan", json={
            "target": "10.0.0.5; rm -rf /", "domain": "corp.local",
            "username": "alice", "password": "x",
        })
    assert bad.status_code == 422

    # ADScanRequest cve görevini kabul eder
    ok = __import__("app.api.routes", fromlist=["ADScanRequest"]).ADScanRequest(
        target="10.0.0.5", domain="corp.local",
        username="a", password="x", tasks=["cve"],
    )
    assert ok.tasks == ["cve"]



def test_ad_findings_pool_endpoint():
    """Havuz: seed edilen bulgular JSON olarak listelenir; bilinmeyen kapsam boş."""
    from app.normalization.schema import ADFinding

    job_id = "jobadpool01"

    async def _seed():
        await init_db()
        async with async_session_factory() as session:
            await repository.create_job(session, job_id, "10.0.0.5", "ad", "ad")
            await repository.save_ad_findings(session, job_id, [
                ADFinding(kind="kerberoast", principal="sqladmin",
                          spn="MSSQLSvc/sql:1433", severity="high",
                          message="Kerberoast + boş şifre",
                          detail={"hash": "$krb5tgs$23$*sqladmin$..."}),
            ])
    asyncio.run(_seed())

    with TestClient(app) as client:
        pool = client.get("/api/v1/ad/findings").json()["findings"]
        mine = next(f for f in pool if f["job_id"] == job_id)
        assert mine["principal"] == "sqladmin"
        assert mine["severity"] == "high"
        assert mine["detail"]["hash"].startswith("$krb5tgs$")

        scoped = client.get(f"/api/v1/ad/findings?job_id={job_id}").json()["findings"]
        assert len(scoped) == 1

        empty = client.get("/api/v1/ad/findings?job_id=yokjob").json()["findings"]
        assert empty == []


# --------------------------------------------------- SÖMÜR (Auto-Pwn) endpoint
_EXPLOIT_BODY = {
    "target": "10.13.38.5", "domain": "corp.local",
    "username": "alice", "password": "Secret123",
    "confirm": "SÖMÜR", "da_user": "Administrator",
    "dc_hostname": "dc01.corp.local",
}


def test_ad_exploit_requires_confirm():
    """confirm alanı olmadan veya yanlışsa istek hiç işlenmez (422)."""
    from app.api.routes import ExploitRequest
    from pydantic import ValidationError

    body = {k: v for k, v in _EXPLOIT_BODY.items() if k != "confirm"}
    with pytest.raises(ValidationError):
        ExploitRequest(**body)
    with pytest.raises(ValidationError):            # yanlış onay
        ExploitRequest(**{**body, "confirm": "evet"})


def test_ad_exploit_gate_off_returns_403():
    """Varsayılan (kapalı) sunucuda 403 — iş hiç başlamaz."""
    with TestClient(app) as client:
        resp = client.post("/api/v1/ad/exploit", json=_EXPLOIT_BODY)
    assert resp.status_code == 403
    assert "kapalı" in resp.json()["detail"]


def test_ad_exploit_not_allowlisted_returns_403(monkeypatch):
    """Açık ama hedef allowlist dışı → 403 ve hedef IP gerekçede görünür."""
    from app.config import settings

    monkeypatch.setattr(settings, "exploit_enabled", True)
    monkeypatch.setattr(settings, "exploit_allowlist", "198.51.100.0/24")
    with TestClient(app) as client:
        resp = client.post("/api/v1/ad/exploit", json=_EXPLOIT_BODY)
    assert resp.status_code == 403
    assert "allowlist" in resp.json()["detail"]


def test_ad_exploit_starts_pwn_job(monkeypatch):
    """Kapılar açıkken tasks=["pwn"] + da_user akışı doğrulanır; şifre
    JobState'e gitmez (params yalnızca _run'a)."""
    from app.config import settings

    captured = {}

    async def fake_start(subnet, **kwargs):
        captured.update({"subnet": subnet, **kwargs})
        return "fakepwnjob01"

    monkeypatch.setattr(job_manager, "start_scan", fake_start)
    monkeypatch.setattr(settings, "exploit_enabled", True)
    monkeypatch.setattr(settings, "exploit_allowlist", "10.13.38.0/24")

    with TestClient(app) as client:
        resp = client.post("/api/v1/ad/exploit", json=_EXPLOIT_BODY)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["job_id"] == "fakepwnjob01"
    assert body["ws_url"] == "/api/v1/ws/jobs/fakepwnjob01"
    assert "warning" in body

    assert captured["subnet"] == "10.13.38.5"
    assert captured["module"] == "ad"
    assert captured["params"]["tasks"] == ["pwn"]
    assert captured["params"]["da_user"] == "Administrator"
    assert captured["params"]["dc_hostname"] == "dc01.corp.local"
    assert captured["params"]["password"] == "Secret123"
    assert "confirm" not in captured["params"]     # onay alanı sızmaz


def test_scan_ad_rejects_pwn_task():
    """'pwn' görevi normal /scan/ad Literal'ında yer almaz (confirm kapısı)."""
    from app.api.routes import ADScanRequest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        ADScanRequest(target="10.13.38.5", domain="corp.local",
                      username="alice", password="x", tasks=["pwn"])


def test_ad_panel_has_pwn_button():
    """AD paneli Sömür butonunu ve kritik severity stilini içerir."""
    with TestClient(app) as client:
        html = client.get("/static/panels/ad_modulu.html").text
    assert 'id="pwn-btn"' in html
    assert "/api/v1/ad/exploit" in html
    assert "risk.critical" in html


def test_report_and_results_reject_bad_scan_id():
    """scan_id format koruması: traversal/uzantı ayıracı içeren girdiler 404."""
    with TestClient(app) as client:
        for bad in ("../etc/passwd", "..%2F..%2Fetc", "a/b", "x" * 65,
                    "scan.pdf/../../x", ""):
            r1 = client.get(f"/api/v1/scans/{bad}/report")
            r2 = client.get(f"/api/v1/scans/{bad}/results")
            assert r1.status_code == 404, bad
            assert r2.status_code == 404, bad


def test_findings_scoped_per_job():
    """Bulgu havuzu job filtresiyle izole: yanlış job_id boş döner (T7)."""
    import asyncio

    from app.normalization.schema import ADFinding
    from app.storage import repository
    from app.storage.database import async_session_factory

    async def _seed():
        async with async_session_factory() as session:
            await repository.create_job(session, "iso_job_1", "10.0.0.5",
                                        "ad", "ad")
            await repository.save_ad_findings(session, "iso_job_1", [
                ADFinding(kind="kerberoast", principal="sadece-bu-is",
                          severity="high", message="x", detail={}),
            ])

    asyncio.run(_seed())
    with TestClient(app) as client:
        mine = client.get(
            "/api/v1/ad/findings?job_id=iso_job_1").json()["findings"]
        assert len(mine) == 1
        other = client.get(
            "/api/v1/ad/findings?job_id=baska_bir_is").json()["findings"]
        assert other == []             # başka işin bulgusu sızmadı
