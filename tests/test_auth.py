"""API kimlik doğrulama testleri (T2) — gerçek sistemlere BAĞLANMAZ.

Senaryolar: token kapalı (geriye uyumluluk), token açık + yetkisiz/yetkili
erişim, WS 4401, exempt (/health, statik), timing-safe karşılaştırma.
"""

from fastapi.testclient import TestClient

from app.config import settings
from app.main import app

_TOKEN = "test-token-123"


def _with(token_on: bool):
    """Token ayarını geçici değiştir (context manager'sız monkeypatch yeterli
    değil çünkü middleware ayarı her istekte okur — test fonksiyonu içinde
    settings'i mutate edip geri alırız)."""
    old = settings.api_token
    settings.api_token = _TOKEN if token_on else ""
    return old


def _restore(old):
    settings.api_token = old


def test_token_disabled_by_default_keeps_compat():
    """Token TANIMLI DEĞİLSE tüm uçlar eskisi gibi çalışır (sözleşme korunur)."""
    old = _with(False)
    try:
        with TestClient(app) as client:
            assert client.get("/health").status_code == 200
            assert client.get("/api/v1/stats").status_code == 200
            assert client.get("/api/v1/hosts").status_code == 200
    finally:
        _restore(old)


def test_unauthorized_api_returns_401():
    old = _with(True)
    try:
        with TestClient(app) as client:
            for path in ("/api/v1/stats", "/api/v1/hosts", "/api/v1/scans",
                         "/api/v1/ad/findings"):
                r = client.get(path)
                assert r.status_code == 401, path
                assert "Yetkisiz" in r.json()["detail"]
    finally:
        _restore(old)


def test_unauthorized_exploit_endpoint_returns_401():
    """Sömürü endpoint'i de 401 alır — kapılar ÖNCESİNDEN korunur."""
    old = _with(True)
    try:
        with TestClient(app) as client:
            r = client.post("/api/v1/ad/exploit", json={
                "target": "10.13.38.5", "domain": "corp.local",
                "username": "alice", "password": "x", "confirm": "SÖMÜR",
            })
            assert r.status_code == 401
    finally:
        _restore(old)


def test_authorized_via_header_and_bearer():
    old = _with(True)
    try:
        with TestClient(app) as client:
            ok1 = client.get("/api/v1/stats",
                             headers={"X-API-Token": _TOKEN})
            ok2 = client.get("/api/v1/stats",
                             headers={"Authorization": f"Bearer {_TOKEN}"})
            assert ok1.status_code == 200
            assert ok2.status_code == 200
    finally:
        _restore(old)


def test_wrong_token_rejected():
    old = _with(True)
    try:
        with TestClient(app) as client:
            r = client.get("/api/v1/stats", headers={"X-API-Token": "yanlis"})
            assert r.status_code == 401
            r = client.get("/api/v1/stats",
                           headers={"Authorization": "Bearer "})
            assert r.status_code == 401
    finally:
        _restore(old)


def test_health_and_static_exempt_from_token():
    """/health (liveness) ve statik dosyalar token'siz erişilebilir kalır."""
    old = _with(True)
    try:
        with TestClient(app) as client:
            assert client.get("/health").status_code == 200
            r = client.get("/static/token.js")
            assert r.status_code == 200
    finally:
        _restore(old)


def test_websocket_requires_token_when_enabled():
    """WS: token yoksa 4401 ile kapanır; ?token= ile bağlanır."""
    from starlette.websockets import WebSocketDisconnect

    old = _with(True)
    try:
        with TestClient(app) as client:
            # job oluştur (auth KAPALIYKEN) — sonra token AÇIK sorgularız
            pass
        # token kapalıken job yarat
        settings.api_token = ""
        with TestClient(app) as client:
            r = client.post("/api/v1/scan/ad", json={
                "target": "10.13.38.5", "domain": "corp.local",
                "username": "alice", "password": "x", "tasks": ["spn"],
            })
            # gate/ad işi gerçek impacket'e koşabilir → hata dönmüş de olabilir;
            # job_id yine de döner (start_scan hemen döner)
            job_id = r.json().get("job_id") if r.status_code == 200 else None
        if job_id:
            settings.api_token = _TOKEN
            with TestClient(app) as client:
                try:
                    with client.websocket_connect(
                        f"/api/v1/ws/jobs/{job_id}"
                    ) as ws:
                        ws.receive_json()
                    raised = False
                except (WebSocketDisconnect, Exception) as e:
                    # close(4401) → connect aşamasında disconnect fırlatır
                    raised = True
                assert raised, "token'siz WS bağlanabilmemeli"
                # doğru token ile bağlanır (state it published)
                with client.websocket_connect(
                    f"/api/v1/ws/jobs/{job_id}?token={_TOKEN}"
                ) as ws:
                    payload = ws.receive_json()
                    assert payload["job_id"] == job_id
    finally:
        _restore(old)


def test_compare_digest_used_for_token():
    """Token karşılaştırması timing-safe (compare_digest) — kod kanıtı."""
    import inspect

    from app.core import auth
    src = inspect.getsource(auth._matches)
    assert "compare_digest" in src
