"""ARP Güvenlik paneli ve dashboard entegrasyon testleri."""

from fastapi.testclient import TestClient

from app.main import app


def test_dashboard_contains_arp_security_tab():
    with TestClient(app) as client:
        response = client.get("/")
    assert response.status_code == 200
    assert 'data-view="arp_guvenlik"' in response.text
    assert '/static/panels/arp_guvenlik.html' in response.text


def test_arp_security_panel_exposes_all_defensive_workflows():
    with TestClient(app) as client:
        response = client.get("/static/panels/arp_guvenlik.html")
    assert response.status_code == 200
    html = response.text
    assert "Canlı Pasif ARP Monitörü" in html
    assert "Offline PCAP Analizi" in html
    assert "Switch Konfigürasyon Denetimi" in html
    assert "/static/arp_guvenlik.js" in html
    assert "Paket gönderimi yok" in html


def test_arp_panel_javascript_uses_only_defensive_endpoints():
    with TestClient(app) as client:
        response = client.get("/static/arp_guvenlik.js")
    assert response.status_code == 200
    js = response.text
    assert "/api/v1/arp/monitor/start" in js
    assert "/api/v1/arp/monitor/stop/" in js
    assert "/api/v1/arp/pcap-audit" in js
    assert "/api/v1/arp/config-audit" in js
    for forbidden in ("sendp", "srp(", "/mitm/", "ip_forward", "spoof"):
        assert forbidden not in js
