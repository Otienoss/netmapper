"""Pasif monitör ve ARP API testleri — scapy/ağ çağrıları mock'lu."""

import asyncio
from pathlib import Path

from fastapi.testclient import TestClient

from app.arp_security.models import ARPAnalysisReport, ARPEvent, AnalysisStatus
from app.arp_security.monitor import run_monitor_job
from app.main import app
from app.services.job_manager import job_manager

MAC_A = "00:00:00:00:00:0a"


def test_monitor_job_analyzes_without_packet_send(monkeypatch):
    class FakeListener:
        def __init__(self, interface, max_packets):
            self.events = [ARPEvent(1, 2, "192.168.1.10", MAC_A, "192.168.1.20")]
            self.error = None

        def start(self):
            return None

        def is_alive(self):
            return False

        def stop(self):
            return None

        def join(self, timeout=3):
            return None

    monkeypatch.setattr(
        "app.arp_security.monitor.PassiveARPListener", FakeListener
    )
    job_manager.create_job("arp-job", "192.168.1.1", module="arp_monitor")
    result = asyncio.run(run_monitor_job(
        "arp-job", "192.168.1.1",
        {"interface": "eth0", "duration_sec": 5, "max_packets": 100},
    ))
    assert result["status"] == "clean"
    assert result["analyzed_packets"] == 1
    logs = " ".join(job_manager.get_job("arp-job").logs)
    assert "HİÇBİR paket gönderilmiyor" in logs


def test_config_audit_endpoint():
    with TestClient(app) as client:
        response = client.post("/api/v1/arp/config-audit", json={
            "config_text": "no ip arp inspection vlan 10",
            "config_complete": False,
        })
    assert response.status_code == 200
    assert response.json()["overall"] == "at_risk"


def test_monitor_start_and_stop_endpoints(monkeypatch):
    captured = {}

    async def fake_start(target, profile="full", module="net", params=None):
        captured.update({"target": target, "module": module, "params": params})
        return "arp-api-job"

    monkeypatch.setattr(
        "app.api.arp_routes.job_manager.start_scan", fake_start
    )
    monkeypatch.setattr("app.api.arp_routes.stop_monitor", lambda job_id: True)
    with TestClient(app) as client:
        started = client.post("/api/v1/arp/monitor/start", json={
            "interface": "eth0", "gateway_ip": "192.168.1.1",
            "duration_sec": 5, "max_packets": 100,
        })
        stopped = client.post("/api/v1/arp/monitor/stop/arp-api-job")
    assert started.status_code == 200
    assert captured["module"] == "arp_monitor"
    assert captured["params"]["duration_sec"] == 5
    assert stopped.json()["status"] == "stopping"


def test_pcap_upload_is_analyzed_and_temp_file_deleted(monkeypatch):
    seen = {}

    def fake_analyze(self, path, gateway_ip=None, gateway_mac=None):
        seen["path"] = Path(path)
        return ARPAnalysisReport(AnalysisStatus.CLEAN, 0, 0)

    monkeypatch.setattr(
        "app.arp_security.pcap.OfflinePcapAnalyzer.analyze", fake_analyze
    )
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/arp/pcap-audit",
            content=b"sentetik",
            headers={"Content-Type": "application/octet-stream"},
        )
    assert response.status_code == 200
    assert response.json()["status"] == "clean"
    assert not seen["path"].exists()


def test_pcap_upload_size_limit(monkeypatch):
    monkeypatch.setattr("app.api.arp_routes._MAX_PCAP_BYTES", 4)
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/arp/pcap-audit",
            content=b"12345",
            headers={"Content-Type": "application/octet-stream"},
        )
    assert response.status_code == 413
