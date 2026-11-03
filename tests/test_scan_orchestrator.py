"""Orkestratör akış testleri: gerçek subprocess çalıştırmaz, scanner'lar stub."""

import asyncio

from app.services.job_manager import JobStatus, job_manager
from app.services.scan_orchestrator import ScanOrchestrator

SINGLE_HOST_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

NIKTO_XML = """<?xml version="1.0" ?>
<niktoscan nxmlversion="1.2">
<scandetails targetip="192.168.1.10" targetport="80">
<item id="001406" osvdbid="561" method="GET"><description><![CDATA[OSVDB-561: X-Frame-Options missing]]></description><uri><![CDATA[/]]></uri></item>
<item id="999984" osvdbid="0" method="GET"><description><![CDATA[ETag header info leak]]></description><uri><![CDATA[/]]></uri></item>
</scandetails>
</niktoscan>
"""


def _make_orchestrator(tmp_path, monkeypatch, discovered_ips):
    """Keşif, nmap ve nikto sahtelenmiş orkestratör kurar."""
    orch = ScanOrchestrator()

    async def fake_discover(subnet):
        return discovered_ips

    xml_path = tmp_path / "fake.xml"
    xml_path.write_text(SINGLE_HOST_XML, encoding="utf-8")

    async def fake_nmap_scan(target, **kwargs):
        return xml_path

    nikto_path = tmp_path / "fake_nikto.xml"
    nikto_path.write_text(NIKTO_XML, encoding="utf-8")
    nikto_calls: list = []

    async def fake_nikto_scan(target, ports=None, **kwargs):
        nikto_calls.append((target, ports))
        return nikto_path

    monkeypatch.setattr(orch, "_discover_live_hosts", fake_discover)
    monkeypatch.setattr(orch.nmap, "scan", fake_nmap_scan)
    monkeypatch.setattr(orch.nikto, "scan", fake_nikto_scan)
    orch.nikto_calls = nikto_calls      # test gözlemi için
    return orch


def _run(orch, job_id, subnet, **kwargs):
    """Job hafızada yoksa oluşturup orkestratörü tek event loop'ta çalıştırır."""
    if job_manager.get_job(job_id) is None:
        job_manager.create_job(job_id, subnet, kwargs.get("profile", "full"))
    return asyncio.run(orch.run_full_scan(job_id, subnet, **kwargs))


def test_single_host_skips_discovery(tmp_path, monkeypatch):
    """Tek IP hedefinde netdiscover hiç çalışmadan doğrudan nmap atlanır."""
    orch = _make_orchestrator(tmp_path, monkeypatch, discovered_ips=[])

    async def must_not_discover(subnet):
        raise AssertionError("Tek host hedefinde keşif çalışmemeli")

    monkeypatch.setattr(orch, "_discover_live_hosts", must_not_discover)

    results = _run(orch, "job_singlehost", "192.168.1.10")
    assert [r.ip for r in results] == ["192.168.1.10"]
    assert {s.port for s in results[0].services} == {80}

    # full profilde nikto nmap ile birlikte başlatılır ve bulgular birleşir
    assert orch.nikto_calls == [("192.168.1.10", None)]
    assert len(results[0].web_findings) == 2
    assert {f.severity for f in results[0].web_findings} == {"medium", "low"}

    state = job_manager.get_job("job_singlehost")
    assert state.status == JobStatus.NORMALIZING      # DONE'yı _run atar
    assert any("keşif atlandı" in l for l in state.logs)
    assert any("nikto start" in l for l in state.logs)
    assert any("2 web bulgusu" in l for l in state.logs)
    assert state.progress == {"hosts_total": 1, "hosts_scanned": 1}


def test_subnet_scan_uses_discovery(tmp_path, monkeypatch):
    """/24 aralığında keşiften dönen IP'ler nmap'e girer."""
    orch = _make_orchestrator(tmp_path, monkeypatch, discovered_ips=["192.168.1.10"])
    results = _run(orch, "job_subnet", "192.168.1.0/24")
    assert [r.ip for r in results] == ["192.168.1.10"]
    assert any("canlı host bulundu" in l for l in job_manager.get_job("job_subnet").logs)


def test_subnet_with_no_hosts_returns_empty(tmp_path, monkeypatch):
    """Keşif hiç host bulmazsa tarama yapılmaz, boş liste döner."""
    orch = _make_orchestrator(tmp_path, monkeypatch, discovered_ips=[])

    async def must_not_scan(target, **kwargs):
        raise AssertionError("Host yokken nmap çalışmameli")

    monkeypatch.setattr(orch.nmap, "scan", must_not_scan)
    assert _run(orch, "job_empty", "192.168.1.0/24") == []
    assert job_manager.get_job("job_empty").status == JobStatus.NORMALIZING


def test_quick_profile_skips_nmap(tmp_path, monkeypatch):
    """Hızlı Keşif profili: keşif yapar, nmap ve nikto'yu hiç çağırmaz."""
    orch = _make_orchestrator(tmp_path, monkeypatch, discovered_ips=["192.168.1.10"])

    async def must_not_scan(target, **kwargs):
        raise AssertionError("Hızlı Keşif'te nmap çalışmamalı")

    async def must_not_nikto(target, ports=None, **kwargs):
        raise AssertionError("Hızlı Keşif'te nikto çalışmamalı")

    monkeypatch.setattr(orch.nmap, "scan", must_not_scan)
    monkeypatch.setattr(orch.nikto, "scan", must_not_nikto)

    results = _run(orch, "job_quick", "192.168.1.0/24", profile="quick")
    assert len(results) == 1
    assert results[0].services == []
    assert results[0].web_findings == []
    assert results[0].source_tool == "netdiscover"
    assert orch.nikto_calls == []
    state = job_manager.get_job("job_quick")
    assert state.status == JobStatus.NORMALIZING
    assert any("nmap atlandı" in l for l in state.logs)


def test_custom_profile_nikto_uses_open_web_ports(tmp_path, monkeypatch):
    """Özel profilde kör nikto turu yok — nmap'in bulduğu web portlarında çalışır."""
    orch = _make_orchestrator(tmp_path, monkeypatch, discovered_ips=["192.168.1.10"])

    results = _run(
        orch, "job_custom", "192.168.1.0/24",
        profile="custom", ports="22,80",
    )
    # sample XML'de tek web portu 80 açık → nikto bir kez ve "80" ile çağrılır
    assert orch.nikto_calls == [("192.168.1.10", "80")]
    assert len(results[0].web_findings) == 2
