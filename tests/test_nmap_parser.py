from pathlib import Path

from app.normalization.nmap_parser import parse_nmap_xml

SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sT -sV -oX out.xml 192.168.1.10" start="1">
  <host>
    <status state="up"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="TestVendor"/>
    <hostnames><hostname name="nas.local" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx"/>
      </port>
      <port protocol="tcp" portid="23">
        <state state="closed"/>
        <service name="telnet"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

DOWN_HOST_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host><status state="down"/><address addr="192.168.1.99" addrtype="ipv4"/></host>
</nmaprun>
"""

EMPTY_XML = """<?xml version="1.0"?><nmaprun scanner="nmap"></nmaprun>"""


def _write(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "scan.xml"
    p.write_text(content, encoding="utf-8")
    return p


def test_parse_full_host(tmp_path):
    host = parse_nmap_xml(_write(tmp_path, SAMPLE_XML))
    assert host is not None
    assert host.ip == "192.168.1.10"
    assert host.mac == "AA:BB:CC:DD:EE:FF"
    assert host.vendor == "TestVendor"
    assert host.hostname == "nas.local"
    assert host.source_tool == "nmap"
    # sadece açık portlar normalize edilir (23 closed -> yok)
    assert {s.port for s in host.services} == {22, 80}
    ssh = next(s for s in host.services if s.port == 22)
    assert ssh.product == "OpenSSH"
    assert ssh.version == "8.9p1"
    assert ssh.state == "open"


def test_parse_down_host_returns_none(tmp_path):
    assert parse_nmap_xml(_write(tmp_path, DOWN_HOST_XML)) is None


def test_parse_no_host_returns_none(tmp_path):
    assert parse_nmap_xml(_write(tmp_path, EMPTY_XML)) is None
