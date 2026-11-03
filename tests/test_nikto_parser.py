from pathlib import Path

from app.normalization.nikto_parser import parse_nikto_xml

# nikto 2.1.5 XML gerçek yapısıyla birebir (DOCTYPE karmaşası olmadan)
SAMPLE = """<?xml version="1.0" ?>
<niktoscan nxmlversion="1.2" version="2.1.5">
<scandetails targetip="192.168.1.10" targetport="80" targetbanner="Apache/2.4.58">
<item id="001406" osvdbid="561" method="GET">
<description><![CDATA[OSVDB-561: X-Frame-Options header missing]]></description>
<uri><![CDATA[/]]></uri>
</item>
<item id="999984" osvdbid="0" method="GET">
<description><![CDATA[Server leaks inodes via ETags, header found with file /]]></description>
<uri><![CDATA[/]]></uri>
</item>
<item id="999990" osvdbid="0" method="OPTIONS">
<description><![CDATA[]]></description>
<uri><![CDATA[/]]></uri>
</item>
</scandetails>
</niktoscan>
"""

SEVERITY_ELEMENT_XML = """<?xml version="1.0"?>
<niktoscan>
<scandetails targetip="10.0.0.2" targetport="80">
<item id="1" osvdbid="0">
<description><![CDATA[Trivial finding]]></description>
<severity>high</severity>
</item>
</scandetails>
</niktoscan>
"""


def _write(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "nikto.xml"
    p.write_text(content, encoding="utf-8")
    return p


def test_parse_items_and_severity_derivation(tmp_path):
    findings = parse_nikto_xml(_write(tmp_path, SAMPLE))
    # boş description'lı item filtrelenir
    assert len(findings) == 2
    first, second = findings
    assert first.id == "001406"
    assert first.osvdb_id == "561"
    assert first.severity == "medium"        # OSVDB referansı → medium
    assert "X-Frame-Options" in first.message
    assert first.uri == "/"
    assert second.severity == "low"          # osvdbid=0 → low (genel kontrol)


def test_severity_element_preferred_when_present(tmp_path):
    findings = parse_nikto_xml(_write(tmp_path, SEVERITY_ELEMENT_XML))
    assert len(findings) == 1
    assert findings[0].severity == "high"    # element varsa onu kullan
