"""Nikto XML -> ortak şema (WebFinding).

Nikto 2.1.5 XML formatı (gerçek çıktıdan doğrulandı):

    <niktoscan ...>
      <scandetails targetip="..." targetport="80">
        <item id="001406" osvdbid="561" method="GET">
          <description><![CDATA[...]]></description>
          <uri><![CDATA[/]]></uri>
        </item>
        ...

`severity` alanı bu sürümde XML'e yazılmaz; varsa element'ten okunur,
yoksa OSVDB referansından türetilir:
  - osvdbid > 0  -> medium  (bilinen açık referansı var)
  - osvdbid == 0 -> low     (genel kontrol bulgusu)
"""

from pathlib import Path
from xml.etree import ElementTree as ET

from app.core.exceptions import ParseError
from app.normalization.schema import WebFinding

_VALID_LEVELS = ("info", "low", "medium", "high")


def _child_text(item: ET.Element, tag: str) -> str | None:
    for child in item:
        if child.tag.split("}")[-1] == tag and child.text:
            text = " ".join(child.text.split())
            return text or None
    return None


def _derive_severity(item: ET.Element) -> str:
    sev_text = _child_text(item, "severity")
    if sev_text and sev_text.lower() in _VALID_LEVELS:
        return sev_text.lower()

    osvdb = (item.get("osvdbid") or "0").strip()
    if osvdb and osvdb != "0":
        return "medium"      # OSVDB-561 gibi: bilinen açık kaydı var
    return "low"


def parse_nikto_xml(xml_path: Path) -> list[WebFinding]:
    """Nikto -Format xml çıktısını WebFinding listesine çevirir."""
    try:
        tree = ET.parse(xml_path)
    except ET.ParseError as e:
        raise ParseError(f"Geçersiz nikto XML dosyası {xml_path}: {e}") from e

    findings: list[WebFinding] = []
    for item in tree.getroot().iter():
        if item.tag.split("}")[-1] != "item":
            continue
        description = _child_text(item, "description")
        if not description:
            continue
        findings.append(WebFinding(
            id=item.get("id"),
            osvdb_id=item.get("osvdbid"),
            severity=_derive_severity(item),
            message=description,
            uri=_child_text(item, "uri"),
        ))
    return findings
