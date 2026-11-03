"""Netdiscover çıktısını ortak şemaya (HostResult) çevirir.

netdiscover -P çıktısı şu formattadır (kolonlar boşlukla ayrılır):

    IP              MAC Address        Count     Length    MAC Vendor / Hostname
    -----------------------------------------------------------------------------
    192.168.1.1     aa:bb:cc:dd:ee:ff  1         60        SomeVendor
"""

import re

from app.normalization.schema import HostResult

_ROW_RE = re.compile(
    r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(?P<mac>[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\s+"
    r"\d+\s+\d+\s*"
    r"(?P<vendor>.*)$"
)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def parse_netdiscover_output(raw: str) -> list[HostResult]:
    """Netdiscover tablo çıktısını HostResult listesine çevirir."""
    hosts: list[HostResult] = []
    seen: set[str] = set()
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("IP") or line.startswith("-"):
            continue
        m = _ROW_RE.match(line)
        if not m:
            continue
        ip = m.group("ip")
        if ip in seen:
            continue
        seen.add(ip)
        hosts.append(HostResult(
            ip=ip,
            mac=m.group("mac").lower(),
            vendor=m.group("vendor").strip() or None,
            source_tool="netdiscover",
        ))
    return hosts


def extract_ips(raw: str) -> list[str]:
    """Ham çıktıdan benzersiz IP listesi çıkarır (satır sırası korunur)."""
    return list(dict.fromkeys(_IP_RE.findall(raw)))
