from pathlib import Path
from xml.etree import ElementTree as ET

from app.core.exceptions import ParseError
from app.normalization.schema import HostResult, ServiceInfo


def parse_nmap_xml(xml_path: Path) -> HostResult | None:
    """nmap -oX çıktısını ortak şemaya (HostResult) çevirir.

    Host yoksa veya 'down' ise None döner.
    """
    try:
        tree = ET.parse(xml_path)
    except ET.ParseError as e:
        raise ParseError(f"Geçersiz nmap XML dosyası {xml_path}: {e}") from e

    root = tree.getroot()
    host_el = root.find("host")
    if host_el is None:
        return None

    status = host_el.find("status")
    if status is not None and status.get("state") != "up":
        return None

    addr_el = host_el.find("address[@addrtype='ipv4']")
    ip = addr_el.get("addr") if addr_el is not None else None
    if ip is None:
        return None

    mac_el = host_el.find("address[@addrtype='mac']")
    mac = mac_el.get("addr") if mac_el is not None else None
    vendor = mac_el.get("vendor") if mac_el is not None else None

    hostname_el = host_el.find("hostnames/hostname")
    hostname = hostname_el.get("name") if hostname_el is not None else None

    services = []
    for port_el in host_el.findall("ports/port"):
        state_el = port_el.find("state")
        if state_el is None or state_el.get("state") != "open":
            continue
        service_el = port_el.find("service")
        services.append(ServiceInfo(
            port=int(port_el.get("portid")),
            protocol=port_el.get("protocol", "tcp"),
            state=state_el.get("state"),
            service_name=service_el.get("name") if service_el is not None else None,
            product=service_el.get("product") if service_el is not None else None,
            version=service_el.get("version") if service_el is not None else None,
        ))

    return HostResult(
        ip=ip, mac=mac, vendor=vendor, hostname=hostname,
        services=services, source_tool="nmap",
    )
