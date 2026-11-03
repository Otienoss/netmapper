import re
import asyncio
from dataclasses import dataclass
from app.core.process_runner import ProcessRunner


@dataclass
class ActiveDevice:
    ip: str
    mac: str
    vendor: str | None = None
    device_type: str | None = None  # printer, camera, switch vb.


# NAC ortamında "güvenilir" sayılan cihaz türü ipuçları
TRUSTED_DEVICE_HINTS = {
    "printer":  ["brother", "hp", "canon", "xerox", "ricoh", "kyocera"],
    "camera":   ["hikvision", "dahua", "axis", "vivotek", "bosch"],
    "switch":   ["cisco", "aruba", "juniper", "netgear", "extreme"],
    "voip":     ["polycom", "cisco", "yealink", "grandstream"],
    "iot":      ["raspberry", "espressif", "microchip"],
}


class NacScanner:
    """
    Subnet'teki canlı cihazların MAC adreslerini ve vendor bilgisini toplar.
    ARP tabanlı — auth gerektirmez, Layer 2'de çalışır.
    """

    async def collect_arp_table(self, interface: str, subnet: str) -> list[ActiveDevice]:
        """
        arp-scan ile canlı cihazları ve MAC adreslerini toplar.
        arp-scan kurulu değilse 'sudo apt-get install -y arp-scan'
        """
        result = await ProcessRunner.run_privileged(
            ["arp-scan", "--interface", interface, subnet, "--quiet"],
            timeout=60,
        )
        return self._parse_arp_scan(result.stdout)

    async def collect_from_nmap(self, subnet: str) -> list[ActiveDevice]:
        """
        Alternatif: nmap -sn ile MAC toplama (root gerektirmez ama
        aynı subnet'te olman gerekir — ARP yanıtları yalnızca L2'de görünür)
        """
        result = await ProcessRunner.run(
            ["nmap", "-sn", "--send-eth", subnet, "-oG", "-"],
            timeout=120,
        )
        return self._parse_nmap_grep(result.stdout)

    def _parse_arp_scan(self, output: str) -> list[ActiveDevice]:
        devices = []
        for line in output.splitlines():
            m = re.match(
                r"(\d{1,3}(?:\.\d{1,3}){3})\s+"
                r"([0-9a-f:]{17})\s*(.*)",
                line.strip(), re.IGNORECASE
            )
            if m:
                ip, mac, vendor = m.group(1), m.group(2).lower(), m.group(3).strip()
                devices.append(ActiveDevice(
                    ip=ip, mac=mac, vendor=vendor,
                    device_type=self._classify(vendor),
                ))
        return devices

    def _parse_nmap_grep(self, output: str) -> list[ActiveDevice]:
        devices = []
        current_ip = None
        for line in output.splitlines():
            ip_m = re.search(r"Host: (\S+)", line)
            if ip_m:
                current_ip = ip_m.group(1)
            mac_m = re.search(r"MAC Address: ([0-9A-F:]{17})\s*\(([^)]*)\)", line)
            if mac_m and current_ip:
                mac = mac_m.group(1).lower()
                vendor = mac_m.group(2)
                devices.append(ActiveDevice(
                    ip=current_ip, mac=mac, vendor=vendor,
                    device_type=self._classify(vendor),
                ))
        return devices

    def _classify(self, vendor: str) -> str | None:
        if not vendor:
            return None
        vendor_l = vendor.lower()
        for dtype, hints in TRUSTED_DEVICE_HINTS.items():
            if any(h in vendor_l for h in hints):
                return dtype
        return None