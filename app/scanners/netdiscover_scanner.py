from app.config import settings
from app.core.exceptions import ScannerError
from app.core.process_runner import ProcessRunner
from app.scanners.base import BaseScanner


class NetdiscoverScanner(BaseScanner):
    """
    Pasif/aktif ARP taraması ile LAN üzerindeki canlı host'ları bulur.
    Auth gerektirmez, sadece ağ katmanında ARP paketleri gönderir.
    """

    name = "netdiscover"

    async def scan(self, subnet: str, timeout: int | None = None) -> str:
        timeout = timeout or settings.netdiscover_timeout_sec
        # -r: range taraması, -P: parse edilebilir (script-friendly) çıktı bas
        cmd = [
            settings.netdiscover_binary,
            "-r", subnet,
            "-P",       # script-friendly çıktı
            "-N",       # banner'ı gösterme
        ]
        result = await ProcessRunner.run(cmd, timeout=timeout)
        if result.returncode not in (0, 1):  # netdiscover bazen 1 ile de başarılı döner
            raise ScannerError(f"netdiscover failed: {result.stderr}")
        if "must be root" in (result.stdout + result.stderr).lower():
            # root'suz AF_PACKET: çıktı "You must be root to run this." —
            # boş sonuç sanılmamalı, çağıran fallback'e geçsin
            raise ScannerError("netdiscover root gerektiriyor (AF_PACKET)")
        return result.stdout
