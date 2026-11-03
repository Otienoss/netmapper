"""Pasif ARP dinleme oturumları — yalnızca sniff; paket gönderimi YOK."""

from __future__ import annotations

import asyncio
import threading
import time

from app.arp_security.analyzer import ARPAnomalyAnalyzer
from app.arp_security.models import ARPEvent
from app.arp_security.pcap import packet_to_event
from app.services.job_manager import JobStatus, job_manager


class PassiveARPListener:
    """Scapy sniff'i ayrı thread'de çalıştırır; herhangi bir send çağrısı yok."""

    def __init__(self, interface: str, max_packets: int = 5000) -> None:
        self.interface = interface
        self.max_packets = max_packets
        self.events: list[ARPEvent] = []
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._error: Exception | None = None

    @property
    def error(self) -> Exception | None:
        return self._error

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="arp-passive-listener"
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()

    def join(self, timeout: float = 3.0) -> None:
        if self._thread is not None:
            self._thread.join(timeout=timeout)

    def is_alive(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def _run(self) -> None:
        try:
            from scapy.all import sniff
            while (
                not self._stop_event.is_set()
                and len(self.events) < self.max_packets
            ):
                # timeout=1: trafik olmasa bile stop sinyali düzenli kontrol edilir.
                sniff(
                    iface=self.interface,
                    filter="arp",
                    prn=self._process,
                    store=False,
                    timeout=1,
                )
        except ImportError:
            self._error = RuntimeError(
                "Pasif ARP dinleme için scapy gerekli: pip install scapy"
            )
        except Exception as exc:
            self._error = exc

    def _process(self, packet) -> None:
        if self._stop_event.is_set() or len(self.events) >= self.max_packets:
            return
        event = packet_to_event(packet)
        if event is not None:
            self.events.append(event)


_MONITOR_STOPS: dict[str, asyncio.Event] = {}


def stop_monitor(job_id: str) -> bool:
    event = _MONITOR_STOPS.get(job_id)
    if event is None:
        return False
    event.set()
    return True


async def run_monitor_job(job_id: str, target: str, params: dict) -> dict:
    """Süreli/durdurulabilir pasif dinleme yapar ve analiz sonucunu döner."""
    interface = params["interface"]
    duration = int(params.get("duration_sec", 60))
    max_packets = int(params.get("max_packets", 5000))
    gateway_ip = params.get("gateway_ip")
    gateway_mac = params.get("gateway_mac")
    stop_event = asyncio.Event()
    _MONITOR_STOPS[job_id] = stop_event
    listener = PassiveARPListener(interface, max_packets)

    await job_manager.update(job_id, status=JobStatus.SCANNING)
    await job_manager.log(
        job_id,
        f"Pasif ARP dinleme başladı: interface={interface} süre={duration}s "
        f"limit={max_packets} paket — ağa HİÇBİR paket gönderilmiyor",
    )
    listener.start()
    deadline = time.monotonic() + duration
    try:
        while (
            time.monotonic() < deadline
            and not stop_event.is_set()
            and listener.is_alive()
            and len(listener.events) < max_packets
        ):
            await asyncio.sleep(0.2)
    finally:
        listener.stop()
        await asyncio.to_thread(listener.join, 3.0)
        _MONITOR_STOPS.pop(job_id, None)

    if listener.error is not None:
        raise RuntimeError(f"Pasif ARP dinleme başarısız: {listener.error}")

    report = ARPAnomalyAnalyzer().analyze(
        listener.events, gateway_ip, gateway_mac
    )
    await job_manager.update(job_id, status=JobStatus.NORMALIZING)
    await job_manager.log(
        job_id,
        f"Pasif ARP analizi tamam: {report.analyzed_packets} olay, "
        f"{len(report.alerts)} uyarı, durum={report.status.value}",
    )
    return report.to_dict()
