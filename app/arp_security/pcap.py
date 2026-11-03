"""Offline PCAP/PCAPNG ARP olayı çıkarımı — ağ erişimi yoktur."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from app.arp_security.analyzer import ARPAnomalyAnalyzer
from app.arp_security.models import ARPAnalysisReport, ARPEvent


def packet_to_event(packet: Any) -> ARPEvent | None:
    """Scapy paketini yalnızca ARP metadata'sına indirger; payload saklamaz."""
    try:
        from scapy.all import ARP
        if ARP not in packet:
            return None
        arp = packet[ARP]
        return ARPEvent(
            ts=float(packet.time),
            op=int(arp.op),
            sender_ip=str(arp.psrc),
            sender_mac=str(arp.hwsrc).lower(),
            target_ip=str(arp.pdst),
            target_mac=str(arp.hwdst).lower(),
        )
    except (AttributeError, TypeError, ValueError):
        return None


class OfflinePcapAnalyzer:
    """PCAP dosyasını akış halinde okur ve pasif anomali analizi uygular."""

    def __init__(self, max_packets: int = 100_000) -> None:
        self.max_packets = max_packets

    def analyze(
        self, path: str | Path, gateway_ip: str | None = None,
        gateway_mac: str | None = None,
    ) -> ARPAnalysisReport:
        try:
            from scapy.all import PcapReader
        except ImportError as exc:
            raise RuntimeError(
                "PCAP analizi için scapy gerekli: pip install scapy"
            ) from exc

        events: list[ARPEvent] = []
        reader = PcapReader(str(path))
        try:
            for index, packet in enumerate(reader):
                if index >= self.max_packets:
                    break
                event = packet_to_event(packet)
                if event is not None:
                    events.append(event)
        finally:
            reader.close()
        return ARPAnomalyAnalyzer().analyze(events, gateway_ip, gateway_mac)
