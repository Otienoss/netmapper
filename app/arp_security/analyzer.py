"""Ham ARP olaylarından pasif ve deterministik anomali bulguları üretir."""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict

from app.arp_security.models import (
    ARPAlert, ARPAnalysisReport, ARPEvent, AnalysisStatus,
)

_MAC_RE = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$", re.IGNORECASE)


def _valid_event(event: ARPEvent) -> bool:
    try:
        ipaddress.ip_address(event.sender_ip)
        ipaddress.ip_address(event.target_ip)
    except ValueError:
        return False
    mac = event.sender_mac.lower()
    return bool(
        _MAC_RE.fullmatch(mac)
        and mac not in {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}
    )


def _window_peak(timestamps: list[float], window: float = 60.0) -> int:
    values = sorted(timestamps)
    peak = left = 0
    for right, timestamp in enumerate(values):
        while timestamp - values[left] > window:
            left += 1
        peak = max(peak, right - left + 1)
    return peak


class ARPAnomalyAnalyzer:
    """Yalnızca gözlem analizi yapar; paket üretmez/göndermez."""

    def __init__(self, gratuitous_burst_threshold: int = 10) -> None:
        self.gratuitous_burst_threshold = gratuitous_burst_threshold

    def analyze(
        self, events: list[ARPEvent], gateway_ip: str | None = None,
        gateway_mac: str | None = None,
    ) -> ARPAnalysisReport:
        valid = sorted(
            (event for event in events if _valid_event(event)),
            key=lambda event: event.ts,
        )
        if not valid:
            return ARPAnalysisReport(
                AnalysisStatus.INCONCLUSIVE,
                total_packets=len(events), analyzed_packets=0,
                stats={"reason": "Analiz edilebilir ARP olayı yok"},
            )

        ip_macs: dict[str, set[str]] = defaultdict(set)
        mac_ips: dict[str, set[str]] = defaultdict(set)
        gratuitous: dict[str, list[float]] = defaultdict(list)
        gateway_seen: str | None = None
        gateway_packets = 0
        expected_gateway_mac = gateway_mac.lower() if gateway_mac else None

        for event in valid:
            mac = event.sender_mac.lower()
            ip_macs[event.sender_ip].add(mac)
            mac_ips[mac].add(event.sender_ip)
            if event.gratuitous:
                gratuitous[event.sender_ip].append(event.ts)
            if gateway_ip and event.sender_ip == gateway_ip:
                gateway_packets += 1
                if gateway_seen is None:
                    gateway_seen = mac

        alerts: list[ARPAlert] = []
        observed_gateway: dict[str, str] = {}
        if gateway_ip:
            observed_gateway = {
                "ip": gateway_ip,
                "mac": expected_gateway_mac or gateway_seen or "",
            }
            conflicts = sorted(
                mac for mac in ip_macs.get(gateway_ip, set())
                if mac != (expected_gateway_mac or gateway_seen)
            )
            if conflicts:
                alerts.append(ARPAlert(
                    "gateway_mac_conflict", "critical",
                    f"Gateway {gateway_ip} birden fazla MAC ile görüldü",
                    {
                        "baseline_mac": expected_gateway_mac or gateway_seen,
                        "conflicting_macs": conflicts,
                        "gateway_packets": gateway_packets,
                    },
                    "Switch DHCP snooping/DAI binding'lerini ve gateway'in "
                    "gerçek MAC adresini doğrulayın; HA/failover olasılığını "
                    "eleyerek ARP inspection uygulayın.",
                ))

        for ip, macs in sorted(ip_macs.items()):
            if ip != gateway_ip and len(macs) > 1:
                alerts.append(ARPAlert(
                    "ip_mac_flap", "medium",
                    f"{ip} için MAC-IP eşleşmesi değişiyor",
                    {"ip": ip, "observed_macs": sorted(macs)},
                    "DHCP adres devri veya cihaz değişimini eleyin; switch "
                    "CAM ve DHCP binding kayıtlarıyla karşılaştırın.",
                ))

        for mac, ips in sorted(mac_ips.items()):
            if len(ips) > 1:
                alerts.append(ARPAlert(
                    "duplicate_mac", "medium",
                    f"Aynı MAC birden fazla IP tarafından kullanılıyor: {mac}",
                    {"mac": mac, "ips": sorted(ips)},
                    "HA/anycast yapılandırmasını eleyin; port ve DHCP binding "
                    "kayıtlarında aynı MAC'in kaynağını doğrulayın.",
                ))

        for ip, timestamps in sorted(gratuitous.items()):
            peak = _window_peak(timestamps)
            if peak >= self.gratuitous_burst_threshold:
                alerts.append(ARPAlert(
                    "gratuitous_arp_burst", "high",
                    f"{ip} kaynaklı yoğun gratuitous ARP aktivitesi",
                    {
                        "sender_ip": ip,
                        "total_gratuitous": len(timestamps),
                        "peak_per_minute": peak,
                    },
                    "Failover/VRRP davranışını eleyin; ARP rate-limit ve DAI "
                    "istatistiklerini inceleyin.",
                ))

        if alerts:
            status = AnalysisStatus.ALERTS
        elif gateway_ip and gateway_seen is None:
            status = AnalysisStatus.INCONCLUSIVE
        else:
            status = AnalysisStatus.CLEAN
        stats = {
            "requests": sum(event.op == 1 for event in valid),
            "replies": sum(event.op == 2 for event in valid),
            "gratuitous_replies": sum(event.gratuitous for event in valid),
            "unique_sender_ips": len(ip_macs),
            "unique_sender_macs": len(mac_ips),
            "capture_duration_sec": round(valid[-1].ts - valid[0].ts, 3),
            "gateway_packets": gateway_packets,
        }
        return ARPAnalysisReport(
            status, len(events), len(valid), alerts, stats, observed_gateway
        )
