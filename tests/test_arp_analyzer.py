"""Pasif ARP anomali analiz motoru testleri — sentetik olaylar, ağ yok."""

from app.arp_security.analyzer import ARPAnomalyAnalyzer
from app.arp_security.models import ARPEvent, AnalysisStatus

MAC_A = "00:00:00:00:00:0a"
MAC_B = "00:00:00:00:00:0b"
MAC_C = "00:00:00:00:00:0c"


def _event(ts, sender_ip, sender_mac, target_ip="192.168.1.50", op=2):
    return ARPEvent(ts, op, sender_ip, sender_mac, target_ip)


def test_empty_or_invalid_capture_is_inconclusive():
    analyzer = ARPAnomalyAnalyzer()
    assert analyzer.analyze([]).status is AnalysisStatus.INCONCLUSIVE
    invalid = _event(1, "not-an-ip", MAC_A)
    assert analyzer.analyze([invalid]).analyzed_packets == 0


def test_consistent_arp_mapping_is_clean():
    events = [
        _event(1, "192.168.1.10", MAC_A, op=1),
        _event(2, "192.168.1.10", MAC_A),
        _event(3, "192.168.1.20", MAC_B),
    ]
    report = ARPAnomalyAnalyzer().analyze(events)
    assert report.status is AnalysisStatus.CLEAN
    assert report.alerts == []
    assert report.stats["unique_sender_macs"] == 2


def test_gateway_mac_change_is_critical_evidence():
    events = [
        _event(1, "192.168.1.1", MAC_A),
        _event(2, "192.168.1.1", MAC_B),
    ]
    report = ARPAnomalyAnalyzer().analyze(events, "192.168.1.1", MAC_A)
    assert report.status is AnalysisStatus.ALERTS
    alert = report.alerts[0]
    assert alert.kind == "gateway_mac_conflict"
    assert alert.severity == "critical"
    assert alert.evidence["baseline_mac"] == MAC_A
    assert alert.evidence["conflicting_macs"] == [MAC_B]


def test_ip_flap_and_duplicate_mac_are_separate_findings():
    events = [
        _event(1, "192.168.1.10", MAC_A),
        _event(2, "192.168.1.20", MAC_B),
        _event(3, "192.168.1.10", MAC_B),
    ]
    report = ARPAnomalyAnalyzer().analyze(events)
    kinds = {alert.kind for alert in report.alerts}
    assert kinds == {"ip_mac_flap", "duplicate_mac"}


def test_gratuitous_burst_threshold():
    events = [
        _event(index, "192.168.1.10", MAC_A, "192.168.1.10")
        for index in range(10)
    ]
    report = ARPAnomalyAnalyzer().analyze(events)
    assert any(a.kind == "gratuitous_arp_burst" for a in report.alerts)
    below_threshold = ARPAnomalyAnalyzer().analyze(events[:9])
    assert below_threshold.status is AnalysisStatus.CLEAN


def test_unseen_gateway_is_inconclusive_not_clean():
    events = [_event(1, "192.168.1.10", MAC_A)]
    report = ARPAnomalyAnalyzer().analyze(events, "192.168.1.1", MAC_A)
    assert report.status is AnalysisStatus.INCONCLUSIVE
    assert report.stats["gateway_packets"] == 0
