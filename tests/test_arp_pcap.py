"""OfflinePcapAnalyzer testi — sahte Scapy reader, dosya/ağ erişimi yok."""

import sys
import types

from app.arp_security.models import AnalysisStatus
from app.arp_security.pcap import OfflinePcapAnalyzer

MAC_A = "00:00:00:00:00:0a"
MAC_B = "00:00:00:00:00:0b"


class _FakeARP:
    def __init__(self, sender_mac):
        self.op = 2
        self.psrc = "192.168.1.1"
        self.hwsrc = sender_mac
        self.pdst = "192.168.1.10"
        self.hwdst = "00:00:00:00:00:00"


class _FakePacket:
    def __init__(self, arp, timestamp):
        self.arp = arp
        self.time = timestamp

    def __contains__(self, layer):
        return layer is _FakeARP and self.arp is not None

    def __getitem__(self, layer):
        return self.arp


class _FakeReader:
    def __init__(self, packets):
        self.packets = packets
        self.closed = False

    def __iter__(self):
        return iter(self.packets)

    def close(self):
        self.closed = True


def test_offline_pcap_analyzer_uses_streaming_reader(monkeypatch):
    reader = _FakeReader([
        _FakePacket(_FakeARP(MAC_A), 1),
        _FakePacket(_FakeARP(MAC_B), 2),
        _FakePacket(None, 3),                    # ARP olmayan paket atlanır
    ])
    fake_scapy = types.ModuleType("scapy")
    fake_all = types.ModuleType("scapy.all")
    fake_all.ARP = _FakeARP
    fake_all.PcapReader = lambda path: reader
    fake_scapy.all = fake_all
    monkeypatch.setitem(sys.modules, "scapy", fake_scapy)
    monkeypatch.setitem(sys.modules, "scapy.all", fake_all)

    report = OfflinePcapAnalyzer().analyze(
        "sentetik.pcap", "192.168.1.1", MAC_A
    )
    assert report.status is AnalysisStatus.ALERTS
    assert report.alerts[0].kind == "gateway_mac_conflict"
    assert report.analyzed_packets == 2
    assert reader.closed is True
