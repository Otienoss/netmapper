"""Switch konfigürasyon denetimi testleri."""

from app.arp_security.config_audit import SwitchConfigAuditor

SECURE_CONFIG = """
ip dhcp snooping
ip arp inspection vlan 10
interface GigabitEthernet1/0/1
 ip arp inspection trust
interface GigabitEthernet1/0/2
 ip verify source
 switchport port-security maximum 2
dot1x system-auth-control
"""


def test_secure_config_passes_controls():
    report = SwitchConfigAuditor().audit(SECURE_CONFIG, config_complete=True)
    assert report.overall == "pass"
    assert report.summary["fail"] == 0
    assert report.summary["unknown"] == 0


def test_partial_config_absence_is_unknown_not_fail():
    report = SwitchConfigAuditor().audit("interface Gi1/0/1\n")
    assert report.overall == "review"
    assert report.summary["fail"] == 0
    assert report.summary["unknown"] == 5


def test_complete_config_missing_controls_fails():
    report = SwitchConfigAuditor().audit("hostname lab-switch\n", True)
    assert report.overall == "at_risk"
    assert report.summary["fail"] == 5


def test_explicitly_disabled_dai_fails_even_in_partial_config():
    report = SwitchConfigAuditor().audit("no ip arp inspection vlan 10\n")
    dai = next(f for f in report.findings if f.control == "dynamic_arp_inspection")
    assert dai.status.value == "fail"
    assert dai.severity == "critical"


def test_dai_without_visible_uplink_trust_needs_review():
    config = "ip arp inspection vlan 10\n"
    report = SwitchConfigAuditor().audit(config)
    trust = next(f for f in report.findings if f.control == "dai_uplink_trust")
    assert trust.status.value == "unknown"
