from app.normalization.schema import HostResult, ServiceInfo
from app.reporting.risk_rules import evaluate_host, evaluate_port


def test_telnet_is_high_risk():
    r = evaluate_port(ServiceInfo(port=23, protocol="tcp", state="open",
                                  service_name="telnet"))
    assert r.level == "high"
    assert r.score == 75
    assert any("Telnet" in reason for reason in r.reasons)


def test_https_is_info_and_http_is_low():
    https = evaluate_port(ServiceInfo(port=443, protocol="tcp", state="open",
                                      service_name="https"))
    http = evaluate_port(ServiceInfo(port=80, protocol="tcp", state="open",
                                     service_name="http"))
    assert https.level == "info"
    assert http.level == "low"


def test_host_score_is_max_of_ports():
    host = HostResult(ip="192.168.1.10", services=[
        ServiceInfo(port=80, protocol="tcp", state="open", service_name="http"),
        ServiceInfo(port=23, protocol="tcp", state="open", service_name="telnet"),
        ServiceInfo(port=443, protocol="tcp", state="open", service_name="https"),
    ])
    risk = evaluate_host(host)
    assert risk.level == "high"
    assert risk.score == 75
    assert len(risk.findings) == 3


def test_host_without_services_is_info():
    risk = evaluate_host(HostResult(ip="192.168.1.11"))
    assert risk.level == "info"
    assert risk.score == 0
    assert risk.findings == []


def test_version_leak_flagged_as_info():
    r = evaluate_port(ServiceInfo(port=9999, protocol="tcp", state="open",
                                  service_name="unknown", product="MyApp", version="1.0"))
    assert any("Sürüm" in reason for reason in r.reasons)


def test_web_findings_raise_host_risk():
    """Nikto 'high' bulgusu, düşük riskli portlara rağmen host'u yüksek riske çeker."""
    from app.normalization.schema import WebFinding
    host = HostResult(
        ip="1.2.3.4",
        services=[ServiceInfo(port=80, protocol="tcp", state="open",
                              service_name="http")],
        web_findings=[WebFinding(message="X-Frame-Options missing", severity="high")],
    )
    risk = evaluate_host(host)
    assert risk.level == "high"
    assert risk.score == 75


def test_host_with_only_info_web_finding_stays_info():
    from app.normalization.schema import WebFinding
    host = HostResult(ip="1.2.3.5",
                      web_findings=[WebFinding(message="bilgi", severity="info")])
    risk = evaluate_host(host)
    assert risk.level == "info"
    assert risk.score == 0
