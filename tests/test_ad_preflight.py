"""LDAP pre-flight engine testleri — sahte bağlantı, gerçek LDAP yok."""

import asyncio

import pytest

from app.ad_probes.models import ADProbeContext, ProbeOutcome
from app.ad_probes.maq import MachineAccountQuotaProbe
from app.ad_probes.preflight import PreFlightError, PreflightEngine, sid_to_string


def _sid_bytes(*sub_authorities):
    return (
        bytes([1, len(sub_authorities)])
        + (5).to_bytes(6, "big")
        + b"".join(int(v).to_bytes(4, "little") for v in sub_authorities)
    )


class _Entry:
    def __init__(self, **attributes):
        for name, value in attributes.items():
            setattr(self, name, value)


class _Connection:
    def __init__(self, domain_entry, dc_entries):
        self.domain_entry = domain_entry
        self.dc_entries = dc_entries
        self.entries = []
        self.unbound = False

    def search(self, base, search_filter, attributes):
        if search_filter == "(objectClass=domainDNS)":
            self.entries = [self.domain_entry] if self.domain_entry else []
        else:
            self.entries = self.dc_entries
        return True

    def unbind(self):
        self.unbound = True


def _domain_entry(maq="10"):
    return _Entry(
        objectSid=_sid_bytes(21, 111, 222, 333),
        **{
            "ms-DS-MachineAccountQuota": maq,
            "maxTicketAge": "360000000000",
            "maxRenewAge": "6048000000000",
            "maxServiceAge": "360000000000",
            "maxClockSkew": "3000000000",
        },
    )


def _dc(name="DC01$", fqdn="dc01.corp.local"):
    return _Entry(
        sAMAccountName=name, dNSHostName=fqdn,
        **{"msDS-SupportedEncryptionTypes": "28"},
    )


def _context(target="10.0.0.5"):
    return ADProbeContext(
        target=target, domain="corp.local", username="alice", password="pw"
    )


def test_preflight_collects_sid_maq_kerberos_and_dc():
    conn = _Connection(_domain_entry(), [_dc()])
    engine = PreflightEngine(connection_factory=lambda context: conn)
    report = asyncio.run(engine.collect(_context()))

    assert report.dc_sam_account_name == "DC01$"
    assert report.dc_dns_host_name == "dc01.corp.local"
    assert report.domain_sid == "S-1-5-21-111-222-333"
    assert report.machine_account_quota == 10
    assert report.kerberos["maxTicketAgeMinutes"] == 600.0
    assert report.kerberos["maxClockSkewMinutes"] == 5.0
    assert report.kerberos["dcSupportedEncryptionTypes"] == 28
    assert conn.unbound is True


def test_multiple_dc_records_do_not_guess_target_identity():
    conn = _Connection(_domain_entry(), [
        _dc(), _dc("DC02$", "dc02.corp.local"),
    ])
    engine = PreflightEngine(connection_factory=lambda context: conn)
    report = asyncio.run(engine.collect(_context()))

    assert report.dc_sam_account_name is None
    assert any("eşleştirilemedi" in error for error in report.errors)
    # Eksik hedef kimliği olumsuz kanıt değildir: probe inconclusive olur.
    probe = MachineAccountQuotaProbe(engine)
    result = asyncio.run(probe.run(_context()))
    assert result.outcome is ProbeOutcome.INCONCLUSIVE


def test_hostname_selects_exact_dc_record():
    conn = _Connection(_domain_entry(), [
        _dc(), _dc("DC02$", "dc02.corp.local"),
    ])
    engine = PreflightEngine(connection_factory=lambda context: conn)
    report = asyncio.run(engine.collect(_context("dc02.corp.local")))
    assert report.dc_sam_account_name == "DC02$"


def test_connection_failure_raises_preflight_error():
    def unavailable(context):
        raise OSError("kontrollü bağlantı hatası")

    engine = PreflightEngine(connection_factory=unavailable)
    with pytest.raises(PreFlightError, match="bağlantısı"):
        asyncio.run(engine.collect(_context()))


def test_sid_parser_rejects_truncated_data():
    assert sid_to_string(b"\x01\x04\x00") is None
    assert sid_to_string("not-a-sid") is None
