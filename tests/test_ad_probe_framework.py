"""BaseADProbe yaşam döngüsü ve MAQ ön koşul testleri — ağ trafiği yok."""

import asyncio

from app.ad_probes.base import BaseADProbe
from app.ad_probes.maq import MachineAccountQuotaProbe
from app.ad_probes.models import (
    ADProbeContext,
    CleanupStatus,
    Evidence,
    PreflightReport,
    ProbeOutcome,
    Proof,
)


def _context():
    return ADProbeContext(
        target="10.0.0.5", domain="corp.local",
        username="alice", password="GizliSifre1!",
    )


def _report(maq=10, sid="S-1-5-21-1-2-3", sam="DC01$"):
    return PreflightReport(
        target="10.0.0.5", domain="corp.local",
        dc_sam_account_name=sam, domain_sid=sid,
        machine_account_quota=maq,
    )


class _StubEngine:
    def __init__(self, report):
        self.report = report

    async def collect(self, context):
        return self.report


class _DummyProbe(BaseADProbe):
    name = "dummy"

    def __init__(self, report, trigger_error=False):
        super().__init__(_StubEngine(report))
        self.trigger_called = False
        self.trigger_error = trigger_error

    async def minimal_trigger(self, context, report):
        self.trigger_called = True
        if self.trigger_error:
            raise RuntimeError("kontrollü tetik hatası")
        from app.ad_probes.models import TriggerData
        return TriggerData(attempted=True)

    async def verify_proof(self, context, trigger):
        return Proof(
            ProbeOutcome.VALIDATED, "kanıt tamam",
            [Evidence("mock", "proof", True, "sentetik")],
        )


def test_missing_preflight_data_is_inconclusive_and_skips_trigger():
    probe = _DummyProbe(_report(sid=None))
    result = asyncio.run(probe.run(_context()))
    assert result.outcome is ProbeOutcome.INCONCLUSIVE
    assert probe.trigger_called is False
    assert result.cleanup.status is CleanupStatus.VERIFIED


def test_maq_zero_fails_before_trigger():
    probe = MachineAccountQuotaProbe(_StubEngine(_report(maq=0)))

    async def unexpected_trigger(context, report):
        raise AssertionError("MAQ=0 iken tetik çalışmamalı")

    probe.minimal_trigger = unexpected_trigger
    result = asyncio.run(probe.run(_context()))
    assert result.outcome is ProbeOutcome.FAILED
    assert "MAQ" in result.reason or "MachineAccountQuota" in result.reason


def test_maq_unknown_is_inconclusive_not_negative_finding():
    probe = MachineAccountQuotaProbe(_StubEngine(_report(maq=None)))
    result = asyncio.run(probe.run(_context()))
    assert result.outcome is ProbeOutcome.INCONCLUSIVE
    assert result.preflight.machine_account_quota is None


def test_positive_maq_is_validated_with_ldap_evidence():
    probe = MachineAccountQuotaProbe(_StubEngine(_report(maq=10)))
    result = asyncio.run(probe.run(_context()))
    assert result.outcome is ProbeOutcome.VALIDATED
    assert result.evidence[0].source == "ldap"
    assert result.evidence[0].passed is True
    assert result.to_dict()["cleanup"]["status"] == "verified"


def test_trigger_exception_is_attempted_not_false_negative():
    probe = _DummyProbe(_report(), trigger_error=True)
    result = asyncio.run(probe.run(_context()))
    assert result.outcome is ProbeOutcome.ATTEMPTED
    assert probe.trigger_called is True
    assert "kontrollü tetik hatası" in result.error


def test_cleanup_failure_is_independent_unverified():
    class CleanupBoomProbe(_DummyProbe):
        async def cleanup(self, context):
            raise RuntimeError("artefakt silinemedi")

    result = asyncio.run(CleanupBoomProbe(_report()).run(_context()))
    assert result.outcome is ProbeOutcome.VALIDATED
    assert result.cleanup.status is CleanupStatus.UNVERIFIED
    assert "silinemedi" in result.cleanup.error
