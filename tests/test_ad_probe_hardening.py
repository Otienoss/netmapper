"""Çoklu DC seçimi ve katı async timeout testleri — gerçek ağ yok."""

import asyncio
import time

import pytest
from fastapi.testclient import TestClient

from app.ad_probes.base import BaseADProbe
from app.ad_probes.cleanup import cleanup_ldap_object_verified
from app.ad_probes.models import (
    ADProbeContext,
    CleanupStatus,
    ProbeOutcome,
)
from app.ad_probes.preflight import PreFlightError, PreflightEngine
from app.main import app
from tests.test_ad_preflight import _Connection, _dc, _domain_entry
from tests.test_ad_probe_framework import _DummyProbe, _report


def test_explicit_target_dc_selects_exact_record():
    conn = _Connection(_domain_entry(), [
        _dc(), _dc("DC02$", "dc02.corp.local"),
    ])
    engine = PreflightEngine(connection_factory=lambda context: conn)
    context = ADProbeContext(
        target="10.0.0.5", domain="corp.local", username="alice",
        password="pw", target_dc="DC02$",
    )
    report = asyncio.run(engine.collect(context))
    assert report.dc_sam_account_name == "DC02$"
    assert report.dc_dns_host_name == "dc02.corp.local"


def test_explicit_target_dc_never_falls_back_to_single_other_dc():
    conn = _Connection(_domain_entry(), [_dc()])
    engine = PreflightEngine(connection_factory=lambda context: conn)
    context = ADProbeContext(
        target="10.0.0.5", domain="corp.local", username="alice",
        password="pw", target_dc="dc02.corp.local",
    )
    report = asyncio.run(engine.collect(context))
    assert report.dc_sam_account_name is None
    assert any("eşleşen DC kaydı yok" in error for error in report.errors)


def test_preflight_overall_timeout_is_bounded():
    class SlowConnection(_Connection):
        def search(self, *args, **kwargs):
            time.sleep(0.05)
            return super().search(*args, **kwargs)

    conn = SlowConnection(_domain_entry(), [_dc()])
    engine = PreflightEngine(
        connection_factory=lambda context: conn, timeout=0.01,
    )
    context = ADProbeContext(
        target="10.0.0.5", domain="corp.local", username="alice", password="pw"
    )
    with pytest.raises(PreFlightError, match="zaman aşımı"):
        asyncio.run(engine.collect(context))


def test_trigger_timeout_returns_attempted():
    class SlowTriggerProbe(_DummyProbe):
        stage_timeouts = {
            **BaseADProbe.stage_timeouts, "minimal_trigger": 0.01,
        }

        async def minimal_trigger(self, context, report):
            self.trigger_called = True
            await asyncio.sleep(1)

    result = asyncio.run(SlowTriggerProbe(_report()).run(
        ADProbeContext(
            target="10.0.0.5", domain="corp.local",
            username="alice", password="pw",
        )
    ))
    assert result.outcome is ProbeOutcome.ATTEMPTED
    assert "zaman aşımı" in result.reason


def test_cleanup_timeout_is_unverified():
    async def slow_delete():
        await asyncio.sleep(1)

    async def absent():
        return False

    report = asyncio.run(cleanup_ldap_object_verified(
        "CN=test", slow_delete, absent, timeout=0.01,
    ))
    assert report.status is CleanupStatus.UNVERIFIED
    assert "zaman aşımı" in report.error


def test_api_accepts_dc_fqdn_alias(monkeypatch):
    captured = {}

    async def fake_start_scan(target, profile="full", module="net", params=None):
        captured["params"] = params
        return "dc-select-job"

    monkeypatch.setattr(
        "app.api.routes.job_manager.start_scan", fake_start_scan
    )
    with TestClient(app) as client:
        response = client.post("/api/v1/ad/probe", json={
            "target": "10.0.0.5", "domain": "corp.local",
            "username": "alice", "password": "pw",
            "dc_fqdn": "dc02.corp.local",
        })
    assert response.status_code == 200
    assert captured["params"]["target_dc"] == "dc02.corp.local"
