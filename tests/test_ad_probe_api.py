"""FastAPI + job_manager AD probe adaptör testleri."""

import asyncio

from fastapi.testclient import TestClient

from app.ad_probes.models import ProbeOutcome, ProbeResult
from app.main import app
from app.services import ad_probe_runner
from app.services.job_manager import JobStatus, job_manager


def test_ad_probe_endpoint_starts_ad_probe_job(monkeypatch):
    captured = {}

    async def fake_start_scan(target, profile="full", module="net", params=None):
        captured.update({
            "target": target, "profile": profile,
            "module": module, "params": params,
        })
        return "probe-job-1"

    monkeypatch.setattr(
        "app.api.routes.job_manager.start_scan", fake_start_scan
    )
    with TestClient(app) as client:
        response = client.post("/api/v1/ad/probe", json={
            "target": "10.0.0.5", "domain": "corp.local",
            "username": "alice", "password": "GizliSifre1!", "probe": "maq",
        })

    assert response.status_code == 200
    assert response.json()["job_id"] == "probe-job-1"
    assert captured["module"] == "ad_probe"
    assert captured["params"]["probe"] == "maq"
    assert "tasks" not in captured["params"]


def test_job_manager_ad_probe_branch_stores_result(monkeypatch):
    class FakeProbe:
        async def run(self, context):
            assert context.password == "GizliSifre1!"
            return ProbeResult(
                probe="fake", outcome=ProbeOutcome.VALIDATED,
                reason="sentetik kanıt",
            )

    monkeypatch.setitem(ad_probe_runner._PROBE_TYPES, "maq", FakeProbe)
    job_manager.create_job(
        "probe-job-2", "10.0.0.5", profile="ad", module="ad_probe"
    )
    asyncio.run(job_manager._run(
        "probe-job-2", "10.0.0.5", "ad", None, "ad_probe",
        {
            "domain": "corp.local", "username": "alice",
            "password": "GizliSifre1!", "probe": "maq",
        },
    ))

    state = job_manager.get_job("probe-job-2")
    assert state.status is JobStatus.DONE
    assert state.results[0]["outcome"] == "validated"
    assert state.results[0]["cleanup"]["status"] == "verified"
    assert "password" not in state.meta
    assert "GizliSifre1!" not in " ".join(state.logs)
