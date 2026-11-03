"""dcinfo görevi uçtan uca testleri — LDAP mock'lu, ağ trafiği yok."""

import asyncio

from fastapi.testclient import TestClient

from app.main import app
from app.services.ad_orchestrator import ADOchestrator
from app.services.job_manager import job_manager


def test_dcinfo_task_adds_samaccountname_to_findings(monkeypatch):
    ad = ADOchestrator()
    captured = {}

    async def fake_query(**kwargs):
        captured.update(kwargs)
        return [{
            "sAMAccountName": "DC01$",
            "dNSHostName": "dc01.corp.local",
            "distinguishedName":
                "CN=DC01,OU=Domain Controllers,DC=corp,DC=local",
            "operatingSystem": "Windows Server 2019",
            "source": "ldap",
            "read_only": True,
        }]

    async def fake_persist(job_id, findings, **kwargs):
        captured["persisted"] = findings

    monkeypatch.setattr(
        "app.services.ad_orchestrator.query_domain_controllers", fake_query
    )
    monkeypatch.setattr(ad, "_persist", fake_persist)
    job_manager.create_job(
        "job_dcinfo", "10.0.0.5", profile="ad", module="ad"
    )

    findings = asyncio.run(ad.run(
        "job_dcinfo", target="10.0.0.5", domain="corp.local",
        username="alice", password="GizliSifre1!", tasks=["dcinfo"],
    ))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.kind == "dcinfo"
    assert finding.principal == "DC01$"
    assert finding.severity == "info"
    assert finding.detail["sAMAccountName"] == "DC01$"
    assert finding.detail["dNSHostName"] == "dc01.corp.local"
    assert finding.detail["read_only"] is True
    assert "sAMAccountName" in finding.message
    assert captured["persisted"] == findings
    assert captured["target"] == "10.0.0.5"
    assert captured["domain"] == "corp.local"

    logs = " ".join(job_manager.get_job("job_dcinfo").logs)
    assert "DC01$" in logs and "dc01.corp.local" in logs
    assert "GizliSifre1!" not in logs


def test_ad_panel_exposes_dcinfo_and_samaccountname():
    with TestClient(app) as client:
        response = client.get("/static/panels/ad_modulu.html")
    assert response.status_code == 200
    assert 'value="dcinfo"' in response.text
    assert "sAMAccountName" in response.text
