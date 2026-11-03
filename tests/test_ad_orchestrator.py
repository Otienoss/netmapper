"""AD orkestratör testleri: Impacket süreçleri stub'lanır, ağ trafiği yok."""

import asyncio

import pytest

from app.core.exceptions import ScannerError
from app.services.ad_orchestrator import ADOchestrator
from app.services.job_manager import JobStatus, job_manager
from tests.test_ad_parser import GETNPUSERS_HASH_FILE, GETUSERSPNS_STDOUT

import json


def _make_ad(monkeypatch):
    ad = ADOchestrator()
    calls = []

    async def fake_kerberoast(target, domain, username, password, timeout=None):
        calls.append(("spn", target, domain, username, password))
        return GETUSERSPNS_STDOUT, None

    async def fake_asrep(target, domain, username, password, timeout=None):
        calls.append(("asrep", target, domain, username, password))
        return GETNPUSERS_HASH_FILE, None      # hash'ler stdout'ta

    async def fake_persist(job_id, findings, **kw):
        calls.append(("persist", job_id, len(findings)))

    monkeypatch.setattr(ad.impacket, "kerberoast", fake_kerberoast)
    monkeypatch.setattr(ad.impacket, "asrep", fake_asrep)
    monkeypatch.setattr(ad, "_persist", fake_persist)
    return ad, calls


def test_ad_orchestrator_runs_tasks_and_persists(monkeypatch):
    ad, calls = _make_ad(monkeypatch)
    job_id = "job_ad_flow"
    job_manager.create_job(job_id, "10.0.0.5", profile="ad", module="ad")

    findings = asyncio.run(ad.run(
        job_id, target="10.0.0.5", domain="corp.local",
        username="alice", password="GizliSifre1!", tasks=["spn", "asrep"],
    ))

    # kerberoast 3 + asrep 2 = 5 bulgu; persist çağrıldı
    assert len(findings) == 5
    assert {f.kind for f in findings} == {"kerberoast", "asrep"}
    assert ("persist", job_id, 5) in calls

    state = job_manager.get_job(job_id)
    assert state.status == JobStatus.NORMALIZING          # DONE'yı _run atar
    assert state.progress == {"task_total": 2, "task_done": 2}
    joined = " ".join(state.logs)
    assert "Kerberoast: 3 SPN" in joined
    assert "AS-REP: 2" in joined
    # şifre asla loglara sızmamalı
    assert "GizliSifre1!" not in joined
    # meta'da da şifre yok
    assert "password" not in state.meta


def test_ad_orchestrator_all_tasks_fail_raises(monkeypatch):
    ad = ADOchestrator()

    async def boom(*a, **k):
        raise ScannerError("bağlantı reddedildi")

    monkeypatch.setattr(ad.impacket, "kerberoast", boom)
    monkeypatch.setattr(ad.impacket, "asrep", boom)
    job_manager.create_job("job_ad_fail", "10.0.0.9", profile="ad", module="ad")

    with pytest.raises(RuntimeError, match="Tüm AD görevleri başarısız"):
        asyncio.run(ad.run(
            job_id="job_ad_fail", target="10.0.0.9", domain="corp.local",
            username="alice", password="pw", tasks=["spn", "asrep"],
        ))


def test_ad_orchestrator_partial_failure_continues(monkeypatch):
    """spn başarısız olsa bile asrep koşar ve job biter."""
    ad = ADOchestrator()

    async def boom(*a, **k):
        raise ScannerError("ldap kapalı")

    async def ok_asrep(*a, **k):
        return GETNPUSERS_HASH_FILE, None      # hash'ler stdout'ta

    async def fake_persist(job_id, findings, **kw):
        pass

    monkeypatch.setattr(ad.impacket, "kerberoast", boom)
    monkeypatch.setattr(ad.impacket, "asrep", ok_asrep)
    monkeypatch.setattr(ad, "_persist", fake_persist)
    job_manager.create_job("job_ad_partial", "10.0.0.8", profile="ad", module="ad")

    findings = asyncio.run(ad.run(
        job_id="job_ad_partial", target="10.0.0.8", domain="corp.local",
        username="alice", password="pw", tasks=["spn", "asrep"],
    ))
    assert len(findings) == 2                      # asrep bulguları geldi
    state = job_manager.get_job("job_ad_partial")
    assert state.status == JobStatus.NORMALIZING
    assert any("Görev spn başarısız" in l for l in state.logs)


def _write_bh_zip(tmp_path):
    """Küçük, gerçekçi BloodHound toplama zip'i (SQLSVC → DA yolu)."""
    import zipfile

    users = {
        "meta": {"type": "users"},
        "data": [
            {"ObjectIdentifier": "S-1-5-21-1-SQLSVC",
             "Properties": {"name": "SQLSVC@CORP.LOCAL"}, "Aces": []},
            {"ObjectIdentifier": "S-1-5-21-1-BOB",
             "Properties": {"name": "BOB@CORP.LOCAL"}, "Aces": []},
        ],
    }
    groups = {
        "meta": {"type": "groups"},
        "data": [
            {"ObjectIdentifier": "S-1-5-21-1-SQLADM",
             "Properties": {"name": "SQL ADMINS@CORP.LOCAL"}, "Aces": [],
             "Members": [{"ObjectIdentifier": "S-1-5-21-1-SQLSVC"}]},
            {"ObjectIdentifier": "S-1-5-21-1-DA",
             "Properties": {"name": "DOMAIN ADMINS@CORP.LOCAL"},
             "Aces": [{"PrincipalSID": "S-1-5-21-1-SQLADM",
                       "PrincipalName": "SQL ADMINS@CORP.LOCAL",
                       "RightName": "GenericAll"}],
             "Members": []},
        ],
    }
    zpath = tmp_path / "collection.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("users.json", json.dumps(users))
        zf.writestr("groups.json", json.dumps(groups))
    return zpath


def test_ad_orchestrator_acl_task_finds_privesc_path(tmp_path, monkeypatch):
    """acl görevi: BloodHound zip → graf → privesc yolu bulgusu (+ dc_hostname akışı)."""
    ad = ADOchestrator()
    zpath = _write_bh_zip(tmp_path)
    bh_calls = []

    async def fake_bh(*a, **k):
        bh_calls.append(k)
        return zpath

    async def fake_persist(job_id, findings, **kw):
        pass

    monkeypatch.setattr(ad.bloodhound, "scan", fake_bh)
    monkeypatch.setattr(ad, "_persist", fake_persist)
    job_manager.create_job("job_ad_acl", "dc.corp.local", profile="ad", module="ad")

    findings = asyncio.run(ad.run(
        job_id="job_ad_acl", target="10.0.0.5", domain="corp.local",
        username="alice", password="Sup3rS3cret!", tasks=["acl"],
        dc_hostname="winterfell.north.sevenkingdoms.local",
        # privesc_start verilmedi → en yakın kullanıcı otomatik seçilir
    ))

    # scanner'a doğru argümanlar geçmiş olmalı
    assert bh_calls == [{
        "domain": "corp.local", "username": "alice",
        "password": "Sup3rS3cret!", "dc_ip": "10.0.0.5",
        "dc_hostname": "winterfell.north.sevenkingdoms.local",
    }]

    assert len(findings) == 1
    p = findings[0]
    assert p.kind == "privesc"
    assert p.severity == "high"
    assert p.principal == "SQLSVC@CORP.LOCAL"
    assert p.detail["hop_count"] == 2
    assert [h["right"] for h in p.detail["hops"]] == ["MemberOf", "GenericAll"]
    assert p.detail["auto_selected"] is True
    assert "DOMAIN ADMINS" in p.message
    # şifre hiçbir yerde (bulgu JSON'u dahil) geçmemeli
    assert "Sup3rS3cret!" not in json.dumps(p.model_dump())

    state = job_manager.get_job("job_ad_acl")
    joined = " ".join(state.logs)
    assert "BloodHound:" in joined and "Privesc:" in joined
    assert "Sup3rS3cret!" not in joined


def test_ad_orchestrator_acl_explicit_start(tmp_path, monkeypatch):
    """privesc_start verilirse o hesaptan yol aranır; BOB'a yol yoktur."""
    ad = ADOchestrator()
    zpath = _write_bh_zip(tmp_path)

    async def fake_bh(*a, **k):
        return zpath

    async def fake_persist(job_id, findings, **kw):
        pass

    monkeypatch.setattr(ad.bloodhound, "scan", fake_bh)
    monkeypatch.setattr(ad, "_persist", fake_persist)
    job_manager.create_job("job_ad_acl2", "dc.corp.local", profile="ad", module="ad")

    findings = asyncio.run(ad.run(
        job_id="job_ad_acl2", target="dc.corp.local", domain="corp.local",
        username="alice", password="pw", tasks=["acl"],
        privesc_start="bob",          # kenarı olmayan hesap → info bulgusu
    ))
    assert findings[0].severity == "info"
    assert "yolU bulunamadı" in findings[0].message

    job_manager.create_job("job_ad_acl3", "dc.corp.local", profile="ad", module="ad")
    findings2 = asyncio.run(ad.run(
        job_id="job_ad_acl3", target="dc.corp.local", domain="corp.local",
        username="alice", password="pw", tasks=["acl"],
        privesc_start="sqlsvc",
    ))
    assert findings2[0].severity == "high"
    assert findings2[0].detail["auto_selected"] is False
    assert findings2[0].principal == "SQLSVC@CORP.LOCAL"


def test_ad_orchestrator_acl_failure_falls_through(monkeypatch):
    """bloodhound-binary yok/DC erişilemez → acl hatası, job çökmez (tek görevse RuntimeError)."""
    ad = ADOchestrator()

    async def boom(*a, **k):
        raise ScannerError("bloodhound-python başarısız: LDAP bağlantısı yok")

    async def ok_asrep(*a, **k):
        return GETNPUSERS_HASH_FILE, None

    async def fake_persist(job_id, findings, **kw):
        pass

    monkeypatch.setattr(ad.bloodhound, "scan", boom)
    monkeypatch.setattr(ad.impacket, "asrep", ok_asrep)
    monkeypatch.setattr(ad, "_persist", fake_persist)
    job_manager.create_job("job_ad_acl_fail", "10.0.0.7", profile="ad", module="ad")

    findings = asyncio.run(ad.run(
        job_id="job_ad_acl_fail", target="10.0.0.7", domain="corp.local",
        username="alice", password="pw", tasks=["acl", "asrep"],
    ))
    assert any(f.kind == "asrep" for f in findings)
    state = job_manager.get_job("job_ad_acl_fail")
    assert any("Görev acl başarısız" in l for l in state.logs)


def test_ad_orchestrator_cve_task(monkeypatch):
    """cve görevi: CveScanner sonuçları bulguya dönüşür (+ parametre akışı)."""
    ad = ADOchestrator()
    seen: dict = {}

    async def fake_scan(**kw):
        seen.update(kw)
        return [
            {"cve": "CVE-2020-1472", "vulnerable": True, "detail": "boş oturum kabul"},
            {"cve": "CVE-2021-34527", "vulnerable": False, "detail": "spooler kapalı"},
            {"cve": "CVE-2021-42278/42287", "vulnerable": False, "detail": "PAC eşit"},
        ]

    async def fake_persist(job_id, findings, **kw):
        pass

    monkeypatch.setattr(ad.cve, "scan", fake_scan)
    monkeypatch.setattr(ad, "_persist", fake_persist)
    job_manager.create_job("job_ad_cve", "10.0.0.5", profile="ad", module="ad")

    findings = asyncio.run(ad.run(
        job_id="job_ad_cve", target="10.0.0.5", domain="corp.local",
        username="alice", password="Sifre123!", tasks=["cve"],
        dc_hostname="dc01.corp.local",
    ))

    # tüm parametreler scanner'a ulaşmış olmalı
    assert seen == {
        "domain": "corp.local", "dc_ip": "10.0.0.5",
        "username": "alice", "password": "Sifre123!",
        "dc_hostname": "dc01.corp.local",
    }
    assert [f.kind for f in findings] == ["cve", "cve", "cve"]
    assert [f.severity for f in findings] == ["high", "info", "info"]
    assert findings[0].principal == "CVE-2020-1472"
    assert findings[0].detail["vulnerable"] is True
    assert findings[1].detail["vulnerable"] is False
    assert findings[0].detail["target"] == "10.0.0.5"
    # job logları: özet + şifre sızıntısı yok
    joined = " ".join(job_manager.get_job("job_ad_cve").logs)
    assert "3 kontrol, 1 açık" in joined
    assert "Sifre123!" not in joined


def test_ad_orchestrator_pwn_task(monkeypatch):
    """pwn görevi: exploiter.pwn sonucu bulguya dönüşür + da_user/job_id akışı."""
    ad = ADOchestrator()
    seen: dict = {}

    async def fake_pwn(**kw):
        seen.update(kw)
        on_step = kw.get("on_step")
        if on_step:
            await on_step("CVE-2021-42278: sAMAccountName → 'dc01'")
        return {
            "success": True,
            "outcome": "exploited",
            "error": None,
            "computer_account": "NM-ABC123$",
            "tgt_ccache": "data/tickets/j1/dc01.ccache",
            "da_ccache": "data/tickets/j1/Administrator@CIFS_dc01@CORP.LOCAL.ccache",
            "da_user": kw.get("da_user"),
            "spn": "cifs/dc01.corp.local",
            "dc_fqdn": "dc01.corp.local",
            "job_dir": "data/tickets/j1",
            "steps": ["…"],
            "cleanup": {"attempted": True, "verified": True,
                        "status": "ok", "error": None, "manual_hint": None},
        }

    async def fake_persist(job_id, findings, **kw):
        pass

    monkeypatch.setattr(ad.exploiter, "pwn", fake_pwn)
    monkeypatch.setattr(ad, "_persist", fake_persist)
    job_manager.create_job("job_ad_pwn", "10.13.38.5", profile="ad", module="ad")

    findings = asyncio.run(ad.run(
        job_id="job_ad_pwn", target="10.13.38.5", domain="corp.local",
        username="alice", password="Sifre123!", tasks=["pwn"],
        da_user="Enterprise Admins", dc_hostname="dc01.corp.local",
    ))

    # exploiter doğru parametrelerle çağrılmış (+ job_id izolasyonu için)
    assert seen["da_user"] == "Enterprise Admins"
    assert seen["dc_hostname"] == "dc01.corp.local"
    assert seen["target"] == "10.13.38.5"
    assert seen["job_id"] == "job_ad_pwn"

    # bulgu: kind=pwn, severity=critical YALNIZCA exploited'da
    assert [f.kind for f in findings] == ["pwn"]
    f = findings[0]
    assert f.severity == "critical"
    assert f.principal == "Enterprise Admins"
    assert f.spn == "cifs/dc01.corp.local"
    assert f.detail["outcome"] == "exploited"
    assert f.detail["success_claim"] is True
    assert f.detail["ccache_path"].endswith(".ccache")
    assert f.detail["cleanup_verified"] is True
    assert f.detail["cleanup_failed"] is False
    assert "42278" in f.detail["chain"] and "42287" in f.detail["chain"]

    # adım akışı + özet job loglarına düşmüş; şifre sızmamış
    state = job_manager.get_job("job_ad_pwn")
    joined = " ".join(state.logs)
    assert "GERÇEK AD DEĞİŞİKLİĞİ" in joined
    assert "DOĞRULANDI" in joined
    assert "Sifre123!" not in joined


def test_ad_orchestrator_pwn_finding_evidence_levels(monkeypatch):
    """Görev 6: kanıt seviyesi → severity eşlemesi (dosya varlığı KANIT DEĞİL)."""
    from app.services.ad_orchestrator import ADOchestrator

    _base = {
        "computer_account": "NM-X$", "tgt_ccache": None,
        "da_user": "Administrator", "spn": "cifs/dc01.corp.local",
        "dc_fqdn": "dc01.corp.local", "steps": [],
        "cleanup": {"attempted": False, "verified": False,
                    "status": "skipped", "error": None, "manual_hint": None},
    }
    cases = {
        "exploited": ("critical", True),
        "validated": ("high", False),
        "attempted": ("medium", False),
        "inconclusive": ("medium", False),
    }
    for oc, (sev, claim) in cases.items():
        outcome = {**_base, "outcome": oc, "success": claim,
                   "error": None if claim else "x",
                   "da_ccache": "t.ccache" if claim else None}
        f = ADOchestrator._pwn_finding(outcome)
        assert f.severity == sev, oc
        assert f.detail["success_claim"] is claim, oc
        if not claim:
            assert f.detail["ccache_path"] is None, oc


def test_ad_orchestrator_pwn_cleanup_failed_flag(monkeypatch):
    """Temizlik doğrulanamadıysa bulgu cleanup_failed=true taşır (gizlenmez)."""
    from app.services.ad_orchestrator import ADOchestrator

    outcome = {
        "success": True, "outcome": "exploited", "error": None,
        "computer_account": "NM-X$", "tgt_ccache": "t",
        "da_ccache": "d.ccache", "da_user": "Administrator",
        "spn": "cifs/dc01", "dc_fqdn": "dc01.corp.local", "steps": [],
        "cleanup": {"attempted": True, "verified": False,
                    "status": "unverified", "error": "hesap hâlâ mevcut",
                    "manual_hint": "NM-X$ elle silin"},
    }
    f = ADOchestrator._pwn_finding(outcome)
    assert f.detail["cleanup_failed"] is True
    assert f.detail["cleanup_status"] == "unverified"
    assert f.detail["cleanup_error"] == "hesap hâlâ mevcut"
    assert f.detail["manual_hint"] == "NM-X$ elle silin"
    assert f.severity == "critical"      # erişim kanıtı bağımsız olarak korunur


def test_ad_orchestrator_pwn_gate_blocked_raises(monkeypatch):
    """Kapı engeli (outcome=failed) görev hatasıdır → job error, bulgu YOK."""
    ad = ADOchestrator()

    async def fake_pwn(**kw):
        return {"success": False, "outcome": "failed",
                "error": "Sömürü engellendi: allowlist", "da_user": "Administrator",
                "cleanup": {"attempted": False, "verified": False,
                            "status": "skipped", "error": None,
                            "manual_hint": None}}

    async def fake_persist(job_id, findings, **kw):
        pass

    monkeypatch.setattr(ad.exploiter, "pwn", fake_pwn)
    monkeypatch.setattr(ad, "_persist", fake_persist)
    job_manager.create_job("job_ad_pwn_gate", "10.13.38.5",
                          profile="ad", module="ad")
    with pytest.raises(RuntimeError, match="engellendi"):
        asyncio.run(ad.run(
            job_id="job_ad_pwn_gate", target="10.13.38.5",
            domain="corp.local", username="alice", password="x",
            tasks=["pwn"],
        ))
