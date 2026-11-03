"""Salt-okunur LDAP DC envanteri testleri — gerçek LDAP bağlantısı yok."""

import asyncio

import ldap3
import pytest

from app.core.exceptions import ScannerError
from app.scanners.ldap_discovery import query_domain_controllers


class _Entry:
    def __init__(self, sam, fqdn, dn, operating_system=None):
        self.sAMAccountName = sam
        self.dNSHostName = fqdn
        self.entry_dn = dn
        self.operatingSystem = operating_system


def _fake_ldap(monkeypatch, entries, search_ok=True):
    state = {}

    class FakeConnection:
        def __init__(self, server, **kwargs):
            state["server"] = server
            state["connection_kwargs"] = kwargs
            self.entries = entries
            self.result = {"result": 0 if search_ok else 50}

        def search(self, base, search_filter, attributes):
            state["search"] = {
                "base": base,
                "filter": search_filter,
                "attributes": attributes,
            }
            return search_ok

        def unbind(self):
            state["unbound"] = True

    monkeypatch.setattr(
        ldap3, "Server",
        lambda target, **kwargs: {"target": target, **kwargs},
    )
    monkeypatch.setattr(ldap3, "Connection", FakeConnection)
    return state


def test_query_domain_controllers_returns_sam_and_fqdn(monkeypatch):
    entries = [
        _Entry("DC02$", "dc02.corp.local",
               "CN=DC02,OU=Domain Controllers,DC=corp,DC=local"),
        _Entry("DC01$", "dc01.corp.local",
               "CN=DC01,OU=Domain Controllers,DC=corp,DC=local",
               "Windows Server 2019"),
        _Entry(None, None, "CN=NO-SAM,DC=corp,DC=local"),
    ]
    state = _fake_ldap(monkeypatch, entries)

    records = asyncio.run(query_domain_controllers(
        domain="corp.local", target="10.0.0.5",
        username="alice", password="GizliSifre1!",
    ))

    assert [r["sAMAccountName"] for r in records] == ["DC01$", "DC02$"]
    assert records[0]["dNSHostName"] == "dc01.corp.local"
    assert records[0]["operatingSystem"] == "Windows Server 2019"
    assert records[0]["read_only"] is True
    assert records[0]["source"] == "ldap"

    search = state["search"]
    assert search["base"] == "DC=corp,DC=local"
    assert "primaryGroupID=516" in search["filter"]
    assert "sAMAccountName" in search["attributes"]
    assert "dNSHostName" in search["attributes"]
    assert state["server"]["target"] == "10.0.0.5"
    assert state["connection_kwargs"]["user"] == "corp.local\\alice"
    assert state["connection_kwargs"]["authentication"] == ldap3.NTLM
    assert state["unbound"] is True


def test_query_domain_controllers_missing_optional_values(monkeypatch):
    """Boş LDAP alanları 'None' metnine dönüştürülmez."""
    state = _fake_ldap(monkeypatch, [
        _Entry("DC01$", None, "CN=DC01,DC=corp,DC=local", None),
    ])
    records = asyncio.run(query_domain_controllers(
        "corp.local", "10.0.0.5", "alice", "pw",
    ))
    assert records[0]["sAMAccountName"] == "DC01$"
    assert records[0]["dNSHostName"] is None
    assert records[0]["operatingSystem"] is None
    assert state["unbound"] is True


def test_query_domain_controllers_search_failure(monkeypatch):
    state = _fake_ldap(monkeypatch, [], search_ok=False)
    with pytest.raises(ScannerError, match="reddedildi"):
        asyncio.run(query_domain_controllers(
            "corp.local", "10.0.0.5", "alice", "pw",
        ))
    assert state["unbound"] is True
