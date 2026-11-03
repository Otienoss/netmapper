"""BloodHound parser + PathFinder testleri (gerçek CLI/doming yok)."""

import json
import zipfile

import pytest

from app.core.exceptions import ParseError
from app.normalization.bloodhound_parser import parse_bloodhound_zip
from app.services.path_finder import PathFinder

USERS = {
    "meta": {"type": "users", "count": 3},
    "data": [
        {"ObjectIdentifier": "S-1-5-21-1-SQLSVC",
         "Properties": {"name": "SQLSVC@CORP.LOCAL"}, "Aces": [], "Members": []},
        {"ObjectIdentifier": "S-1-5-21-1-BOB",
         "Properties": {"name": "BOB@CORP.LOCAL"}, "Aces": [], "Members": []},
        {"ObjectIdentifier": "S-1-5-21-1-ADMIN",
         "Properties": {"name": "ADMIN@CORP.LOCAL"}, "Aces": [], "Members": []},
    ],
}
GROUPS = {
    "meta": {"type": "groups", "count": 2},
    "data": [
        {"ObjectIdentifier": "S-1-5-21-1-SQLADM",
         "Properties": {"name": "SQL ADMINS@CORP.LOCAL"},
         "Aces": [],
         "Members": [{"ObjectIdentifier": "S-1-5-21-1-SQLSVC",
                      "Properties": {"name": "SQLSVC@CORP.LOCAL"}}]},
        # DOMAIN ADMINS üzerinde SQL ADMINS GenericAll (tehlikeli kenar)
        {"ObjectIdentifier": "S-1-5-21-1-DA",
         "Properties": {"name": "DOMAIN ADMINS@CORP.LOCAL"},
         "Aces": [{"PrincipalSID": "S-1-5-21-1-SQLADM",
                   "PrincipalName": "SQL ADMINS@CORP.LOCAL",
                   "RightName": "GenericAll"}],
         "Members": [{"ObjectIdentifier": "S-1-5-21-1-ADMIN",
                      "Properties": {"name": "ADMIN@CORP.LOCAL"}}]},
    ],
}


def _make_zip(tmp_path, name="bh.zip"):
    zpath = tmp_path / name
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("users.json", json.dumps(USERS))
        zf.writestr("groups.json", json.dumps(GROUPS))
        zf.writestr("data.json", "bozuk json")     # hattırılmalı, çökertmemeli
    return zpath


def test_parse_zip_builds_graph(tmp_path):
    graph = parse_bloodhound_zip(_make_zip(tmp_path))
    assert graph.sid_to_name["S-1-5-21-1-DA"] == "DOMAIN ADMINS@CORP.LOCAL"
    assert set(graph.user_sids) == {"S-1-5-21-1-SQLSVC", "S-1-5-21-1-BOB",
                                    "S-1-5-21-1-ADMIN"}
    rights = {(e.source_sid, e.right, e.target_sid) for e in graph.edges}
    assert ("S-1-5-21-1-SQLSVC", "MemberOf", "S-1-5-21-1-SQLADM") in rights
    assert ("S-1-5-21-1-SQLADM", "GenericAll", "S-1-5-21-1-DA") in rights
    dangerous = [e for e in graph.edges if e.is_dangerous]
    assert len(dangerous) == 1


def test_parse_bad_zip_raises(tmp_path):
    bad = tmp_path / "bad.zip"
    bad.write_text("zip degil")
    with pytest.raises(ParseError):
        parse_bloodhound_zip(bad)


def test_pathfinder_shortest_path_from_users(tmp_path):
    graph = parse_bloodhound_zip(_make_zip(tmp_path))
    result = PathFinder(graph).shortest_path_from_users()
    assert result["found"] is True
    # ADMIN zaten DOMAIN ADMINS üyesi (sadece MemberOf) → elemine edilir;
    # en yakın SALDIRGAN aday SQLSVC'dir
    assert result["excluded_privileged"] >= 1
    assert result["hop_count"] == 2
    assert result["start"] == "SQLSVC@CORP.LOCAL"
    assert [h["right"] for h in result["hops"]] == ["MemberOf", "GenericAll"]
    assert result["hops"][-1]["to"] == "DOMAIN ADMINS@CORP.LOCAL"
    assert result["hops"][0]["dangerous"] is False
    assert result["hops"][1]["dangerous"] is True


def test_pathfinder_explicit_start_and_misses(tmp_path):
    graph = parse_bloodhound_zip(_make_zip(tmp_path))
    finder = PathFinder(graph)
    # tam isim, önek ve domain'siz hepsi SID'e bağlanır
    assert finder.find_name_sid("DOMAIN ADMINS") == "S-1-5-21-1-DA"
    assert finder.find_name_sid("sqlsvc@corp.local") == "S-1-5-21-1-SQLSVC"

    ok = finder.shortest_path_to("sqlsvc")
    assert ok["found"] and ok["hop_count"] == 2

    # BOB'ın hiç kenarı yok → grafe hiç girmemiş → yol yok
    none = finder.shortest_path_to("bob")
    assert none["found"] is False
    assert "düğüm yok" in none["reason"]

    # bulunamayan hedef grup
    missing = finder.shortest_path_to("sqlsvc", target_name="ENTERPRISE ADMINS")
    assert missing["found"] is False


def test_pathfinder_empty_graph(tmp_path):
    finder = PathFinder(parse_bloodhound_zip(_make_zip(tmp_path)))
    res = finder.shortest_path_from_users("OLMAYAN GRUP")
    assert res["found"] is False
