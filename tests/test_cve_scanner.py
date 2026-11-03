"""CveScanner testleri — ağ TRAFİĞİ YOK: kontroller stub'lanır.

Doğrulananlar:
  * BaseScanner mirası + istenen scan(domain, dc_ip, username, password) imzası
  * Çıktı formatı: [{"cve", "vulnerable", "detail"}] sırası/sözleşmesi
  * Kontrol hatası → "Test edilemedi" (asla exception, asla yanlış 'açık')
  * Şifre hiçbir detay metninde görünmez (redact)
"""

import asyncio
import inspect

from app.scanners.base import BaseScanner
from app.scanners.cve_scanner import CveScanner

CVE_ORDER = ["CVE-2020-1472", "CVE-2021-34527", "CVE-2021-42278/42287"]


def _stub_all(scanner, monkeypatch, results, raise_for=()):
    """Kontrol metotlarını verilen sözlük/vadeli döndürücülerle değiştirir."""
    stubs = {
        "_zerologon_check": results[0],
        "_printnightmare_check": results[1],
        "_nopac_check": results[2],
    }
    for name, out in stubs.items():
        if name in raise_for:
            def boom(*_a, _n=name, **_k):
                raise RuntimeError(f"{_n} bağlantı hatası")
            monkeypatch.setattr(scanner, name, boom)
        else:
            def canned(*_a, _o=out, **_k):
                return dict(_o)
            monkeypatch.setattr(scanner, name, canned)


CANNED = [
    {"cve": "CVE-2020-1472", "vulnerable": True, "detail": "boş oturum kabul edildi"},
    {"cve": "CVE-2021-34527", "vulnerable": False, "detail": "spooler kapalı"},
    {"cve": "CVE-2021-42278/42287", "vulnerable": False, "detail": "PAC eşit"},
]


def test_inheritance_and_signature():
    """BaseScanner'dan miras + istenen async scan imzası."""
    assert issubclass(CveScanner, BaseScanner)
    assert inspect.iscoroutinefunction(CveScanner.scan)
    params = list(inspect.signature(CveScanner.scan).parameters)
    assert params[:5] == ["self", "domain", "dc_ip", "username", "password"]
    assert params[5] == "dc_hostname"          # opsiyonel ek (BloodHound ile hizalı)


def test_scan_result_format(monkeypatch):
    """Tam istenen formatta 3 kayıt, sabit sıra; kimlik bilgisi akar."""
    scanner = CveScanner()
    _stub_all(scanner, monkeypatch, CANNED)
    results = asyncio.run(scanner.scan(
        domain="corp.local", dc_ip="10.0.0.5",
        username="alice", password="Gizli123!",
    ))
    assert len(results) == 3
    assert [r["cve"] for r in results] == CVE_ORDER   # girilen sıra korunur
    for r in results:
        assert list(r.keys()) == ["cve", "vulnerable", "detail"]
        assert isinstance(r["vulnerable"], bool)
        assert isinstance(r["detail"], str) and r["detail"]


def test_scan_check_failure_is_inconclusive(monkeypatch):
    """Bir kontrol patlarsa → 'Test edilemedi', vulnerable=False; diğerleri korunur."""
    scanner = CveScanner()
    _stub_all(scanner, monkeypatch, CANNED, raise_for=("_zerologon_check",))
    results = asyncio.run(scanner.scan(
        domain="corp.local", dc_ip="10.0.0.5",
        username="alice", password="Gizli123!",
    ))
    assert len(results) == 3
    z, p, n = results
    assert z["cve"] == "CVE-2020-1472"
    assert z["vulnerable"] is False
    assert "Test edilemedi" in z["detail"]
    assert p == CANNED[1] and n == CANNED[2]          # diğer iki kontrol etkilensiz


def test_scan_redacts_password(monkeypatch):
    """Şifre hiçbir detail metnine sızmamalı."""
    scanner = CveScanner()
    leaky = [dict(CANNED[0]), dict(CANNED[1]), dict(CANNED[2])]
    leaky[0]["detail"] = "hata metni Gizli123! içeriyor"
    _stub_all(scanner, monkeypatch, leaky)
    results = asyncio.run(scanner.scan(
        domain="corp.local", dc_ip="10.0.0.5",
        username="alice", password="Gizli123!",
    ))
    assert "Gizli123!" not in results[0]["detail"]
    assert "***" in results[0]["detail"]


def test_dc_netbios_name_from_dc_hostname():
    """dc_hostname verildiğinde LDAP'a GİTMEDEN ilk etiket alınır."""
    name = CveScanner._dc_netbios_name(
        "corp.local", "10.0.0.5", "alice", "pw",
        "winterfell.north.sevenkingdoms.local",
    )
    assert name == "winterfell"
    # kısaltılmış biçim de çalışır
    assert CveScanner._dc_netbios_name(
        "corp.local", "10.0.0.5", "alice", "pw", "DC01"
    ) == "DC01"


def test_base_dn_derivation():
    assert CveScanner._base_dn("corp.local") == "DC=corp,DC=local"
