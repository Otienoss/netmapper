from pathlib import Path

from app.normalization.ad_parser import (
    parse_getnpusers,
    parse_getuserspns,
    parse_secretsdump,
)

# ------------------------------------------------- gerçek biçimde örnek çıktılar
GETUSERSPNS_STDOUT = """\
Impacket v0.11.0 - Copyright 2023 Fortra

ServicePrincipalName                     Name       Password   Last Logon
======================================== ========== ========== =========
MSSQLSvc/sql.corp.local:1433             sqladmin   <no pw>    12/01/25 10:00:00
HTTP/web.corp.local                      webadmin   <never>    11/30/25 09:12:00
cifs/fs.corp.local                       backupops  password   12/02/25 08:00:00

Getting TGS for SPN MSSQLSvc/sql.corp.local:1433
$krb5tgs$23$*sqladmin$CORP.LOCAL$MSSQLSvc/sql.corp.local:1433*$A1B2C3D4$DEADBEEF
Getting TGS for SPN HTTP/web.corp.local
$krb5tgs$23$*webadmin$CORP.LOCAL$HTTP/web.corp.local*$E5F6A7B8$CAFEBABE
"""

GETUSERSPNS_HASH_FILE = """\
$krb5tgs$23$*sqladmin$CORP.LOCAL$MSSQLSvc/sql.corp.local:1433*$A1B2C3D4$DEADBEEF
$krb5tgs$23$*webadmin$CORP.LOCAL$HTTP/web.corp.local*$E5F6A7B8$CAFEBABE
"""

GETNPUSERS_HASH_FILE = """\
$krb5asrep$23$bob@CORP.LOCAL:$16$c0ffee$1234567890abcdef
$krb5asrep$23$svc_backup@CORP.LOCAL:$16$badc0de$fedcba0987654321
"""

SECRETSDUMP_STDOUT = """\
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)
[*] Searching dump for accounts with DCSync rights
CORP\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
CORP\\alice:1105:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
CORP\\WORKSTATION01$:1106:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
CORP\\alice:1105:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
[*] Cleaning up...
"""


def test_parse_getuserspns_table_and_hashes(tmp_path):
    hash_file = tmp_path / "tgs.txt"
    hash_file.write_text(GETUSERSPNS_HASH_FILE, encoding="utf-8")

    findings = parse_getuserspns(GETUSERSPNS_STDOUT, str(hash_file))
    assert len(findings) == 3

    sqladmin = findings[0]
    assert sqladmin.kind == "kerberoast"
    assert sqladmin.principal == "sqladmin"
    assert sqladmin.spn == "MSSQLSvc/sql.corp.local:1433"
    assert sqladmin.severity == "high"            # <no pw> → yüksek
    assert "BOŞ ŞİFRE" in sqladmin.message
    assert sqladmin.detail["hash"] and sqladmin.detail["hash"].startswith("$krb5tgs$")

    webadmin = findings[1]
    assert webadmin.severity == "medium"          # <never> boş şifre değil
    assert webadmin.detail["password_status"] == "<never>"

    backup = findings[2]
    assert backup.principal == "backupops"
    assert backup.severity == "medium"


def test_parse_getuserspns_without_hash_file():
    findings = parse_getuserspns(GETUSERSPNS_STDOUT, None)
    # stdout içindeki hash satırları da yakalanır
    assert len(findings) == 3
    assert findings[0].detail["hash"] is not None


def test_parse_getuserspns_empty_output():
    assert parse_getuserspns("Impacket v0.11.0\n\nno entries\n") == []


def test_parse_getnpusers_hashes(tmp_path):
    hash_file = tmp_path / "asrep.txt"
    hash_file.write_text(GETNPUSERS_HASH_FILE, encoding="utf-8")
    findings = parse_getnpusers("", str(hash_file))
    assert len(findings) == 2
    assert findings[0].kind == "asrep"
    # etype 23 varyantı: $krb5asrep$23$user@realm:checksum$...
    assert findings[0].principal == "bob@CORP.LOCAL"
    assert findings[0].severity == "medium"
    assert findings[0].detail["realm"] == "CORP.LOCAL"
    assert findings[0].detail["hash"].startswith("$krb5asrep$")
    # stdout fallback
    assert len(parse_getnpusers(GETNPUSERS_HASH_FILE, None)) == 2


def test_parse_getnpusers_etype17_variant():
    """etype 17/18 varyantı: $krb5asrep$17$user$realm$c1$c2"""
    line = "$krb5asrep$17$carol$CORP.LOCAL$0011aabbcc$ddeeff9988"
    findings = parse_getnpusers(line, None)
    assert len(findings) == 1
    assert findings[0].principal == "carol"
    assert findings[0].detail["realm"] == "CORP.LOCAL"


def test_parse_secretsdump_stdout():
    findings = parse_secretsdump(SECRETSDUMP_STDOUT)
    # tekrar eden satır ayıklanır → 3 benzersiz principal
    assert len(findings) == 3
    assert findings[0].kind == "dcsync"
    assert findings[0].principal == "CORP\\Administrator"
    assert findings[0].severity == "high"
    assert findings[0].detail["nt_hash"] == "31d6cfe0d16ae931b73c59d7e0c089c0"
    machine = next(f for f in findings if f.principal.endswith("$"))
    assert machine.detail["machine_account"] is True
    assert parse_secretsdump("hiç hash yok") == []
