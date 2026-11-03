r"""Impacket çıktı parser'ları → ortak ADFinding şeması.

- GetUserSPNs  : SPN tablosu (stdout) + `$krb5tgs$` hash'leri (-outputfile)
- GetNPUsers   : `$krb5asrep$` hash'leri (-outputfile / stdout)
- secretsdump  : `DOMAIN\user:rid:lmhash:nthash:::` satırları (stdout)
"""

import re
from pathlib import Path

from app.normalization.schema import ADFinding

# ------------------------------------------------------------------ yardımcılar
# TGS hash formatları (GetUserSPNs kaynak kodu, 4 varyant):
#   $krb5tgs$23$*user$realm$spn*$c1$c2   /   $krb5tgs$23$user$realm$*spn*$c1$c2
_TGS_RE = re.compile(
    r"^\$krb5tgs\$\d+\$(?:\*)?(?P<user>[^$]+)\$(?P<realm>[^$]+)"
    r"\$(?:\*)?(?P<spn>[^$*]+)\*?\$"
)
# AS-REP hash formatları (GetNPUsers, 2 varyant):
#   etype 17/18 : $krb5asrep$17$user$realm$c1$c2
#   etype 23    : $krb5asrep$23$user@realm:checksum$data
_ASREP_RE = re.compile(r"^\$krb5asrep\$(?P<enc>\d+)\$(?P<rest>.+)$")
_DCSYNC_RE = re.compile(
    r"^(?P<domain>\S+)\\(?P<user>[^:]+):(?P<rid>\d+):"
    r"(?P<lm>[0-9a-fA-F]{32}):(?P<nt>[0-9a-fA-F]{32}):::"
)


def _parse_asrep_line(line: str) -> tuple[str, str] | None:
    """AS-REP satırından (principal, realm) çıkarır."""
    m = _ASREP_RE.match(line)
    if not m:
        return None
    rest = m.group("rest")
    first = rest.split("$", 1)[0]
    if "@" in first:
        # etype 23: user@realm:checksum$...
        principal = first.split(":", 1)[0]
        realm = principal.rsplit("@", 1)[-1]
    else:
        # etype 17/18: user$realm$...
        parts = rest.split("$")
        principal = parts[0]
        realm = parts[1] if len(parts) > 1 else ""
    return principal, realm


def _read_lines(path: str | Path | None, stdout: str = "") -> list[str]:
    if path:
        try:
            return Path(path).read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            pass
    return stdout.splitlines()


# ------------------------------------------------------------------ kerberoast
def parse_getuserspns(stdout: str, hash_file: str | None = None) -> list[ADFinding]:
    """SPN tablosunu + hash eşleşmelerini ADFinding listesine çevirir."""
    # hash'ler: (user, spn) ve user -> ilk hash
    by_user_spn: dict[tuple[str, str], str] = {}
    by_user: dict[str, str] = {}
    for line in _read_lines(hash_file, stdout):
        m = _TGS_RE.match(line.strip())
        if m:
            key = (m.group("user").lower(), m.group("spn").lower())
            by_user_spn[key] = line.strip()
            by_user.setdefault(m.group("user").lower(), line.strip())

    findings: list[ADFinding] = []
    lines = stdout.splitlines()
    header_idx = next(
        (i for i, l in enumerate(lines)
         if "ServicePrincipalName" in l and "Name" in l),
        None,
    )
    if header_idx is None:
        return findings

    for line in lines[header_idx + 1:]:
        stripped = line.strip()
        if not stripped or set(stripped) <= {"=", "-"}:
            continue
        if stripped.startswith("$krb5"):
            continue  # hash satırı tablo verisi değil
        if stripped.startswith("[") or stripped.startswith("Getting"):
            break    # tablo bitti, loglar başladı
        parts = re.split(r"\s{2,}", stripped)
        if len(parts) < 2:
            continue
        spn = parts[0].strip()
        if "/" not in spn:          # tablo satırları SPN içerir (svc/host:port)
            continue
        principal = parts[1].strip()
        password_status = parts[2].strip() if len(parts) > 2 else ""

        empty_pw = password_status.lower().replace(" ", "") in ("<nopw>", "<nopassword>", "-", "")
        severity = "high" if empty_pw else "medium"
        message = (
            f"Kerberoast: '{principal}' hesabında SPN var → {spn}"
            + (" (BOŞ ŞİFRE!)" if empty_pw else "")
            + (f" · şifre durumu: {password_status}" if password_status and not empty_pw else "")
        )
        hsh = by_user_spn.get((principal.lower(), spn.lower())) \
            or by_user.get(principal.lower())
        findings.append(ADFinding(
            kind="kerberoast",
            principal=principal,
            spn=spn,
            severity=severity,
            message=message,
            detail={
                "password_status": password_status or None,
                "hash": hsh,
                "hash_source": "tgs" if hsh else None,
            },
        ))
    return findings


# ---------------------------------------------------------------------- as-rep
def parse_getnpusers(stdout: str, hash_file: str | None = None) -> list[ADFinding]:
    """`$krb5asrep$` hash satırlarını ADFinding listesine çevirir."""
    findings: list[ADFinding] = []
    seen: set[str] = set()
    for line in _read_lines(hash_file, stdout):
        stripped = line.strip()
        parsed = _parse_asrep_line(stripped)
        if not parsed:
            continue
        principal, realm = parsed
        if principal.lower() in seen:
            continue
        seen.add(principal.lower())
        findings.append(ADFinding(
            kind="asrep",
            principal=principal,
            severity="medium",
            message=(
                f"AS-REP Roast: '{principal}' hesabında Kerberos pre-authentication "
                f"kapalı — TGT hash'i ele geçirilebilir"
            ),
            detail={"realm": realm, "hash": stripped},
        ))
    return findings


# --------------------------------------------------------------------- dcsync
def parse_secretsdump(stdout: str) -> list[ADFinding]:
    r"""`DOMAIN\user:rid:lm:nt:::` satırlarını ADFinding listesine çevirir."""
    findings: list[ADFinding] = []
    seen: set[str] = set()
    for line in stdout.splitlines():
        m = _DCSYNC_RE.match(line.strip())
        if not m:
            continue
        principal = f"{m.group('domain')}\\{m.group('user')}"
        if principal.lower() in seen:
            continue
        seen.add(principal.lower())
        is_machine = m.group("user").endswith("$")
        findings.append(ADFinding(
            kind="dcsync",
            principal=principal,
            severity="high",
            message=(
                f"DCSync: '{principal}' hesabının NTDS NTLM hash'i elde edildi"
                + (" (bilgisayar hesabı)" if is_machine else "")
            ),
            detail={
                "rid": m.group("rid"),
                "lm_hash": m.group("lm"),
                "nt_hash": m.group("nt"),
                "machine_account": is_machine,
            },
        ))
    return findings
