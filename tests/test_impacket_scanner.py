import pytest

from app.core.exceptions import ScannerError
from app.scanners.impacket_scanner import (
    _check_result,
    _failure_marker,
    _resolve_cmd,
)


def test_resolve_cmd_finds_installed_tools():
    # bu makinede kurulu: GetUserSPNs/GetNPUsers örnekleri + secretsdump binary
    assert _resolve_cmd("GetUserSPNs")[0] in ("python3",) \
        and _resolve_cmd("GetUserSPNs")[1].endswith("GetUserSPNs.py")
    assert _resolve_cmd("secretsdump")[0].endswith("secretsdump")


def test_failure_marker_detects_refused():
    out = "Impacket v0.11.0 - Copyright 2023 Fortra\n\n[-] [Errno 111] Connection refused"
    assert _failure_marker(out) == "connection refused"
    assert _failure_marker("Impacket v0.11.0\nServicePrincipalName  Name\n") is None


def test_failure_marker_ignores_hash_lines():
    # hash içine rastgele oturabilecek 'timeout' kelimesi sayılmamalı
    hash_line = "$krb5tgs$23$*u$R$spn*$YXRpbWVvdXQ=$data"
    assert _failure_marker(hash_line) is None


def test_check_result_treats_exit0_error_as_failure():
    """Impacket bazen hatalarda exit 0 döner — imza yeterli."""
    with pytest.raises(ScannerError, match="başarısız"):
        _check_result(
            "GetUserSPNs", 0,
            "banner\n\n[-] [Errno 111] Connection refused\n", "",
        )


def test_check_result_clean_success_passes():
    _check_result("GetUserSPNs", 0, "banner\nServicePrincipalName  Name\n====\n", "")


def test_check_result_nonzero_fails():
    with pytest.raises(ScannerError):
        _check_result("GetNPUsers", 2, "", "usage error")
