"""Dosya, ASN.1/DER ve RPC durum kodu tabanlı deterministik kanıt kontrolleri."""

from __future__ import annotations

from enum import IntEnum
from pathlib import Path

from app.ad_probes.models import Evidence


class KerberosMessage(IntEnum):
    AS_REP = 11
    TGS_REP = 13
    AP_REP = 15
    KRB_ERROR = 30


def ccache_evidence(path: str | Path) -> Evidence:
    """ccache v4 magic + header uzunluğu + dosya sınırı doğrular."""
    file_path = Path(path)
    try:
        data = file_path.read_bytes()
    except OSError as exc:
        return Evidence("ccache", "file-header", False, str(exc))
    if len(data) < 4:
        return Evidence("ccache", "file-header", False, "Dosya 4 bayttan kısa")
    if data[:2] != b"\x05\x04":
        return Evidence(
            "ccache", "file-header", False,
            f"Beklenen magic 0x0504, bulunan 0x{data[:2].hex()}",
        )
    header_length = int.from_bytes(data[2:4], "big")
    if len(data) < 4 + header_length:
        return Evidence(
            "ccache", "file-header", False,
            "Beyan edilen header uzunluğu dosya sınırını aşıyor",
        )
    return Evidence(
        "ccache", "file-header", True,
        f"ccache v4; header={header_length} bayt; dosya={len(data)} bayt",
    )


def _der_length(data: bytes, offset: int) -> tuple[int, int] | None:
    """DER length octet'lerini okur; indefinite/non-minimal biçimi reddeder."""
    if offset >= len(data):
        return None
    first = data[offset]
    if first < 0x80:
        return first, offset + 1
    count = first & 0x7F
    if count == 0 or count > 4 or offset + 1 + count > len(data):
        return None
    if data[offset + 1] == 0:
        return None
    value = int.from_bytes(data[offset + 1:offset + 1 + count], "big")
    if value < 0x80:
        return None
    return value, offset + 1 + count


def kerberos_der_evidence(
    data: bytes, expected: KerberosMessage | None = None,
) -> Evidence:
    """Kerberos APPLICATION etiketi ve dış DER sınırlarını doğrular.

    Bu kontrol yalnızca yapısal kanıttır; tek başına kimlik doğrulama veya
    erişim başarısı anlamına gelmez.
    """
    if not data:
        return Evidence("asn1", "kerberos-der", False, "Boş yanıt")
    tag = data[0]
    try:
        message = KerberosMessage(tag & 0x1F)
    except ValueError:
        return Evidence(
            "asn1", "kerberos-der", False,
            f"Bilinmeyen Kerberos application tag: 0x{tag:02x}",
        )
    if tag != (0x60 | int(message)):
        return Evidence(
            "asn1", "kerberos-der", False,
            f"Geçersiz constructed/application tag: 0x{tag:02x}",
        )
    parsed = _der_length(data, 1)
    if parsed is None:
        return Evidence("asn1", "kerberos-der", False, "DER uzunluğu geçersiz")
    length, content_offset = parsed
    if content_offset + length != len(data):
        return Evidence(
            "asn1", "kerberos-der", False,
            "DER içerik uzunluğu yanıt sınırıyla uyuşmuyor",
        )
    expected_text = ""
    passed = True
    if expected is not None:
        passed = message is expected
        expected_text = f"; beklenen={expected.name}"
    return Evidence(
        "asn1", "kerberos-der", passed,
        f"{message.name}; DER sınırları geçerli{expected_text}",
    )


_RPC_NAMES = {
    0x00000000: "STATUS_SUCCESS",
    0x00000709: "ERROR_INVALID_PRINTER_NAME",
    0xC0000022: "STATUS_ACCESS_DENIED",
    0xC0000034: "STATUS_OBJECT_NAME_NOT_FOUND",
    0xC000006D: "STATUS_LOGON_FAILURE",
}


def rpc_status_evidence(status: int | str, expected: int | None = None) -> Evidence:
    """NTSTATUS/HRESULT değerini metin logundan bağımsız karşılaştırır."""
    try:
        code = int(status, 0) if isinstance(status, str) else int(status)
    except (TypeError, ValueError):
        return Evidence("rpc", "status-code", False, f"Geçersiz kod: {status!r}")
    code &= 0xFFFFFFFF
    name = _RPC_NAMES.get(code, "UNMAPPED_STATUS")
    passed = expected is None or code == (expected & 0xFFFFFFFF)
    detail = f"{name} (0x{code:08X})"
    if expected is not None:
        detail += f"; beklenen=0x{expected & 0xFFFFFFFF:08X}"
    return Evidence("rpc", "status-code", passed, detail)
