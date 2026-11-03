"""ccache, ASN.1/DER ve RPC kanıt doğrulayıcılarının sentetik testleri."""

from app.ad_probes.verifiers import (
    KerberosMessage,
    ccache_evidence,
    kerberos_der_evidence,
    rpc_status_evidence,
)


def _der(application_tag: int, content: bytes) -> bytes:
    assert len(content) < 128
    return bytes([0x60 | application_tag, len(content)]) + content


def test_ccache_magic_and_header_bounds(tmp_path):
    valid = tmp_path / "valid.ccache"
    valid.write_bytes(b"\x05\x04\x00\x02\xaa\xbb" + b"payload")
    evidence = ccache_evidence(valid)
    assert evidence.passed is True
    assert "ccache v4" in evidence.detail

    bad_magic = tmp_path / "bad.ccache"
    bad_magic.write_bytes(b"\x05\x03\x00\x00")
    assert ccache_evidence(bad_magic).passed is False

    truncated = tmp_path / "truncated.ccache"
    truncated.write_bytes(b"\x05\x04\x00\x20\xaa")
    assert ccache_evidence(truncated).passed is False


def test_kerberos_der_structure_and_expected_message():
    evidence = kerberos_der_evidence(
        _der(11, b"\x30\x00"), KerberosMessage.AS_REP
    )
    assert evidence.passed is True
    assert "AS_REP" in evidence.detail

    mismatch = kerberos_der_evidence(
        _der(11, b"\x30\x00"), KerberosMessage.TGS_REP
    )
    assert mismatch.passed is False       # geçerli DER, yanlış mesaj türü
    assert kerberos_der_evidence(b"\x6b\x05\x00").passed is False
    assert kerberos_der_evidence(b"\x6c\x00").passed is False


def test_kerberos_der_long_form_length():
    content = b"\x00" * 128
    packet = b"\x6d\x81\x80" + content
    evidence = kerberos_der_evidence(packet, KerberosMessage.TGS_REP)
    assert evidence.passed is True


def test_rpc_status_is_deterministic_not_log_based():
    denied = rpc_status_evidence(0xC0000022, expected=0)
    assert denied.passed is False
    assert "STATUS_ACCESS_DENIED" in denied.detail

    printer = rpc_status_evidence("0x00000709")
    assert printer.passed is True         # kod başarıyla çözümlendi
    assert "ERROR_INVALID_PRINTER_NAME" in printer.detail

    assert rpc_status_evidence("not-a-code").passed is False
