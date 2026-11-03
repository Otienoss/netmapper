"""Cleanup doğrulama yardımcılarının kontrollü testleri."""

import asyncio

from app.ad_probes.cleanup import (
    cleanup_files_verified,
    cleanup_ldap_object_verified,
    combine_cleanup_reports,
)
from app.ad_probes.models import CleanupStatus


def test_file_cleanup_rechecks_absence(tmp_path):
    ticket = tmp_path / "job.ccache"
    ticket.write_bytes(b"temporary")
    report = cleanup_files_verified([ticket])
    assert report.status is CleanupStatus.VERIFIED
    assert not ticket.exists()


def test_file_cleanup_missing_file_is_verified(tmp_path):
    report = cleanup_files_verified([tmp_path / "zaten-yok.ccache"])
    assert report.status is CleanupStatus.VERIFIED


def test_ldap_cleanup_requires_absence_proof():
    async def delete_ok():
        return None

    async def still_exists():
        return True

    report = asyncio.run(cleanup_ldap_object_verified(
        "CN=test", delete_ok, still_exists,
    ))
    assert report.status is CleanupStatus.UNVERIFIED
    assert report.remaining == ["CN=test"]


def test_ldap_cleanup_query_failure_is_not_success():
    async def delete_ok():
        return None

    async def query_failed():
        raise RuntimeError("LDAP yeniden sorgusu kapalı")

    report = asyncio.run(cleanup_ldap_object_verified(
        "CN=test", delete_ok, query_failed,
    ))
    assert report.status is CleanupStatus.UNVERIFIED
    assert "yeniden sorgusu" in report.error


def test_combined_cleanup_fails_closed(tmp_path):
    clean = cleanup_files_verified([tmp_path / "yok"])

    async def delete_ok():
        return None

    async def absent():
        return False

    ldap_clean = asyncio.run(cleanup_ldap_object_verified(
        "CN=test", delete_ok, absent,
    ))
    combined = combine_cleanup_reports(clean, ldap_clean)
    assert combined.status is CleanupStatus.VERIFIED
    assert combined.artifacts == [str(tmp_path / "yok"), "CN=test"]
