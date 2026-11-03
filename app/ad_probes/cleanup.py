"""Artefakt temizliği ve bağımsız silme doğrulaması."""

from __future__ import annotations

import asyncio
import shutil
from collections.abc import Awaitable, Callable
from pathlib import Path

from app.ad_probes.models import CleanupReport


def cleanup_files_verified(paths: list[str | Path]) -> CleanupReport:
    """Dosya/dizinleri siler ve varlıklarını yeniden kontrol eder.

    unlink/rmtree çağrısının hata vermemesi tek başına başarı sayılmaz;
    `verified` yalnızca hiçbir yol artık mevcut değilse döner.
    """
    artifacts = [str(path) for path in paths]
    remaining: list[str] = []
    errors: list[str] = []
    for raw_path in paths:
        path = Path(raw_path)
        try:
            if path.is_symlink() or not path.is_dir():
                path.unlink(missing_ok=True)
            else:
                shutil.rmtree(path)
        except OSError as exc:
            errors.append(f"{path}: silme hatası: {exc}")
        try:
            if path.exists():
                remaining.append(str(path))
        except OSError as exc:
            errors.append(f"{path}: varlık doğrulaması başarısız: {exc}")
            remaining.append(str(path))
    if remaining or errors:
        return CleanupReport.unverified(
            "; ".join(errors) or "Bazı artefaktlar hâlâ mevcut",
            artifacts, remaining,
        )
    return CleanupReport.clean(artifacts)


async def cleanup_ldap_object_verified(
    name: str,
    delete: Callable[[], Awaitable[None]],
    exists: Callable[[], Awaitable[bool]],
    timeout: float = 10.0,
) -> CleanupReport:
    """LDAP silme sonrası nesnenin yokluğunu bağımsız sorguyla doğrular.

    delete/exists fonksiyonları çağıran modül tarafından sağlanır; bu sınıf
    bağlantı veya nesne oluşturma bilgisi taşımaz. Doğrulama sorgusu
    başarısızsa sonuç ASLA verified olmaz.
    """
    try:
        await asyncio.wait_for(delete(), timeout=timeout)
    except TimeoutError:
        return CleanupReport.unverified(
            f"LDAP delete {timeout:g}s zaman aşımına uğradı", [name]
        )
    except Exception as exc:
        return CleanupReport.unverified(
            f"LDAP delete hatası: {exc}", [name]
        )
    try:
        still_exists = await asyncio.wait_for(exists(), timeout=timeout)
    except TimeoutError:
        return CleanupReport.unverified(
            f"LDAP doğrulama sorgusu {timeout:g}s zaman aşımına uğradı", [name]
        )
    except Exception as exc:
        return CleanupReport.unverified(
            f"Silme sonrası LDAP yeniden sorgusu başarısız: {exc}", [name]
        )
    if still_exists:
        return CleanupReport.unverified(
            "Delete başarı döndü ancak nesne LDAP'ta hâlâ mevcut",
            [name], [name],
        )
    return CleanupReport.clean([name])


def combine_cleanup_reports(*reports: CleanupReport) -> CleanupReport:
    """Birden fazla temizlik raporunu birleştirir; biri bile unverified ise sonuç unverified."""
    artifacts = [item for report in reports for item in report.artifacts]
    remaining = [item for report in reports for item in report.remaining]
    errors = [report.error for report in reports if report.error]
    if any(not report.to_dict()["verified"] for report in reports):
        return CleanupReport.unverified(
            "; ".join(errors) or "Temizlik doğrulanamadı",
            artifacts, remaining,
        )
    return CleanupReport.clean(artifacts)
