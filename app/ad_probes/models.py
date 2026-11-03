"""AD probe çerçevesinin taşınabilir, şifre sızdırmayan sonuç modelleri."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ProbeOutcome(str, Enum):
    # Check-only modüllerde KULLANILMAZ; durum değiştiren kanıtlar için rezerv.
    EXPLOITED = "exploited"
    VALIDATED = "validated"
    ATTEMPTED = "attempted"
    INCONCLUSIVE = "inconclusive"
    FAILED = "failed"


class CleanupStatus(str, Enum):
    VERIFIED = "verified"
    UNVERIFIED = "unverified"


@dataclass(slots=True)
class ADProbeContext:
    target: str
    domain: str
    username: str
    password: str = field(repr=False)
    job_id: str | None = None
    # Çoklu DC ortamında zorunlu hedef seçici: FQDN, kısa hostname veya sAMAccountName
    target_dc: str | None = None
    on_log: Callable[[str], Awaitable[None]] | None = field(
        default=None, repr=False
    )

    async def log(self, message: str) -> None:
        if self.on_log is not None:
            await self.on_log(message)


@dataclass(slots=True)
class Evidence:
    """Tek bir deterministik kontrolün sonucu; passed ≠ exploit başarısı."""

    source: str
    check: str
    passed: bool
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "check": self.check,
            "passed": self.passed,
            "detail": self.detail,
        }


@dataclass(slots=True)
class CleanupReport:
    status: CleanupStatus
    artifacts: list[str] = field(default_factory=list)
    remaining: list[str] = field(default_factory=list)
    error: str | None = None

    @classmethod
    def clean(cls, artifacts: list[str] | None = None) -> "CleanupReport":
        return cls(CleanupStatus.VERIFIED, artifacts or [])

    @classmethod
    def unverified(
        cls, error: str, artifacts: list[str] | None = None,
        remaining: list[str] | None = None,
    ) -> "CleanupReport":
        return cls(
            CleanupStatus.UNVERIFIED, artifacts or [], remaining or [], error
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "verified": self.status is CleanupStatus.VERIFIED,
            "artifacts": self.artifacts,
            "remaining": self.remaining,
            "error": self.error,
        }


@dataclass(slots=True)
class PreflightReport:
    target: str
    domain: str
    dc_sam_account_name: str | None = None
    dc_dns_host_name: str | None = None
    domain_sid: str | None = None
    machine_account_quota: int | None = None
    kerberos: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "domain": self.domain,
            "dc_sam_account_name": self.dc_sam_account_name,
            "dc_dns_host_name": self.dc_dns_host_name,
            "domain_sid": self.domain_sid,
            "machine_account_quota": self.machine_account_quota,
            "kerberos": self.kerberos,
            "errors": self.errors,
        }


@dataclass(slots=True)
class PreCheckDecision:
    proceed: bool
    outcome: ProbeOutcome | None = None
    reason: str = ""

    @classmethod
    def allow(cls) -> "PreCheckDecision":
        return cls(True)

    @classmethod
    def stop(cls, outcome: ProbeOutcome, reason: str) -> "PreCheckDecision":
        return cls(False, outcome, reason)


@dataclass(slots=True)
class TriggerData:
    attempted: bool
    observations: dict[str, Any] = field(default_factory=dict)
    artifacts: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Proof:
    outcome: ProbeOutcome
    reason: str
    evidence: list[Evidence] = field(default_factory=list)


@dataclass(slots=True)
class ProbeResult:
    probe: str
    outcome: ProbeOutcome
    reason: str
    preflight: PreflightReport | None = None
    evidence: list[Evidence] = field(default_factory=list)
    cleanup: CleanupReport = field(default_factory=CleanupReport.clean)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "probe": self.probe,
            "outcome": self.outcome.value,
            "reason": self.reason,
            "preflight": self.preflight.to_dict() if self.preflight else None,
            "evidence": [item.to_dict() for item in self.evidence],
            "cleanup": self.cleanup.to_dict(),
            "error": self.error,
        }
