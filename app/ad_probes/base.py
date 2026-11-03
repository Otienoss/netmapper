"""Beş aşamalı, check-only AD probe yaşam döngüsü."""

from __future__ import annotations

from abc import ABC, abstractmethod
import asyncio
from collections.abc import Awaitable
from typing import TypeVar

from app.ad_probes.models import (
    ADProbeContext,
    CleanupReport,
    PreCheckDecision,
    PreflightReport,
    ProbeOutcome,
    ProbeResult,
    Proof,
    TriggerData,
)
from app.ad_probes.preflight import PreFlightError, PreflightEngine

_T = TypeVar("_T")


class BaseADProbe(ABC):
    """discovery → pre_check → minimal_trigger → verify_proof → cleanup.

    Alt sınıflar yalnızca sınırlı ve tahribatsız tetikleri uygulamalıdır.
    Veri toplanamaması `inconclusive`, açık ön koşul ihlali `failed` olur;
    ikisi birbirine karıştırılmaz. Cleanup her sonuçta ayrı raporlanır.
    """

    name = "base"
    required_preflight_fields: tuple[str, ...] = (
        "dc_sam_account_name", "domain_sid",
    )
    requires_positive_maq = False
    # Her aşama için katı üst sınır; alt sınıf ihtiyacına göre daraltabilir.
    stage_timeouts = {
        "discovery": 15.0,
        "pre_check": 5.0,
        "minimal_trigger": 30.0,
        "verify_proof": 10.0,
        "cleanup": 10.0,
    }

    def __init__(self, preflight_engine: PreflightEngine | None = None) -> None:
        self.preflight_engine = preflight_engine or PreflightEngine()

    async def _with_timeout(self, stage: str, operation: Awaitable[_T]) -> _T:
        return await asyncio.wait_for(
            operation, timeout=self.stage_timeouts[stage]
        )

    async def discovery(self, context: ADProbeContext) -> PreflightReport:
        return await self.preflight_engine.collect(context)

    async def pre_check(
        self, context: ADProbeContext, report: PreflightReport,
    ) -> PreCheckDecision:
        missing = [
            name for name in self.required_preflight_fields
            if getattr(report, name) is None
        ]
        if missing:
            return PreCheckDecision.stop(
                ProbeOutcome.INCONCLUSIVE,
                "Zorunlu pre-flight alanları okunamadı: " + ", ".join(missing),
            )
        if self.requires_positive_maq:
            maq = report.machine_account_quota
            if maq is None:
                return PreCheckDecision.stop(
                    ProbeOutcome.INCONCLUSIVE,
                    "ms-DS-MachineAccountQuota bilinmiyor; test başlatılmadı",
                )
            if maq <= 0:
                return PreCheckDecision.stop(
                    ProbeOutcome.FAILED,
                    f"Ön koşul sağlanmıyor: ms-DS-MachineAccountQuota={maq}; "
                    "test hiç çalıştırılmadı",
                )
        return PreCheckDecision.allow()

    @abstractmethod
    async def minimal_trigger(
        self, context: ADProbeContext, report: PreflightReport,
    ) -> TriggerData:
        """Sınırlı, tahribatsız test gözlemini üretir."""

    @abstractmethod
    async def verify_proof(
        self, context: ADProbeContext, trigger: TriggerData,
    ) -> Proof:
        """Yalnızca deterministik kanıta dayanarak sonucu sınıflandırır."""

    async def cleanup(self, context: ADProbeContext) -> CleanupReport:
        """Artefakt yoksa temizlik doğrulanmış sayılır; alt sınıf ezebilir."""
        return CleanupReport.clean()

    async def run(self, context: ADProbeContext) -> ProbeResult:
        stage = "discovery"
        preflight: PreflightReport | None = None
        result: ProbeResult | None = None
        try:
            try:
                await context.log(f"{self.name}: discovery başladı")
                preflight = await self._with_timeout(
                    stage, self.discovery(context)
                )
                stage = "pre_check"
                decision = await self._with_timeout(
                    stage, self.pre_check(context, preflight)
                )
                if not decision.proceed:
                    result = ProbeResult(
                        self.name,
                        decision.outcome or ProbeOutcome.INCONCLUSIVE,
                        decision.reason,
                        preflight=preflight,
                    )
                else:
                    await context.log(f"{self.name}: pre_check geçti")
                    stage = "minimal_trigger"
                    trigger = await self._with_timeout(
                        stage, self.minimal_trigger(context, preflight)
                    )
                    stage = "verify_proof"
                    proof = await self._with_timeout(
                        stage, self.verify_proof(context, trigger)
                    )
                    result = ProbeResult(
                        self.name, proof.outcome, proof.reason,
                        preflight=preflight, evidence=proof.evidence,
                    )
            except PreFlightError as exc:
                result = ProbeResult(
                    self.name, ProbeOutcome.INCONCLUSIVE, str(exc),
                    preflight=preflight, error=str(exc),
                )
            except TimeoutError as exc:
                outcome = (
                    ProbeOutcome.ATTEMPTED if stage == "minimal_trigger"
                    else ProbeOutcome.INCONCLUSIVE
                )
                reason = (
                    f"{stage} aşaması {self.stage_timeouts[stage]:g}s "
                    "zaman aşımına uğradı"
                )
                result = ProbeResult(
                    self.name, outcome, reason,
                    preflight=preflight, error=reason,
                )
            except Exception as exc:
                # Trigger başladıysa attempted; kanıt doğrulanamıyorsa inconclusive.
                outcome = (
                    ProbeOutcome.ATTEMPTED if stage == "minimal_trigger"
                    else ProbeOutcome.INCONCLUSIVE
                )
                result = ProbeResult(
                    self.name, outcome, f"{stage} aşamasında hata: {exc}",
                    preflight=preflight, error=str(exc),
                )
        finally:
            try:
                cleanup = await self._with_timeout(
                    "cleanup", self.cleanup(context)
                )
            except TimeoutError:
                cleanup = CleanupReport.unverified(
                    f"cleanup {self.stage_timeouts['cleanup']:g}s zaman aşımı"
                )
            except Exception as exc:
                cleanup = CleanupReport.unverified(str(exc))
            if result is not None:
                result.cleanup = cleanup
        if result is None:
            raise RuntimeError("Probe yaşam döngüsü sonuç üretemedi")
        return result
