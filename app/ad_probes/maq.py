"""Örnek check-only probe: MachineAccountQuota ön koşulunu kanıtlar."""

from app.ad_probes.base import BaseADProbe
from app.ad_probes.models import (
    ADProbeContext,
    Evidence,
    PreflightReport,
    ProbeOutcome,
    Proof,
    TriggerData,
)


class MachineAccountQuotaProbe(BaseADProbe):
    """MAQ>0 ön koşulunu doğrular; hesap oluşturma veya AD değişikliği YOK.

    `validated` burada yalnızca LDAP ön koşulunun kanıtlandığı anlamına gelir;
    herhangi bir CVE'nin sömürülebildiği anlamına gelmez. MAQ=0 açık ön koşul
    ihlali olduğundan tetik çalışmadan `failed`, MAQ okunamıyorsa
    `inconclusive` döner.
    """

    name = "machine_account_quota"
    required_preflight_fields = (
        "dc_sam_account_name", "domain_sid", "machine_account_quota",
    )
    requires_positive_maq = True

    async def minimal_trigger(
        self, context: ADProbeContext, report: PreflightReport,
    ) -> TriggerData:
        # Bilinçli no-op: pre-flight LDAP kanıtı dışında trafik üretmez.
        return TriggerData(
            attempted=False,
            observations={
                "machine_account_quota": report.machine_account_quota,
                "operation": "read_only_preflight",
            },
        )

    async def verify_proof(
        self, context: ADProbeContext, trigger: TriggerData,
    ) -> Proof:
        maq = trigger.observations["machine_account_quota"]
        evidence = Evidence(
            source="ldap",
            check="ms-DS-MachineAccountQuota",
            passed=isinstance(maq, int) and maq > 0,
            detail=f"Domain kökünden okunan MAQ={maq}",
        )
        if not evidence.passed:
            return Proof(
                ProbeOutcome.INCONCLUSIVE,
                "MAQ kanıtı doğrulanamadı",
                [evidence],
            )
        return Proof(
            ProbeOutcome.VALIDATED,
            "Makine hesabı ön koşulu doğrulandı (yalnızca check-only MAQ>0)",
            [evidence],
        )
