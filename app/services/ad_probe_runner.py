"""BaseADProbe sonuçlarını mevcut asenkron job akışına bağlayan adaptör."""

from app.ad_probes.maq import MachineAccountQuotaProbe
from app.ad_probes.models import ADProbeContext
from app.services.job_manager import JobStatus, job_manager

_PROBE_TYPES = {
    "maq": MachineAccountQuotaProbe,
}


async def run_probe_job(job_id: str, target: str, params: dict) -> dict:
    """Seçilen check-only probu koşar ve JSON-serializable sonuç döner."""
    probe_name = params.get("probe") or "maq"
    try:
        probe_type = _PROBE_TYPES[probe_name]
    except KeyError as exc:
        raise ValueError(f"Bilinmeyen AD probe: {probe_name}") from exc

    async def _log(message: str) -> None:
        await job_manager.log(job_id, message)

    context = ADProbeContext(
        target=target,
        domain=params["domain"],
        username=params["username"],
        password=params["password"],
        job_id=job_id,
        target_dc=params.get("target_dc"),
        on_log=_log,
    )
    await job_manager.update(job_id, status=JobStatus.DISCOVERING)
    result = await probe_type().run(context)
    await job_manager.update(job_id, status=JobStatus.NORMALIZING)
    await job_manager.log(
        job_id,
        f"AD probe tamam: {probe_name} outcome={result.outcome.value} "
        f"cleanup={result.cleanup.status.value} — {result.reason}",
    )
    return result.to_dict()
