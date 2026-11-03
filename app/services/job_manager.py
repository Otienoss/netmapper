"""WebSocket destekli job takibi (in-memory pub/sub + kalıcı DB kaydı).

- Her job için asyncio.Queue abonelerine anlık durum/log push edilir
  (WebSocket endpoint'i bu kuyruklara bağlanır — polling yok).
- Dışa giden HTTP/WS payload'ı `app.core.sanitizer` ile maskelenir; parola,
  token ve hash alanları canlı yayına çıkmaz. Ham kanıt DB'si korunur.
- Aynı durum SQLite'a yazılır: sunucu yeniden başlasa bile job sorgulanır,
  rapor/envanter uçları çalışmaya devam eder.
- Çoklu worker senaryosunda bu katman Redis Pub/Sub'a taşınabilir;
  arayüz (create/update/log/subscribe) aynı kalır.
"""

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from app.config import settings
from app.core.sanitizer import (
    collect_secret_values,
    sanitize_payload,
    sanitize_text,
)
from app.normalization.schema import HostResult
from app.storage import repository
from app.storage.database import async_session_factory

logger = logging.getLogger(__name__)


class JobStatus(str, Enum):
    PENDING = "pending"
    DISCOVERING = "discovering"
    SCANNING = "scanning"
    NORMALIZING = "normalizing"
    DONE = "done"
    ERROR = "error"


_TERMINAL = {JobStatus.DONE, JobStatus.ERROR}

# Eski DB satırları (ilk sürümdeki queued/running) → yeni durumlar
_LEGACY_STATUS = {
    "queued": JobStatus.PENDING,
    "running": JobStatus.SCANNING,
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class JobState:
    job_id: str
    subnet: str
    profile: str = "full"
    module: str = "net"                        # net | ad
    meta: dict = field(default_factory=dict)   # domain/username/görevler (ŞİFRE YOK)
    status: JobStatus = JobStatus.PENDING
    progress: dict = field(default_factory=dict)  # {"hosts_total": 14, "hosts_scanned": 9}
    logs: list[str] = field(default_factory=list)
    results: list[dict] | None = None
    error: str | None = None
    updated_at: datetime = field(default_factory=_utcnow)


class JobManager:
    def __init__(self) -> None:
        self._jobs: dict[str, JobState] = {}
        self._subscribers: dict[str, list[asyncio.Queue]] = {}
        # Yalnızca canlı işin loglarını maskelemek için; terminal durumda silinir.
        self._job_secrets: dict[str, list[str]] = {}

    def _secrets_for(self, job_id: str) -> list[str]:
        secrets = list(self._job_secrets.get(job_id, []))
        if settings.api_token:
            secrets.append(settings.api_token)
        return secrets

    # ------------------------------------------------------------- oluştur
    def create_job(self, job_id: str, subnet: str, profile: str = "full",
                   module: str = "net", meta: dict | None = None) -> JobState:
        state = JobState(
            job_id=job_id, subnet=subnet, profile=profile,
            module=module, meta=meta or {},
        )
        self._jobs[job_id] = state
        self._subscribers[job_id] = []
        self._job_secrets.setdefault(job_id, [])
        return state

    async def start_scan(self, subnet: str, profile: str = "full",
                         ports: str | None = None,
                         module: str = "net",
                         params: dict | None = None) -> str:
        """Job'ı kaydeder, taramayı arka planda başlatır, job_id döner.

        params: sadece _run'a giden çalıştırma bilgileri (AD: domain/
        username/**password**/tasks). Şifre asla JobState'e veya DB'ye konmaz;
        meta'ya yalnızca gösterim bilgileri alınır.
        """
        params = params or {}
        job_id = uuid.uuid4().hex
        meta = {k: v for k, v in params.items() if k != "password"}
        self._job_secrets[job_id] = collect_secret_values(params)
        self.create_job(job_id, subnet, profile, module, meta)
        try:
            async with async_session_factory() as session:
                await repository.create_job(
                    session, job_id, subnet, profile, module
                )
        except Exception as e:
            logger.warning("Job DB kaydı yapılamadı (%s): %s", job_id, e)

        asyncio.create_task(
            self._run(job_id, subnet, profile, ports, module, params)
        )
        logger.info(
            "Job %s started (%s, module=%s, profile=%s)",
            job_id, subnet, module, profile,
        )
        return job_id

    async def _run(self, job_id: str, subnet: str,
                   profile: str, ports: str | None,
                   module: str = "net", params: dict | None = None) -> None:
        params = params or {}
        try:
            if module == "arp_monitor":
                # Pasif ARP dinleme + anomali analizi (paket gönderimi yok)
                from app.arp_security.monitor import run_monitor_job
                result = await run_monitor_job(job_id, subnet, params)
                await self.update(
                    job_id, status=JobStatus.DONE, results=[result],
                )
                return

            if module == "ad_probe":
                # Check-only BaseADProbe yaşam döngüsü (döngüsel import için yerel)
                from app.services.ad_probe_runner import run_probe_job
                result = await run_probe_job(job_id, subnet, params)
                await self.update(
                    job_id, status=JobStatus.DONE, results=[result],
                )
                return

            if module == "ad":
                # AD modülü: Impacket görevleri (döngüsel import için yerel)
                from app.services.ad_orchestrator import ADOchestrator
                ad = ADOchestrator()
                await ad.run(
                    job_id,
                    target=subnet,
                    domain=params["domain"],
                    username=params["username"],
                    password=params["password"],
                    tasks=params.get("tasks") or ["spn", "asrep"],
                    privesc_start=params.get("privesc_start"),
                    dc_hostname=params.get("dc_hostname"),
                    da_user=params.get("da_user"),
                )
                await self.log(job_id, "AD görevi tamamlandı.")
                await self.update(job_id, status=JobStatus.DONE)
                return

            # Standart ağ modülü: keşif → nmap + nikto
            # döngüsel importu önlemek için yerel import
            from app.services.scan_orchestrator import ScanOrchestrator
            orchestrator = ScanOrchestrator()
            results = await orchestrator.run_full_scan(
                job_id, subnet, profile=profile, ports=ports
            )
            # Önce kalıcı kayıt: UI "done" gördüğünde rapor/results hazır olsun
            await self.save_results(job_id, results)
            await self.log(job_id, f"Tamamlandı: {len(results)} host kaydedildi.")
            await self.update(
                job_id,
                status=JobStatus.DONE,
                results=[r.model_dump(mode="json") for r in results],
            )
        except Exception as e:
            logger.exception("Job %s failed", job_id)
            await self.log(job_id, f"Hata: {e}")
            await self.update(job_id, status=JobStatus.ERROR, error=str(e))

    # ------------------------------------------------------------- sorgu
    def get_job(self, job_id: str) -> JobState | None:
        return self._jobs.get(job_id)

    async def get_state(self, job_id: str) -> JobState | None:
        """Önce hafıza, yoksa DB (yeniden başlatma sonrası job sorgusu)."""
        if job_id in self._jobs:
            return self._jobs[job_id]
        try:
            async with async_session_factory() as session:
                job = await repository.get_job(session, job_id)
            if job is None:
                return None
        except Exception as e:
            logger.warning("DB'den job okunamadı (%s): %s", job_id, e)
            return None
        status = (
            JobStatus(job.status)
            if job.status in JobStatus._value2member_map_
            else _LEGACY_STATUS.get(job.status, JobStatus.PENDING)
        )
        state = JobState(
            job_id=job.id, subnet=job.subnet,
            profile=getattr(job, "profile", "full") or "full",
            module=getattr(job, "module", "net") or "net",
            status=status, error=job.error,
        )
        # Hafızaya geri yaz: WS aboneliği ve sonraki sorgular tek seferlik
        # DB yüklemesinden devam etsin
        self._jobs[job_id] = state
        self._subscribers.setdefault(job_id, [])
        return state

    # ------------------------------------------------------------- güncelle
    async def update(self, job_id: str, **kwargs) -> None:
        state = self._jobs.get(job_id)
        if not state:
            return
        if isinstance(kwargs.get("error"), str):
            kwargs["error"] = sanitize_text(
                kwargs["error"], self._secrets_for(job_id)
            )
        for k, v in kwargs.items():
            setattr(state, k, v)
        state.updated_at = _utcnow()

        # Durum değişimini kalıcıya da yaz (dashboard listesi DB'den okunur)
        if isinstance(state.status, JobStatus):
            try:
                async with async_session_factory() as session:
                    await repository.set_job_status(
                        session, job_id, state.status.value, error=state.error
                    )
            except Exception as e:
                logger.warning("Job durumu DB'ye yazılamadı (%s): %s", job_id, e)

        await self._broadcast(job_id, state)
        if state.status in _TERMINAL:
            # Ham parola/token'ı canlı job ömründen sonra bellekte tutma.
            self._job_secrets.pop(job_id, None)

    async def log(self, job_id: str, message: str) -> None:
        state = self._jobs.get(job_id)
        if not state:
            return
        message = sanitize_text(message, self._secrets_for(job_id))
        stamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
        state.logs.append(f"[{stamp}] {message}")
        await self._broadcast(job_id, state)

    async def save_results(self, job_id: str, results: list[HostResult]) -> None:
        try:
            async with async_session_factory() as session:
                await repository.save_scan_results(session, job_id, results)
        except Exception as e:
            logger.error("Sonuçlar DB'ye yazılamadı (%s): %s", job_id, e)

    # ------------------------------------------------------------- pub/sub
    async def subscribe(self, job_id: str) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        self._subscribers.setdefault(job_id, []).append(q)
        # Yeni bağlanan client anında mevcut durumu alsın
        if state := self._jobs.get(job_id):
            await q.put(self.serialize(state))
        return q

    def unsubscribe(self, job_id: str, q: asyncio.Queue) -> None:
        subs = self._subscribers.get(job_id, [])
        if q in subs:
            subs.remove(q)

    async def _broadcast(self, job_id: str, state: JobState) -> None:
        payload = self.serialize(state)
        for q in self._subscribers.get(job_id, []):
            await q.put(payload)

    def serialize(self, state: JobState) -> dict[str, Any]:
        payload = {
            "job_id": state.job_id,
            "subnet": state.subnet,
            "profile": state.profile,
            "module": state.module,
            "meta": state.meta,     # domain/username/görevler — şifre YOK
            "status": state.status.value if isinstance(state.status, JobStatus)
            else str(state.status),
            "progress": state.progress,
            "logs": state.logs[-20:],  # son 20 log satırı yeterli
            "results": state.results,
            "error": state.error,
            "updated_at": state.updated_at.isoformat(),
        }
        # HTTP job detail ve WebSocket aynı temiz payload'ı kullanır.
        return sanitize_payload(payload, self._secrets_for(state.job_id))

    @staticmethod
    def is_terminal(payload_or_state) -> bool:
        """Durum done/error mu? (serialize edilmiş dict veya JobState kabul eder.)"""
        status = payload_or_state
        if isinstance(payload_or_state, dict):
            status = payload_or_state.get("status")
        elif isinstance(payload_or_state, JobState):
            status = payload_or_state.status
        value = status.value if isinstance(status, JobStatus) else str(status)
        return value in ("done", "error")


# Uygulama genelinde tek örnek (singleton)
job_manager = JobManager()
