"""Salt-okunur ARP güvenlik uçları: config, offline PCAP ve pasif izleme."""

import asyncio
import ipaddress
import re
import tempfile
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from app.arp_security.config_audit import SwitchConfigAuditor
from app.arp_security.monitor import stop_monitor
from app.arp_security.pcap import OfflinePcapAnalyzer
from app.services.job_manager import job_manager

router = APIRouter(prefix="/arp", tags=["arp-security"])
_MAX_PCAP_BYTES = 25 * 1024 * 1024


class ConfigAuditRequest(BaseModel):
    config_text: str = Field(min_length=1, max_length=200_000)
    config_complete: bool = False


class MonitorRequest(BaseModel):
    interface: str = Field(min_length=1, max_length=32)
    gateway_ip: str | None = None
    gateway_mac: str | None = None
    duration_sec: int = Field(default=60, ge=5, le=600)
    max_packets: int = Field(default=5000, ge=100, le=50_000)

    @field_validator("interface")
    @classmethod
    def _interface(cls, value: str) -> str:
        value = value.strip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}", value):
            raise ValueError("Geçersiz interface adı")
        return value

    @field_validator("gateway_ip")
    @classmethod
    def _gateway_ip(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return str(ipaddress.ip_address(value.strip()))

    @field_validator("gateway_mac")
    @classmethod
    def _gateway_mac(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip().lower()
        if not re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", value):
            raise ValueError("Geçersiz gateway MAC adresi")
        return value


@router.post("/config-audit")
async def config_audit(req: ConfigAuditRequest) -> dict:
    """Switch konfigürasyon metnini cihaza bağlanmadan denetler."""
    return SwitchConfigAuditor().audit(
        req.config_text, req.config_complete
    ).to_dict()


@router.post("/monitor/start")
async def monitor_start(req: MonitorRequest) -> dict:
    """Süreli pasif ARP dinlemesi başlatır; paket göndermez."""
    job_id = await job_manager.start_scan(
        req.gateway_ip or req.interface,
        profile="arp",
        module="arp_monitor",
        params=req.model_dump(),
    )
    return {
        "job_id": job_id,
        "status": "started",
        "ws_url": f"/api/v1/ws/jobs/{job_id}",
        "detail_url": f"/api/v1/jobs/{job_id}",
    }


@router.post("/monitor/stop/{job_id}")
async def monitor_stop(job_id: str) -> dict:
    if not stop_monitor(job_id):
        raise HTTPException(status_code=404, detail="Aktif ARP monitörü yok")
    return {"job_id": job_id, "status": "stopping"}


@router.post("/pcap-audit")
async def pcap_audit(
    request: Request,
    gateway_ip: str | None = None,
    gateway_mac: str | None = None,
) -> dict:
    """Octet-stream PCAP gövdesini geçici dosyada analiz eder ve hemen siler."""
    if gateway_ip:
        try:
            gateway_ip = str(ipaddress.ip_address(gateway_ip.strip()))
        except ValueError as exc:
            raise HTTPException(422, "Geçersiz gateway_ip") from exc
    if gateway_mac and not re.fullmatch(
        r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}", gateway_mac
    ):
        raise HTTPException(422, "Geçersiz gateway_mac")

    temp = tempfile.NamedTemporaryFile(
        prefix="netmapper-arp-", suffix=".pcap", delete=False
    )
    path = Path(temp.name)
    size = 0
    try:
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > _MAX_PCAP_BYTES:
            raise HTTPException(413, "PCAP boyut sınırı 25 MiB")
        async for chunk in request.stream():
            size += len(chunk)
            if size > _MAX_PCAP_BYTES:
                raise HTTPException(413, "PCAP boyut sınırı 25 MiB")
            temp.write(chunk)
        temp.close()
        try:
            report = await asyncio.to_thread(
                OfflinePcapAnalyzer().analyze,
                path, gateway_ip, gateway_mac,
            )
        except Exception as exc:
            raise HTTPException(400, f"PCAP analizi başarısız: {exc}") from exc
        return report.to_dict()
    finally:
        temp.close()
        path.unlink(missing_ok=True)
