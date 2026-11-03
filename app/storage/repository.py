"""CRUD katmanı: services/ iş katmanı ile veritabanı arasında tek kapı.

Sadece bu modül SQLModel sorgularını bilir; orkestratör/job_manager
yalnızca fonksiyon imzalarına bağlıdır.
"""

from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from app.normalization.schema import ADFinding, HostResult, ServiceInfo, WebFinding
from app.storage.models import (
    ADFindingRow,
    Host,
    ScanJob,
    Service,
    WebFinding as WebFindingRow,
)


async def create_job(
    session: AsyncSession,
    job_id: str,
    subnet: str,
    profile: str = "full",
    module: str = "net",
) -> ScanJob:
    job = ScanJob(
        id=job_id, subnet=subnet, profile=profile,
        module=module, status="pending",
    )
    session.add(job)
    await session.commit()
    await session.refresh(job)
    return job


# ---------------------------------------------------------------- AD havuzu
async def save_ad_findings(
    session: AsyncSession, job_id: str, findings: list[ADFinding]
) -> None:
    """AD bulgularını ortak havuza (ad_findings) yazar."""
    import json
    for f in findings:
        session.add(ADFindingRow(
            job_id=job_id,
            kind=f.kind,
            principal=f.principal,
            spn=f.spn,
            severity=f.severity,
            message=f.message,
            detail=json.dumps(f.detail, ensure_ascii=False) if f.detail else None,
        ))
    await session.commit()


async def list_ad_findings(
    session: AsyncSession, job_id: str | None = None, limit: int = 100
) -> list[ADFindingRow]:
    """Havuz sorgusu: job'a özel veya tüm işlerin bulguları (en yeniden eskiye)."""
    import json as _json
    stmt = select(ADFindingRow)
    if job_id:
        stmt = stmt.where(ADFindingRow.job_id == job_id)
    result = await session.exec(
        stmt.order_by(ADFindingRow.created_at.desc()).limit(limit)
    )
    rows = list(result.all())
    for row in rows:                       # detail JSON metnini nesneye çevir
        row.detail = _json.loads(row.detail) if row.detail else {}
    return rows


async def list_jobs(session: AsyncSession, limit: int = 20) -> list[ScanJob]:
    """Son taramalar (en yeniden eskiye) — dashboard listesi için."""
    result = await session.exec(
        select(ScanJob).order_by(ScanJob.created_at.desc()).limit(limit)
    )
    return list(result.all())


async def list_all_hosts(session: AsyncSession) -> list[Host]:
    """Tüm taramaların host'ları (scanned_at, en yeniden eskiye)."""
    result = await session.exec(
        select(Host).order_by(Host.scanned_at.desc())
    )
    return list(result.all())


async def get_job(session: AsyncSession, job_id: str) -> ScanJob | None:
    return await session.get(ScanJob, job_id)


async def set_job_status(
    session: AsyncSession,
    job_id: str,
    status: str,
    error: str | None = None,
) -> None:
    job = await session.get(ScanJob, job_id)
    if job is None:
        return
    job.status = status
    job.error = error
    if status in ("done", "error"):
        job.finished_at = datetime.now(timezone.utc)
    session.add(job)
    await session.commit()


async def save_scan_results(
    session: AsyncSession,
    job_id: str,
    results: list[HostResult],
) -> None:
    """Orkestratörün ürettiği HostResult listesini normalize edip yazar."""
    for host in results:
        db_host = Host(
            scan_id=job_id,
            ip=host.ip,
            mac=host.mac,
            vendor=host.vendor,
            hostname=host.hostname,
            status=host.status,
            scanned_at=host.scanned_at,
            source_tool=host.source_tool,
        )
        session.add(db_host)
        await session.flush()  # db_host.id almak için
        for svc in host.services:
            session.add(Service(
                host_id=db_host.id,
                port=svc.port,
                protocol=svc.protocol,
                state=svc.state,
                service_name=svc.service_name,
                product=svc.product,
                version=svc.version,
            ))
        for finding in host.web_findings:
            session.add(WebFindingRow(
                host_id=db_host.id,
                finding_id=finding.id,
                osvdb_id=finding.osvdb_id,
                severity=finding.severity,
                message=finding.message,
                uri=finding.uri,
            ))
    await session.commit()


async def get_hosts_with_services(session: AsyncSession, scan_id: str) -> list[Host]:
    result = await session.exec(
        select(Host).where(Host.scan_id == scan_id).order_by(Host.ip)
    )
    return list(result.all())


def to_host_result(host: Host) -> HostResult:
    """DB satırını raporlama/ risk katmanının beklediği ortak şemaya çevirir."""
    return HostResult(
        ip=host.ip,
        mac=host.mac,
        vendor=host.vendor,
        hostname=host.hostname,
        status=host.status,
        scanned_at=host.scanned_at,
        source_tool=host.source_tool,
        services=[
            ServiceInfo(
                port=svc.port,
                protocol=svc.protocol,
                state=svc.state,
                service_name=svc.service_name,
                product=svc.product,
                version=svc.version,
            )
            for svc in host.services
        ],
        web_findings=[
            WebFinding(
                id=w.finding_id,
                osvdb_id=w.osvdb_id,
                severity=w.severity,
                message=w.message,
                uri=w.uri,
            )
            for w in host.web_findings
        ],
    )
