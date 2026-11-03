"""Veritabanı tabloları. Pydantic şemasıyla (normalization/schema.py) ayrık tutulur:

- Modeller kalıcı depolama iskeletini tanımlar (ilişkiler, indeksler).
- HostResult ise tarama anındaki "veri transfer" nesnesidir.
Ara dönüşüm repository.to_host_result ile yapılır.
"""

from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Field, Relationship, SQLModel


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ScanJob(SQLModel, table=True):
    __tablename__ = "scan_jobs"

    id: str = Field(primary_key=True)           # job_id (uuid4 hex) — API ile aynı kimlik
    subnet: str                                  # net: CIDR | ad: DC hedefi
    profile: str = "full"                        # quick / full / custom / ad
    module: str = "net"                          # net | ad
    status: str = "pending"                      # pending..done/error (JobStatus değerleri)
    error: Optional[str] = None
    created_at: datetime = Field(default_factory=_utcnow)
    finished_at: Optional[datetime] = None

    hosts: list["Host"] = Relationship(
        back_populates="scan",
        sa_relationship_kwargs={"lazy": "selectin"},
    )


class Host(SQLModel, table=True):
    __tablename__ = "hosts"

    id: Optional[int] = Field(default=None, primary_key=True)
    scan_id: str = Field(foreign_key="scan_jobs.id", index=True)
    ip: str
    mac: Optional[str] = None
    vendor: Optional[str] = None
    hostname: Optional[str] = None
    status: str = "up"
    scanned_at: datetime = Field(default_factory=_utcnow)
    source_tool: str = "nmap"

    scan: Optional[ScanJob] = Relationship(
        back_populates="hosts",
        # Async ortamda lazy-load (MissingGreenlet) hatası verir — eager yükle
        sa_relationship_kwargs={"lazy": "selectin"},
    )
    services: list["Service"] = Relationship(
        back_populates="host",
        sa_relationship_kwargs={"lazy": "selectin"},
    )
    web_findings: list["WebFinding"] = Relationship(
        back_populates="host",
        sa_relationship_kwargs={"lazy": "selectin"},
    )


class WebFinding(SQLModel, table=True):
    """Nikto web bulguları (host başına satırlar)."""

    __tablename__ = "web_findings"

    id: Optional[int] = Field(default=None, primary_key=True)
    host_id: Optional[int] = Field(foreign_key="hosts.id", index=True)
    finding_id: Optional[str] = None       # nikto test id
    osvdb_id: Optional[str] = None
    severity: str = "low"                  # info/low/medium/high
    message: str
    uri: Optional[str] = None

    host: Optional[Host] = Relationship(
        back_populates="web_findings",
        sa_relationship_kwargs={"lazy": "selectin"},
    )


class ADFindingRow(SQLModel, table=True):
    """AD keşif bulguları — ortak havuz (job_id ile JSON dosyası eşleşir)."""

    __tablename__ = "ad_findings"

    id: Optional[int] = Field(default=None, primary_key=True)
    job_id: str = Field(foreign_key="scan_jobs.id", index=True)
    kind: str                                    # kerberoast / asrep / dcsync / privesc / cve
    principal: str
    spn: Optional[str] = None
    severity: str = "medium"
    message: str
    detail: Optional[str] = None                 # JSON metni (hash, rid vb.)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Service(SQLModel, table=True):
    __tablename__ = "services"

    id: Optional[int] = Field(default=None, primary_key=True)
    host_id: Optional[int] = Field(foreign_key="hosts.id", index=True)
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service_name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None

    host: Optional[Host] = Relationship(back_populates="services")
