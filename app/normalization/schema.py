from datetime import datetime, timezone

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ServiceInfo(BaseModel):
    port: int
    protocol: str          # tcp/udp
    state: str             # open/closed/filtered
    service_name: str | None = None
    product: str | None = None
    version: str | None = None


class WebFinding(BaseModel):
    """Nikto web bulgusu."""
    id: str | None = None              # nikto test id
    osvdb_id: str | None = None
    severity: str = "low"              # info / low / medium / high
    message: str
    uri: str | None = None


class ADFinding(BaseModel):
    """Active Directory keşif bulgusu (Impacket). Ortak havuza yazılır."""
    kind: str                          # kerberoast / asrep / dcsync / privesc / cve
    principal: str                     # domain\kullanici veya kullanici
    spn: str | None = None
    severity: str = "medium"           # info / low / medium / high
    message: str
    detail: dict = Field(default_factory=dict)   # hash, rid vb. (JSON havuzu)


class HostResult(BaseModel):
    """Tüm tarayıcıların çıktısının indirgeneceği ortak şema."""

    ip: str
    mac: str | None = None
    vendor: str | None = None
    hostname: str | None = None
    status: str = "up"
    services: list[ServiceInfo] = Field(default_factory=list)
    web_findings: list[WebFinding] = Field(default_factory=list)
    scanned_at: datetime = Field(default_factory=_utcnow)
    source_tool: str = "nmap"
