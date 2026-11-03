"""ARP güvenlik analizlerinin ortak, JSON'a dönüştürülebilir modelleri."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class AnalysisStatus(str, Enum):
    CLEAN = "clean"
    ALERTS = "alerts"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True, slots=True)
class ARPEvent:
    ts: float
    op: int                       # 1=request, 2=reply
    sender_ip: str
    sender_mac: str
    target_ip: str
    target_mac: str = ""

    @property
    def gratuitous(self) -> bool:
        return self.op == 2 and self.sender_ip == self.target_ip


@dataclass(slots=True)
class ARPAlert:
    kind: str
    severity: str
    message: str
    evidence: dict[str, Any]
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "severity": self.severity,
            "message": self.message,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
        }


@dataclass(slots=True)
class ARPAnalysisReport:
    status: AnalysisStatus
    total_packets: int
    analyzed_packets: int
    alerts: list[ARPAlert] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    observed_gateway: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "total_packets": self.total_packets,
            "analyzed_packets": self.analyzed_packets,
            "alerts": [alert.to_dict() for alert in self.alerts],
            "stats": self.stats,
            "observed_gateway": self.observed_gateway,
        }


class ControlStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    UNKNOWN = "unknown"


@dataclass(slots=True)
class ConfigFinding:
    control: str
    status: ControlStatus
    severity: str
    evidence: str
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "control": self.control,
            "status": self.status.value,
            "severity": self.severity,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
        }


@dataclass(slots=True)
class ConfigAuditReport:
    overall: str
    findings: list[ConfigFinding]
    summary: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall": self.overall,
            "summary": self.summary,
            "findings": [finding.to_dict() for finding in self.findings],
        }
