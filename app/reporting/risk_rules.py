"""Basit risk skor kuralları.

Her açık port bir kurala (RiskRule) göre değerlendirilir; host skoru
en yüksek port skorudur. Kural tabanlı ve kasıtlı olarak basit tutulmuştur —
yeni kural eklemek listeye bir RiskRule eklemekten ibarettir.
"""

from dataclasses import dataclass, field

from app.normalization.schema import HostResult, ServiceInfo

LEVEL_SCORES: dict[str, int] = {
    "info": 0,
    "low": 15,
    "medium": 40,
    "high": 75,
}
_LEVEL_ORDER = ["info", "low", "medium", "high"]


@dataclass(frozen=True)
class RiskRule:
    ports: frozenset[int]
    level: str          # info / low / medium / high
    reason: str


RISK_RULES: list[RiskRule] = [
    RiskRule(frozenset({23}), "high",
             "Telnet şifresiz metin protokolü — kimlik bilgileri düz metin taşınır"),
    RiskRule(frozenset({445}), "high",
             "SMB paylaşımı; EternalBlue vb. bilinen sömürülere açık olabilir"),
    RiskRule(frozenset({161}), "high",
             "SNMP açık — varsayılan 'public' topluluk adıyla bilgi sızıntısı"),
    RiskRule(frozenset({3389}), "high",
             "RDP uzak masaüstü; bilinen sömürüler ve bruce-force hedefi"),
    RiskRule(frozenset({21}), "medium",
             "FTP kimlik bilgilerini/veriyi şifresiz taşıyabilir"),
    RiskRule(frozenset({110, 143}), "medium",
             "POP3/IMAP şifresiz erişilebilir — e-posta bilgileri sızabilir"),
    RiskRule(frozenset({1900}), "medium",
             "SSDP/UPnP açık — DDoS amplifikasyonu için kullanılabilir"),
    RiskRule(frozenset({554}), "medium",
             "RTSP akış noktası — yetkisiz izleme yüzeyi"),
    RiskRule(frozenset({25}), "low",
             "Açık SMTP — açık röle (open relay) kontrolü yapılmalı"),
    RiskRule(frozenset({53}), "low",
             "Açık DNS — zone transfer ve önbellek zehirleme yüzeyi"),
    RiskRule(frozenset({80, 8080}), "low",
             "Şifresiz HTTP trafiği (kimlik bilgileri düz metin gidebilir)"),
    RiskRule(frozenset({22}), "low",
             "SSH açık — güçlü şifre/anahtar politikası ve sürüm takibi gerekli"),
    RiskRule(frozenset({443, 8443, 993, 995}), "info",
             "Şifreli servis (HTTPS/IMAPS/POP3S) — düşük risk"),
]


@dataclass
class PortRisk:
    port: int
    protocol: str
    service_name: str | None
    product: str          # "Ürün Sürüm" ya da servis adı
    level: str
    score: int
    reasons: list[str] = field(default_factory=list)


@dataclass
class HostRisk:
    ip: str
    score: int              # 0-100
    level: str              # en yüksek bulgu seviyesi
    findings: list[PortRisk] = field(default_factory=list)


def _max_level(levels: list[str]) -> str:
    if not levels:
        return "info"
    return max(levels, key=lambda lv: _LEVEL_ORDER.index(lv))


def evaluate_port(service: ServiceInfo) -> PortRisk:
    reasons: list[str] = []
    level = "info"
    for rule in RISK_RULES:
        if service.port in rule.ports:
            reasons.append(rule.reason)
            level = _max_level([level, rule.level])

    if service.version:
        reasons.append(f"Sürüm bilgisi dışarı sızdırılıyor: {product_display(service)}")
        level = _max_level([level, "info"])

    if not reasons:
        reasons.append("Bilinen yüksek risk kuralına uymayan açık port")

    return PortRisk(
        port=service.port,
        protocol=service.protocol,
        service_name=service.service_name,
        product=product_display(service),
        level=level,
        score=LEVEL_SCORES[level],
        reasons=reasons,
    )


def product_display(service: ServiceInfo) -> str:
    parts = [p for p in (service.product, service.version) if p]
    if parts:
        return " ".join(parts)
    return service.service_name or "-"


def evaluate_host(host: HostResult) -> HostRisk:
    findings = [evaluate_port(s) for s in host.services]
    score = max((f.score for f in findings), default=0)
    level = _max_level([f.level for f in findings]) if findings else "info"

    # Nikto web bulguları host riskini yükseltebilir (aynı severity sözlüğü)
    nikto_levels = [
        f.severity for f in host.web_findings if f.severity in LEVEL_SCORES
    ]
    if nikto_levels:
        level = _max_level([level, *nikto_levels])
        score = max(score, LEVEL_SCORES[level])

    return HostRisk(ip=host.ip, score=score, level=level, findings=findings)
