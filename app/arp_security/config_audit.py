"""Switch konfigürasyon metninden salt-okunur L2 güvenlik denetimi."""

from __future__ import annotations

import re

from app.arp_security.models import (
    ConfigAuditReport,
    ConfigFinding,
    ControlStatus,
)

_CONTROLS = {
    "dhcp_snooping": {
        "present": r"^\s*ip dhcp snooping(?:\s+vlan\b|\s*$)",
        "disabled": r"^\s*no ip dhcp snooping\b",
        "severity": "high",
        "recommendation": "DHCP snooping'i etkinleştirin ve güvenilir "
                          "IP-MAC-port binding tablosu oluşturun.",
    },
    "dynamic_arp_inspection": {
        "present": r"^\s*ip arp inspection vlan\s+\S+",
        "disabled": r"^\s*no ip arp inspection vlan\b",
        "severity": "critical",
        "recommendation": "DHCP snooping binding'leriyle VLAN bazlı DAI "
                          "etkinleştirin; yalnızca uplink portlarını trust yapın.",
    },
    "ip_source_guard": {
        "present": r"^\s*ip verify source(?:\s+port-security)?\s*$",
        "disabled": r"^\s*no ip verify source\b",
        "severity": "high",
        "recommendation": "Erişim portlarında IP Source Guard ile kaynak "
                          "IP/MAC doğrulaması uygulayın.",
    },
    "port_security": {
        "present": r"^\s*switchport port-security(?:\s+maximum\s+\d+)?\s*$",
        "disabled": r"^\s*no switchport port-security\b",
        "severity": "medium",
        "recommendation": "Erişim portlarında MAC limiti ve violation "
                          "politikası tanımlayın; MAC-flap olaylarını izleyin.",
    },
    "nac_8021x": {
        "present": r"(^\s*dot1x system-auth-control|"
                   r"^\s*authentication port-control auto)",
        "disabled": r"(^\s*no dot1x system-auth-control|"
                    r"^\s*authentication port-control none)",
        "severity": "high",
        "recommendation": "802.1X/MAB politika kapsamını ve istisnaları "
                          "gözden geçirin; MAC'i tek kimlik kanıtı saymayın.",
    },
}


class SwitchConfigAuditor:
    """Cisco IOS benzeri konfigürasyonları analiz eder; cihaza bağlanmaz."""

    @staticmethod
    def _match(config: str, pattern: str) -> str | None:
        match = re.search(pattern, config, re.IGNORECASE | re.MULTILINE)
        return match.group(0).strip() if match else None

    def audit(
        self, config_text: str, config_complete: bool = False,
    ) -> ConfigAuditReport:
        findings: list[ConfigFinding] = []
        for name, spec in _CONTROLS.items():
            disabled = self._match(config_text, spec["disabled"])
            present = self._match(config_text, spec["present"])
            if disabled:
                status = ControlStatus.FAIL
                evidence = f"Açıkça kapalı: {disabled}"
            elif present:
                status = ControlStatus.PASS
                evidence = f"Kontrol mevcut: {present}"
            elif config_complete:
                status = ControlStatus.FAIL
                evidence = "Tam konfigürasyonda kontrol satırı bulunamadı"
            else:
                status = ControlStatus.UNKNOWN
                evidence = "Kısmi konfigürasyonda kontrol kanıtı yok"
            findings.append(ConfigFinding(
                name, status,
                spec["severity"] if status is ControlStatus.FAIL else "info",
                evidence, spec["recommendation"],
            ))

        dai = next(f for f in findings if f.control == "dynamic_arp_inspection")
        if dai.status is ControlStatus.PASS:
            trust = self._match(config_text, r"^\s*ip arp inspection trust\s*$")
            if not trust:
                findings.append(ConfigFinding(
                    "dai_uplink_trust", ControlStatus.UNKNOWN, "info",
                    "DAI aktif ancak konfigürasyonda trust satırı görünmüyor",
                    "Uplink trust ayarlarını ve kısmi konfigürasyon kapsamını "
                    "doğrulayın; yanlış trust modeli trafiği kesebilir.",
                ))

        summary = {
            status.value: sum(f.status is status for f in findings)
            for status in ControlStatus
        }
        overall = (
            "at_risk" if summary["fail"]
            else "review" if summary["unknown"] else "pass"
        )
        return ConfigAuditReport(overall, findings, summary)
