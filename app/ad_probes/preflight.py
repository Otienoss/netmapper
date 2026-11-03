"""LDAP tabanlı, salt-okunur AD ön-keşif katmanı."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

from app.ad_probes.models import ADProbeContext, PreflightReport


class PreFlightError(Exception):
    """Ön-keşif verisi toplanamadı; hedef hakkında olumsuz kanıt DEĞİLDİR."""


ConnectionFactory = Callable[[ADProbeContext], Any]

_DOMAIN_ATTRIBUTES = [
    "objectSid", "ms-DS-MachineAccountQuota", "maxTicketAge",
    "maxRenewAge", "maxServiceAge", "maxClockSkew",
]
_DC_ATTRIBUTES = [
    "sAMAccountName", "dNSHostName", "msDS-SupportedEncryptionTypes",
]
_KERBEROS_INTERVALS = {
    "maxTicketAge": "maxTicketAgeMinutes",
    "maxRenewAge": "maxRenewAgeMinutes",
    "maxServiceAge": "maxServiceAgeMinutes",
    "maxClockSkew": "maxClockSkewMinutes",
}


def _base_dn(domain: str) -> str:
    return ",".join(f"DC={part}" for part in domain.split(".") if part)


def _raw(entry: Any, name: str) -> Any:
    try:
        value = getattr(entry, name)
    except (AttributeError, TypeError):
        return None
    return getattr(value, "value", value)


def _text(entry: Any, name: str) -> str | None:
    value = _raw(entry, name)
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def sid_to_string(value: Any) -> str | None:
    """LDAP objectSid baytlarını S-1-5-21-... biçimine çevirir."""
    if value is None:
        return None
    if isinstance(value, str):
        return value if value.startswith("S-") else None
    if not isinstance(value, (bytes, bytearray)) or len(value) < 8:
        return None
    data = bytes(value)
    revision, count = data[0], data[1]
    if len(data) != 8 + (4 * count):
        return None
    authority = int.from_bytes(data[2:8], "big")
    parts = [f"S-{revision}-{authority}"]
    parts.extend(
        str(int.from_bytes(data[offset:offset + 4], "little"))
        for offset in range(8, len(data), 4)
    )
    return "-".join(parts)


def _interval_minutes(entry: Any, name: str) -> float | None:
    """AD'nin 100-ns aralık değerini dakikaya çevirir."""
    try:
        return round(int(str(_raw(entry, name))) / 10_000_000 / 60, 3)
    except (TypeError, ValueError):
        return None


def _select_dc(
    entries: list[Any], target: str, target_dc: str | None = None,
) -> tuple[Any | None, str | None]:
    """Hedefi DC kaydıyla eşler; belirsizlikte ilk kaydı SEÇMEZ.

    target_dc verildiyse yalnızca açık eşleşme kabul edilir; tek kayıt bile
    olsa farklı bir DC'ye sessizce yönlendirme yapılmaz.
    """
    if not entries:
        return None, "LDAP hiç Domain Controller kaydı döndürmedi"
    if target_dc:
        wanted = target_dc.strip().rstrip(".").lower()
        for entry in entries:
            sam_full = (_text(entry, "sAMAccountName") or "").lower()
            sam = sam_full.rstrip("$")
            fqdn = (_text(entry, "dNSHostName") or "").lower()
            if wanted in {sam_full, sam, fqdn, fqdn.split(".")[0]}:
                return entry, None
        return None, f"target_dc={target_dc!r} için eşleşen DC kaydı yok"
    if len(entries) == 1:
        return entries[0], None
    wanted = target.strip().rstrip(".").lower()
    for entry in entries:
        sam = (_text(entry, "sAMAccountName") or "").rstrip("$").lower()
        fqdn = (_text(entry, "dNSHostName") or "").lower()
        if wanted in {sam, fqdn, fqdn.split(".")[0]}:
            return entry, None
    return None, (
        "Birden fazla DC var; target_dc/dc_fqdn ile tekil DC zorunlu "
        "gösterilmeli (hedef otomatik eşleştirilemedi)"
    )


class PreflightEngine:
    """Domain ve hedef DC ön koşullarını tek LDAP oturumunda toplar."""

    def __init__(
        self, connection_factory: ConnectionFactory | None = None,
        timeout: float = 10.0,
    ) -> None:
        self._connection_factory = connection_factory
        self._timeout = timeout

    def _connect(self, context: ADProbeContext) -> Any:
        if self._connection_factory is not None:
            return self._connection_factory(context)
        import ldap3

        server = ldap3.Server(
            context.target, get_info=ldap3.NONE, connect_timeout=self._timeout
        )
        return ldap3.Connection(
            server,
            user=f"{context.domain}\\{context.username}",
            password=context.password,
            authentication=ldap3.NTLM,
            auto_bind=True,
            receive_timeout=self._timeout,
        )

    async def collect(self, context: ADProbeContext) -> PreflightReport:
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(self._collect_sync, context),
                timeout=self._timeout,
            )
        except TimeoutError as exc:
            # to_thread iptal edilir; LDAP socket timeout'ları da iş parçacığını
            # sınırlar. Job bu sayede ağ donmasında beklemeye devam etmez.
            raise PreFlightError(
                f"LDAP pre-flight {self._timeout:g}s içinde tamamlanamadı "
                "(zaman aşımı)"
            ) from exc

    def _collect_sync(self, context: ADProbeContext) -> PreflightReport:
        report = PreflightReport(context.target, context.domain)
        try:
            conn = self._connect(context)
        except Exception as exc:
            raise PreFlightError(
                f"LDAP pre-flight bağlantısı kurulamadı "
                f"({context.target}:389): {exc}"
            ) from exc

        try:
            base = _base_dn(context.domain)
            if not conn.search(
                base, "(objectClass=domainDNS)", attributes=_DOMAIN_ATTRIBUTES
            ) or not conn.entries:
                report.errors.append("Domain kök nesnesi okunamadı")
            else:
                domain_entry = conn.entries[0]
                report.domain_sid = sid_to_string(
                    _raw(domain_entry, "objectSid")
                )
                try:
                    report.machine_account_quota = int(str(
                        _raw(domain_entry, "ms-DS-MachineAccountQuota")
                    ))
                except (TypeError, ValueError):
                    report.errors.append("ms-DS-MachineAccountQuota okunamadı")
                for ldap_name, output_name in _KERBEROS_INTERVALS.items():
                    report.kerberos[output_name] = _interval_minutes(
                        domain_entry, ldap_name
                    )

            if not conn.search(
                base,
                "(&(objectCategory=computer)(primaryGroupID=516))",
                attributes=_DC_ATTRIBUTES,
            ):
                report.errors.append("DC bilgisayar nesneleri sorgulanamadı")
            else:
                dc_entry, selection_error = _select_dc(
                    list(conn.entries), context.target, context.target_dc
                )
                if selection_error:
                    report.errors.append(selection_error)
                if dc_entry is not None:
                    report.dc_sam_account_name = _text(
                        dc_entry, "sAMAccountName"
                    )
                    report.dc_dns_host_name = _text(dc_entry, "dNSHostName")
                    try:
                        report.kerberos["dcSupportedEncryptionTypes"] = int(
                            str(_raw(dc_entry, "msDS-SupportedEncryptionTypes"))
                        )
                    except (TypeError, ValueError):
                        report.kerberos["dcSupportedEncryptionTypes"] = None
            return report
        except PreFlightError:
            raise
        except Exception as exc:
            raise PreFlightError(f"LDAP pre-flight sorgusu başarısız: {exc}") from exc
        finally:
            try:
                conn.unbind()
            except Exception:
                pass
