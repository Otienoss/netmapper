"""Salt-okunur LDAP Active Directory envanteri.

Bu modül yalnızca Domain Controller bilgisayar nesnelerini okur. AD'de
değişiklik yapmaz; sonuçlar keşif bulgusu olarak raporlanır ve herhangi bir
sömürü zincirine girdi sağlamaz.
"""

import asyncio

from app.core.exceptions import ScannerError

# Domain Controllers grubunun birincil grup RID'i 516'dır.
_DC_FILTER = "(&(objectCategory=computer)(primaryGroupID=516))"
_DC_ATTRIBUTES = [
    "sAMAccountName",
    "dNSHostName",
    "distinguishedName",
    "operatingSystem",
]


def _base_dn(domain: str) -> str:
    return ",".join(f"DC={part}" for part in domain.split(".") if part)


def _attribute(entry, name: str) -> str | None:
    """ldap3 entry alanını güvenli biçimde metne çevirir."""
    try:
        value = getattr(entry, name)
        if value is None:
            return None
        text = str(value).strip()
    except (AttributeError, TypeError, ValueError):
        return None
    return text or None


async def query_domain_controllers(
    domain: str,
    target: str,
    username: str,
    password: str,
    timeout: int = 10,
) -> list[dict]:
    """DC'lerin sAMAccountName ve dNSHostName bilgilerini LDAP'tan okur.

    Dönen her kayıt bir DC'dir. Bağlantı/sorgu hatasında ScannerError fırlatır;
    parola hiçbir sonuç kaydına veya log mesajına eklenmez.
    """

    def _work() -> list[dict]:
        import ldap3

        server = ldap3.Server(
            target, get_info=ldap3.NONE, connect_timeout=timeout
        )
        try:
            conn = ldap3.Connection(
                server,
                user=f"{domain}\\{username}",
                password=password,
                authentication=ldap3.NTLM,
                auto_bind=True,
                receive_timeout=timeout,
            )
        except Exception as exc:
            raise ScannerError(
                f"LDAP DC envanteri bağlantısı kurulamadı ({target}:389): {exc}"
            ) from exc

        try:
            try:
                ok = conn.search(
                    _base_dn(domain),
                    _DC_FILTER,
                    attributes=_DC_ATTRIBUTES,
                )
            except Exception as exc:
                raise ScannerError(
                    f"LDAP DC envanteri sorgusu çalıştırılamadı: {exc}"
                ) from exc
            if not ok:
                raise ScannerError(
                    f"LDAP DC envanteri sorgusu reddedildi: {conn.result}"
                )

            records: list[dict] = []
            for entry in conn.entries:
                sam = _attribute(entry, "sAMAccountName")
                if not sam:
                    continue
                records.append({
                    "sAMAccountName": sam,
                    "dNSHostName": _attribute(entry, "dNSHostName"),
                    "distinguishedName": str(entry.entry_dn),
                    "operatingSystem": _attribute(entry, "operatingSystem"),
                    "source": "ldap",
                    "read_only": True,
                })
            return sorted(
                records, key=lambda item: item["sAMAccountName"].lower()
            )
        finally:
            try:
                conn.unbind()
            except Exception:
                pass

    return await asyncio.to_thread(_work)
