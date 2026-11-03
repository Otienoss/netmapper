"""Kritik CVE tarayıcısı — üç AD zafiyeti için CHECK-ONLY (non-destructive) kontroller.

Hiçbir aşamada sövme/ubah yok: hiçbir şifre, yapılandırma veya AD nesnesi
değiştirilmez; yalnızca zafiyetin VARLIĞI test edilir.

1) CVE-2020-1472 (ZeroLogon)
   MS-NRPC Netlogon güvenli kanalı üzerinden sıfır-anahtarlı (boş oturum)
   NetrServerAuthenticate3 denemesi — Secura'nın resmi `zerologon_tester.py`
   yöntemi. Doğrulama KABUL EDİLSE bile NetrServerPasswordSet2 ASLA
   çağrılmaz; makine hesabı şifresi değiştirilmez.

2) CVE-2021-34527 (PrintNightmare)
   MS-RPRN (\\pipe\\spoolss) pipe'ına bind + salt okunur RpcEnumPrinters ve
   RpcOpenPrinter/RpcClosePrinter ile yetkisiz RPC erişim ön koşulu kontrol
   edilir. RpcAddPrinterDriverEx (sürücü ekleme) gibi DESTRUCTIVE çağrılar
   YAPILMAZ.

3) CVE-2021-42278 / CVE-2021-42287 (NoPac)
   Yalnızca kendi domain hesabımızla requestPAC=True/False iki AS-REQ
   gönderilerek KDC'nin PAC davranışı karşılaştırılır (salt okunur) ve
   LDAP ile ms-DS-MachineAccountQuota okunur. AD nesnesi OLUŞTURMA /
   AD / YENİDEN ADLANDIRMA YAPILMAZ — saldırı zinciri denenmez.

Çıktı formatı: [{"cve": str, "vulnerable": bool, "detail": str}, ...]
`vulnerable=True` yalnızca POZITIF kanıtta döner; erişilemeyen/başarısız
testler `vulnerable=False` + "Test edilemedi" detayıyla döner (bilgi
boşluğu detail metninde açıkça belirtilir).
"""

import time
import asyncio
from typing import Callable

from impacket.dcerpc.v5 import epm, nrpc, rprn, transport
from impacket.krb5 import constants
from impacket.krb5.kerberosv5 import getKerberosTGT
from impacket.krb5.types import Principal

from app.scanners.base import BaseScanner

# ----------------------------------------------------------------- sabitler
_ZERLOGON_MAX_ATTEMPTS = 2000   # Secura: 2000 deneme → %0.04 yalancı-negatif
_ZERLOGON_BUDGET_S = 60.0       # yavaş WAN'larda deneme sayısını sınırlar
_ZERLOGON_FLAGS = 0x212fffff    # Secura tester'ındaki bayrak seti (AES, sign/seal kapalı)
_ZERO_8 = b"\x00" * 8

_STATUS_ACCESS_DENIED = 0xC0000022
_STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034
_STATUS_OBJECT_PATH_NOT_FOUND = 0xC000003A
_STATUS_PIPE_NOT_AVAILABLE = 0xC000000E
_PIPE_MISSING = (
    _STATUS_OBJECT_NAME_NOT_FOUND,
    _STATUS_OBJECT_PATH_NOT_FOUND,
    _STATUS_PIPE_NOT_AVAILABLE,
)

CVE_ZEROLOGON = "CVE-2020-1472"
CVE_PRINTNIGHTMARE = "CVE-2021-34527"
CVE_NOPAC = "CVE-2021-42278/42287"


def _err_code(ex: BaseException) -> int | None:
    """impacket/SMB hatalarından NT durum kodunu çıkarır (yoksa None)."""
    for name in ("get_packet_error_status", "get_error_code"):
        fn = getattr(ex, name, None)
        if callable(fn):
            try:
                code = fn()
                if code is not None:
                    return int(code)
            except Exception:
                continue
    return None


def _redact(text: str, secret: str | None) -> str:
    """Sızıntı güvenliği: şifre hiçbir detay metninde görünmez."""
    if secret and secret in text:
        return text.replace(secret, "***")
    return text


class CveScanner(BaseScanner):
    """Kritik AD CVE kontrolleri (sömürü yok, yalnızca check)."""

    name = "cve"

    async def scan(
        self,
        domain: str,
        dc_ip: str,
        username: str,
        password: str,
        dc_hostname: str | None = None,
    ) -> list[dict]:
        """Üç kontrolü paralel çalıştırır; asla exception fırlatmaz.

        Dönen liste istenen formattadır:
        [{"cve": ..., "vulnerable": bool, "detail": str}, ...]
        """
        checks: list[tuple[str, Callable[..., dict]]] = [
            (CVE_ZEROLOGON, self._zerologon_check),
            (CVE_PRINTNIGHTMARE, self._printnightmare_check),
            (CVE_NOPAC, self._nopac_check),
        ]
        outcomes = await asyncio.gather(
            *(
                asyncio.to_thread(fn, domain, dc_ip, username, password, dc_hostname)
                for _, fn in checks
            ),
            return_exceptions=True,
        )
        results: list[dict] = []
        for (cve, _), out in zip(checks, outcomes):
            if isinstance(out, BaseException):
                results.append({
                    "cve": cve,
                    "vulnerable": False,
                    "detail": f"Test edilemedi: {type(out).__name__}: {out}",
                })
            else:
                out["detail"] = _redact(str(out.get("detail", "")), password)
                results.append(out)
        return results

    # -------------------------------------------------------- ortak yardımcılar
    @staticmethod
    def _base_dn(domain: str) -> str:
        return ",".join(f"DC={p}" for p in domain.split(".") if p)

    @staticmethod
    def _ldap_connect(domain: str, dc_ip: str, username: str, password: str):
        import ldap3

        server = ldap3.Server(dc_ip, get_info=ldap3.NONE, connect_timeout=8)
        conn = ldap3.Connection(
            server,
            user=f"{domain}\\{username}",
            password=password,
            authentication=ldap3.NTLM,
            auto_bind=True,
            receive_timeout=10,
        )
        return conn

    @classmethod
    def _dc_netbios_name(
        cls, domain: str, dc_ip: str, username: str, password: str,
        dc_hostname: str | None,
    ) -> str | None:
        """DC'nin NetBIOS (makine) adını çözer: dc_hostname → LDAP DC sorgusu."""
        if dc_hostname:
            return dc_hostname.split(".")[0].rstrip("$")
        try:
            conn = cls._ldap_connect(domain, dc_ip, username, password)
            try:
                # SERVER_TRUST_ACCOUNT (0x2000): DC bilgisayar nesneleri
                conn.search(
                    cls._base_dn(domain),
                    "(&(objectCategory=computer)"
                    "(userAccountControl:1.2.840.113556.1.4.803:=8192))",
                    attributes=["sAMAccountName"],
                    size_limit=4,
                )
                names = [str(e.sAMAccountName).rstrip("$") for e in conn.entries]
            finally:
                conn.unbind()
            return names[0] if names else None
        except Exception:
            return None

    @classmethod
    def _machine_account_quota(cls, domain: str, dc_ip: str,
                               username: str, password: str) -> int | None:
        """LDAP salt-okunur: domain kökündeki ms-DS-MachineAccountQuota."""
        try:
            conn = cls._ldap_connect(domain, dc_ip, username, password)
            try:
                import ldap3

                ok = conn.search(
                    cls._base_dn(domain), "(objectClass=*)",
                    search_scope=ldap3.BASE,
                    attributes=["ms-DS-MachineAccountQuota"],
                )
                if not ok or not conn.entries:
                    return None
                return int(str(conn.entries[0]["ms-DS-MachineAccountQuota"]))
            finally:
                conn.unbind()
        except Exception:
            return None

    # ------------------------------------------------------- 1) ZeroLogon
    def _zerologon_check(
        self, domain: str, dc_ip: str, username: str, password: str,
        dc_hostname: str | None,
    ) -> dict:
        """CVE-2020-1472 — sıfır-anahtarlı Netlogon doğrulama denemesi.

        Yalnızca NetrServerReqChallenge + NetrServerAuthenticate3 çağrılır;
        oturum kabul edilse bile NetrServerPasswordSet2 YOK → şifre değişmez.
        """
        netbios = self._dc_netbios_name(domain, dc_ip, username, password, dc_hostname)
        if not netbios:
            return {
                "cve": CVE_ZEROLOGON,
                "vulnerable": False,
                "detail": "Test edilemedi: DC NetBIOS adı çözümlenemedi — "
                          "'dc_hostname' alanını doldurun.",
            }
        handle = "\\\\" + netbios

        try:
            binding = epm.hept_map(dc_ip, nrpc.MSRPC_UUID_NRPC, protocol="ncacn_ip_tcp")
        except Exception as ex:
            return {
                "cve": CVE_ZEROLOGON,
                "vulnerable": False,
                "detail": f"Test edilemedi: Netlogon RPC sonlandırıcısına "
                          f"(port 135) ulaşılamadı — {ex}",
            }

        attempts = 0
        started = time.monotonic()
        while (attempts < _ZERLOGON_MAX_ATTEMPTS
               and (time.monotonic() - started) < _ZERLOGON_BUDGET_S):
            attempts += 1
            rpc = None
            try:
                rpc = transport.DCERPCTransportFactory(binding).get_dce_rpc()
                rpc.connect()
                rpc.bind(nrpc.MSRPC_UUID_NRPC)
                # Boş oturum: sıfır istemci meydan okuması + sıfır credential
                nrpc.hNetrServerReqChallenge(
                    rpc, handle + "\x00", netbios + "\x00", _ZERO_8
                )
                resp = nrpc.hNetrServerAuthenticate3(
                    rpc, handle + "\x00", netbios + "$\x00",
                    nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
                    netbios + "\x00", _ZERO_8, _ZERLOGON_FLAGS,
                )
                if resp["ErrorCode"] == 0:
                    return {
                        "cve": CVE_ZEROLOGON,
                        "vulnerable": True,
                        "detail": (
                            f"Netlogon güvenli kanalı sıfır-anahtarlı (boş oturum) "
                            f"doğrulamayı KABUL ETTİ ({attempts} deneme). Yalnızca "
                            f"doğrulama testi yapıldı: NetrServerPasswordSet2 asla "
                            f"çağrılmadı, makine hesabı şifresi DEĞİŞTİRİLMEDİ."
                        ),
                    }
                # ErrorCode != 0 (istisna yükseltilmedi) → bu deneme de reddedildi
            except nrpc.DCERPCSessionError as ex:
                if ex.get_error_code() != _STATUS_ACCESS_DENIED:
                    return {
                        "cve": CVE_ZEROLOGON,
                        "vulnerable": False,
                        "detail": f"Test edilemedi: beklenmeyen Netlogon durum kodu "
                                  f"0x{ex.get_error_code():08x} ({attempts}. deneme).",
                    }
                # STATUS_ACCESS_DENIED → yamalı DC her denemede reddeder; yeniden dene
            except Exception as ex:
                return {
                    "cve": CVE_ZEROLOGON,
                    "vulnerable": False,
                    "detail": f"Test edilemedi: Netlogon RPC bağlantısı kurulamadı — {ex}",
                }
            finally:
                if rpc is not None:
                    try:
                        rpc.disconnect()
                    except Exception:
                        pass

        p_miss = ((255.0 / 256.0) ** attempts) * 100 if attempts else 100.0
        return {
            "cve": CVE_ZEROLOGON,
            "vulnerable": False,
            "detail": (
                f"STATUS_ACCESS_DENIED: sıfır-anahtarlı oturum {attempts} denemede "
                f"reddedildi — yamalı görünüyor (kalan yalancı-negatif olasılığı "
                f"≈ %{p_miss:.1f})."
            ),
        }

    # ------------------------------------------------- 2) PrintNightmare
    def _printnightmare_check(
        self, domain: str, dc_ip: str, username: str, password: str,
        dc_hostname: str | None,
    ) -> dict:
        """CVE-2021-34527 — Print Spooler varlığı + yetkisiz RPC erişimi.

        Yalnızca bind / EnumPrinters / OpenPrinter+ClosePrinter çağrılır;
        sürücü ekleme (RpcAddPrinterDriverEx) YAPILMAZ.
        """
        try:
            tp = transport.DCERPCTransportFactory(rf"ncacn_np:{dc_ip}[\pipe\spoolss]")
            tp.set_credentials(username, password, domain, "", "")
            dce = tp.get_dce_rpc()
            dce.connect()
            dce.bind(rprn.MSRPC_UUID_RPRN)
        except Exception as ex:
            code = _err_code(ex)
            if code in _PIPE_MISSING:
                return {
                    "cve": CVE_PRINTNIGHTMARE,
                    "vulnerable": False,
                    "detail": "Print Spooler (spoolss) pipe'ı bulunamadı — Print "
                              "Spooler hizmeti kapalı/durdurulmuş; PrintNightmare "
                              "yüzeyi kapalı.",
                }
            if code == _STATUS_ACCESS_DENIED:
                return {
                    "cve": CVE_PRINTNIGHTMARE,
                    "vulnerable": False,
                    "detail": "Test edilemedi: spoolss pipe'ına erişim reddedildi "
                              "(STATUS_ACCESS_DENIED).",
                }
            return {
                "cve": CVE_PRINTNIGHTMARE,
                "vulnerable": False,
                "detail": f"Test edilemedi: spoolss RPC'ye ulaşılamadı — {ex}",
            }

        netbios = self._dc_netbios_name(domain, dc_ip, username, password, dc_hostname)
        candidates = ([f"\\\\{netbios}\\*"] if netbios else []) + [f"\\\\{dc_ip}\\*"]

        open_ok = False
        enum_ok = False
        open_err = "bilinmeyen"
        try:
            # 1) Yetkisiz kullanıcıyla zararsız listeleme (salt okunur)
            try:
                rprn.hRpcEnumPrinters(dce, 0, level=1)
                enum_ok = True
            except Exception:
                pass
            # 2) Exploit'in ilk adımı olan handle açma/kapatma — hiçbir sürücü
            #    veya nesne eklenmez, yalnızca erişim ön koşulu sınaması.
            for printer_name in candidates:
                try:
                    resp = rprn.hRpcOpenPrinter(dce, printer_name)
                    try:
                        rprn.hRpcClosePrinter(dce, resp["pHandle"])
                    except Exception:
                        pass
                    open_ok = True
                    break
                except rprn.DCERPCSessionError as ex:
                    open_err = f"0x{ex.get_error_code():08x}"
                except Exception as ex:
                    open_err = str(ex)[:160]
        finally:
            try:
                dce.disconnect()
            except Exception:
                pass

        if open_ok:
            return {
                "cve": CVE_PRINTNIGHTMARE,
                "vulnerable": True,
                "detail": (
                    f"Print Spooler (MS-RPRN) açık; {domain}\\{username} hesabıyla "
                    f"RpcOpenPrinter başarılı — yetkisiz RPC erişim ön koşulu "
                    f"doğrulandı (RpcEnumPrinters={'evet' if enum_ok else 'hayır'}). "
                    f"DESTRUCTIVE çağrı YAPILMADI (sürücü ekleme denenmedi); "
                    f"34527'nin yama durumu yalnızca sürücü kurulumuyla ayrışır."
                ),
            }
        return {
            "cve": CVE_PRINTNIGHTMARE,
            "vulnerable": False,
            "detail": (
                f"Print Spooler pipe'ı açık ancak yetkisiz RpcOpenPrinter "
                f"REDDEDİLDİ ({open_err}) — PrintNightmare ön koşulu sağlanmadı "
                f"(kısıtlı/yamalı yapılandırma)."
            ),
        }

    # --------------------------------------------------------- 3) NoPac
    def _nopac_check(
        self, domain: str, dc_ip: str, username: str, password: str,
        dc_hostname: str | None,
    ) -> dict:
        """CVE-2021-42278/42287 — KDC PAC davranışı + makine quota okuması.

        Salt okunur: yalnızca KENDİ hesabımız için iki AS-REQ (PAC'li/PAC'siz)
        ve LDAP okuması yapılır; AD nesnesi oluşturulmaz/adyeniden adlandırılmaz.
        """
        del dc_hostname   # Kerberos doğrudan dc_ip üzerinden (kdcHost) gider
        try:
            user = Principal(
                username, type=constants.PrincipalNameType.NT_PRINCIPAL.value
            )
            with_pac = getKerberosTGT(
                user, password, domain, b"", b"", kdcHost=dc_ip, requestPAC=True,
            )
            without_pac = getKerberosTGT(
                user, password, domain, b"", b"", kdcHost=dc_ip, requestPAC=False,
            )
        except Exception as ex:
            return {
                "cve": CVE_NOPAC,
                "vulnerable": False,
                "detail": f"Test edilemedi: Kerberos TGT alınamadı "
                          f"(KDC'ye ulaşılamadı/geçersiz kimlik) — {ex}",
            }

        n_pac, n_nopac = len(with_pac[0]), len(without_pac[0])
        quota = self._machine_account_quota(domain, dc_ip, username, password)
        quota_txt = (
            f"ms-DS-MachineAccountQuota={quota}"
            if quota is not None else "ms-DS-MachineAccountQuota okunamadı"
        )

        if n_pac == n_nopac:
            return {
                "cve": CVE_NOPAC,
                "vulnerable": False,
                "detail": (
                    f"KDC her koşulda PAC ekliyor: PAC'li/PAC'siz TGT boyutları eşit "
                    f"({n_pac} bayt) — PAC doğrulanıyor, yamalı görünüyor. {quota_txt}."
                ),
            }
        return {
            "cve": CVE_NOPAC,
            "vulnerable": True,
            "detail": (
                f"KDC PAC-REQUEST anomalisi: PAC'li TGT {n_pac} bayt, PAC'siz TGT "
                f"{n_nopac} bayt — PAC'siz TGT'ye izin veriliyor; sAMAccountName/PAC "
                f"yamaları uygulanmamış olabilir. {quota_txt}. Saldırı zinciri "
                f"DENENMEDİ (AD nesnesi oluşturulmadı/adyeniden adlandırılmadı)."
            ),
        }
