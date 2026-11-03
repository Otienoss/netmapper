"""Keşif + tarama akışını yöneten orkestratör.

Akış (her aşamada job_manager üzerinden WebSocket'e push edilir):
  DISCOVERING → SCANNING → NORMALIZING  → (done, job_manager._run yapar)

Profiller:
  quick  = sadece keşif (netdiscover), nmap yok
  full   = keşif + nmap -sV (settings.critical_ports)
  custom = keşif + nmap -sV (kullanıcının port listesi)
"""

import asyncio
import ipaddress
import logging

from app.config import settings
from app.normalization.netdiscover_parser import extract_ips
from app.normalization.nikto_parser import parse_nikto_xml
from app.normalization.nmap_parser import parse_nmap_xml
from app.normalization.schema import HostResult, WebFinding
from app.scanners.netdiscover_scanner import NetdiscoverScanner
from app.scanners.nikto_scanner import NiktoScanner
from app.scanners.nmap_scanner import NmapScanner
from app.services.job_manager import JobStatus, job_manager

logger = logging.getLogger(__name__)

PROFILE_TR = {"quick": "Hızlı Keşif", "full": "Tam Tarama", "custom": "Özel"}


class ScanOrchestrator:
    def __init__(self):
        self.netdiscover = NetdiscoverScanner()
        self.nmap = NmapScanner()
        self.nikto = NiktoScanner()

    async def run_full_scan(
        self,
        job_id: str,
        subnet: str,
        profile: str = "full",
        ports: str | None = None,
    ) -> list[HostResult]:
        await job_manager.update(job_id, status=JobStatus.DISCOVERING)
        await job_manager.log(
            job_id, f"Host keşfi başladı: {subnet} · profil {PROFILE_TR.get(profile, profile)}"
        )

        net = ipaddress.ip_network(subnet, strict=False)
        if net.num_addresses == 1:
            # Tek host hedefi: netdiscover tek hedefte sonuç döndürmez — atla
            ips = [str(net.network_address)]
            await job_manager.log(job_id, f"Tek hedef: {ips[0]} — keşif atlandı.")
        else:
            ips = await self._discover_live_hosts(subnet)

        if not ips:
            await job_manager.log(job_id, "Canlı host bulunamadı.")
            await job_manager.update(
                job_id, status=JobStatus.NORMALIZING,
                progress={"hosts_total": 0, "hosts_scanned": 0},
            )
            return []

        await job_manager.log(job_id, f"{len(ips)} canlı host bulundu.")

        if profile == "quick":
            # Hızlı Keşif: nmap yok, sadece canlı host listesi normalize edilir
            await job_manager.update(
                job_id, status=JobStatus.NORMALIZING,
                progress={"hosts_total": len(ips), "hosts_scanned": len(ips)},
            )
            await job_manager.log(job_id, "Hızlı Keşif: nmap atlandı.")
            results = [HostResult(ip=ip, source_tool="netdiscover") for ip in ips]
        else:
            await job_manager.update(
                job_id, status=JobStatus.SCANNING,
                progress={"hosts_total": len(ips), "hosts_scanned": 0},
            )
            results = await self._scan_hosts(job_id, ips, ports, profile=profile)
            await job_manager.update(job_id, status=JobStatus.NORMALIZING)

        await job_manager.log(job_id, f"{len(results)} host normalize edildi.")
        # DONE durumunu job_manager._run atar: önce DB'ye yazılır, sonra biter
        return results

    async def _discover_live_hosts(self, subnet: str) -> list[str]:
        """netdiscover ile canlı host bulur; netdiscover çalışamazsa
        (root'suz: 'You must be root to run this') nmap -sn'e düşer."""
        try:
            raw = await self.netdiscover.scan(subnet)
            ips = extract_ips(raw)
            if ips:
                return ips
            logger.info("netdiscover sonuç vermedi — nmap -sn'e düşülüyor")
        except Exception as e:
            logger.info("netdiscover çalışamadı (%s) — nmap -sn'e düşülüyor", e)
        return await self._nmap_ping_sweep(subnet)

    async def _nmap_ping_sweep(self, subnet: str) -> list[str]:
        """Root gerektirmeyen host keşfi: nmap -sn (ICMP/TCP ping sweep)."""
        from app.core.process_runner import ProcessRunner

        result = await ProcessRunner.run(
            [settings.nmap_binary, "-sn", "-n", subnet, "-oG", "-"],
            timeout=settings.nmap_timeout_sec,
        )
        if result.returncode not in (0, 1):
            logger.warning("nmap -sn başarısız: %s", result.stderr)
            return []
        ips: list[str] = []
        for line in result.stdout.splitlines():
            if line.startswith("Host: ") and "Status: Up" in line:
                ip = line.split()[1].strip("()")
                if ip and ip not in ips:
                    ips.append(ip)
        return ips

    async def _scan_hosts(
        self,
        job_id: str,
        ips: list[str],
        ports: str | None = None,
        profile: str = "full",
        max_concurrent: int | None = None,
    ) -> list[HostResult]:
        max_concurrent = max_concurrent or settings.max_concurrent_scans
        sem = asyncio.Semaphore(max_concurrent)
        lock = asyncio.Lock()
        scanned = 0

        web_port_set = {
            int(p) for p in settings.nikto_ports.replace(" ", "").split(",")
            if p.isdigit()
        }

        def _is_web(svc) -> bool:
            name = (svc.service_name or "").lower()
            return svc.port in web_port_set or "http" in name or "ssl" in name

        async def scan_one(ip: str) -> HostResult | None:
            nonlocal scanned
            async with sem:
                nikto_task: asyncio.Task | None = None
                try:
                    await job_manager.log(job_id, f"nmap start → {ip}")
                    # --- Nikto, nmap ile AYNI anda başlatılır (kör web seti) ---
                    if profile == "full":
                        nikto_task = asyncio.ensure_future(
                            self._nikto_safe(job_id, ip, None)
                        )

                    xml_path = await self.nmap.scan(ip, ports=ports)
                    result = parse_nmap_xml(xml_path)
                    open_ports = len(result.services) if result else 0
                    await job_manager.log(
                        job_id, f"{ip} tamamlandı → {open_ports} açık port"
                    )

                    # --- Nikto bulgularını birleştir ---
                    web_findings: list[WebFinding] = (
                        await nikto_task if nikto_task else []
                    )
                    if result is not None:
                        if profile == "custom":
                            # kör tur yok: nmap'in bulduğu web portlarında çalış
                            web_ports = sorted(
                                {s.port for s in result.services if _is_web(s)}
                            )
                            if web_ports:
                                web_findings = await self._nikto_safe(
                                    job_id, ip, ",".join(map(str, web_ports))
                                )
                        elif profile == "full":
                            # kör turda atlanan ek web portları varsa tamamla
                            extra = sorted(
                                {s.port for s in result.services if _is_web(s)}
                                - web_port_set
                            )
                            if extra:
                                web_findings = web_findings + await self._nikto_safe(
                                    job_id, ip, ",".join(map(str, extra))
                                )
                        result.web_findings = web_findings
                        if web_findings:
                            await job_manager.log(
                                job_id,
                                f"{ip} nikto: {len(web_findings)} web bulgusu",
                            )
                    return result
                except Exception as e:
                    await job_manager.log(job_id, f"{ip} taramasında hata: {e}")
                    return None
                finally:
                    # hata yolunda da paralel nikto görevini bekle (asla raise etmez)
                    if nikto_task is not None:
                        await nikto_task
                    async with lock:
                        scanned += 1
                        await job_manager.update(
                            job_id,
                            progress={
                                "hosts_total": len(ips),
                                "hosts_scanned": scanned,
                            },
                        )

        results = await asyncio.gather(*(scan_one(ip) for ip in ips))
        return [r for r in results if r is not None]

    async def _nikto_safe(
        self, job_id: str, ip: str, ports: str | None
    ) -> list[WebFinding]:
        """Nikto'yu çalıştırıp bulguları döner — asla exception fırlatmaz
        (nikto yok/kurulmadıysa iş akışı bozulmasın diye)."""
        try:
            label = f" (port {ports})" if ports else ""
            await job_manager.log(job_id, f"nikto start → {ip}{label}")
            xml_path = await self.nikto.scan(ip, ports=ports)
            findings = parse_nikto_xml(xml_path)
            await job_manager.log(
                job_id, f"nikto tamam → {ip}: {len(findings)} bulgu"
            )
            return findings
        except FileNotFoundError:
            await job_manager.log(
                job_id,
                "nikto kurulu değil — atlandı (kurulum: sudo apt install nikto)",
            )
            return []
        except Exception as e:
            await job_manager.log(job_id, f"nikto hatası ({ip}): {e}")
            return []
