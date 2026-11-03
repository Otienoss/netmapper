import uuid
from pathlib import Path

from app.config import settings
from app.core.exceptions import ScannerError
from app.core.process_runner import ProcessRunner
from app.scanners.base import BaseScanner


class NmapScanner(BaseScanner):
    """
    Belirli bir host için port/servis taraması yapar.
    -sV: servis/versiyon tespiti, -oX: XML çıktısı (parse edilebilir)
    Varsayılan: auth gerektirmeyen SYN/connect taraması (-sT, non-root uyumlu).
    """

    name = "nmap"

    async def scan(
        self,
        target: str,
        ports: str | None = None,
        timeout: int | None = None,
    ) -> Path:
        ports = ports or settings.critical_ports
        timeout = timeout or settings.nmap_timeout_sec
        scan_id = uuid.uuid4().hex[:8]
        safe_target = target.replace("/", "_").replace(":", "_")
        out_path = Path(settings.raw_output_dir) / f"nmap_{safe_target}_{scan_id}.xml"
        out_path.parent.mkdir(parents=True, exist_ok=True)

        cmd = [
            settings.nmap_binary,
            "-sT",              # TCP connect scan — root gerektirmez
            "-sV",              # servis versiyon tespiti
            "-p", ports,
            "-T4",
            "--open",           # sadece açık portları raporla
            "-oX", str(out_path),
            target,
        ]
        result = await ProcessRunner.run(cmd, timeout=timeout)
        if result.returncode != 0:
            raise ScannerError(f"nmap failed for {target}: {result.stderr}")
        return out_path
