import uuid
from pathlib import Path

from app.config import settings
from app.core.exceptions import ScannerError
from app.core.process_runner import ProcessRunner
from app.scanners.base import BaseScanner


class NiktoScanner(BaseScanner):
    """
    Web sunucusu güvenlik taraması (Nikto). Nmap ile eşzamanlı çalışır:
    -h hedef IP, -p web portları (kör turda settings.nikto_ports),
    -nointeractive: script-dostu, -maxtime: host başına süre sınırı,
    -Format xml: parse edilebilir çıktı (data/raw/nikto_*.xml).
    """

    name = "nikto"

    async def scan(
        self,
        target: str,
        ports: str | None = None,
        timeout: int | None = None,
        maxtime: int | None = None,
    ) -> Path:
        ports = ports or settings.nikto_ports
        timeout = timeout or settings.nikto_timeout_sec
        maxtime = maxtime or settings.nikto_maxtime_sec

        scan_id = uuid.uuid4().hex[:8]
        safe_target = target.replace("/", "_").replace(":", "_")
        out_path = Path(settings.raw_output_dir) / f"nikto_{safe_target}_{scan_id}.xml"
        out_path.parent.mkdir(parents=True, exist_ok=True)

        cmd = [
            settings.nikto_binary,
            "-h", target,
            "-p", ports,
            "-nointeractive",
            "-maxtime", str(maxtime),
            "-o", str(out_path),
            "-Format", "xml",
        ]
        result = await ProcessRunner.run(cmd, timeout=timeout)
        # nikto bazı durumlarda "başarılı" dönüp dosya yazmayabilir
        if not out_path.exists():
            raise ScannerError(
                f"nikto çıktı üretmedi ({target}): "
                f"{result.stderr.strip() or result.stdout.strip() or f'exit {result.returncode}'}"
            )
        return out_path
