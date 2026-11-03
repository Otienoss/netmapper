"""bloodhound-python CLI wrapper — AD ACL/topoloji toplama.

bloodhound-python (pip install bloodhound) LDAP+SMB üzerinden AD nesnelerini
(users, groups, computers + ACL) toplayıp zip üretir. AD modülünün mevcut
domain kimlik bilgilerini kullanır (kerberoast ile aynı kimlikler).
"""

import shutil
import uuid
from pathlib import Path

from app.config import settings
from app.core.exceptions import ScannerError
from app.core.process_runner import ProcessRunner
from app.scanners.base import BaseScanner


class BloodhoundScanner(BaseScanner):
    name = "bloodhound"

    async def scan(
        self,
        target: str = "",           # BaseScanner uyumu — dc_ip kullanılır
        *,
        domain: str,
        username: str,
        password: str,
        dc_ip: str,
        dc_hostname: str | None = None,   # örn: "winterfell.north.sevenkingdoms.local"
        timeout: int | None = None,
        collection: str = "All",
    ) -> Path:
        binary = shutil.which("bloodhound-python") or str(
            Path.home() / ".local/bin/bloodhound-python"
        )
        if not shutil.which("bloodhound-python") and not Path(binary).is_file():
            raise ScannerError(
                "bloodhound-python bulunamadı "
                "(kurulum: pip install bloodhound)"
            )

        # -dc FQDN ister (GC/kerberos hostname'e bağlı). Verilmezse yaygın
        # convention'dan türetilir: dc.<domain> — doğru ad farklıysa
        # dc_hostname parametresini geçin (UI'daki "DC Hostname" alanı).
        dc_fqdn = dc_hostname or f"dc.{domain}"

        out_dir = Path(settings.raw_output_dir) / f"bh_{uuid.uuid4().hex[:8]}"
        out_dir.mkdir(parents=True, exist_ok=True)

        cmd = [
            binary,
            "-u", username,
            "-p", password,
            "-d", domain,
            "-ns", dc_ip,          # DNS server IP
            "-dc", dc_fqdn,        # FQDN — hostname, IP değil
            "-gc", dc_fqdn,        # Global Catalog: aynı DC (FQDN)
            "-c", "All",
            "--zip",
        ]
        # cwd=out_dir: zip çıktısı her koşumda bizim dizinimize düşer
        result = await ProcessRunner.run(
            cmd,
            timeout=timeout or settings.ad_timeout_sec,
            redact=(password,),
            cwd=str(out_dir),
        )

        zips = sorted(out_dir.glob("*.zip"))
        if result.returncode != 0 or not zips:
            detail = (
                result.stderr.strip() or result.stdout.strip()
                or f"exit {result.returncode}"
            )
            raise ScannerError(f"bloodhound-python başarısız: {detail[:300]}")

        dest = out_dir / "collection.zip"
        if zips[0] != dest:
            zips[0].replace(dest)
        return dest
