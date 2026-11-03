import asyncio
import logging
import os
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ProcessResult:
    returncode: int
    stdout: str
    stderr: str


class ProcessRunner:
    """Generic async subprocess wrapper. Scanner sınıfları bunun üzerine kurulur."""

    @staticmethod
    async def run_privileged(
        cmd: list[str], timeout: int = 30,
    ) -> ProcessResult:
        """Yalnızca salt-okunur `arp-scan` için sınırlı sudo çalıştırıcısı.

        `sudo -n` etkileşimsizdir; parola beklemez, yetki yoksa hızlı başarısız
        olur. Sudoers/setuid yapılandırması bu kodla DEĞİŞTİRİLMEZ. Genel amaçlı
        root wrapper değildir; özellikle interface/MAC yapılandırması değiştiren
        komutlar kabul edilmez.
        """
        if not cmd or cmd[0] != "arp-scan":
            raise ValueError(
                "run_privileged yalnızca salt-okunur 'arp-scan' komutunu "
                "destekler; interface/MAC yapılandırma komutları desteklenmez"
            )
        return await ProcessRunner.run(
            ["sudo", "-n", "--", *cmd], timeout=timeout
        )

    @staticmethod
    async def run(cmd: list[str], timeout: int = 300,
                  redact: tuple[str, ...] = (),
                  cwd: str | None = None,
                  env: dict[str, str] | None = None) -> ProcessResult:
        """redact: log/timeout mesajında '*' ile değiştirilecek gizli parçalar
        (ör. domain şifresi) — süreç yine gerçek argümanı alır.
        cwd: sürecin çalışma dizini (ör. bloodhound çıktıları hedef klasöre).
        env: ortam değişkeni ekler (ör. KRB5CCNAME); mevcut env üzerine MİRAS alır,
        mevcut değişkenleri ezmez ama verilen önceliklidir (ör. KRB5CCNAME)."""
        def _mask(text: str) -> str:
            for secret in redact:
                if secret:
                    text = text.replace(secret, "***")
            return text

        display = _mask(" ".join(cmd))
        logger.info("Running command: %s", display)
        # env: os.environ (miras) + verilen; verilen KRB5CCNAME gibi alanlar ezilir
        full_env = None
        if env:
            full_env = {**os.environ, **env}
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            env=full_env,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise TimeoutError(
                f"Command timed out after {timeout}s: {display}"
            )

        return ProcessResult(
            returncode=proc.returncode,
            stdout=_mask(stdout.decode(errors="ignore")),
            stderr=_mask(stderr.decode(errors="ignore")),
        )
