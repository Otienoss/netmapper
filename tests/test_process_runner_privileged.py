"""Sınırlı privileged ProcessRunner testleri — gerçek sudo/ağ çağrısı yok."""

import asyncio

import pytest

from app.core.process_runner import ProcessResult, ProcessRunner
from app.scanners.nac_scanner import NacScanner


def test_privileged_arp_scan_uses_noninteractive_sudo(monkeypatch):
    calls = []

    async def fake_run(cmd, timeout=300, **kwargs):
        calls.append((cmd, timeout))
        return ProcessResult(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(ProcessRunner, "run", fake_run)
    asyncio.run(ProcessRunner.run_privileged(
        ["arp-scan", "--interface", "eth0", "192.168.1.0/24", "--quiet"],
        timeout=60,
    ))

    assert calls == [(
        ["sudo", "-n", "--", "arp-scan", "--interface", "eth0",
         "192.168.1.0/24", "--quiet"],
        60,
    )]


@pytest.mark.parametrize("cmd", [
    [],
    ["ip", "link", "set", "eth0", "down"],
    ["nmap", "-sn", "192.168.1.0/24"],
    ["/usr/sbin/arp-scan", "--help"],  # PATH yerine keyfi binary kabul edilmez
])
def test_privileged_wrapper_rejects_other_commands(cmd):
    with pytest.raises(ValueError, match="arp-scan"):
        asyncio.run(ProcessRunner.run_privileged(cmd))


def test_nac_scanner_uses_limited_privileged_wrapper(monkeypatch):
    calls = []

    async def fake_privileged(cmd, timeout=30):
        calls.append((cmd, timeout))
        return ProcessResult(
            returncode=0,
            stdout="192.168.1.50\t00:11:22:33:44:55\tBrother Industries\n",
            stderr="",
        )

    monkeypatch.setattr(ProcessRunner, "run_privileged", fake_privileged)
    devices = asyncio.run(NacScanner().collect_arp_table(
        "eth0", "192.168.1.0/24",
    ))

    assert calls[0][0][:2] == ["arp-scan", "--interface"]
    assert calls[0][1] == 60
    assert len(devices) == 1
    assert devices[0].mac == "00:11:22:33:44:55"
    assert devices[0].device_type == "printer"
