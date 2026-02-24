"""Ping configured IPs; results are shown in UI and included in log snapshot on Save (no auto-log)."""
import asyncio
import re
import sys
from datetime import datetime
from typing import Optional

import config as app_config

_last_status: dict = {}  # ip -> {"success": bool, "timestamp": str}


def _valid_ip(ip: str) -> bool:
    if not ip or not ip.strip():
        return False
    # Simple IPv4
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip.strip()):
        return True
    # Allow hostnames
    return len(ip.strip()) < 256


def _ping_args(ip: str, interface: Optional[str]) -> list:
    """Build ping argv: Linux (-I), macOS (-b), Windows (-n -w); interface only on Unix."""
    if sys.platform == "win32":
        args = ["ping", "-n", "1", "-w", "2000", ip]
        return args
    args = ["ping", "-c", "1", "-W", "2"]
    if interface and interface.strip():
        if sys.platform.startswith("linux"):
            args.extend(["-I", interface.strip()])
        elif sys.platform == "darwin":
            args.extend(["-b", interface.strip()])
    args.append(ip)
    return args


async def _ping_one(ip: str, interface: Optional[str] = None) -> bool:
    args = _ping_args(ip, interface)
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    await proc.wait()
    return proc.returncode == 0


async def run_ping():
    """Ping all configured IPs via the selected interface and update last status."""
    targets = app_config.get_ping_targets()
    interface = app_config.get_interface()
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    results = {}
    for ip in targets:
        if ip and _valid_ip(ip):
            ok = await _ping_one(ip, interface)
            results[ip] = {"success": ok, "timestamp": ts}
    global _last_status
    _last_status = results
    return results


def get_last_status() -> dict:
    return _last_status.copy()


def clear_status():
    """Clear ping results (e.g. when interface goes down)."""
    global _last_status
    _last_status = {}
