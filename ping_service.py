"""Ping configured IPs; results are shown in UI and included in log snapshot on Save (no auto-log)."""
import asyncio
import ipaddress
import re
import sys
import threading
from datetime import datetime, timezone
from typing import Optional

import config as app_config

_last_status: dict = {}  # ip -> {"success": bool, "timestamp": str}
_status_lock = threading.Lock()
_status_generation = 0
_task_lock = threading.Lock()
_active_ping_task: Optional[asyncio.Task] = None


def _valid_ip(ip: str) -> bool:
    """Accept an IPv4 address or RFC-style DNS hostname, never command options."""
    if not ip:
        return False
    value = ip.strip()
    if not value or len(value) > 253:
        return False
    try:
        return ipaddress.ip_address(value).version == 4
    except ValueError:
        if re.fullmatch(r"[0-9.]+", value):
            return False
    labels = value.rstrip(".").split(".")
    hostname_label = re.compile(
        r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
    )
    if labels and all(hostname_label.fullmatch(label) for label in labels):
        return True
    return False


def _ping_args(ip: str, interface: Optional[str]) -> list:
    """Build ping argv: Linux (-I), macOS (-b), Windows (-n -w); interface only on Unix."""
    if sys.platform == "win32":
        args = ["ping", "-n", "1", "-w", "2000", ip]
        return args
    wait = "2000" if sys.platform == "darwin" else "2"
    args = ["ping", "-c", "1", "-W", wait]
    if interface and interface.strip():
        if sys.platform.startswith("linux"):
            args.extend(["-I", interface.strip()])
        elif sys.platform == "darwin":
            args.extend(["-b", interface.strip()])
    args.append(ip)
    return args


async def _ping_one(ip: str, interface: Optional[str] = None) -> bool:
    args = _ping_args(ip, interface)
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(proc.wait(), timeout=5)
        return proc.returncode == 0
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return False
    except (FileNotFoundError, OSError):
        # Minimal Linux images may not have iputils-ping installed.
        return False


async def _run_ping_once(generation: int):
    """Run one bounded ping batch and publish it if its state is still current."""
    targets = app_config.get_ping_targets()
    interface = app_config.get_interface()
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    valid_targets = [ip for ip in targets if ip and _valid_ip(ip)]
    # Keep the request responsive when several hosts are unreachable while also
    # avoiding an unbounded subprocess burst on a small Raspberry Pi.
    semaphore = asyncio.Semaphore(8)

    async def check(ip):
        async with semaphore:
            return ip, await _ping_one(ip, interface)

    checked = await asyncio.gather(*(check(ip) for ip in valid_targets))
    results = {
        ip: {"success": ok, "timestamp": ts}
        for ip, ok in checked
    }
    global _last_status
    with _status_lock:
        if generation == _status_generation:
            _last_status = results
    return results


async def run_ping():
    """Coalesce concurrent callers onto one bounded ping batch."""
    global _active_ping_task
    with _status_lock:
        generation = _status_generation
    with _task_lock:
        task = _active_ping_task
        if task is None or task.done():
            task = asyncio.create_task(_run_ping_once(generation))
            _active_ping_task = task
    try:
        return await asyncio.shield(task)
    finally:
        if task.done():
            with _task_lock:
                if _active_ping_task is task:
                    _active_ping_task = None


def get_last_status() -> dict:
    with _status_lock:
        return {
            target: status.copy()
            for target, status in _last_status.items()
        }


def clear_status():
    """Clear ping results (e.g. when interface goes down)."""
    global _last_status, _status_generation
    with _status_lock:
        _status_generation += 1
        _last_status = {}
