"""List network interfaces and read link state from sysfs or OS commands.
Cross-platform: Linux, macOS, Windows."""
import os
import re
import subprocess
import sys
from pathlib import Path

SYS_NET = Path("/sys/class/net")


def _is_linux():
    return sys.platform.startswith("linux")


def _is_macos():
    return sys.platform == "darwin"


def _is_windows():
    return sys.platform == "win32"


def _prefix_to_netmask(prefix_len: int) -> str:
    """Convert CIDR prefix length to dotted decimal netmask (e.g. 24 -> 255.255.255.0)."""
    if not (0 <= prefix_len <= 32):
        return ""
    mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
    return ".".join(str((mask >> (24 - i * 8)) & 0xFF) for i in range(4))


def _hex_netmask_to_dotted(hex_str: str) -> str:
    """Convert macOS-style hex netmask (0xffffff00) to dotted decimal."""
    hex_str = hex_str.strip().lower().replace("0x", "")
    try:
        n = int(hex_str, 16) & 0xFFFFFFFF
        return ".".join(str((n >> (24 - i * 8)) & 0xFF) for i in range(4))
    except ValueError:
        return ""


def _network_address(ipv4: str, netmask: str) -> str:
    """Compute network address from IPv4 and dotted-decimal netmask (e.g. 192.168.1.0)."""
    if not ipv4 or not netmask:
        return ""
    try:
        ip_octets = [int(x) for x in ipv4.split(".") if x.isdigit()]
        nm_octets = [int(x) for x in netmask.split(".") if x.isdigit()]
        if len(ip_octets) != 4 or len(nm_octets) != 4:
            return ""
        return ".".join(str(ip_octets[i] & nm_octets[i]) for i in range(4))
    except (ValueError, IndexError):
        return ""


def _get_default_gateway() -> str:
    """Return default gateway IPv4 (empty if none). Linux and macOS."""
    if _is_linux():
        try:
            out = subprocess.run(
                ["ip", "-4", "route", "show", "default"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            if out.returncode == 0 and out.stdout.strip():
                m = re.search(r"default\s+via\s+(\d+\.\d+\.\d+\.\d+)", out.stdout)
                if m:
                    return m.group(1)
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass
    elif _is_macos():
        try:
            out = subprocess.run(
                ["route", "-n", "get", "default"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            if out.returncode == 0:
                m = re.search(r"gateway:\s*(\d+\.\d+\.\d+\.\d+)", out.stdout)
                if m:
                    return m.group(1)
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass
    elif _is_windows():
        try:
            out = subprocess.run(
                ["netsh", "interface", "ipv4", "show", "config"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if out.returncode == 0:
                m = re.search(r"Default Gateway[:\s]+(\d+\.\d+\.\d+\.\d+)", out.stdout, re.I)
                if m:
                    return m.group(1)
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass
    return ""


def _get_default_gateway_for_interface(interface: str) -> str:
    """Return default gateway IPv4 for the given interface (empty if none)."""
    if not interface or not interface.strip():
        return _get_default_gateway()
    iface = interface.strip()
    if _is_linux():
        try:
            out = subprocess.run(
                ["ip", "-4", "route", "show", "default", "dev", iface],
                capture_output=True,
                text=True,
                timeout=3,
            )
            if out.returncode == 0 and out.stdout.strip():
                m = re.search(r"default\s+via\s+(\d+\.\d+\.\d+\.\d+)", out.stdout)
                if m:
                    return m.group(1)
            out = subprocess.run(
                ["ip", "-4", "route", "show", "default"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            if out.returncode == 0 and out.stdout.strip():
                for line in out.stdout.strip().splitlines():
                    if re.search(r"\bdev\s+" + re.escape(iface) + r"\b", line):
                        m = re.search(r"via\s+(\d+\.\d+\.\d+\.\d+)", line)
                        if m:
                            return m.group(1)
                        break
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass
    elif _is_macos():
        try:
            out = subprocess.run(
                ["netstat", "-nr", "-f", "inet"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            if out.returncode == 0:
                for line in out.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] == "default":
                        gw = parts[1]
                        dev = parts[-1] if parts else ""
                        if dev == iface and re.match(r"^\d+\.\d+\.\d+\.\d+$", gw):
                            return gw
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass
    elif _is_windows():
        try:
            out = subprocess.run(
                ["netsh", "interface", "ipv4", "show", "route"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if out.returncode == 0:
                in_block = False
                for line in out.stdout.splitlines():
                    if iface in line and "prefix" not in line.lower():
                        in_block = True
                    if in_block and "0.0.0.0/0" in line:
                        m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+0\.0\.0\.0/0", line)
                        if m:
                            return m.group(1)
                        break
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass
    return _get_default_gateway()


def _list_from_sysfs(exclude_loopback: bool) -> list:
    """Use /sys/class/net (Linux). Returns list of { name, connected }."""
    if not SYS_NET.exists():
        return []
    result = []
    try:
        names = os.listdir(SYS_NET)
    except OSError:
        return []
    for iface in sorted(names):
        if exclude_loopback and iface in ("lo", "lo0"):
            continue
        connected = is_connected(iface)
        result.append({"name": iface, "connected": connected})
    return result


def _list_from_netifaces(exclude_loopback: bool) -> list:
    """Use netifaces if available (cross-platform)."""
    try:
        import netifaces
        result = []
        for iface in netifaces.interfaces():
            if exclude_loopback and iface in ("lo", "lo0"):
                continue
            result.append({"name": iface, "connected": is_connected(iface)})
        return sorted(result, key=lambda x: x["name"])
    except ImportError:
        return []


def _list_from_ip_link(exclude_loopback: bool) -> list:
    """Parse 'ip link show' (Linux)."""
    try:
        out = subprocess.run(
            ["ip", "-o", "link", "show"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if out.returncode != 0:
            return []
        result = []
        for line in out.stdout.splitlines():
            # Format: "1: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> ..." or "2: wlan0: ..."
            m = re.match(r"^\d+:\s+([^:@]+)", line)
            if m:
                iface = m.group(1).strip()
                if exclude_loopback and iface in ("lo", "lo0"):
                    continue
                connected = "LOWER_UP" in line or "state UP" in line
                result.append({"name": iface, "connected": connected})
        return sorted(result, key=lambda x: x["name"])
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return []


def _list_from_ifconfig(exclude_loopback: bool) -> list:
    """Parse ifconfig (BSD/macOS) for interface names."""
    try:
        out = subprocess.run(
            ["ifconfig"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if out.returncode != 0:
            return []
        result = []
        # Lines like "eth0: flags=..." or "en0: flags=..."
        for line in out.stdout.splitlines():
            m = re.match(r"^([a-zA-Z0-9]+):\s+flags=", line)
            if m:
                iface = m.group(1)
                if exclude_loopback and iface in ("lo", "lo0"):
                    continue
                result.append({"name": iface, "connected": is_connected(iface)})
        return sorted(result, key=lambda x: x["name"])
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return []


def _list_from_windows(exclude_loopback: bool) -> list:
    """List network adapters on Windows via PowerShell."""
    try:
        creationflags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             "Get-NetAdapter | Where-Object { $_.Status -ne 'Disabled' } | Select-Object -ExpandProperty Name"],
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=creationflags,
        )
        if out.returncode != 0:
            return []
        result = []
        for name in out.stdout.strip().splitlines():
            name = name.strip()
            if not name:
                continue
            result.append({"name": name, "connected": is_connected(name)})
        return sorted(result, key=lambda x: x["name"])
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return []


def list_interfaces(exclude_loopback: bool = True):
    """Return list of dicts: { name, connected } for each available interface.
    Linux: sysfs, netifaces, ip link, ifconfig. Windows: PowerShell. macOS: netifaces, ifconfig."""
    if _is_windows():
        result = _list_from_windows(exclude_loopback)
        if result:
            return result
    result = _list_from_sysfs(exclude_loopback)
    if result:
        return result
    result = _list_from_netifaces(exclude_loopback)
    if result:
        return result
    result = _list_from_ip_link(exclude_loopback)
    if result:
        return result
    result = _list_from_ifconfig(exclude_loopback)
    if result:
        return result
    return []


def _is_connected_ip_link(interface: str) -> bool:
    """Parse 'ip link show <iface>' for LOWER_UP or state UP."""
    try:
        out = subprocess.run(
            ["ip", "-o", "link", "show", interface],
            capture_output=True,
            text=True,
            timeout=3,
        )
        if out.returncode != 0:
            return False
        return "LOWER_UP" in out.stdout or "state UP" in out.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def _is_connected_ifconfig(interface: str) -> bool:
    """Parse 'ifconfig <iface>' for status: active (macOS/BSD)."""
    try:
        out = subprocess.run(
            ["ifconfig", interface],
            capture_output=True,
            text=True,
            timeout=3,
        )
        if out.returncode != 0:
            return False
        return "status: active" in out.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def _is_connected_windows(interface: str) -> bool:
    """Windows: adapter status Up and media connected."""
    try:
        if_esc = interface.replace("'", "''")
        creationflags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             f"(Get-NetAdapter -Name '{if_esc}' -ErrorAction SilentlyContinue).Status -eq 'Up'"],
            capture_output=True,
            text=True,
            timeout=5,
            creationflags=creationflags,
        )
        if out.returncode != 0:
            return False
        return "True" in out.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def is_connected(interface: str) -> bool:
    """True if interface has carrier (link up). Linux: sysfs/ip link. macOS: ifconfig. Windows: PowerShell."""
    if _is_windows():
        return _is_connected_windows(interface)
    carrier_path = SYS_NET / interface / "carrier"
    if carrier_path.exists():
        try:
            with open(carrier_path, "r") as f:
                return f.read().strip() == "1"
        except (IOError, OSError):
            pass
    if _is_connected_ip_link(interface):
        return True
    if _is_connected_ifconfig(interface):
        return True
    return False


def get_operstate(interface: str) -> str:
    """Return operstate (e.g. 'up', 'down', 'unknown'). Linux: sysfs. macOS: ifconfig status/flags. Windows: from adapter status."""
    path = SYS_NET / interface / "operstate"
    if path.exists():
        try:
            with open(path, "r") as f:
                s = f.read().strip().lower()
            if s:
                return s
        except (IOError, OSError):
            pass
    if _is_linux():
        try:
            out = subprocess.run(
                ["ip", "-o", "link", "show", interface],
                capture_output=True,
                text=True,
                timeout=3,
            )
            if out.returncode == 0:
                if "state UP" in out.stdout:
                    return "up"
                if "state DOWN" in out.stdout:
                    return "down"
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass
    if _is_macos():
        try:
            out = subprocess.run(
                ["ifconfig", interface],
                capture_output=True,
                text=True,
                timeout=3,
            )
            if out.returncode == 0:
                if "status: active" in out.stdout:
                    return "up"
                if "RUNNING" in out.stdout and "UP" in out.stdout:
                    return "up"
                return "down"
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass
    if _is_windows():
        return "up" if is_connected(interface) else "down"
    return "unknown"


def _read_sysfs(interface: str, filename: str, default: str = "") -> str:
    """Read a file from /sys/class/net/<iface>/<filename>. Returns default if missing or error."""
    path = SYS_NET / interface / filename
    if not path.exists():
        return default
    try:
        return open(path, "r").read().strip()
    except (IOError, OSError):
        return default


def _get_linux_ip_details(interface: str) -> tuple:
    """Linux: (ipv4, netmask, broadcast) from 'ip -4 addr show'."""
    try:
        out = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", interface],
            capture_output=True,
            text=True,
            timeout=3,
        )
        if out.returncode != 0 or not out.stdout.strip():
            return ("", "", "")
        line = out.stdout.splitlines()[0]
        inet_m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
        if not inet_m:
            return ("", "", "")
        ipv4, prefix = inet_m.group(1), int(inet_m.group(2))
        netmask = _prefix_to_netmask(prefix)
        brd_m = re.search(r"brd\s+(\d+\.\d+\.\d+\.\d+)", line)
        broadcast = brd_m.group(1) if brd_m else ""
        return (ipv4, netmask, broadcast)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError, IndexError, ValueError):
        return ("", "", "")


def _get_linux_mtu(interface: str) -> str:
    """Linux: MTU from sysfs or 'ip link show'."""
    mtu = _read_sysfs(interface, "mtu", "")
    if mtu:
        return mtu
    try:
        out = subprocess.run(
            ["ip", "link", "show", interface],
            capture_output=True,
            text=True,
            timeout=3,
        )
        if out.returncode == 0:
            m = re.search(r"mtu\s+(\d+)", out.stdout)
            if m:
                return m.group(1)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    return ""


def _get_linux_speed_duplex(interface: str) -> tuple:
    """Linux: (speed_str, duplex_str) from sysfs then ethtool."""
    speed = _read_sysfs(interface, "speed", "")
    duplex = _read_sysfs(interface, "duplex", "")
    if speed and speed.isdigit():
        speed = speed + " Mbps"
    if duplex:
        duplex = duplex.capitalize()
    if speed or duplex:
        return (speed or "", duplex or "")
    try:
        out = subprocess.run(
            ["ethtool", interface],
            capture_output=True,
            text=True,
            timeout=3,
        )
        if out.returncode == 0:
            sm = re.search(r"Speed:\s*(\d+)\s*([MG])?b/s?", out.stdout, re.I)
            if sm:
                n, unit = sm.group(1), (sm.group(2) or "M").upper()
                speed = n + (" Gbps" if unit == "G" else " Mbps")
            dm = re.search(r"Duplex:\s*(\w+)", out.stdout, re.I)
            if dm:
                duplex = dm.group(1).strip().capitalize()
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    return (speed or "", duplex or "")


def _parse_macos_media_line(stdout: str) -> tuple:
    """Parse ifconfig 'media: autoselect (1000baseT <full-duplex>)' for speed and duplex."""
    speed, duplex = "", ""
    # media: autoselect (1000baseT <full-duplex>) status: active
    media_m = re.search(r"media:\s*\S+\s*\((\d+)(?:base)?[T\w]*\s*(?:<([^>]+)>)?", stdout, re.I)
    if media_m:
        num = media_m.group(1)
        if num == "1000":
            speed = "1000 Mbps"
        elif num == "100":
            speed = "100 Mbps"
        elif num == "10":
            speed = "10 Mbps"
        else:
            speed = num + " Mbps"
        dup = media_m.group(2) if media_m.lastindex >= 2 else ""
        if dup:
            duplex = dup.strip().lower()
            if duplex == "full-duplex":
                duplex = "Full"
            elif duplex == "half-duplex":
                duplex = "Half"
    return (speed, duplex)


def _get_macos_ifconfig_details(interface: str) -> dict:
    """macOS/BSD: ipv4, netmask, broadcast, mtu, speed, duplex from ifconfig."""
    result = {"ipv4": "", "netmask": "", "broadcast": "", "mtu": "", "speed": "", "duplex": ""}
    try:
        out = subprocess.run(
            ["ifconfig", interface],
            capture_output=True,
            text=True,
            timeout=3,
        )
        if out.returncode != 0:
            return result
        m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+(0x[0-9a-fA-F]+|\d+\.\d+\.\d+\.\d+)", out.stdout)
        if m:
            result["ipv4"] = m.group(1)
            nm = m.group(2)
            if nm.startswith("0x"):
                result["netmask"] = _hex_netmask_to_dotted(nm)
            else:
                result["netmask"] = nm
        m = re.search(r"broadcast\s+(\d+\.\d+\.\d+\.\d+)", out.stdout)
        if m:
            result["broadcast"] = m.group(1)
        m = re.search(r"mtu\s+(\d+)", out.stdout)
        if m:
            result["mtu"] = m.group(1)
        result["speed"], result["duplex"] = _parse_macos_media_line(out.stdout)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    return result


def _get_macos_speed(interface: str) -> str:
    """macOS: link speed from system_profiler if available."""
    try:
        out = subprocess.run(
            ["system_profiler", "SPNetworkDataType", "-json"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if out.returncode != 0:
            return ""
        import json
        data = json.loads(out.stdout)
        for item in data.get("SPNetworkDataType", []):
            if item.get("interface") == interface or item.get("BSD Device Name") == interface:
                return item.get("link_speed") or item.get("linkSpeed") or ""
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError, ValueError, KeyError):
        pass
    return ""


def _get_windows_interface_details(interface: str) -> dict:
    """Windows: get ipv4, netmask, broadcast, mtu, speed, duplex via PowerShell."""
    result = {
        "ipv4": "", "netmask": "", "broadcast": "", "mtu": "",
        "speed": "", "duplex": "", "mac": "",
    }
    if not interface:
        return result
    try:
        if_esc = interface.replace("'", "''")
        ps = f'''
$adapter = Get-NetAdapter | Where-Object {{ $_.Name -eq '{if_esc}' -or $_.InterfaceDescription -eq '{if_esc}' -or $_.ifIndex -eq '{if_esc}' }} | Select-Object -First 1
if (-not $adapter) {{ exit 1 }}
$ifIndex = $adapter.ifIndex
$mac = ($adapter.MacAddress -replace '-',':')
$mtu = (Get-NetIPInterface -InterfaceIndex $ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).NlMtuBytes
$addr = Get-NetIPAddress -InterfaceIndex $ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
if ($addr) {{
  $ip = $addr.IPAddress
  $prefix = $addr.PrefixLength
  $m = [uint32](([uint32]0xFFFFFFFF -shl (32 - $prefix)) -band [uint32]0xFFFFFFFF)
  $mask = [System.Net.IPAddress]::new($m)
  Write-Output "IP:$ip"
  Write-Output "MASK:$($mask.ToString())"
}}
Write-Output "MAC:$mac"
Write-Output "MTU:$mtu"
Write-Output "LINKSPEED:$($adapter.LinkSpeed)"
'''
        creationflags = 0
        if _is_windows() and hasattr(subprocess, "CREATE_NO_WINDOW"):
            creationflags = subprocess.CREATE_NO_WINDOW
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=creationflags,
        )
        if out.returncode != 0:
            return result
        for line in out.stdout.splitlines():
            line = line.strip()
            if line.startswith("IP:"):
                result["ipv4"] = line[3:].strip()
            elif line.startswith("MASK:"):
                result["netmask"] = line[5:].strip()
            elif line.startswith("MAC:"):
                result["mac"] = line[4:].strip()
            elif line.startswith("MTU:"):
                result["mtu"] = line[4:].strip() if line[4:].strip().isdigit() else ""
            elif line.startswith("LINKSPEED:"):
                result["speed"] = line[10:].strip()
        # Broadcast: not commonly exposed in PowerShell; leave empty or compute from ip+prefix
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError, Exception):
        pass
    return result


def _get_ipv4_from_ifconfig(interface: str) -> str:
    """Fallback: IPv4 only from ifconfig (any platform)."""
    d = _get_macos_ifconfig_details(interface)
    return d.get("ipv4", "")


def get_interface_details(interface: str) -> dict:
    """Return local Ethernet port details for the given interface.
    Cross-platform: Linux, macOS, Windows.
    Keys: name, mac, connected, operstate, speed, duplex, ipv4, mtu, netmask, broadcast, network_address, default_gateway."""
    if not interface:
        return {
            "name": "", "mac": "—", "connected": False, "operstate": "unknown",
            "speed": "—", "duplex": "—", "ipv4": "—", "mtu": "—", "netmask": "—", "broadcast": "—",
            "network_address": "—", "default_gateway": "—",
        }
    connected = is_connected(interface)
    operstate = get_operstate(interface)
    mac = ""
    ipv4 = ""
    netmask = ""
    broadcast = ""
    mtu = ""
    speed = ""
    duplex = ""

    if _is_windows():
        win = _get_windows_interface_details(interface)
        mac = win.get("mac", "")
        ipv4 = win.get("ipv4", "")
        netmask = win.get("netmask", "")
        broadcast = win.get("broadcast", "")
        mtu = win.get("mtu", "")
        speed = win.get("speed", "")
        duplex = win.get("duplex", "")
    else:
        # MAC
        mac = _read_sysfs(interface, "address", "")
        if not mac:
            try:
                out = subprocess.run(
                    ["ip", "link", "show", interface],
                    capture_output=True,
                    text=True,
                    timeout=3,
                )
                if out.returncode == 0:
                    m = re.search(r"link/ether\s+([0-9a-f:]+)", out.stdout, re.I)
                    if m:
                        mac = m.group(1).strip()
            except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
                pass
        if not mac:
            try:
                out = subprocess.run(
                    ["ifconfig", interface],
                    capture_output=True,
                    text=True,
                    timeout=3,
                )
                if out.returncode == 0:
                    m = re.search(r"ether\s+([0-9a-f:]+)", out.stdout, re.I)
                    if m:
                        mac = m.group(1).strip()
            except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
                pass

        if _is_linux():
            ipv4, netmask, broadcast = _get_linux_ip_details(interface)
            mtu = _get_linux_mtu(interface)
            speed, duplex = _get_linux_speed_duplex(interface)
            if speed and speed.isdigit():
                speed = speed + " Mbps"
        elif _is_macos():
            ifconfig_d = _get_macos_ifconfig_details(interface)
            ipv4 = ifconfig_d.get("ipv4", "")
            netmask = ifconfig_d.get("netmask", "")
            broadcast = ifconfig_d.get("broadcast", "")
            mtu = ifconfig_d.get("mtu", "")
            speed = ifconfig_d.get("speed", "") or _get_macos_speed(interface)
            duplex = ifconfig_d.get("duplex", "")

    network_address = _network_address(ipv4, netmask) if (ipv4 and netmask) else ""
    default_gateway = _get_default_gateway_for_interface(interface)

    return {
        "name": interface,
        "mac": mac or "—",
        "connected": connected,
        "operstate": operstate,
        "speed": speed or "—",
        "duplex": duplex or "—",
        "ipv4": ipv4 or "—",
        "mtu": mtu or "—",
        "netmask": netmask or "—",
        "broadcast": broadcast or "—",
        "network_address": network_address or "—",
        "default_gateway": default_gateway or "—",
    }
