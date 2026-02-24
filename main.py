"""
LLDProwl — Real-time LLDP network discovery and cable tracing.

Web app for sniffing LLDP frames, viewing connected switch/port details,
logging snapshots to CSV, and pinging targets. Cross-platform: Linux, macOS, Windows.
"""
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import config as app_config
import interface_state
import lldp_service
import log_store
import ping_service

app = FastAPI(title="LLDProwl", version="0.2.0")
STATIC_DIR = Path(__file__).resolve().parent / "static"


# --- Interface APIs ---
@app.get("/api/interfaces")
def get_interfaces():
    """List all network interfaces with link state (including unconnected)."""
    ifaces = interface_state.list_interfaces(exclude_loopback=True)
    current = app_config.get_interface()
    if current and not any(i["name"] == current for i in ifaces):
        ifaces.append({"name": current, "connected": interface_state.is_connected(current)})
        ifaces.sort(key=lambda x: x["name"])
    return ifaces


@app.get("/api/interface")
def get_interface():
    """Current selected interface from config."""
    return {"interface": app_config.get_interface()}


class InterfaceBody(BaseModel):
    interface: str


@app.put("/api/interface")
def put_interface(body: InterfaceBody):
    """Set interface for sniffing and link state; persist in config.
    If sniffing is active, restarts the sniffer on the new interface so results match the selection."""
    name = (body.interface or "").strip()
    if not name:
        raise HTTPException(400, "Interface name required")
    if not app_config.is_valid_interface_name(name):
        raise HTTPException(400, "Invalid interface name (use only letters, numbers, underscore, hyphen, period)")
    ifaces = [i["name"] for i in interface_state.list_interfaces(exclude_loopback=True)]
    if ifaces and name not in ifaces:
        raise HTTPException(400, f"Unknown interface: {name}")
    was_sniffing = lldp_service.is_sniffing()
    if was_sniffing:
        lldp_service.stop_sniff()
    lldp_service.clear_current()
    ping_service.clear_status()
    app_config.set_interface(name)
    if was_sniffing:
        lldp_service.start_sniff()
    return {"interface": name}


@app.get("/api/interface/state")
def get_interface_state():
    """Selected interface name and link state."""
    iface = app_config.get_interface()
    connected = interface_state.is_connected(iface)
    return {"interface": iface, "connected": connected}


@app.get("/api/interface/details")
def get_interface_details():
    """Local Ethernet port details for the selected interface (MAC, link state, speed, duplex, IPv4).
    When the interface is down, clears ping results and Connected Switch data."""
    iface = app_config.get_interface()
    details = interface_state.get_interface_details(iface)
    if not details.get("connected"):
        lldp_service.clear_current()
        ping_service.clear_status()
    return details


# --- Sniff ---
@app.get("/api/sniff/status")
def sniff_status():
    return {"sniffing": lldp_service.is_sniffing()}


@app.post("/api/sniff/start")
def sniff_start():
    lldp_service.start_sniff()
    return {"ok": True}


@app.post("/api/sniff/stop")
def sniff_stop():
    lldp_service.stop_sniff()
    return {"ok": True}


@app.get("/api/current")
def get_current():
    """Last parsed LLDP data for current port."""
    current = lldp_service.get_current()
    current.setdefault("caps", "")
    current.setdefault("switch_mac", "")
    return current


# --- Notes / Save snapshot ---
class NotesBody(BaseModel):
    note: str


@app.post("/api/notes")
def post_notes(body: NotesBody):
    """Save snapshot to log: timestamp, system name, management address, port ID/description,
    VLAN, switch MAC, chassis ID, caps, local IP, ping results, notes."""
    current = lldp_service.get_current()
    current.setdefault("caps", "")
    current.setdefault("switch_mac", "")
    iface = app_config.get_interface()
    details = interface_state.get_interface_details(iface)
    local_ip = (details.get("ipv4") or "").strip() or "—"
    ping_status = ping_service.get_last_status()
    parts = [f"{ip}:{('pass' if (s and s.get('success')) else 'fail')}" for ip, s in ping_status.items()]
    ping_results = ", ".join(parts) if parts else "—"
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    log_store.append_snapshot({
        "timestamp": ts,
        "system_name": current.get("system_name", ""),
        "management_address": current.get("management_address", ""),
        "port_id": current.get("port_id", ""),
        "port_description": current.get("port_description", ""),
        "vlan_id": current.get("vlan_id", ""),
        "switch_mac": current.get("switch_mac", ""),
        "chassis_id": current.get("chassis_id", ""),
        "caps": current.get("caps", ""),
        "local_ip": local_ip,
        "ping_results": ping_results,
        "notes": body.note or "",
    })
    return {"ok": True}


# --- Log ---
@app.get("/api/log")
def get_log(page: int = 1, per_page: int = 20):
    entries, total = log_store.read_log_page(page=page, per_page=per_page, newest_first=True)
    return {"entries": entries, "total": total}


@app.get("/api/log/download")
def download_log():
    """Return detection history as a CSV file download."""
    path = log_store.LOG_PATH
    if not path.exists() or path.stat().st_size == 0:
        return Response(
            content="timestamp,type,system_name,management_address,port_id,port_description,vlan_id,switch_mac,chassis_id,caps,local_ip,ping_results,notes\n",
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="detection_history.csv"'},
        )
    return FileResponse(
        path,
        media_type="text/csv",
        filename="detection_history.csv",
    )


@app.delete("/api/log")
def purge_log():
    """Purge (clear) all log entries and reset CSV header."""
    log_store.purge_log()
    return {"ok": True}


@app.delete("/api/log/entry")
def delete_log_entry(index: int):
    """Delete a single log entry by index (0-based, newest-first)."""
    if index < 0:
        raise HTTPException(400, "Invalid index")
    # Reject unreasonably large index to avoid abuse
    if index > 100_000:
        raise HTTPException(400, "Invalid index")
    if not log_store.delete_entry_at_index(index):
        raise HTTPException(404, "Entry not found")
    return {"ok": True}


# --- Ping ---
@app.get("/api/ping-targets")
def get_ping_targets():
    return {"ips": app_config.get_ping_targets()}


class PingTargetsBody(BaseModel):
    ips: list[str] = []


@app.put("/api/ping-targets")
def put_ping_targets(body: PingTargetsBody):
    app_config.set_ping_targets(body.ips or [])
    return get_ping_targets()


@app.get("/api/ping/status")
def get_ping_status():
    return ping_service.get_last_status()


@app.post("/api/ping/run")
async def ping_run():
    await ping_service.run_ping()
    return {"ok": True}


# --- Static / SPA ---
@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")


if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
