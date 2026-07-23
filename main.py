"""
LLDProwl — Real-time LLDP/CDP network discovery and cable tracing.

Web app for sniffing discovery frames, viewing connected switch/port details,
logging snapshots to CSV, and pinging targets. Cross-platform: Linux, macOS, Windows.
"""
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import config as app_config
import interface_state
import lldp_service
import log_store
import ping_service


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Release packet-capture resources during a normal server shutdown."""
    try:
        yield
    finally:
        lldp_service.stop_sniff()


app = FastAPI(title="LLDProwl", version="0.4.0", lifespan=lifespan)
STATIC_DIR = Path(__file__).resolve().parent / "static"


@app.get("/api/health")
def health():
    """Lightweight process health check; packet capture need not be active."""
    return {"status": "ok", "version": app.version}


# --- Interface APIs ---
def _get_or_select_interface(ifaces=None) -> str:
    """Return the configured interface, selecting a usable default on first run."""
    current = app_config.get_interface()
    if current:
        return current
    available = ifaces if ifaces is not None else interface_state.list_interfaces(
        exclude_loopback=True
    )
    if not available:
        return ""
    # Prefer a connected conventional Ethernet interface. This avoids choosing
    # macOS AWDL/LLW or Linux tunnel interfaces merely because they sort first.
    selected = min(
        available,
        key=lambda item: (
            not item.get("connected"),
            not item["name"].lower().startswith(("eth", "en")),
            item["name"],
        ),
    )
    selected = selected["name"]
    app_config.set_interface(selected)
    return selected


@app.get("/api/interfaces")
def get_interfaces():
    """List all network interfaces with link state (including unconnected)."""
    ifaces = interface_state.list_interfaces(exclude_loopback=True)
    current = _get_or_select_interface(ifaces)
    if current and not any(i["name"] == current for i in ifaces):
        ifaces.append({"name": current, "connected": interface_state.is_connected(current)})
        ifaces.sort(key=lambda x: x["name"])
    return ifaces


@app.get("/api/interface")
def get_interface():
    """Current selected interface from config."""
    return {"interface": _get_or_select_interface()}


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
        raise HTTPException(400, "Invalid interface name")
    ifaces = [i["name"] for i in interface_state.list_interfaces(exclude_loopback=True)]
    if ifaces and name not in ifaces:
        raise HTTPException(400, f"Unknown interface: {name}")
    was_sniffing = lldp_service.is_sniffing()
    if was_sniffing:
        lldp_service.stop_sniff()
    lldp_service.clear_current()
    ping_service.clear_status()
    interface_state.clear_interface_details_cache()
    app_config.set_interface(name)
    if was_sniffing:
        lldp_service.start_sniff()
    return {"interface": name}


@app.get("/api/interface/state")
def get_interface_state():
    """Selected interface name and link state."""
    iface = _get_or_select_interface()
    connected = interface_state.is_connected(iface)
    return {"interface": iface, "connected": connected}


@app.get("/api/interface/details")
def get_interface_details():
    """Local Ethernet port details for the selected interface (MAC, link state, speed, duplex, IPv4).
    When the interface is down, clears ping results and Connected Switch data."""
    iface = _get_or_select_interface()
    details = interface_state.get_interface_details(iface)
    if not details.get("connected"):
        lldp_service.clear_current()
        ping_service.clear_status()
    return details


# --- Sniff ---
@app.get("/api/sniff/status")
def sniff_status():
    return {
        "sniffing": lldp_service.is_sniffing(),
        "error": lldp_service.get_last_error(),
    }


@app.post("/api/sniff/start")
def sniff_start():
    if not _get_or_select_interface():
        raise HTTPException(409, "No network interface is available")
    lldp_service.start_sniff()
    return {"ok": True, "interface": app_config.get_interface()}


@app.post("/api/sniff/stop")
def sniff_stop():
    lldp_service.stop_sniff()
    return {"ok": True}


@app.get("/api/current")
def get_current():
    """Last parsed LLDP or CDP data for the current port."""
    current = lldp_service.get_current()
    if current:
        current.setdefault("protocol", "")
        current.setdefault("caps", "")
        current.setdefault("switch_mac", "")
        current.setdefault("vlan_name", "")
        current.setdefault("observed_vlan_tags", "")
    return current


# --- Notes / Save snapshot ---
class NotesBody(BaseModel):
    note: str


@app.post("/api/notes")
def post_notes(body: NotesBody):
    """Save snapshot to log: timestamp, system name, management address, port ID/description,
    VLAN, switch MAC, chassis ID, caps, local IP, ping results, notes."""
    current = lldp_service.get_current()
    current.setdefault("protocol", "")
    current.setdefault("caps", "")
    current.setdefault("switch_mac", "")
    current.setdefault("vlan_name", "")
    current.setdefault("observed_vlan_tags", "")
    iface = _get_or_select_interface()
    details = interface_state.get_interface_details(iface)
    local_ip = (details.get("ipv4") or "").strip() or "—"
    ping_status = ping_service.get_last_status()
    parts = [f"{ip}:{('pass' if (s and s.get('success')) else 'fail')}" for ip, s in ping_status.items()]
    ping_results = ", ".join(parts) if parts else "—"
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    try:
        log_store.append_snapshot({
            "timestamp": ts,
            "protocol": current.get("protocol", ""),
            "system_name": current.get("system_name", ""),
            "management_address": current.get("management_address", ""),
            "port_id": current.get("port_id", ""),
            "port_description": current.get("port_description", ""),
            "vlan_id": current.get("vlan_id", ""),
            "vlan_name": current.get("vlan_name", ""),
            "observed_vlan_tags": current.get("observed_vlan_tags", ""),
            "switch_mac": current.get("switch_mac", ""),
            "chassis_id": current.get("chassis_id", ""),
            "caps": current.get("caps", ""),
            "local_ip": local_ip,
            "ping_results": ping_results,
            "notes": body.note or "",
        })
    except (OSError, log_store.LogReadError) as exc:
        raise HTTPException(500, "Detection history could not be written") from exc
    return {"ok": True}


# --- Log ---
@app.get("/api/log")
def get_log(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    q: str = Query("", max_length=200),
    protocol: str = Query("", max_length=10),
    ping: str = Query("", max_length=10),
    date_from: str = Query("", max_length=10),
    date_to: str = Query("", max_length=10),
):
    try:
        entries, total = log_store.read_log_page(
            page=page,
            per_page=per_page,
            newest_first=True,
            query=q,
            protocol=protocol,
            ping=ping,
            date_from=date_from,
            date_to=date_to,
        )
    except log_store.LogReadError as exc:
        raise HTTPException(500, str(exc)) from exc
    return {"entries": entries, "total": total}


@app.get("/api/log/download")
def download_log():
    """Return detection history as a CSV file download."""
    path = log_store.LOG_PATH
    try:
        missing_or_empty = not path.exists() or path.stat().st_size == 0
        if not missing_or_empty:
            with path.open("rb"):
                pass
    except OSError as exc:
        raise HTTPException(500, "Detection history could not be read") from exc
    if missing_or_empty:
        return Response(
            content=",".join(log_store.FIELDNAMES) + "\n",
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
    try:
        log_store.purge_log()
    except OSError as exc:
        raise HTTPException(500, "Detection history could not be cleared") from exc
    return {"ok": True}


@app.delete("/api/log/entry")
def delete_log_entry(index: int):
    """Delete a single log entry by index (0-based, newest-first)."""
    if index < 0:
        raise HTTPException(400, "Invalid index")
    # Reject unreasonably large index to avoid abuse
    if index > 100_000:
        raise HTTPException(400, "Invalid index")
    try:
        if not log_store.delete_entry_at_index(index):
            raise HTTPException(404, "Entry not found")
    except log_store.LogReadError as exc:
        raise HTTPException(500, str(exc)) from exc
    return {"ok": True}


# --- Ping ---
@app.get("/api/ping-targets")
def get_ping_targets():
    return {"ips": app_config.get_ping_targets()}


class PingTargetsBody(BaseModel):
    ips: list[str] = Field(default_factory=list)


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
    uvicorn.run(
        app,
        host=os.environ.get("LLDPROWL_HOST", "127.0.0.1"),
        port=int(os.environ.get("LLDPROWL_PORT", "8001")),
    )
