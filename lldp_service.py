"""LLDP sniffing and parsing with Scapy; extract chassis, port, system name, VLAN ID."""
import logging
import threading
import time
from datetime import datetime
from typing import Optional

from scapy.all import sniff
from scapy.contrib.lldp import LLDPDU

import config as app_config

logger = logging.getLogger(__name__)

# IEEE 802.1 org code for VLAN TLVs
ORG_IEEE_802_1 = 32962
# Port VLAN ID TLV subtype (common value)
PORT_VLAN_ID_SUBTYPE = 1

# System Capabilities (TLV 7) bit names for "enabled" (display)
_CAP_ENABLED_NAMES = [
    ("other_enabled", "Other"),
    ("repeater_enabled", "Repeater"),
    ("mac_bridge_enabled", "Bridge"),
    ("wlan_access_point_enabled", "WLAN AP"),
    ("router_enabled", "Router"),
    ("telephone_enabled", "Telephone"),
    ("docsis_cable_device_enabled", "DOCSIS"),
    ("station_only_enabled", "Station"),
    ("c_vlan_component_enabled", "C-VLAN"),
    ("s_vlan_component_enabled", "S-VLAN"),
    ("two_port_mac_relay_enabled", "Two-Port MAC Relay"),
]

_current: Optional[dict] = None
_current_lock = threading.Lock()
_sniff_thread: Optional[threading.Thread] = None
_stop_sniff = threading.Event()
_packet_queue: list = []
_queue_lock = threading.Lock()


def _decode_str(raw) -> str:
    """Decode bytes as UTF-8 text. Do not treat 4-byte fields as IPv4 (that's only for management_address)."""
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        try:
            return raw.decode("utf-8", errors="replace").strip()
        except Exception:
            return ""
    return str(raw).strip()


def _format_mac(addr) -> str:
    """Format chassis/port id as MAC (xx:xx:xx:xx:xx:xx) when it's 6 bytes or already a MAC string."""
    if addr is None:
        return ""
    if isinstance(addr, (bytes, bytearray)) and len(addr) >= 6:
        return ":".join("%02x" % b for b in addr[:6])
    s = _decode_str(addr)
    if s and len(s) >= 17 and ":" in s:
        return s
    return ""


def _format_management_address(addr, subtype=None) -> str:
    """Format management address as IPv4. LLDP TLV: optional 1-byte IANA family (1=IPv4) then address bytes."""
    if addr is None:
        return ""
    if not isinstance(addr, (bytes, bytearray)):
        return ""
    raw = bytes(addr)
    # IANA address family: 1 = IPv4
    if len(raw) == 4:
        return ".".join(str(b) for b in raw)
    if len(raw) >= 5 and (subtype == 1 or raw[0] == 1):
        return ".".join(str(b) for b in raw[1:5])
    return ""


def _extract_vlan_from_lldp(lldp) -> Optional[str]:
    """Walk LLDP payload for IEEE 802.1 org TLV (Port VLAN ID) and return VLAN ID."""
    if lldp is None:
        return None
    layer = lldp
    while layer:
        name = type(layer).__name__
        if name == "LLDPDUGenericOrganisationSpecific":
            try:
                org = getattr(layer, "org_code", None)
                if org == ORG_IEEE_802_1:
                    subtype = getattr(layer, "subtype", 0)
                    if subtype == PORT_VLAN_ID_SUBTYPE:
                        data = getattr(layer, "data", b"")
                        if isinstance(data, bytes) and len(data) >= 2:
                            # VLAN ID is 12 bits; often in 2 bytes big-endian
                            vlan = (data[0] << 8 | data[1]) & 0x0FFF
                            return str(vlan)
            except Exception:
                pass
        layer = layer.payload
    return None


def _extract_capabilities_from_lldp(lldp) -> Optional[str]:
    """Walk LLDP for System Capabilities TLV (type 7) and return comma-separated enabled capabilities."""
    if lldp is None:
        return None
    layer = lldp
    while layer:
        name = type(layer).__name__
        if name == "LLDPDUSystemCapabilities":
            try:
                parts = []
                for attr, label in _CAP_ENABLED_NAMES:
                    if getattr(layer, attr, 0):
                        parts.append(label)
                return ", ".join(parts) if parts else ""
            except Exception:
                pass
        layer = layer.payload
    return None


def _parse_lldp_packet(pkt) -> Optional[dict]:
    if not pkt or not pkt.haslayer(LLDPDU):
        return None
    lldp = pkt[LLDPDU]
    result = {
        "chassis_id": "",
        "switch_mac": "",
        "system_name": "",
        "port_id": "",
        "port_description": "",
        "vlan_id": "",
        "system_description": "",
        "management_address": "",
        "notes": "",
        "caps": "",
    }
    layer = lldp
    while layer:
        name = type(layer).__name__
        try:
            if "ChassisID" in name:
                lid = getattr(layer, "id", None)
                result["chassis_id"] = _decode_str(lid)
                subtype = getattr(layer, "subtype", None)
                if subtype == 4:  # MAC address
                    result["switch_mac"] = _format_mac(lid)
            elif "PortID" in name:
                result["port_id"] = _decode_str(getattr(layer, "id", None))
            elif "SystemName" in name:
                result["system_name"] = _decode_str(getattr(layer, "system_name", None))
            elif "PortDescription" in name:
                result["port_description"] = _decode_str(getattr(layer, "description", None))
            elif "SystemDescription" in name:
                result["system_description"] = _decode_str(getattr(layer, "description", None))
            elif "ManagementAddress" in name:
                addr = getattr(layer, "management_address", None)
                subtype = getattr(layer, "management_address_subtype", None)
                if addr:
                    result["management_address"] = _format_management_address(addr, subtype)
        except Exception:
            pass
        layer = layer.payload

    vlan = _extract_vlan_from_lldp(lldp)
    if vlan is not None:
        result["vlan_id"] = vlan

    if not result.get("switch_mac") and result.get("chassis_id"):
        cid = result["chassis_id"].strip()
        if len(cid) == 17 and cid.count(":") == 5:
            parts = cid.split(":")
            if len(parts) == 6 and all(len(p) == 2 and p.isalnum() for p in parts):
                result["switch_mac"] = cid

    caps = _extract_capabilities_from_lldp(lldp)
    if caps is not None:
        result["caps"] = caps

    return result


def _on_packet(pkt):
    parsed = _parse_lldp_packet(pkt)
    if parsed:
        with _queue_lock:
            _packet_queue.append(parsed)
        _process_queue()


def _process_queue():
    """Process queued packets: update current port only. Log is written only when user clicks Save."""
    global _current
    while True:
        with _queue_lock:
            if not _packet_queue:
                break
            parsed = _packet_queue.pop(0)
        ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        parsed["timestamp"] = ts
        with _current_lock:
            _current = parsed.copy()


def _sniff_loop(iface: str):
    """Run sniff on iface; exit promptly when _stop_sniff is set by using short timeouts."""
    _stop_sniff.clear()
    try:
        while not _stop_sniff.is_set():
            sniff(
                iface=iface,
                filter="ether proto 0x88cc",
                prn=_on_packet,
                stop_filter=lambda _: _stop_sniff.is_set(),
                store=False,
                timeout=1,
            )
    except Exception as e:
        logger.warning("Sniff failed on interface %s: %s", iface, e)


def start_sniff():
    global _sniff_thread
    if _sniff_thread and _sniff_thread.is_alive():
        return
    iface = app_config.get_interface()
    _sniff_thread = threading.Thread(target=_sniff_loop, args=(iface,), daemon=True)
    _sniff_thread.start()


def stop_sniff():
    global _sniff_thread
    _stop_sniff.set()
    if _sniff_thread is not None:
        _sniff_thread.join(timeout=3.0)
        if not _sniff_thread.is_alive():
            _sniff_thread = None


def get_current() -> dict:
    with _current_lock:
        return (_current or {}).copy()


def clear_current():
    """Clear current LLDP data (e.g. when interface goes down)."""
    global _current
    with _current_lock:
        _current = None


def is_sniffing() -> bool:
    return _sniff_thread is not None and _sniff_thread.is_alive()
