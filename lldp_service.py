"""LLDP and CDP sniffing/parsing with Scapy."""
import logging
import threading
from datetime import datetime, timezone
from typing import Optional

from scapy.all import AsyncSniffer, Dot1Q, Ether
from scapy.contrib.cdp import (
    CDPAddrRecordIPv4,
    CDPMsgAddr,
    CDPMsgCapabilities,
    CDPMsgDeviceID,
    CDPMsgMgmtAddr,
    CDPMsgNativeVLAN,
    CDPMsgPlatform,
    CDPMsgPortID,
    CDPMsgSoftwareVersion,
    CDPv2_HDR,
)
from scapy.contrib.lldp import LLDPDU

import config as app_config

logger = logging.getLogger(__name__)

# IEEE 802.1 org code for VLAN TLVs
ORG_IEEE_802_1 = 32962
# Port VLAN ID TLV subtype (common value)
PORT_VLAN_ID_SUBTYPE = 1
# VLAN Name TLV subtype; data is VLAN ID, name length, then name.
VLAN_NAME_SUBTYPE = 3

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
_sniffer: Optional[AsyncSniffer] = None
_sniff_lock = threading.Lock()
_last_error = ""
_observed_vlan_tags: set[int] = set()
_observed_vlan_tags_lock = threading.Lock()

CAPTURE_FILTER = (
    "ether proto 0x88cc or "
    "ether dst 01:00:0c:cc:cc:cc or "
    "vlan"
)


def _decode_str(raw) -> str:
    """Decode bytes as UTF-8 text. Do not treat 4-byte fields as IPv4 (that's only for management_address)."""
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        try:
            return raw.decode("utf-8", errors="replace").strip()
        except Exception:
            logger.debug("Unable to decode discovery field", exc_info=True)
            return ""
    return str(raw).strip()


def _format_mac(addr) -> str:
    """Format chassis/port id as MAC (xx:xx:xx:xx:xx:xx) when it's 6 bytes or already a MAC string."""
    if addr is None:
        return ""
    if isinstance(addr, (bytes, bytearray)) and len(addr) >= 6:
        return ":".join("%02x" % b for b in addr[:6])
    s = _decode_str(addr)
    if s and len(s) == 17:
        parts = s.split(":")
        if len(parts) == 6 and all(
            len(part) == 2
            and all(char in "0123456789abcdefABCDEF" for char in part)
            for part in parts
        ):
            return s.lower()
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


def _extract_vlan_details_from_lldp(lldp) -> tuple[Optional[str], str]:
    """Return the IEEE 802.1 PVID and advertised VLAN name information."""
    if lldp is None:
        return None, ""
    pvid = None
    vlan_names: dict[str, str] = {}
    layer = lldp
    while layer:
        name = type(layer).__name__
        if name == "LLDPDUGenericOrganisationSpecific":
            try:
                org = getattr(layer, "org_code", None)
                if org == ORG_IEEE_802_1:
                    subtype = getattr(layer, "subtype", 0)
                    data = getattr(layer, "data", b"")
                    if subtype == PORT_VLAN_ID_SUBTYPE:
                        if isinstance(data, (bytes, bytearray)) and len(data) >= 2:
                            # VLAN ID is 12 bits; often in 2 bytes big-endian
                            vlan = (data[0] << 8 | data[1]) & 0x0FFF
                            pvid = str(vlan)
                    elif (
                        subtype == VLAN_NAME_SUBTYPE
                        and isinstance(data, (bytes, bytearray))
                        and len(data) >= 3
                    ):
                        vlan_id = str((data[0] << 8 | data[1]) & 0x0FFF)
                        name_length = min(data[2], len(data) - 3)
                        vlan_name = bytes(data[3 : 3 + name_length]).decode(
                            "utf-8", errors="replace"
                        ).strip()
                        if vlan_name:
                            vlan_names[vlan_id] = vlan_name
            except Exception:
                logger.debug("Unable to parse LLDP VLAN information", exc_info=True)
        layer = layer.payload
    if pvid and pvid in vlan_names:
        display_name = vlan_names[pvid]
    elif len(vlan_names) == 1:
        display_name = next(iter(vlan_names.values()))
    else:
        display_name = ", ".join(
            f"{vlan_id}: {vlan_name}"
            for vlan_id, vlan_name in sorted(
                vlan_names.items(), key=lambda item: int(item[0])
            )
        )
    return pvid, display_name


def _extract_vlan_from_lldp(lldp) -> Optional[str]:
    """Compatibility helper returning only the IEEE 802.1 PVID."""
    return _extract_vlan_details_from_lldp(lldp)[0]


def _extract_observed_vlan_tags(pkt) -> set[int]:
    """Return all valid 802.1Q VLAN identifiers carried by a frame."""
    tags = set()
    layer = pkt
    while layer:
        if isinstance(layer, Dot1Q):
            try:
                vlan_id = int(getattr(layer, "vlan", -1))
                if 0 <= vlan_id <= 4094:
                    tags.add(vlan_id)
            except (TypeError, ValueError):
                logger.debug("Unable to parse 802.1Q VLAN tag", exc_info=True)
        layer = getattr(layer, "payload", None)
    return tags


def _observed_vlan_tags_text() -> str:
    with _observed_vlan_tags_lock:
        return ", ".join(str(tag) for tag in sorted(_observed_vlan_tags))


def _clear_observed_vlan_tags() -> None:
    with _observed_vlan_tags_lock:
        _observed_vlan_tags.clear()


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
                logger.debug("Unable to parse LLDP capability TLV", exc_info=True)
        layer = layer.payload
    return None


def _parse_lldp_packet(pkt) -> Optional[dict]:
    if not pkt or not pkt.haslayer(LLDPDU):
        return None
    lldp = pkt[LLDPDU]
    result = {
        "protocol": "LLDP",
        "chassis_id": "",
        "switch_mac": "",
        "system_name": "",
        "port_id": "",
        "port_description": "",
        "vlan_id": "",
        "vlan_name": "",
        "observed_vlan_tags": "",
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
            logger.debug("Unable to parse LLDP TLV %s", name, exc_info=True)
        layer = layer.payload

    vlan, vlan_name = _extract_vlan_details_from_lldp(lldp)
    if vlan is not None:
        result["vlan_id"] = vlan
    result["vlan_name"] = vlan_name

    if not result.get("switch_mac") and result.get("chassis_id"):
        cid = result["chassis_id"].strip()
        if len(cid) == 17 and cid.count(":") == 5:
            parts = cid.split(":")
            if len(parts) == 6 and all(
                len(part) == 2
                and all(char in "0123456789abcdefABCDEF" for char in part)
                for part in parts
            ):
                result["switch_mac"] = cid

    caps = _extract_capabilities_from_lldp(lldp)
    if caps is not None:
        result["caps"] = caps

    return result


def _parse_cdp_packet(pkt) -> Optional[dict]:
    """Translate a Scapy CDP packet into the same fields used for LLDP."""
    if not pkt or not pkt.haslayer(CDPv2_HDR):
        return None
    cdp = pkt[CDPv2_HDR]
    switch_mac = ""
    if pkt.haslayer(Ether):
        switch_mac = _format_mac(getattr(pkt[Ether], "src", ""))
    result = {
        "protocol": "CDP",
        "chassis_id": "",
        "switch_mac": switch_mac,
        "system_name": "",
        "port_id": "",
        "port_description": "",
        "vlan_id": "",
        "vlan_name": "",
        "observed_vlan_tags": "",
        "system_description": "",
        "management_address": "",
        "notes": "",
        "caps": "",
    }
    platform = ""
    software = ""
    address_candidates = []
    for message in getattr(cdp, "msg", []) or []:
        try:
            if isinstance(message, CDPMsgDeviceID):
                device_id = _decode_str(getattr(message, "val", None))
                result["system_name"] = device_id
                result["chassis_id"] = device_id
            elif isinstance(message, CDPMsgPortID):
                result["port_id"] = _decode_str(getattr(message, "iface", None))
            elif isinstance(message, CDPMsgCapabilities):
                result["caps"] = str(getattr(message, "cap", "")).replace("+", ", ")
            elif isinstance(message, CDPMsgPlatform):
                platform = _decode_str(getattr(message, "val", None))
            elif isinstance(message, CDPMsgSoftwareVersion):
                software = _decode_str(getattr(message, "val", None))
            elif isinstance(message, CDPMsgNativeVLAN):
                result["vlan_id"] = str(getattr(message, "vlan", "") or "")
            elif isinstance(message, (CDPMsgMgmtAddr, CDPMsgAddr)):
                # Prefer the management-address TLV, but retain the ordinary
                # address TLV as a fallback for older CDP implementations.
                priority = 0 if isinstance(message, CDPMsgMgmtAddr) else 1
                for address in getattr(message, "addr", []) or []:
                    if isinstance(address, CDPAddrRecordIPv4):
                        address_candidates.append(
                            (priority, str(getattr(address, "addr", "") or ""))
                        )
        except Exception:
            logger.debug("Unable to parse CDP TLV", exc_info=True)
            continue
    if address_candidates:
        result["management_address"] = min(address_candidates)[1]
    descriptions = [value for value in (platform, software) if value]
    result["system_description"] = " — ".join(descriptions)
    return result


def _parse_discovery_packet(pkt) -> Optional[dict]:
    """Parse either supported neighbor-discovery protocol."""
    return _parse_lldp_packet(pkt) or _parse_cdp_packet(pkt)


def _on_packet(pkt):
    global _current
    observed = _extract_observed_vlan_tags(pkt)
    if observed:
        with _observed_vlan_tags_lock:
            changed = not observed.issubset(_observed_vlan_tags)
            _observed_vlan_tags.update(observed)
            observed_text = ", ".join(
                str(tag) for tag in sorted(_observed_vlan_tags)
            )
        if changed:
            with _current_lock:
                if _current is not None:
                    _current["observed_vlan_tags"] = observed_text
    parsed = _parse_discovery_packet(pkt)
    if parsed:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        parsed["timestamp"] = ts
        parsed["observed_vlan_tags"] = _observed_vlan_tags_text()
        with _current_lock:
            _current = parsed.copy()


def _capture_exception(sniffer) -> Optional[BaseException]:
    """Return a background capture exception when Scapy exposes one."""
    return getattr(sniffer, "exception", None) if sniffer is not None else None


def start_sniff():
    """Start one persistent libpcap capture for the configured interface."""
    global _sniffer, _last_error
    with _sniff_lock:
        if _sniffer is not None and getattr(_sniffer, "running", False):
            return
        iface = app_config.get_interface()
        if not iface:
            _last_error = "No network interface is selected"
            return
        _last_error = ""
        _clear_observed_vlan_tags()
        sniffer = AsyncSniffer(
            iface=iface,
            filter=CAPTURE_FILTER,
            prn=_on_packet,
            store=False,
        )
        _sniffer = sniffer
        try:
            sniffer.start()
        except Exception as exc:
            _sniffer = None
            _last_error = str(exc)
            logger.warning("Sniff failed on interface %s: %s", iface, exc)


def stop_sniff():
    """Stop and join the active capture without waiting for another packet."""
    global _sniffer, _last_error
    with _sniff_lock:
        sniffer = _sniffer
        if sniffer is None:
            return
        try:
            if getattr(sniffer, "running", False):
                sniffer.stop(join=True)
            else:
                sniffer.join(timeout=3.0)
        except Exception as exc:
            _last_error = str(exc)
            logger.warning("Failed to stop packet capture cleanly: %s", exc)
        finally:
            if _sniffer is sniffer:
                _sniffer = None


def get_current() -> dict:
    with _current_lock:
        return (_current or {}).copy()


def clear_current():
    """Clear current LLDP data (e.g. when interface goes down)."""
    global _current
    with _current_lock:
        _current = None
    _clear_observed_vlan_tags()


def is_sniffing() -> bool:
    global _last_error
    with _sniff_lock:
        sniffer = _sniffer
    error = _capture_exception(sniffer)
    if error is not None:
        _last_error = str(error)
    return sniffer is not None and bool(getattr(sniffer, "running", False))


def get_last_error() -> str:
    """Return the most recent capture error for diagnostics and the UI."""
    return _last_error
