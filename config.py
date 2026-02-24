"""Load and save app config (interface, ping targets)."""
import json
import re
from pathlib import Path

CONFIG_DIR = Path(__file__).resolve().parent / "data"
CONFIG_PATH = CONFIG_DIR / "config.json"
LOG_PATH = CONFIG_DIR / "detection_history.csv"

# Interface name: only safe chars (no path traversal, no shell/PS injection)
INTERFACE_NAME_RE = re.compile(r"^[a-zA-Z0-9_.\-]{1,64}$")
MAX_PING_TARGETS = 50
MAX_PING_TARGET_LENGTH = 253

DEFAULT_CONFIG = {
    "interface": "eth0",
    "ping_targets": [],
}


def is_valid_interface_name(name: str) -> bool:
    """True if name is safe for sysfs paths, subprocess argv, and PowerShell -Name."""
    return bool(name and INTERFACE_NAME_RE.match(name.strip()))


def ensure_data_dir():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def load_config():
    ensure_data_dir()
    if not CONFIG_PATH.exists():
        return DEFAULT_CONFIG.copy()
    try:
        with open(CONFIG_PATH, "r") as f:
            data = json.load(f)
        return {**DEFAULT_CONFIG, **data}
    except (json.JSONDecodeError, IOError):
        return DEFAULT_CONFIG.copy()


def save_config(config: dict):
    ensure_data_dir()
    with open(CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=2)


def get_interface():
    raw = load_config().get("interface", "eth0")
    if raw is None or (isinstance(raw, str) and raw.strip().lower() == "none"):
        return DEFAULT_CONFIG["interface"]
    s = str(raw).strip()
    if not is_valid_interface_name(s):
        return DEFAULT_CONFIG["interface"]
    return s


def set_interface(interface: str):
    config = load_config()
    config["interface"] = interface
    save_config(config)


def get_ping_targets():
    config = load_config()
    targets = config.get("ping_targets", [])
    if not isinstance(targets, list):
        targets = [t for t in [targets] if t] if targets else []
    out = []
    for t in targets[: MAX_PING_TARGETS]:
        s = str(t).strip()
        if s and len(s) <= MAX_PING_TARGET_LENGTH:
            out.append(s)
    return out


def set_ping_targets(ips: list):
    config = load_config()
    limited = (ips or [])[: MAX_PING_TARGETS]
    config["ping_targets"] = [
        str(x).strip() for x in limited
        if str(x).strip() and len(str(x).strip()) <= MAX_PING_TARGET_LENGTH
    ]
    save_config(config)
