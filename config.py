"""Load and save app config (interface, ping targets)."""
import json
import os
import tempfile
import threading
from pathlib import Path

# Local runs keep state in the repository by default. Services can put mutable
# state elsewhere (for example /var/lib/lldprowl) without modifying the source.
CONFIG_DIR = Path(
    os.environ.get("LLDPROWL_DATA_DIR", Path(__file__).resolve().parent / "data")
).expanduser()
CONFIG_PATH = CONFIG_DIR / "config.json"
LOG_PATH = CONFIG_DIR / "detection_history.csv"
_config_lock = threading.RLock()

MAX_PING_TARGETS = 50
MAX_PING_TARGET_LENGTH = 253

DEFAULT_CONFIG = {
    # An empty value lets the API select the first connected interface. Hard
    # coding eth0 prevents a clean first run on macOS and predictable-interface
    # Linux installations.
    "interface": "",
    "ping_targets": [],
}


def is_valid_interface_name(name: str) -> bool:
    """True if a platform interface name is safe as one path/argv component."""
    if not isinstance(name, str):
        return False
    value = name.strip()
    return bool(
        value
        and len(value) <= 64
        and value not in (".", "..")
        and not any(char in value for char in ("/", "\\", "\0", "\r", "\n"))
    )


def ensure_data_dir():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def load_config():
    with _config_lock:
        ensure_data_dir()
        if not CONFIG_PATH.exists():
            return DEFAULT_CONFIG.copy()
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                return DEFAULT_CONFIG.copy()
            return {**DEFAULT_CONFIG, **data}
        except (json.JSONDecodeError, IOError):
            return DEFAULT_CONFIG.copy()


def save_config(config: dict):
    """Atomically persist config so an interrupted write cannot corrupt it."""
    with _config_lock:
        ensure_data_dir()
        fd, temporary_name = tempfile.mkstemp(
            dir=CONFIG_DIR, prefix=".config-", suffix=".json"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=2)
                f.write("\n")
                f.flush()
                os.fsync(f.fileno())
            os.replace(temporary_name, CONFIG_PATH)
        finally:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass


def get_interface():
    raw = load_config().get("interface", "")
    if raw is None or (isinstance(raw, str) and raw.strip().lower() == "none"):
        return DEFAULT_CONFIG["interface"]
    s = str(raw).strip()
    if not is_valid_interface_name(s):
        return DEFAULT_CONFIG["interface"]
    return s


def set_interface(interface: str):
    with _config_lock:
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
    with _config_lock:
        config = load_config()
        limited = (ips or [])[: MAX_PING_TARGETS]
        config["ping_targets"] = [
            str(x).strip() for x in limited
            if str(x).strip() and len(str(x).strip()) <= MAX_PING_TARGET_LENGTH
        ]
        save_config(config)
