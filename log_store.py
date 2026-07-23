"""Log file: snapshot entries saved when user clicks Save (Time, System Name, Management Address, etc.)."""
import csv
import logging
import os
import tempfile
import threading
from typing import Optional

import config as app_config

LOG_PATH = app_config.LOG_PATH
_log_lock = threading.RLock()
_cache_lock = threading.Lock()
_row_cache: Optional[tuple[str, tuple[int, int], list[dict]]] = None
logger = logging.getLogger(__name__)


class LogReadError(RuntimeError):
    """The history file exists but could not be read safely."""


def _invalidate_cache() -> None:
    global _row_cache
    with _cache_lock:
        _row_cache = None


def _log_path():
    """Resolved path to the log file (same for read and write)."""
    return LOG_PATH.resolve()


# Snapshot schema when user clicks Save
FIELDNAMES = [
    "timestamp", "type", "protocol", "system_name", "management_address",
    "port_id", "port_description", "vlan_id", "vlan_name",
    "observed_vlan_tags", "switch_mac", "chassis_id", "caps", "local_ip",
    "ping_results", "notes",
]


def _ensure_log():
    app_config.ensure_data_dir()
    path = _log_path()
    if not path.exists():
        path.write_text("", encoding="utf-8")


def _write_rows(rows: list) -> None:
    """Atomically replace the CSV with the current schema."""
    _ensure_log()
    path = _log_path()
    fd, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=".history-", suffix=".csv"
    )
    try:
        with os.fdopen(fd, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
            writer.writeheader()
            for source in rows:
                row = {key: source.get(key, "") for key in FIELDNAMES}
                row["type"] = "snapshot"
                writer.writerow(row)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary_name, path)
        _invalidate_cache()
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def _migrate_schema_if_needed() -> None:
    """Upgrade older CSV headers before appending a row with new fields."""
    path = _log_path()
    if not path.exists() or path.stat().st_size == 0:
        return
    try:
        with open(path, "r", newline="", encoding="utf-8") as f:
            header = next(csv.reader(f), [])
    except (OSError, csv.Error) as exc:
        logger.exception("Unable to inspect detection history schema at %s", path)
        raise LogReadError("Detection history is unavailable") from exc
    if header != FIELDNAMES:
        _write_rows(_read_all_rows())


def purge_log():
    """Clear all log entries and write a fresh CSV header line."""
    with _log_lock:
        _write_rows([])


def append_snapshot(entry: dict) -> None:
    """Append one snapshot row when user clicks Save. Entry must include all FIELDNAMES (except type)."""
    with _log_lock:
        _ensure_log()
        _migrate_schema_if_needed()
        row = {k: "" for k in FIELDNAMES}
        row["timestamp"] = entry.get("timestamp", "")
        row["type"] = "snapshot"
        row["protocol"] = (entry.get("protocol") or "").upper()
        row["system_name"] = entry.get("system_name", "")
        row["management_address"] = entry.get("management_address", "")
        row["port_id"] = entry.get("port_id", "")
        row["port_description"] = entry.get("port_description", "")
        row["vlan_id"] = entry.get("vlan_id", "")
        row["vlan_name"] = entry.get("vlan_name", "")
        row["observed_vlan_tags"] = entry.get("observed_vlan_tags", "")
        row["switch_mac"] = entry.get("switch_mac", "")
        row["chassis_id"] = entry.get("chassis_id", "")
        row["caps"] = entry.get("caps", "")
        row["local_ip"] = entry.get("local_ip", "")
        row["ping_results"] = entry.get("ping_results", "")
        row["notes"] = (entry.get("notes") or "")[:1000]
        path = _log_path()
        with open(path, "a", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=FIELDNAMES)
            if path.stat().st_size == 0:
                w.writeheader()
            w.writerow(row)
            f.flush()
            os.fsync(f.fileno())
        _invalidate_cache()


def _sanitize_log_entry(row: dict) -> dict:
    """Ensure values are strings, strip control characters, replace newlines for safe JSON/UI."""
    out = {}
    for k, v in row.items():
        s = (v or "").strip() if v is not None else ""
        if isinstance(s, str):
            s = "".join(c for c in s if ord(c) >= 32 or c in " \t").replace("\n", " ").replace("\r", " ")
        out[k] = s
    return out


def _read_all_rows() -> list:
    """Read all log rows (file order = oldest first). Returns list of sanitized dicts.
    Missing protocol fields in older files are inferred as LLDP."""
    global _row_cache
    path = _log_path()
    if not path.exists():
        return []
    try:
        stat = path.stat()
        signature = (stat.st_mtime_ns, stat.st_size)
    except OSError as exc:
        logger.exception("Unable to inspect detection history at %s", path)
        raise LogReadError("Detection history is unavailable") from exc
    cache_key = str(path)
    with _cache_lock:
        cached = _row_cache
        if cached and cached[0] == cache_key and cached[1] == signature:
            return [row.copy() for row in cached[2]]
    rows = []
    try:
        with open(path, "r", newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            header = next(reader, None)
            if not header:
                return []
            for row_values in reader:
                if len(row_values) < 2:
                    continue
                if row_values[1] != "snapshot":
                    continue
                if len(row_values) <= len(header):
                    r = dict(zip(header, row_values + [""] * (len(header) - len(row_values))))
                else:
                    r = dict(zip(header, row_values[: len(header)]))
                if not r.get("protocol"):
                    r["protocol"] = "LLDP"
                rows.append(_sanitize_log_entry(r))
    except (OSError, csv.Error, UnicodeError) as exc:
        logger.exception("Unable to read detection history at %s", path)
        raise LogReadError("Detection history is unavailable") from exc
    with _cache_lock:
        _row_cache = (cache_key, signature, [row.copy() for row in rows])
    return [row.copy() for row in rows]


def delete_entry_at_index(index: int) -> bool:
    """Delete the entry at index (0-based, newest-first order). Returns True if deleted."""
    with _log_lock:
        rows = _read_all_rows()
        if index < 0 or index >= len(rows):
            return False
        newest_first = list(reversed(rows))
        newest_first.pop(index)
        file_order = list(reversed(newest_first))
        _write_rows(file_order)
        return True


def read_log_page(
    page: int = 1,
    per_page: int = 20,
    newest_first: bool = True,
    query: str = "",
    protocol: str = "",
    ping: str = "",
    date_from: str = "",
    date_to: str = "",
) -> tuple[list, int]:
    """Return a filtered page and count, retaining each row's delete index."""
    with _log_lock:
        rows = _read_all_rows()
    source_total = len(rows)
    for oldest_index, row in enumerate(rows):
        row["_source_index"] = source_total - oldest_index - 1
    if newest_first:
        rows = list(reversed(rows))
    search = (query or "").strip().casefold()
    protocol_filter = (protocol or "").strip().upper()
    ping_filter = (ping or "").strip().lower()
    filtered = []
    for row in rows:
        if protocol_filter in ("LLDP", "CDP"):
            if row.get("protocol", "").upper() != protocol_filter:
                continue
        ping_results = row.get("ping_results", "").lower()
        if ping_filter in ("pass", "fail") and f":{ping_filter}" not in ping_results:
            continue
        row_date = row.get("timestamp", "")[:10]
        if date_from and row_date < date_from:
            continue
        if date_to and row_date > date_to:
            continue
        if search:
            searchable = " ".join(
                str(row.get(key, ""))
                for key in FIELDNAMES
                if key not in ("timestamp", "type")
            ).casefold()
            if search not in searchable and search not in row.get("timestamp", "").casefold():
                continue
        filtered.append(row)
    total = len(filtered)
    start = (page - 1) * per_page
    page_rows = filtered[start : start + per_page]
    return page_rows, total
