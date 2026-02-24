"""Log file: snapshot entries saved when user clicks Save (Time, System Name, Management Address, etc.)."""
import csv
import os
from pathlib import Path

import config as app_config

LOG_PATH = app_config.LOG_PATH


def _log_path():
    """Resolved path to the log file (same for read and write)."""
    return LOG_PATH.resolve()


# Snapshot schema when user clicks Save
FIELDNAMES = [
    "timestamp", "type", "system_name", "management_address", "port_id", "port_description",
    "vlan_id", "switch_mac", "chassis_id", "caps", "local_ip", "ping_results", "notes",
]


def _ensure_log():
    app_config.ensure_data_dir()
    path = _log_path()
    if not path.exists():
        path.write_text("")


def purge_log():
    """Clear all log entries and write a fresh CSV header line."""
    _ensure_log()
    path = _log_path()
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDNAMES)
        w.writeheader()
        f.flush()
        os.fsync(f.fileno())


def append_snapshot(entry: dict) -> None:
    """Append one snapshot row when user clicks Save. Entry must include all FIELDNAMES (except type)."""
    _ensure_log()
    row = {k: "" for k in FIELDNAMES}
    row["timestamp"] = entry.get("timestamp", "")
    row["type"] = "snapshot"
    row["system_name"] = entry.get("system_name", "")
    row["management_address"] = entry.get("management_address", "")
    row["port_id"] = entry.get("port_id", "")
    row["port_description"] = entry.get("port_description", "")
    row["vlan_id"] = entry.get("vlan_id", "")
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
    Handles both old CSV format (header includes mac_phy) and new format (13 columns)."""
    path = _log_path()
    if not path.exists():
        return []
    rows = []
    try:
        with open(path, "r", newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            header = next(reader, None)
            if not header:
                return []
            has_old_mac_phy = "mac_phy" in header
            for row_values in reader:
                if len(row_values) < 2:
                    continue
                if row_values[1] != "snapshot":
                    continue
                if has_old_mac_phy and len(row_values) == len(FIELDNAMES):
                    r = dict(zip(FIELDNAMES, row_values))
                elif len(row_values) <= len(header):
                    r = dict(zip(header, row_values + [""] * (len(header) - len(row_values))))
                else:
                    r = dict(zip(header, row_values[: len(header)]))
                rows.append(_sanitize_log_entry(r))
    except Exception:
        return []
    return rows


def delete_entry_at_index(index: int) -> bool:
    """Delete the entry at index (0-based, newest-first order). Returns True if deleted."""
    path = _log_path()
    rows = _read_all_rows()
    if index < 0 or index >= len(rows):
        return False
    newest_first = list(reversed(rows))
    newest_first.pop(index)
    file_order = list(reversed(newest_first))
    _ensure_log()
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDNAMES)
        w.writeheader()
        for r in file_order:
            row = {k: r.get(k, "") for k in FIELDNAMES}
            row["type"] = "snapshot"
            w.writerow(row)
        f.flush()
        os.fsync(f.fileno())
    return True


def read_log_page(page: int = 1, per_page: int = 20, newest_first: bool = True) -> tuple[list, int]:
    """Return (list of entry dicts for this page, total count)."""
    rows = _read_all_rows()
    total = len(rows)
    if newest_first:
        rows = list(reversed(rows))
    start = (page - 1) * per_page
    page_rows = rows[start : start + per_page]
    return page_rows, total
