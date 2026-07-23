# LLDProwl

LLDProwl is a small FastAPI web app that captures LLDP and Cisco Discovery
Protocol (CDP) frames from a selected network interface, displays the connected
switch and port, runs optional ping checks, and stores snapshots in CSV format.

It is intended to run on Linux (including Raspberry Pi OS), macOS, and Windows.
Packet capture requires elevated capture privileges and a libpcap-compatible
driver.

## Local setup

Requirements:

- Python 3.10 or newer
- Linux: `libpcap` and `iputils-ping`
- macOS: libpcap is included; Wireshark's ChmodBPF component is the preferred
  way to grant non-root capture access
- Windows: Npcap in WinPcap-compatible mode

Create an environment and install the Python packages:

```bash
git clone <repo-url>
cd lldprowl
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python main.py
```

On Windows PowerShell, activate with `.venv\Scripts\Activate.ps1` instead of
the `source` command.

Open <http://127.0.0.1:8001>. On first load, LLDProwl selects the first
connected non-loopback interface. You can choose another interface in the UI.

The web app works without capture privileges, but starting an LLDP/CDP sniff
does not. Prefer Wireshark's ChmodBPF component on macOS and the capability-
limited systemd unit on Linux. If you temporarily run the local process with
`sudo`, restore ownership of `data/` before returning to a normal user account;
otherwise History saves can fail.

Runtime settings are controlled with environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `LLDPROWL_HOST` | `127.0.0.1` | Address used by `python main.py` |
| `LLDPROWL_PORT` | `8001` | HTTP port used by `python main.py` |
| `LLDPROWL_DATA_DIR` | `./data` | Writable config and CSV directory |

For LAN access during a local run:

```bash
LLDPROWL_HOST=0.0.0.0 python main.py
```

Binding to `0.0.0.0` exposes the app's unauthenticated configuration and log
endpoints to the network. Use it only on a trusted LAN or place it behind an
authenticated reverse proxy.

## Raspberry Pi OS installation

These instructions work on current 32-bit and 64-bit Raspberry Pi OS releases.
They install the code read-only under `/opt` and keep mutable state under
`/var/lib/lldprowl`.

```bash
sudo apt update
sudo apt install -y git python3-venv libpcap-dev iputils-ping
sudo useradd --system --home-dir /opt/lldprowl --shell /usr/sbin/nologin lldprowl
sudo git clone <repo-url> /opt/lldprowl
sudo python3 -m venv /opt/lldprowl/.venv
sudo /opt/lldprowl/.venv/bin/python -m pip install -r /opt/lldprowl/requirements.txt
sudo cp /opt/lldprowl/systemd/lldprowl.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now lldprowl
```

The included unit grants only `CAP_NET_RAW` and `CAP_NET_ADMIN` to the service;
it does not run the web app as root. It also creates and owns
`/var/lib/lldprowl` automatically. LLDProwl must use exactly one Uvicorn worker
because capture and live discovery state are process-local. The included unit
sets `--workers 1` explicitly.

Verify the service:

```bash
systemctl status lldprowl
curl http://127.0.0.1:8001/api/health
journalctl -u lldprowl -n 50 --no-pager
```

From another device, open `http://<pi-address>:8001`. If a firewall is enabled,
allow TCP port 8001 only from the trusted management network.

To update an existing installation:

```bash
sudo git -C /opt/lldprowl pull --ff-only
sudo /opt/lldprowl/.venv/bin/python -m pip install -r /opt/lldprowl/requirements.txt
sudo systemctl restart lldprowl
```

## Data

- `config.json`: selected interface and up to 50 ping targets
- `detection_history.csv`: saved switch/port snapshots

Local runs store these files in `data/`. The systemd service stores them in
`/var/lib/lldprowl`, so code updates do not overwrite runtime data.

Detection History can be searched across all saved fields and filtered by
protocol, ping outcome, and date range. Older CSV files are upgraded
automatically on the next save; existing rows are identified as LLDP. Parsed
rows are cached until the CSV changes, keeping repeated History refreshes cheap
while retaining a directly downloadable CSV.

## Development checks

```bash
python -m unittest discover -s tests -v
python -m compileall -q .
```

Live discovery can only be fully verified on a host connected to a switch port
with LLDP or CDP enabled.
