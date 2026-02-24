# LLDProwl

Gather network switch information for the connected port and log detection history.

## Description

LLDProwl is a web app that captures LLDP frames on a selected network interface and displays the connected switch and port details (chassis ID, system name, port ID/description, VLAN, management address, capabilities). It uses Scapy to sniff LLDP traffic. You can add notes, run ping tests against configurable IPs, and save snapshots to a CSV log. Detection history is paged in the UI with options to download the log, delete individual entries, or purge the log. The UI is a single-page app with a dark, Fluke-style theme. Cross-platform: Linux, macOS, Windows.

## Prerequisites

- **Python 3.9+**
- **Packet capture**: Npcap (Windows) or libpcap (Linux/macOS) so Scapy can capture on interfaces. Wireshark installs the drivers needed; if Wireshark is already installed, no further action is required for capture support.

## Usage

1. **Install the required Python modules**

   ```bash
   git clone <repo-url>
   cd LLDProwl
   python3 -m venv venv
   source venv/bin/activate   # Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

2. **Run the app**

   ```bash
   python main.py
   ```

   Or with uvicorn:

   ```bash
   uvicorn main:app --host 0.0.0.0 --port 8000
   ```

   Open **http://localhost:8000** in a browser.

3. **In the UI**

   - Choose the **interface** from the dropdown (Local Interface card).
   - Optionally set **Ping IPs** (comma-separated), click Save, then **Ping Now**.
   - Click **Start Sniff** on the Connected Switch card to capture LLDP. Switch/port details and optional notes appear there; click **Save** to append a snapshot to Detection History.
   - Use **Detection History** to view, download (CSV), delete rows, or purge the log.

**Note:** On Linux, raw packet capture usually requires either running as root (`sudo python main.py`) or setting capabilities on the Python binary:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))
```

## Configuration

- **`data/config.json`** (created on first run): `interface` (e.g. `eth0`, `en0`), `ping_targets` (list of IPs/hostnames, max 50).
- **`data/detection_history.csv`**: Snapshot log (timestamp, system name, management address, port ID, port description, VLAN, switch MAC, chassis, caps, local IP, ping results, notes).

## Systemd (e.g. Raspberry Pi)

```bash
sudo cp systemd/lldprowl.service /etc/systemd/system/
# Edit User=, WorkingDirectory=, ExecStart= to match your install
sudo systemctl daemon-reload
sudo systemctl enable lldprowl
sudo systemctl start lldprowl
```

## About

Utility to get network switch information and check connectivity via LLDP and ping, with CSV detection history and a web UI.
