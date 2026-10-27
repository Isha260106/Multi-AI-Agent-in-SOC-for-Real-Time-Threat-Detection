# Sensor Installation & Adapter Configuration Guide

> **Project:** Multi-Agent AI SOC for Real-Time Threat Detection  
> **Component:** Sensor VM (`soc-sensor-vm`) & Telemetry Streaming  
> **Target OS:** Ubuntu Server 22.04 LTS (x86_64)  
> **Host OS:** Windows 11 Home (`192.168.56.1`)

---

## 1. Sensor Selection Analysis: The 78-Feature Mandate

The Multi-Agent SOC machine learning pipeline (`models/network_detection_model.pkl` Random Forest classifier) expects an exact vector of **78 bidirectional network flow metrics** originating from the CSE-CIC-IDS2018 benchmark.

### 1.1 Why Traditional NIDS Logs Fail the 78-Feature Schema

| Engine | Log Artifact | Available Fields | Missing Mandatory Model Features | Verdict |
| :--- | :--- | :--- | :--- | :---: |
| **Zeek** | `conn.log` | Duration, Total Bytes/Pkts, Conn State, Service | Forward/Backward IAT (Mean, Std, Min, Max), Pkt Length Skew/Variance, Subflow Fwd/Bwd Bytes, Bulk Rates | **Incompatible** (Fails 50+ features) |
| **Suricata** | `eve.json` (flow) | Start/End, Bytes, Packets, TCP Flags | Packet Length Statistical Moments (Variance, Std Dev), Inter-Arrival Time distributions, Active/Idle timing | **Incompatible** (Fails 40+ features) |
| **CICFlowMeter** | `flows.csv` | **83 Bidirectional statistical flow features** | None. All 78 canonical model features are present and calculated over complete flow lifecycles. | **100% Compatible** (Satisfies all 78 features) |

> [!NOTE]
> Zeek and Suricata are valuable for signature detection and protocol decoding, but they cannot replace a statistical bidirectional flow meter for our trained Random Forest model.

### 1.2 Selected Tool: Python `cicflowmeter`
We deploy the Python implementation of `cicflowmeter` (`hieulw/cicflowmeter` / `cicflowmeter` CLI) inside the Sensor VM. It uses `scapy` / `libpcap` to aggregate packets into bidirectional flows, tracks TCP/UDP sessions, computes all 83 statistical properties upon flow timeout or termination (FIN/RST), and outputs CSV rows.

---

## 2. Sensor VM OS Prerequisites & Package Installation

Log in to the Sensor VM (`soc-sensor-vm`) via VirtualBox console or SSH:

```bash
# 1. Update package lists
sudo apt-get update && sudo apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    libpcap-dev \
    tcpdump \
    ethtool \
    curl \
    jq \
    git

# 2. Create dedicated unprivileged system user for the SOC telemetry daemon
sudo useradd -r -s /bin/false -d /opt/soc-sensor socservice
sudo usermod -aG sudo socservice 2>/dev/null || true

# 3. Create working directories
sudo mkdir -p /opt/soc-sensor
sudo mkdir -p /var/log/soc
sudo chown -R socservice:socservice /opt/soc-sensor /var/log/soc
sudo chmod 755 /var/log/soc
```

---

## 3. Python Environment & Dependency Setup

Set up an isolated Python virtual environment on the Sensor VM:

```bash
# 1. Initialize virtual environment in /opt/soc-sensor/venv
sudo -u socservice python3 -m venv /opt/soc-sensor/venv

# 2. Upgrade core tooling
sudo -u socservice /opt/soc-sensor/venv/bin/pip install --upgrade pip setuptools wheel

# 3. Install cicflowmeter and HTTP streaming dependencies
sudo -u socservice /opt/soc-sensor/venv/bin/pip install \
    cicflowmeter==0.1.6 \
    requests>=2.28.0 \
    pydantic>=2.0.0

# 4. Grant Python binary capability to capture raw packets without root
sudo setcap cap_net_raw,cap_net_admin=eip /opt/soc-sensor/venv/bin/python3
```

---

## 4. Deploying the Live Flow Adapter (`live_adapter.py`)

The Sensor VM runs `kafka.live_adapter` to read new CSV rows incrementally, normalize column headers, apply valid median imputations, build authenticated payloads, and POST them to the Windows host.

### 4.1 Copy Adapter Code to Sensor VM
From the Windows host, copy the adapter module to `/opt/soc-sensor/`:
```bash
# Example scp or direct file placement:
# scp e:\multi-agent-soc\kafka\live_adapter.py soc@192.168.56.10:/opt/soc-sensor/live_adapter.py
```

Ensure correct ownership:
```bash
sudo chown socservice:socservice /opt/soc-sensor/live_adapter.py
```

### 4.2 Adapter Execution Parameters
The adapter accepts runtime configuration through command-line flags or environment variables:

| Argument | Environment Variable | Default | Description |
| :--- | :--- | :--- | :--- |
| `--csv-file` | `SOC_CSV_PATH` | `/var/log/soc/flows.csv` | File written by `cicflowmeter` |
| `--target-url` | `SOC_INGEST_URL` | `http://192.168.56.1:8000/api/ingest/flow` | Windows Host Ingestion endpoint |
| `--api-key` | `SOC_SENSOR_KEY` | *(Required)* | Shared secret matching host `.env` |
| `--batch-size` | `SOC_BATCH_SIZE` | `25` | Maximum flows sent per HTTP POST |
| `--poll-interval` | `SOC_POLL_INTERVAL`| `1.0` | Seconds to wait between file checks |

---

## 5. Systemd Daemon Configurations

To ensure headless, persistent operation, two systemd service units are established on the Sensor VM:

### 5.1 `cicflowmeter.service` (Packet Sniffing Daemon)
Create `/etc/systemd/system/cicflowmeter.service`:

```ini
[Unit]
Description=CICFlowMeter Live Network Flow Capture Daemon
After=network.target sensor-interface-tuning.service
Requires=sensor-interface-tuning.service

[Service]
Type=simple
User=root
# Sniffs enp0s3 (lab_internal) and writes completed flows to CSV
ExecStart=/opt/soc-sensor/venv/bin/cicflowmeter -i enp0s3 -c -u /var/log/soc/flows.csv
Restart=always
RestartSec=3
KillMode=process

# Resource safety limits
LimitNOFILE=65535
MemoryMax=1500M

[Install]
WantedBy=multi-user.target
```

### 5.2 `soc-adapter.service` (Streaming Ingestion Daemon)
Create `/etc/systemd/system/soc-adapter.service`:

```ini
[Unit]
Description=SOC Live Flow Normalization and Ingestion Adapter
After=network.target cicflowmeter.service
Requires=cicflowmeter.service

[Service]
Type=simple
User=socservice
WorkingDirectory=/opt/soc-sensor
Environment=PYTHONPATH=/opt/soc-sensor
Environment=SOC_SENSOR_KEY=soc-sensor-dev-key-2026
ExecStart=/opt/soc-sensor/venv/bin/python3 -m live_adapter \
    --csv-file /var/log/soc/flows.csv \
    --target-url http://192.168.56.1:8000/api/ingest/flow \
    --api-key soc-sensor-dev-key-2026 \
    --batch-size 25 \
    --poll-interval 1.0
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and reload both services:
```bash
sudo systemctl daemon-reload
sudo systemctl enable cicflowmeter.service
sudo systemctl enable soc-adapter.service
```

---

## 6. Windows Host Backend Setup & Secure Connectivity

The FastAPI backend must be reachable by the Sensor VM on `192.168.56.1` while remaining isolated from the home/campus Wi-Fi network.

### 6.1 Host Ingestion Secret Configuration
Configure `SOC_SENSOR_KEY` on the Windows host. In PowerShell:

```powershell
# Set environment variable in session or add to .env file in e:\multi-agent-soc:
$env:SOC_SENSOR_KEY="soc-sensor-dev-key-2026"

# Verify .env in e:\multi-agent-soc contains matching key
Add-Content -Path "e:\multi-agent-soc\.env" -Value "`nSOC_SENSOR_KEY=soc-sensor-dev-key-2026"
```

### 6.2 Host Ingestion Service Binding
Start the SOC API server bound strictly to the Host-Only interface:

```powershell
cd E:\multi-agent-soc
$env:SOC_SENSOR_KEY="soc-sensor-dev-key-2026"
python -m uvicorn dashboard_api:app --host 192.168.56.1 --port 8000 --reload
```

> [!CAUTION]
> Do NOT bind the API server to `0.0.0.0` unless Windows Defender Firewall specifically blocks all interfaces except the VirtualBox Host-Only adapter. Binding directly to `192.168.56.1` ensures the endpoint is physically unreachable from the external LAN (`192.168.21.0/24`).

### 6.3 Windows Firewall Verification
If the Sensor VM cannot connect to `192.168.56.1:8000`, add an explicit inbound allow rule for the VirtualBox subnet only:

```powershell
# Run as Administrator in PowerShell:
New-NetFirewallRule -DisplayName "SOC Lab Ingestion (Host-Only)" `
    -Direction Inbound `
    -LocalIP 192.168.56.1 `
    -LocalPort 8000 `
    -Protocol TCP `
    -Action Allow
```

---

## 7. Verifying Sensor-to-Host Connectivity

Inside the Sensor VM, execute a diagnostic curl request to verify network routing and authentication:

```bash
# 1. Test basic connectivity and model health endpoint (Public GET)
curl -s http://192.168.56.1:8000/api/models/health | jq .

# Expected Response:
# {
#   "status": "ok",
#   "models": {
#     "network_detection": {"loaded": true, ...},
#     "anomaly_detection": {"loaded": true, ...}
#   }
# }

# 2. Test authenticated ingestion endpoint with invalid key (Should return 401)
curl -s -o /dev/null -w "%{http_code}\n" -X POST http://192.168.56.1:8000/api/ingest/flow \
  -H "Content-Type: application/json" \
  -H "X-SOC-Sensor-Key: wrong-key" \
  -d '{"events": []}'
# Expected Output: 401

# 3. Test authenticated ingestion endpoint with valid key (Should return 200)
curl -s -X POST http://192.168.56.1:8000/api/ingest/flow \
  -H "Content-Type: application/json" \
  -H "X-SOC-Sensor-Key: soc-sensor-dev-key-2026" \
  -d '{"events": []}'
# Expected Response: {"status":"accepted","received_count":0,"accepted_count":0,...}
```
