# Live Monitoring Validation Playbook & Safe Scan Scenarios

> **Project:** Multi-Agent AI SOC for Real-Time Threat Detection  
> **Component:** Phase 3 Validation & Lab Execution Playbook  
> **Target Network:** `lab_internal` (`10.10.10.0/24`)  
> **Target Systems:** Attacker VM (`10.10.10.100`), Victim VM (`10.10.10.20`), Sensor VM (`10.10.10.10`)  
> **Host Backend:** Windows 11 Host (`192.168.56.1:8000`)

---

## 1. Safety Boundaries & Code-Freeze Rules

Before executing any commands in this playbook, review the strict operational rules:

> [!CAUTION]
> 1. **Zero External Exposure:** The Attacker VM and Victim VM must **NEVER** have interfaces bridged to the host Wi-Fi (`192.168.21.0/24`) or the internet. All scanning traffic must remain strictly confined to the internal virtual switch `lab_internal`.
> 2. **Explicit User Approval:** Do not run port scans, generate attack traffic, modify host firewall rules, or make configuration changes without explicit confirmation.
> 3. **Truthful Verification:** Do not report that packet capture works until verified with live tcpdump traces and generated CSV flow records.
> 4. **No Code Retraining:** Do not retrain or overwrite the existing saved models (`models/network_detection_model.pkl`, `models/anomaly_detection_model.pkl`).

---

## 2. Lab Pre-Flight Checks & Ordered Startup Sequence

Components must be started in the following strict sequential order to prevent dropped events or connection failures:

```
Step 1: Windows Host API Backend (FastAPI on 192.168.56.1:8000)
   |
Step 2: Windows Host Dashboard UI (Vite dev server on localhost:5173)
   |
Step 3: Victim VM (Ubuntu 22.04 LTS - Nginx web server active on 10.10.10.20)
   |
Step 4: Sensor VM (Ubuntu 22.04 LTS - Promiscuous capture & adapter streaming)
   |
Step 5: Attacker VM (Ubuntu / Kali - Benign traffic generation & lab testing)
```

### 2.1 Step 1: Start Windows Host Backend
In a Windows PowerShell window:
```powershell
cd E:\multi-agent-soc
$env:SOC_SENSOR_KEY="soc-sensor-dev-key-2026"
python -m uvicorn dashboard_api:app --host 192.168.56.1 --port 8000
```
Verify listener:
```powershell
curl http://192.168.56.1:8000/api/models/health
```

### 2.2 Step 2: Start Windows Host Dashboard
In a separate terminal:
```powershell
cd E:\multi-agent-soc
npm run dev
# Dashboard opens on http://localhost:5173
```

### 2.3 Step 3: Boot Victim VM
```cmd
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" startvm "soc-victim-vm" --type headless
```
Inside the Victim VM, verify Nginx is serving on port 80:
```bash
sudo systemctl status nginx
curl -I http://10.10.10.20/
```

### 2.4 Step 4: Boot Sensor VM
```cmd
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" startvm "soc-sensor-vm" --type headless
```
Inside the Sensor VM, verify promiscuous mode and services:
```bash
ip link show enp0s3 | grep PROMISC
sudo systemctl status cicflowmeter.service
sudo systemctl status soc-adapter.service
```

### 2.5 Step 5: Boot Attacker VM
```cmd
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" startvm "soc-attacker-vm" --type headless
```
Verify connectivity from Attacker to Victim:
```bash
ping -c 3 10.10.10.20
curl -I http://10.10.10.20/
```

---

## 3. Benign-Traffic Validation Procedure (Mandatory First Step)

Before executing any scan scenarios, baseline benign traffic must be generated and verified through the entire SOC pipeline.

### 3.1 Generate Benign Workload from Attacker VM
Execute the automated benign traffic generator on the Attacker VM (`soc-attacker-vm`):

```bash
# Run benign traffic script (downloads web pages, small files, and API endpoints)
python3 /opt/soc/scripts/attacker_benign_traffic.py \
    --target-ip 10.10.10.20 \
    --duration-sec 60 \
    --requests-per-min 120
```

*Or manually using a bash curl loop:*
```bash
for i in {1..50}; do
    curl -s -o /dev/null "http://10.10.10.20/index.html?session=$i"
    curl -s -o /dev/null -X POST "http://10.10.10.20/api/test" -d "data=sample_test_value_$i"
    sleep 0.5
done
```

### 3.2 Verify Flow Capture on Sensor VM
Inspect the Sensor VM to confirm that packets were assembled into bidirectional flows:

```bash
# 1. Verify packet sniffer is observing packets
sudo tcpdump -i enp0s3 -nn -c 10 "host 10.10.10.20"

# 2. Check that completed flows are appended to CSV
sudo tail -n 5 /var/log/soc/flows.csv

# 3. Check live adapter streaming logs
sudo journalctl -u soc-adapter.service -n 20 --no-pager
# Expected log line:
# INFO: LiveFlowTailer: Sent 15 flows to http://192.168.56.1:8000/api/ingest/flow (status: 200, accepted: 15)
```

### 3.3 Verify Ingestion and Pipeline Execution on Host
Check the Windows host terminal and database:

1. **Uvicorn Server Console:**
   ```
   INFO: Ingested 15 flows: 15 accepted, 0 duplicate, 0 validation errors. Max latency: 18.2ms.
   ```
2. **SQLite Database Verification (`soc.db`):**
   ```powershell
   python -c "import sqlite3; con=sqlite3.connect('soc.db'); print(con.execute('SELECT count(*), threat_category, severity FROM events GROUP BY threat_category, severity').fetchall())"
   ```
   **Expected Result:**
   - `threat_category`: `Benign`
   - `severity`: `LOW`
   - `anomaly_score`: In normal range (< 0.60)
3. **Dashboard Inspection (`http://localhost:5173`):**
   - **Total Events Counter:** Increments in real time.
   - **Threat Category Distribution:** Displays 100% `Benign`.
   - **Active Incidents Table:** Zero incidents escalated to investigation.

---

## 4. Safe, Authorized Lab-Only Scan Scenarios

Once benign baseline traffic has been successfully verified, execute authorized security testing scenarios within `lab_internal`.

### 4.1 Scenario A: Low-Rate TCP SYN Port Sweep (Reconnaissance)
Simulate network reconnaissance targeting the Victim VM web server:

```bash
# Execute from Attacker VM (10.10.10.100) targeting ONLY Victim VM (10.10.10.20):
nmap -sS -p 21,22,80,443,3306,8080 -T3 10.10.10.20
```

#### What Happens in the Network:
- Rapid TCP SYN packets are transmitted across multiple ports.
- Closed ports reply with TCP RST. Open ports reply with SYN-ACK.
- Flows have low duration, zero backward payload bytes, and distinctive flag counts (`SYN Flag Cnt = 1`, `RST Flag Cnt = 1`).

#### Expected SOC Pipeline Behavior:
1. **Sensor Capture:** `cicflowmeter` aggregates the probes into individual flows and flushes them to `/var/log/soc/flows.csv`.
2. **Adapter Normalization:** `LiveFlowTailer` converts features, computes header statistics, and posts payload to host.
3. **ML Classification:**
   - Isolation Forest calculates high anomaly score (> 0.65) due to asymmetric packet/byte ratios.
   - Random Forest or Correlation Engine flags scan activity.
4. **Unified Threat Assessment:** Evaluates threat level to `MEDIUM` or `HIGH`.
5. **Dashboard Verification:**
   - "Alerts" tab shows incoming port scan events with timestamp and source IP `10.10.10.100`.
   - Threat matrix updates.

---

### 4.2 Scenario B: Simulated Web Path Fuzzing / Infiltration
Simulate rapid HTTP directory enumeration targeting the Victim VM web server:

```bash
# Execute from Attacker VM (10.10.10.100):
for path in admin login config backup private secret test v1 v2 db shell cgi-bin; do
    curl -s -o /dev/null -w "%{http_code}\n" "http://10.10.10.20/$path"
    sleep 0.1
done
```

#### Expected SOC Pipeline Behavior:
1. **Flow Metric Characteristics:** High `Fwd Pkts/s`, high `Flow Byts/s`, high HTTP 404 response rate.
2. **ML Classification:** Random Forest model flags flow patterns matching `Infilteration` or `DoS-Syn` signatures.
3. **Multi-Agent Escalation:**
   - Alert Correlation Engine aggregates repeated anomaly events from `10.10.10.100`.
   - Threat Assessment raises incident severity to `HIGH`.
   - **Stage 10 Automated Investigation:** Coordinator triggers deep forensic investigation.
4. **Dashboard Verification:**
   - Active Incidents table populates with a new incident.
   - Clicking the incident reveals investigation timeline, MITRE ATT&CK mapping (`T1595.002 - Vulnerability Scanning`), and recommended containment actions.

---

## 5. Comprehensive Troubleshooting Guide

| Symptom | Probable Cause | Diagnostic Command & Remediation |
| :--- | :--- | :--- |
| **`flows.csv` remains empty** on Sensor VM | Promiscuous mode not enabled on VirtualBox switch | Check with `VBoxManage getvminfo "soc-sensor-vm" \| grep Promisc`. Fix with `VBoxManage modifyvm "soc-sensor-vm" --nicpromisc1 allow-all`. |
| **`flows.csv` remains empty** (Kernel issue) | Checksum offloading enabled | Run `sudo ethtool -K enp0s3 rx off tx off tso off gso off gro off`. |
| **`soc-adapter` HTTP 401 Unauthorized** | `SOC_SENSOR_KEY` mismatch | Verify key in Sensor `/etc/systemd/system/soc-adapter.service` matches Host Windows PowerShell `$env:SOC_SENSOR_KEY`. |
| **`soc-adapter` HTTP 422 Unprocessable** | Incompatible CSV schema or missing feature | Check sensor logs: `journalctl -u soc-adapter -n 30`. Verify CSV contains required aliases; `LiveFlowAdapter` will log missing fields. |
| **`soc-adapter` HTTP 413 Payload Too Large** | Batch size exceeds 1 MB limit | In `soc-adapter.service`, lower `--batch-size` from `25` to `10`. |
| **Sensor cannot connect to `192.168.56.1:8000`** | Windows Firewall blocking Host-Only port | In Windows PowerShell, run: `Test-NetConnection -ComputerName 192.168.56.1 -Port 8000`. Add firewall rule for 192.168.56.0/24 subnet. |
| **Sensor cannot connect to `192.168.56.1:8000`** | Host backend bound to `127.0.0.1` | Verify Uvicorn startup flag: must be `--host 192.168.56.1`, not `127.0.0.1` or `localhost`. |

---

## 6. Teardown & Cleanup Instructions

When testing is complete, restore the environment to an idle, clean state:

### 6.1 Stop Sensor Streaming Services (Inside Sensor VM)
```bash
sudo systemctl stop soc-adapter.service
sudo systemctl stop cicflowmeter.service
# Optionally archive or truncate the lab flow log:
sudo truncate -s 0 /var/log/soc/flows.csv
```

### 6.2 Graceful VM Shutdown (From Windows Host)
```cmd
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" controlvm "soc-attacker-vm" acpipowerbutton
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" controlvm "soc-victim-vm" acpipowerbutton
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" controlvm "soc-sensor-vm" acpipowerbutton
```

### 6.3 Complete Lab Deletion (If Decommissioning Lab)
To remove the lab VMs and reclaim host disk space:
```cmd
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" unregistervm "soc-attacker-vm" --delete
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" unregistervm "soc-victim-vm" --delete
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" unregistervm "soc-sensor-vm" --delete
rmdir /s /q "%VM_DIR%"
```

### 6.4 Clean Host Firewall Rules
```powershell
Remove-NetFirewallRule -DisplayName "SOC Lab Ingestion (Host-Only)" -ErrorAction SilentlyContinue
```

---

## 7. End-to-End Operational Checklist

Before declaring Phase 3 operational, check off each item:

- [ ] **Hypervisor & Network Isolation:**
  - [ ] VirtualBox 7.0+ installed and verified on Windows 11 Home.
  - [ ] Host-Only adapter `192.168.56.1/24` configured with DHCP disabled.
  - [ ] Internal Network `lab_internal` has zero routing to home Wi-Fi (`192.168.21.0/24`).
- [ ] **VM Provisioning:**
  - [ ] Sensor VM configured with 2 vCPU, 4GB RAM, NIC1 (`intnet` promisc `allow-all`), NIC2 (Host-Only).
  - [ ] Victim VM configured with 1 vCPU, 2GB RAM, NIC1 (`intnet`), Nginx active.
  - [ ] Attacker VM configured with 1 vCPU, 2GB RAM, NIC1 (`intnet`).
- [ ] **Sensor & Adapter Deployment:**
  - [ ] `cicflowmeter` installed and capturing on `enp0s3`.
  - [ ] Checksum offloading disabled on `enp0s3` (`ethtool -K`).
  - [ ] `LiveFlowTailer` active and tailing `/var/log/soc/flows.csv`.
  - [ ] `SOC_SENSOR_KEY` authenticated against `http://192.168.56.1:8000/api/ingest/flow`.
- [ ] **Traffic Validation:**
  - [ ] Benign HTTP loop executed from Attacker VM.
  - [ ] Sensor generates flow records in CSV.
  - [ ] Host API receives and persists events in `soc.db`.
  - [ ] Events classified as `Benign` with `LOW` severity and no erroneous incident escalation.
  - [ ] Authorized SYN scan executed from Attacker VM.
  - [ ] Model flags scan activity, updates Dashboard counters, and displays incident telemetry.
