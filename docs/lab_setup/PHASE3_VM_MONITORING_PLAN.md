# Phase 3: Live VM-Based Monitoring Lab Architecture & Implementation Plan

> **Multi-Agent AI SOC Project**  
> **Status:** Planning & Setup Specification  
> **Target Environment:** Windows 11 Home Host + Oracle VM VirtualBox 7.0+  
> **Safety Level:** Isolated Lab-Only (Zero External Routing / Zero Public Exposure)

---

## 1. Executive Summary & Objectives

Phase 1 established an authenticated, size-limited, 78-feature ingestion endpoint (`POST /api/ingest/flow`) wired directly to the complete multi-agent pipeline and central SQLite storage. Phase 2 delivered the `LiveFlowAdapter` and incremental `LiveFlowTailer` (`kafka/live_adapter.py`) capable of normalizing live sensor CSV outputs, mapping 275+ column aliases to the 78 canonical model features, isolating metadata, and performing legitimate cell-level imputation without fabricating statistics.

**Phase 3** defines the planning, architecture, and step-by-step setup documentation required to deploy a fully isolated virtual machine laboratory. This lab will produce genuine live network packets, convert them into bidirectional flow records via an in-guest sensor, normalize them via `kafka.live_adapter`, and stream them into the host-hosted SOC pipeline.

```
       ========================================================================================
                                     ISOLATED LAB ENVIRONMENT
       ========================================================================================

       +-----------------------------------+             +-----------------------------------+
       |            Attacker VM            |             |             Victim VM             |
       |     (Kali Linux / Minimal OS)     |             |      (Ubuntu Server 22.04 LTS)    |
       |                                   |             |                                   |
       |  eth0: 10.10.10.100/24            |             |  eth0: 10.10.10.20/24             |
       |  (Benign generator & nmap)        |             |  (Nginx HTTP/HTTPS Target)        |
       +-----------------+-----------------+             +-----------------+-----------------+
                         |                                                 |
                         +------------------------+------------------------+
                                                  |
                                                  | VirtualBox Internal Network: "lab_internal"
                                                  | (10.10.10.0/24 - Fully Isolated Virtual Switch)
                                                  v
                               +-----------------------------------+
                               |             Sensor VM             |
                               |      (Ubuntu Server 22.04 LTS)    |
                               |                                   |
                               |  eth0: 10.10.10.10/24 (Promisc)   |
                               |  [ cicflowmeter packet sniffer ]  |
                               |                |                  |
                               |                v writes flows     |
                               |       /var/log/soc/flows.csv      |
                               |                |                  |
                               |                v tails & sends    |
                               |       [ kafka.live_adapter ]      |
                               |                                   |
                               |  eth1: 192.168.56.10/24           |
                               +-----------------+-----------------+
                                                 |
                                                 | VirtualBox Host-Only: "vboxnet0"
                                                 | (192.168.56.0/24 - Host-to-Sensor Only)
                                                 v
       ========================================================================================
                                          WINDOWS 11 HOST OS
       ========================================================================================
       |                                                                                      |
       |  VirtualBox Host-Only Adapter: 192.168.56.1                                          |
       |                                                                                      |
       |  FastAPI SOC Dashboard & Pipeline Backend:                                           |
       |    Listening on: http://192.168.56.1:8000/api/ingest/flow                            |
       |    Authentication: Header 'X-SOC-Sensor-Key: <SOC_SENSOR_KEY>'                       |
       |                                                                                      |
       |  Complete Multi-Agent SOC Pipeline:                                                  |
       |    1. Network Detection (Random Forest - 78 features)                                |
       |    2. Anomaly Detection (Isolation Forest)                                           |
       |    3. Alert Correlation Engine (Multi-Agent Synthesis)                               |
       |    4. Unified Threat Assessment (Deterministic Policy Engine)                        |
       |    5. Threat Investigation Coordinator (Stage 10 Automated Deep Forensics)           |
       |    6. Central Storage (SQLite soc.db WAL)                                            |
       |    7. Real-Time SOC Dashboard (Vite / React on localhost:5173)                       |
       ========================================================================================
```

---

## 2. Host Environment Assessment & Hypervisor Selection

### 2.1 Audit of Existing Host Environment
An inspection of the host operating system yielded the following baseline:
- **Operating System:** Microsoft Windows 11 Home Single Language (64-bit), Build 26100.
- **Physical Network Adapters:** Intel(R) Wi-Fi 6E AX211 (`192.168.21.112`), Realtek Gaming GbE (`Disconnected`).
- **Existing Hypervisors:** 
  - `VBoxManage` / VirtualBox: Not installed.
  - `vmrun` / VMware Workstation: Not installed.
  - Native Hyper-V: Not available (Windows 11 Home lacks native Hyper-V Manager / VMMS).
  - WSL2: Installed (`Ubuntu` default distribution present).

### 2.2 Hypervisor Decision: Oracle VM VirtualBox 7.0+
**Oracle VM VirtualBox 7.0.x** is the selected platform for this lab:
1. **Windows 11 Home Compatibility:** VirtualBox runs natively on Windows 11 Home using the Windows Hypervisor Platform (WHP) backend without requiring Windows Pro or registry hacks.
2. **True Air-Gapped Internal Switching:** VirtualBox provides native Internal Networks (`intnet`) implemented entirely within hypervisor memory. Traffic generated inside `intnet` is physically isolated from the host's Wi-Fi network (`192.168.21.0/24`).
3. **Promiscuous Mode Support:** VirtualBox supports setting guest adapters into Promiscuous Mode (`Allow All` / `allow-all`), allowing the Sensor VM to monitor all unicast, multicast, and broadcast frames exchanged between other VMs on the internal switch.
4. **Reproducibility:** VirtualBox configuration can be completely scripted via `VBoxManage` commands.

---

## 3. Lab Network Topology & Traffic Observation

### 3.1 Network Addressing Architecture

The lab implements a **dual-network isolation architecture**:

| Network Name | VirtualBox Type | Subnet | Scope & Security Boundaries |
| :--- | :--- | :--- | :--- |
| **`lab_internal`** | Internal Network (`intnet`) | `10.10.10.0/24` | **Air-gapped lab traffic.** Connects Attacker VM (`10.10.10.100`), Victim VM (`10.10.10.20`), and Sensor VM monitoring port (`10.10.10.10`). Zero routing to the host or internet. |
| **`soc_management`**| Host-Only Network | `192.168.56.0/24` | **Sensor telemetry egress only.** Connects Sensor VM management port (`192.168.56.10`) to Windows Host (`192.168.56.1`). Attacker and Victim VMs have **no** interface on this network. |

### 3.2 Promiscuous Mode & Virtual Switch Requirements

Virtual switches in modern hypervisors generally forward unicast traffic only to the designated MAC address of the destination port. To enable the Sensor VM to observe packets exchanged between the Attacker VM and the Victim VM, the following settings are required:

1. **VirtualBox Hypervisor Setting:**
   The Sensor VM's primary adapter (`eth0` on `lab_internal`) must have promiscuous mode enabled:
   ```cmd
   VBoxManage modifyvm "SOC-Sensor-VM" --nicpromisc1 allow-all
   ```
2. **Guest Operating System Setting:**
   Inside the Sensor VM, the Linux kernel must place interface `eth0` into promiscuous mode:
   ```bash
   sudo ip link set eth0 promisc on
   ```
3. **Hardware Checksum Offloading Disabled:**
   When capturing synthetic or replayed packets, TCP checksum offloading can cause packet sniffer libraries (e.g. Scapy / libpcap) to drop packets with uncalculated checksums:
   ```bash
   sudo ethtool -K eth0 rx off tx off tso off gso off
   ```

#### Alternative Observation Topology: In-Line Sensor Bridge / Router
If the host Windows Hypervisor Platform (WHP) driver prevents full promiscuous frame replication on `intnet`, use the **In-Line Sensor Gateway Topology**:
- Attacker on `intnet_attack` (`10.10.10.0/24`), Gateway = `10.10.10.1` (Sensor `eth0`).
- Victim on `intnet_victim` (`10.10.20.0/24`), Gateway = `10.10.20.1` (Sensor `eth1`).
- Sensor VM enables IP forwarding (`net.ipv4.ip_forward = 1`) and sniffs the forward path. Every single packet between attacker and victim physically traverses the Sensor VM, guaranteeing 100% flow observation without relying on hypervisor promiscuous replication.

---

## 4. Sensor Selection & 78-Feature Compatibility

### 4.1 Sensor Audit & The 78-Feature Requirement

The Multi-Agent SOC machine learning models (Random Forest and Isolation Forest) require an exact, ordered vector of **78 bidirectional network flow metrics** derived from the CSE-CIC-IDS2018 dataset.

#### Why Zeek and Suricata Alone Are Insufficient:
- **Zeek (`conn.log`):** Records connection metadata (timestamps, duration, total bytes, connection history state flags). It **does not calculate** statistical distributions of packet lengths (variance, skew, standard deviation), inter-arrival times (IAT mean, min, max, std), or subflow bulk transmission rates.
- **Suricata (`eve.json`):** Specializes in rule-based signature alerts and flow duration/byte summaries, but **does not output** bidirectional packet-timing statistics.
- **Conclusion:** While Zeek and Suricata provide valuable supplemental host/NIDS logs, they **cannot satisfy the 78-feature model input vector**. A dedicated bidirectional statistical flow meter is mandatory.

### 4.2 Selected Sensor: Python `cicflowmeter` (or Java CICFlowMeter v4)
- **Primary Recommendation:** Python `cicflowmeter` (`hieulw/cicflowmeter` package, installed in Python 3.10+ on the Sensor VM).
- **Output:** Writes flow records directly to `/var/log/soc/flows.csv`.
- **Feature Alignment:** Extends 80+ network flow attributes. All 78 canonical model features are extracted and normalized via `LiveFlowAdapter` (`kafka/live_adapter.py`).
- **Headless Execution:** Runs as a native background daemon via `systemd`.

---

## 5. End-to-End Telemetry Pipeline & Connectivity

```
[Packet Stream on eth0] 
       |
       v (libpcap / scapy)
[cicflowmeter daemon] 
       |
       v writes completed flow rows
[/var/log/soc/flows.csv]
       |
       v (incremental tailing via kafka.live_adapter)
[LiveFlowTailer]
       |
       v (alias normalization, duration scaling, median imputation)
[78-Feature Payload with Metadata]
       |
       v HTTP POST (Header: X-SOC-Sensor-Key)
[http://192.168.56.1:8000/api/ingest/flow]
```

### 5.1 Host Endpoint Security & Binding
To receive flows from the Sensor VM (`192.168.56.10`) while preventing exposure to untrusted local networks (`192.168.21.0/24`):
1. **Binding Address:** The host API should bind specifically to the Host-Only interface:
   ```cmd
   python -m uvicorn dashboard_api:app --host 192.168.56.1 --port 8000
   ```
2. **Sensor Authentication:** The request must provide:
   ```http
   X-SOC-Sensor-Key: soc-sensor-dev-key-2026
   ```
3. **Payload Verification:** The endpoint verifies `Content-Length <= 1MB`, verifies all 78 numeric features, checks duplicate UUIDs in `soc.db`, routes through `SOCPipeline`, and writes WAL records.

---

## 6. Document Map & Reference Links

The setup documentation is partitioned into modular, step-by-step guides:

1. **[Network Topology & VM Provisioning Guide](file:///e:/multi-agent-soc/docs/lab_setup/network_topology.md):**
   Exact `VBoxManage` commands, RAM/CPU allocation, network interface assignments, and guest netplan configs.
2. **[Sensor Installation & Adapter Configuration Guide](file:///e:/multi-agent-soc/docs/lab_setup/sensor_config.md):**
   Installation of `cicflowmeter`, CSV directory permissions, systemd service units, and `kafka.live_adapter` daemonization.
3. **[Validation Playbook & Authorized Scan Scenarios](file:///e:/multi-agent-soc/docs/lab_setup/validation_playbook.md):**
   Benign verification procedure, authorized lab scan procedures, troubleshooting tree, cleanup steps, and the end-to-end operational checklist.
4. **Automation Helper Scripts:**
   - [`scripts/sensor_setup.sh`](file:///e:/multi-agent-soc/scripts/sensor_setup.sh): One-click provisioner for Ubuntu Sensor VM.
   - [`scripts/victim_setup.sh`](file:///e:/multi-agent-soc/scripts/victim_setup.sh): Target web server provisioner for Ubuntu Victim VM.
   - [`scripts/attacker_benign_traffic.py`](file:///e:/multi-agent-soc/scripts/attacker_benign_traffic.py): Automated benign traffic generator script.
