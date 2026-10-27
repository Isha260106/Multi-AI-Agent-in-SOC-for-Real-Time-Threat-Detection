# Isolated Lab Network Topology & VM Provisioning Guide

> **Project:** Multi-Agent AI SOC for Real-Time Threat Detection  
> **Component:** Phase 3 Live VM-Based Monitoring Lab  
> **Target Hypervisor:** Oracle VM VirtualBox 7.0+ on Windows 11 Home (64-bit)  
> **Primary Isolation Constraint:** Zero external bridge or routing to home/campus LAN (`192.168.21.0/24`).

---

## 1. Architecture & Addressing Topology

The laboratory environment consists of three virtual machines running inside Oracle VM VirtualBox on the Windows 11 host. Two strictly isolated virtual networks partition traffic so that simulated security traffic cannot leave the hypervisor.

```
+--------------------------------------------------------------------------------------------------+
|                                    WINDOWS 11 HOST (HYPERVISOR)                                  |
|                                                                                                  |
|   Physical Wi-Fi Interface: 192.168.21.112 (No VM lab traffic touches this adapter)             |
|                                                                                                  |
|   VirtualBox Host-Only Adapter ("VirtualBox Host-Only Ethernet Adapter" / vboxnet0):            |
|     IPv4: 192.168.56.1 / 24                                                                      |
|     Listening Service: FastAPI Ingestion API (http://192.168.56.1:8000/api/ingest/flow)          |
|                                                                                                  |
+-----------------------------------+--------------------------------------------------------------+
                                    |
                                    | Host-Only Network: "soc_management" (192.168.56.0/24)
                                    | (Restricted to Host <--> Sensor VM telemetry only)
                                    v
+--------------------------------------------------------------------------------------------------+
|                                              SENSOR VM                                           |
| Hostname: soc-sensor-vm | OS: Ubuntu Server 22.04 LTS | 2 vCPU | 4096 MB RAM                     |
|                                                                                                  |
| Interface eth1 (Management): 192.168.56.10/24 (Routes HTTP flow telemetry to Host:8000)         |
| Interface eth0 (Sniffer):    10.10.10.10/24    (Promiscuous Mode: "Allow All", No Default GW)    |
| Packet Sniffer: cicflowmeter daemon listening on eth0 -> writing /var/log/soc/flows.csv         |
| Streaming Adapter: kafka.live_adapter tailing CSV -> POST http://192.168.56.1:8000/api/ingest/flow|
+---------------------------------------------------+----------------------------------------------+
                                                    |
                                                    | VirtualBox Internal Network: "lab_internal"
                                                    | (10.10.10.0/24 - Air-Gapped Virtual Switch)
                        +---------------------------+---------------------------+
                        |                                                       |
                        v                                                       v
+-----------------------------------------------+   +-----------------------------------------------+
|                  ATTACKER VM                  |   |                   VICTIM VM                   |
| Hostname: soc-attacker-vm                     |   | Hostname: soc-victim-vm                       |
| OS: Kali Linux Minimal or Ubuntu 22.04 LTS   |   | OS: Ubuntu Server 22.04 LTS                   |
| 1 vCPU | 2048 MB RAM                          |   | 1 vCPU | 2048 MB RAM                          |
|                                               |   |                                               |
| Interface eth0: 10.10.10.100/24               |   | Interface eth0: 10.10.10.20/24                |
| Roles: Benign traffic generator, authorized   |   | Roles: Nginx HTTP/HTTPS web target, sshd,     |
| lab nmap scan simulator                       |   | test services (ports 80, 443, 22)             |
| Gateway: None (Zero Host/Internet Access)     |   | Gateway: None (Zero Host/Internet Access)     |
+-----------------------------------------------+   +-----------------------------------------------+
```

### 1.1 IP Allocation Matrix

| Node | Interface | Network | IP Address | MAC Address Assignment | Role |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Windows Host** | VirtualBox Host-Only | `soc_management` | `192.168.56.1/24` | Auto-assigned by VBox | Hosts FastAPI SOC backend & Dashboard |
| **Sensor VM** | `eth1` | `soc_management` | `192.168.56.10/24` | `08:00:27:56:00:10` | Sends normalized flow JSON via HTTP |
| **Sensor VM** | `eth0` | `lab_internal` | `10.10.10.10/24` | `08:00:27:10:00:10` | Passive promiscuous packet sniffer |
| **Victim VM** | `eth0` | `lab_internal` | `10.10.10.20/24` | `08:00:27:10:00:20` | Web server target for benign & scan flows |
| **Attacker VM** | `eth0` | `lab_internal` | `10.10.10.100/24`| `08:00:27:10:00:99` | Source of benign requests and lab scans |

---

## 2. VM Resource Sizing & Host Hardware Budget

On a standard 16 GB Windows 11 host, resources must be strictly bounded so that the ML pipeline, FastAPI server, Vite UI, and background processes run smoothly:

| Virtual Machine | vCPUs | RAM | Disk (VDI) | Base Image Recommended |
| :--- | :---: | :---: | :---: | :--- |
| **Sensor VM** | 2 | 4096 MB | 30 GB (Dynamic) | Ubuntu Server 22.04 LTS (x86_64 minimal) |
| **Victim VM** | 1 | 2048 MB | 20 GB (Dynamic) | Ubuntu Server 22.04 LTS (x86_64 minimal) |
| **Attacker VM** | 1 | 2048 MB | 20 GB (Dynamic) | Kali Linux Minimal or Ubuntu 22.04 LTS |
| **Total VM Usage** | **4 vCPUs** | **8192 MB (8 GB)** | **70 GB dynamic** | *Leaves 8 GB RAM free for Windows 11 host* |

---

## 3. Host-Side VirtualBox Provisioning (CLI Commands)

Execute the following commands in an Administrative Command Prompt or PowerShell on the Windows 11 host.

### 3.1 Verify and Configure the Host-Only Adapter
VirtualBox creates `VirtualBox Host-Only Ethernet Adapter` during installation. Verify its configuration:

```cmd
:: 1. List host-only interfaces
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" list hostonlyifs

:: 2. If no host-only adapter exists, create one:
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" hostonlyif create

:: 3. Configure the adapter IP to 192.168.56.1 / 255.255.255.0
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" hostonlyif ipconfig "VirtualBox Host-Only Ethernet Adapter" --ip 192.168.56.1 --netmask 255.255.255.0

:: 4. Disable DHCP on host-only adapter to ensure static addressing:
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" dhcpserver remove --netname "HostInterfaceNetworking-VirtualBox Host-Only Ethernet Adapter" 2>nul
```

---

### 3.2 Create and Configure the Sensor VM (`soc-sensor-vm`)

```cmd
:: Set VM directory variable
set VM_DIR=C:\VirtualMachines\SOC_Lab

:: 1. Create VM
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" createvm --name "soc-sensor-vm" --ostype "Ubuntu_64" --register --basefolder "%VM_DIR%"

:: 2. Set CPU, RAM, and boot parameters
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" modifyvm "soc-sensor-vm" --cpus 2 --memory 4096 --vram 16 --audio none --boot1 disk --boot2 dvd

:: 3. Storage controller & virtual hard disk
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" storagectl "soc-sensor-vm" --name "SATA Controller" --add sata --controller IntelAhci
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" createmedium disk --filename "%VM_DIR%\soc-sensor-vm\sensor_disk.vdi" --size 30720 --format VDI
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" storageattach "soc-sensor-vm" --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium "%VM_DIR%\soc-sensor-vm\sensor_disk.vdi"

:: 4. Attach ISO for installation
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" storageattach "soc-sensor-vm" --storagectl "SATA Controller" --port 1 --device 0 --type dvddrive --medium "C:\ISOs\ubuntu-22.04.4-live-server-amd64.iso"

:: 5. Adapter 1: Sniffer Interface on "lab_internal" with PROMISCUOUS MODE ALLOW-ALL
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" modifyvm "soc-sensor-vm" --nic1 intnet --intnet1 "lab_internal" --macaddress1 "080027100010" --nicpromisc1 allow-all --nictype1 82540EM

:: 6. Adapter 2: Management Interface on "VirtualBox Host-Only Ethernet Adapter"
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" modifyvm "soc-sensor-vm" --nic2 hostonly --hostonlyadapter2 "VirtualBox Host-Only Ethernet Adapter" --macaddress2 "080027560010" --nicpromisc2 deny --nictype2 82540EM
```

> [!IMPORTANT]
> `--nicpromisc1 allow-all` is the critical hypervisor switch directive. Without this flag, the virtual switch discards packets addressed to the Victim VM's MAC address before they reach the Sensor VM's tap interface.

---

### 3.3 Create and Configure the Victim VM (`soc-victim-vm`)

```cmd
:: 1. Create VM
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" createvm --name "soc-victim-vm" --ostype "Ubuntu_64" --register --basefolder "%VM_DIR%"

:: 2. CPU and RAM
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" modifyvm "soc-victim-vm" --cpus 1 --memory 2048 --vram 16 --audio none --boot1 disk --boot2 dvd

:: 3. Storage controller & virtual disk
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" storagectl "soc-victim-vm" --name "SATA Controller" --add sata --controller IntelAhci
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" createmedium disk --filename "%VM_DIR%\soc-victim-vm\victim_disk.vdi" --size 20480 --format VDI
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" storageattach "soc-victim-vm" --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium "%VM_DIR%\soc-victim-vm\victim_disk.vdi"
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" storageattach "soc-victim-vm" --storagectl "SATA Controller" --port 1 --device 0 --type dvddrive --medium "C:\ISOs\ubuntu-22.04.4-live-server-amd64.iso"

:: 4. Single Adapter: Connected exclusively to "lab_internal"
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" modifyvm "soc-victim-vm" --nic1 intnet --intnet1 "lab_internal" --macaddress1 "080027100020" --nicpromisc1 deny --nictype1 82540EM
```

---

### 3.4 Create and Configure the Attacker VM (`soc-attacker-vm`)

```cmd
:: 1. Create VM
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" createvm --name "soc-attacker-vm" --ostype "Ubuntu_64" --register --basefolder "%VM_DIR%"

:: 2. CPU and RAM
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" modifyvm "soc-attacker-vm" --cpus 1 --memory 2048 --vram 16 --audio none --boot1 disk --boot2 dvd

:: 3. Storage controller & virtual disk
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" storagectl "soc-attacker-vm" --name "SATA Controller" --add sata --controller IntelAhci
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" createmedium disk --filename "%VM_DIR%\soc-attacker-vm\attacker_disk.vdi" --size 20480 --format VDI
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" storageattach "soc-attacker-vm" --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium "%VM_DIR%\soc-attacker-vm\attacker_disk.vdi"
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" storageattach "soc-attacker-vm" --storagectl "SATA Controller" --port 1 --device 0 --type dvddrive --medium "C:\ISOs\ubuntu-22.04.4-live-server-amd64.iso"

:: 4. Single Adapter: Connected exclusively to "lab_internal"
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" modifyvm "soc-attacker-vm" --nic1 intnet --intnet1 "lab_internal" --macaddress1 "080027100099" --nicpromisc1 deny --nictype1 82540EM
```

---

## 4. Guest OS Network Configurations (Netplan)

Ubuntu 22.04 LTS uses `netplan` for static network interface configuration.

### 4.1 Sensor VM Netplan (`/etc/netplan/01-sensor-net.yaml`)

```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    # Interface 1 (eth0 / enp0s3): Promiscuous Sniffer on lab_internal
    enp0s3:
      dhcp4: false
      dhcp6: false
      addresses:
        - 10.10.10.10/24
      # Note: No gateway or DNS on the sniffer interface
      activation-mode: manual

    # Interface 2 (eth1 / enp0s8): Host-Only Management Interface
    enp0s8:
      dhcp4: false
      dhcp6: false
      addresses:
        - 192.168.56.10/24
      routes:
        - to: 192.168.56.0/24
          via: 192.168.56.1
```

Apply inside the Sensor VM:
```bash
sudo chmod 600 /etc/netplan/01-sensor-net.yaml
sudo netplan apply
```

### 4.2 Victim VM Netplan (`/etc/netplan/01-victim-net.yaml`)

```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    enp0s3:
      dhcp4: false
      dhcp6: false
      addresses:
        - 10.10.10.20/24
      # No gateway - completely air-gapped
```

Apply inside the Victim VM:
```bash
sudo chmod 600 /etc/netplan/01-victim-net.yaml
sudo netplan apply
```

### 4.3 Attacker VM Netplan (`/etc/netplan/01-attacker-net.yaml`)

```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    enp0s3:
      dhcp4: false
      dhcp6: false
      addresses:
        - 10.10.10.100/24
      # No gateway - completely air-gapped
```

Apply inside the Attacker VM:
```bash
sudo chmod 600 /etc/netplan/01-attacker-net.yaml
sudo netplan apply
```

---

## 5. Sensor Interface Promiscuous & Offload Optimization

Inside the Sensor VM, the Linux kernel network stack and hardware offload engines must be configured to pass all unsegmented frames directly to user-space `libpcap`:

```bash
# 1. Put sniffer interface into promiscuous mode
sudo ip link set enp0s3 promisc on

# 2. Disable Hardware Checksum and Segmentation Offloading
# If offloads remain enabled, packets reconstructed on the NIC may have 
# partial checksums, causing packet analyzers to drop them silently.
sudo ethtool -K enp0s3 rx off tx off tso off gso off gro off

# 3. Verify interface state
ip link show enp0s3
# Expected flags: <BROADCAST,MULTICAST,PROMISC,UP,LOWER_UP>
```

### 5.1 Persisting Promiscuous Mode on Sensor Boot
Create a systemd oneshot service on the Sensor VM:

```ini
# /etc/systemd/system/sensor-interface-tuning.service
[Unit]
Description=Configure Sensor Promiscuous Mode and Disable Offloads
After=network.target

[Service]
Type=oneshot
ExecStart=/sbin/ip link set enp0s3 promisc on
ExecStart=/sbin/ethtool -K enp0s3 rx off tx off tso off gso off gro off
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```

Enable the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable sensor-interface-tuning.service
```

---

## 6. Fallback Architecture: In-Line Sensor Gateway Topology

If the host virtualization environment (e.g., Windows Hypervisor Platform driver) fails to replicate non-broadcast unicast packets across VirtualBox internal switch ports despite `--nicpromisc1 allow-all`, activate the **In-Line Sensor Gateway Topology**:

```
+-------------------+        +-----------------------------------+        +-------------------+
|    Attacker VM    |        |             Sensor VM             |        |     Victim VM     |
| 10.10.10.100/24   | =====> | eth0: 10.10.10.1/24 (Gateway)     | =====> | 10.10.20.20/24    |
| GW: 10.10.10.1    |        | eth1: 10.10.20.1/24 (Gateway)     |        | GW: 10.10.20.1    |
+-------------------+        | eth2: 192.168.56.10/24 (Mgmt)     |        +-------------------+
  (intnet_attack)            | [ IP Forwarding + Sniffer on any] |          (intnet_victim)
                             +-----------------+-----------------+
                                               |
                                               v (Host-Only vboxnet0)
                                     [ Windows Host :8000 ]
```

### 6.1 In-Line Gateway Configuration Commands
1. Separate the internal networks:
   - Attacker VM on `intnet_attack`
   - Victim VM on `intnet_victim`
2. Sensor VM equipped with 3 NICs:
   - NIC1 (`enp0s3`): `10.10.10.1/24` on `intnet_attack`
   - NIC2 (`enp0s8`): `10.10.20.1/24` on `intnet_victim`
   - NIC3 (`enp0s9`): `192.168.56.10/24` on `VirtualBox Host-Only Ethernet Adapter`
3. Enable routing on Sensor VM:
   ```bash
   sudo sysctl -w net.ipv4.ip_forward=1
   sudo iptables -A FORWARD -i enp0s3 -o enp0s8 -j ACCEPT
   sudo iptables -A FORWARD -i enp0s8 -o enp0s3 -m state --state ESTABLISHED,RELATED -j ACCEPT
   ```
4. Point `cicflowmeter` to sniff interface `any` or `enp0s3`. Because the Sensor VM is the physical next-hop gateway for both machines, 100% of packets traverse its network stack with zero dependence on switch-level promiscuous replication.
