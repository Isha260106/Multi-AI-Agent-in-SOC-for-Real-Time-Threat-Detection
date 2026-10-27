#!/usr/bin/env bash
# ==============================================================================
# Script: sensor_setup.sh
# Target OS: Ubuntu Server 22.04 LTS (SOC Sensor VM)
# Description: Automated provisioner for Sensor VM: installs libpcap, cicflowmeter,
#              configures promiscuous mode, offload tuning, systemd services, and
#              the kafka.live_adapter streaming pipeline.
# ==============================================================================

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
   echo "[!] This script must be run as root (e.g. sudo bash sensor_setup.sh)" 
   exit 1
fi

echo "[*] Step 1/6: Installing core system dependencies..."
apt-get update -qq
apt-get install -y -qq \
    python3 \
    python3-pip \
    python3-venv \
    libpcap-dev \
    tcpdump \
    ethtool \
    curl \
    jq

echo "[*] Step 2/6: Creating dedicated system user and directories..."
if ! id -u socservice >/dev/null 2>&1; then
    useradd -r -s /bin/false -d /opt/soc-sensor socservice
fi

mkdir -p /opt/soc-sensor
mkdir -p /var/log/soc
chown -R socservice:socservice /opt/soc-sensor /var/log/soc
chmod 755 /var/log/soc
touch /var/log/soc/flows.csv
chown socservice:socservice /var/log/soc/flows.csv

echo "[*] Step 3/6: Setting up Python virtual environment..."
sudo -u socservice python3 -m venv /opt/soc-sensor/venv
sudo -u socservice /opt/soc-sensor/venv/bin/pip install --upgrade pip setuptools wheel
sudo -u socservice /opt/soc-sensor/venv/bin/pip install \
    cicflowmeter==0.1.6 \
    requests>=2.28.0 \
    pydantic>=2.0.0

# Allow raw packet sniffing for unprivileged Python binary
setcap cap_net_raw,cap_net_admin=eip /opt/soc-sensor/venv/bin/python3

echo "[*] Step 4/6: Configuring network interface promiscuous mode and offload tuning..."
SNIFFER_IF="enp0s3"
ip link set "$SNIFFER_IF" promisc on 2>/dev/null || true
ethtool -K "$SNIFFER_IF" rx off tx off tso off gso off gro off 2>/dev/null || true

# Persist interface settings via systemd unit
cat <<EOF > /etc/systemd/system/sensor-interface-tuning.service
[Unit]
Description=Configure Sensor Promiscuous Mode and Disable Offloads
After=network.target

[Service]
Type=oneshot
ExecStart=/sbin/ip link set ${SNIFFER_IF} promisc on
ExecStart=/sbin/ethtool -K ${SNIFFER_IF} rx off tx off tso off gso off gro off
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable sensor-interface-tuning.service

echo "[*] Step 5/6: Setting up cicflowmeter systemd service..."
cat <<EOF > /etc/systemd/system/cicflowmeter.service
[Unit]
Description=CICFlowMeter Live Flow Sniffer Daemon
After=network.target sensor-interface-tuning.service
Requires=sensor-interface-tuning.service

[Service]
Type=simple
User=root
ExecStart=/opt/soc-sensor/venv/bin/cicflowmeter -i ${SNIFFER_IF} -c -u /var/log/soc/flows.csv
Restart=always
RestartSec=3
KillMode=process
LimitNOFILE=65535
MemoryMax=1500M

[Install]
WantedBy=multi-user.target
EOF

echo "[*] Step 6/6: Setting up soc-adapter streaming service..."
cat <<EOF > /etc/systemd/system/soc-adapter.service
[Unit]
Description=SOC Live Flow Adapter Streaming Daemon
After=network.target cicflowmeter.service
Requires=cicflowmeter.service

[Service]
Type=simple
User=socservice
WorkingDirectory=/opt/soc-sensor
Environment=PYTHONPATH=/opt/soc-sensor
Environment=SOC_SENSOR_KEY=soc-sensor-dev-key-2026
ExecStart=/opt/soc-sensor/venv/bin/python3 /opt/soc-sensor/live_adapter.py \
    --csv-file /var/log/soc/flows.csv \
    --target-url http://192.168.56.1:8000/api/ingest/flow \
    --api-key soc-sensor-dev-key-2026 \
    --batch-size 25 \
    --poll-interval 1.0
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
echo "[+] Sensor VM setup completed successfully!"
echo "[i] Place live_adapter.py in /opt/soc-sensor/live_adapter.py"
echo "[i] Start services with:"
echo "    sudo systemctl start cicflowmeter.service"
echo "    sudo systemctl start soc-adapter.service"
