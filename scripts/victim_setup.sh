#!/usr/bin/env bash
# ==============================================================================
# Script: victim_setup.sh
# Target OS: Ubuntu Server 22.04 LTS (SOC Victim VM)
# Description: Automated provisioner for Victim VM: installs and configures Nginx,
#              sets up static endpoints for benign baseline testing, and prepares
#              standard ports for lab-only scan scenarios.
# ==============================================================================

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
   echo "[!] This script must be run as root (e.g. sudo bash victim_setup.sh)" 
   exit 1
fi

echo "[*] Step 1/4: Installing Nginx and utilities..."
apt-get update -qq
apt-get install -y -qq nginx curl openssl

echo "[*] Step 2/4: Creating simulated test pages and endpoints..."
mkdir -p /var/www/soc-lab/api

cat << 'EOF' > /var/www/soc-lab/index.html
<!DOCTYPE html>
<html>
<head>
    <title>Victim Web Service - SOC Lab</title>
    <style>body { font-family: sans-serif; margin: 40px; background: #f4f6f8; }</style>
</head>
<body>
    <h1>Multi-Agent SOC Lab: Victim Target Service</h1>
    <p>Status: Online (Internal Lab Network Only: 10.10.10.20)</p>
</body>
</html>
EOF

cat << 'EOF' > /var/www/soc-lab/api/health
{"status":"healthy","service":"victim-target","uptime":"active"}
EOF

cat << 'EOF' > /var/www/soc-lab/api/test
{"status":"ok","message":"Test payload received"}
EOF

echo "[*] Step 3/4: Configuring Nginx site..."
cat << 'EOF' > /etc/nginx/sites-available/soc-lab
server {
    listen 80 default_server;
    listen [::]:80 default_server;

    root /var/www/soc-lab;
    index index.html;

    server_name _;

    location / {
        try_files $uri $uri/ =404;
    }

    location /api/ {
        default_type application/json;
        try_files $uri =404;
    }
}
EOF

# Activate site
rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/soc-lab /etc/nginx/sites-enabled/

nginx -t
systemctl restart nginx
systemctl enable nginx

echo "[*] Step 4/4: Verifying local service response..."
curl -s http://127.0.0.1/ | grep -q "SOC Lab"
echo "[+] Victim VM provisioned successfully on port 80!"
