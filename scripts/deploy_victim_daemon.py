"""
scripts/deploy_victim_daemon.py
===============================
Uploads and verifies the live flow extractor daemon on the remote victim VM.
"""
import base64
import os
import pathlib
import subprocess
import sys

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
daemon_file = PROJECT_ROOT / "agents" / "vm_sensor" / "victim_flow_daemon.py"
key_path = os.path.expandvars(r"%USERPROFILE%\.ssh\soc_lab")

code = daemon_file.read_text(encoding="utf-8")
b64 = base64.b64encode(code.encode("utf-8")).decode("ascii")

# Try direct connection first, fallback to ProxyCommand via 45.74.156.53
base_args = [
    "ssh",
    "-o", "BatchMode=yes",
    "-o", "ConnectTimeout=6",
    "-o", "StrictHostKeyChecking=no",
    "-i", key_path,
]

target_host = "ubuntu@45.74.156.54"

def run_remote(remote_cmd):
    # Try direct
    cmd = base_args + [target_host, remote_cmd]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=12)
        if res.returncode == 0:
            return res.returncode, res.stdout, res.stderr
    except Exception:
        pass

    # Fallback to ProxyCommand via 45.74.156.53 to 10.0.0.12
    proxy_cmd = f"ssh -i \"{key_path}\" -W %h:%p ubuntu@45.74.156.53"
    fallback_args = base_args + ["-o", f"ProxyCommand={proxy_cmd}", "ubuntu@10.0.0.12", remote_cmd]
    res = subprocess.run(fallback_args, capture_output=True, text=True, timeout=15)
    return res.returncode, res.stdout, res.stderr

print("[*] Creating /var/log/soc on victim...")
rc, out, err = run_remote("sudo mkdir -p /var/log/soc && sudo chown -R ubuntu:ubuntu /var/log/soc")
print(f"[-] /var/log/soc setup: rc={rc}")

print("[*] Uploading /home/ubuntu/soc_flow_daemon.py...")
chunk_size = 2000
chunks = [b64[i:i+chunk_size] for i in range(0, len(b64), chunk_size)]

run_remote("rm -f /home/ubuntu/soc_flow_daemon.b64")
for i, chunk in enumerate(chunks):
    run_remote(f"echo -n '{chunk}' >> /home/ubuntu/soc_flow_daemon.b64")

run_remote("base64 -d /home/ubuntu/soc_flow_daemon.b64 > /home/ubuntu/soc_flow_daemon.py && chmod +x /home/ubuntu/soc_flow_daemon.py && rm -f /home/ubuntu/soc_flow_daemon.b64")

rc, out, err = run_remote("ls -lh /home/ubuntu/soc_flow_daemon.py; head -n 3 /home/ubuntu/soc_flow_daemon.py")
print("[+] Deployed Daemon:")
print(out)
