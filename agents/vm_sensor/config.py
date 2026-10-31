"""
agents/vm_sensor/config.py
==========================
Configuration for Remote Ubuntu Victim VM Telemetry Collector.

Multi-Agent SOC Project -- Live Victim VM Telemetry Integration
"""

import os
import pathlib

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
LOG_DIR = PROJECT_ROOT / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

STATE_FILE = LOG_DIR / "vm_sensor_state.json"
SENSOR_RUNTIME_LOG = LOG_DIR / "vm_sensor_runtime.log"

# Remote VM Access Configuration
SOC_VM_HOST = os.getenv("SOC_VM_HOST", "45.74.156.54")
SOC_VM_USER = os.getenv("SOC_VM_USER", "ubuntu")
DEFAULT_KEY_PATH = os.path.expanduser(os.path.join("~", ".ssh", "soc_lab"))
SOC_VM_SSH_KEY = os.path.expanduser(os.path.expandvars(os.getenv("SOC_VM_SSH_KEY", DEFAULT_KEY_PATH)))
SOC_VM_PORT = int(os.getenv("SOC_VM_PORT", "22"))
SOC_VM_CONNECT_TIMEOUT = float(os.getenv("SOC_VM_CONNECT_TIMEOUT", "10.0"))
SOC_VM_POLL_INTERVAL = float(os.getenv("SOC_VM_POLL_INTERVAL", "3.0"))

# Known Hosts for Strict Host Key Verification
KNOWN_HOSTS_FILE = os.path.expanduser(os.path.join("~", ".ssh", "known_hosts"))
SOC_STRICT_HOST_KEY_CHECKING = os.getenv("SOC_STRICT_HOST_KEY_CHECKING", "yes")

# Telemetry Source Mode: 'replay', 'vm_logs', 'vm_flows', 'vm_all'
SOC_VM_TELEMETRY_MODE = os.getenv("SOC_VM_TELEMETRY_MODE", "vm_all").lower()

# Local & Tunnel Ingestion Endpoints
SOC_INGEST_URL = os.getenv("SOC_INGEST_URL", "http://127.0.0.1:8000/api/ingest/flow")
SOC_LOG_INGEST_URL = os.getenv("SOC_LOG_INGEST_URL", "http://127.0.0.1:8000/api/ingest/log")
SOC_LOGS_BATCH_URL = os.getenv("SOC_LOGS_BATCH_URL", "http://127.0.0.1:8000/api/ingest/logs")
SOC_HEALTH_URL = os.getenv("SOC_HEALTH_URL", "http://127.0.0.1:8000/api/health")
SOC_MODELS_HEALTH_URL = os.getenv("SOC_MODELS_HEALTH_URL", "http://127.0.0.1:8000/api/models/health")

# Reverse Tunnel Parameters (Victim 18000 -> Windows 8000)
SOC_REMOTE_TUNNEL_PORT = int(os.getenv("SOC_REMOTE_TUNNEL_PORT", "18000"))
SOC_LOCAL_BACKEND_PORT = int(os.getenv("SOC_LOCAL_BACKEND_PORT", "8000"))

# Authentication Pre-Shared Key (PSK)
SOC_SENSOR_KEY = os.getenv("SOC_SENSOR_KEY", "soc-sensor-dev-key-2026")

# Remote Log Sources to Ingest
REMOTE_AUTH_LOG_PATH = "/var/log/auth.log"
REMOTE_FLOW_CSV_PATH = os.getenv("SOC_REMOTE_FLOW_CSV", "/var/log/soc/flows.csv")
