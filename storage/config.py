"""
storage/config.py
==================
Central configuration for the Stage 5 storage layer.

Multi-Agent SOC Project -- Stage 5: Central Event and Alert Storage

All storage-related parameters live here. No values are hardcoded
in db.py, query.py, or ingest.py.
"""

import pathlib

# ---------------------------------------------------------------------------
# Project root
# ---------------------------------------------------------------------------
PROJECT_ROOT = pathlib.Path(r"E:\multi-agent-soc")

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
# Primary storage backend.
# Future extension: set BACKEND = "elasticsearch" when a broker is available.
BACKEND = "sqlite"

# Path to the SQLite database file.
DB_PATH = PROJECT_ROOT / "data" / "soc.db"

# ---------------------------------------------------------------------------
# Log paths (for reference — storage module writes to streaming_runtime.log)
# ---------------------------------------------------------------------------
LOG_DIR               = PROJECT_ROOT / "logs"
STREAMING_RUNTIME_LOG = LOG_DIR / "streaming_runtime.log"

ALERT_LOGS = {
    "streaming":         LOG_DIR / "streaming_alerts.json",
    "network_detection": LOG_DIR / "network_detection_alerts.json",
    "live_monitor":      LOG_DIR / "live_monitor_alerts.json",
}

# ---------------------------------------------------------------------------
# SQLite pragmas
# ---------------------------------------------------------------------------
# Enable foreign-key enforcement on every new connection.
SQLITE_PRAGMAS = [
    "PRAGMA foreign_keys = ON;",
    "PRAGMA journal_mode = WAL;",   # better concurrency; safe for single-machine use
]

# ---------------------------------------------------------------------------
# Agent name used in the alerts table
# ---------------------------------------------------------------------------
AGENT_NAME = "Network Detection Agent"
