"""
agents/threat_investigation/config.py
=====================================
Configuration and Constants for Stage 10: Multi-Agent Threat Investigation

Multi-Agent SOC Project -- Stage 10
"""

import pathlib

# ---------------------------------------------------------------------------
# Project Paths
# ---------------------------------------------------------------------------
PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent

AGENT_NAME = "Threat Investigation Coordinator"

# ---------------------------------------------------------------------------
# Investigation Trigger Thresholds
# ---------------------------------------------------------------------------
# Categories that warrant formal multi-agent investigation
TRIGGER_CATEGORIES = [
    "Confirmed Attack",
    "Suspected Attack",
    "Suspicious Anomaly",
]

# Severities that warrant formal multi-agent investigation
TRIGGER_SEVERITIES = [
    "HIGH",
    "MEDIUM",
]

# ---------------------------------------------------------------------------
# Investigation Status Taxonomy
# ---------------------------------------------------------------------------
STATUS_OPEN = "OPEN"
STATUS_IN_PROGRESS = "IN_PROGRESS"
STATUS_COMPLETED = "COMPLETED"
STATUS_REQUIRES_TIER2 = "REQUIRES_TIER2"
STATUS_INCONCLUSIVE = "INCONCLUSIVE"
STATUS_CLOSED_BENIGN = "CLOSED_BENIGN"

ALL_INVESTIGATION_STATUSES = [
    STATUS_OPEN,
    STATUS_IN_PROGRESS,
    STATUS_COMPLETED,
    STATUS_REQUIRES_TIER2,
    STATUS_INCONCLUSIVE,
    STATUS_CLOSED_BENIGN,
]

# ---------------------------------------------------------------------------
# Logging Paths
# ---------------------------------------------------------------------------
LOG_DIR = PROJECT_ROOT / "logs"
INVESTIGATION_LOG_FILE = LOG_DIR / "threat_investigations.json"
INVESTIGATION_RUNTIME_LOG = LOG_DIR / "threat_investigation_runtime.log"
