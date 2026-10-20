"""
agents/threat_assessment/config.py
==================================
Configuration and Constants for Stage 9A: Unified Threat Assessment Engine

Multi-Agent SOC Project -- Stage 9A
"""

import pathlib

# ---------------------------------------------------------------------------
# Project Paths
# ---------------------------------------------------------------------------
PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent

AGENT_NAME = "Threat Assessment Engine"

# ---------------------------------------------------------------------------
# Threat Categories (Deterministic Decision Table Outputs)
# ---------------------------------------------------------------------------
CATEGORY_CONFIRMED_ATTACK   = "Confirmed Attack"
CATEGORY_SUSPECTED_ATTACK   = "Suspected Attack"
CATEGORY_SUSPICIOUS_ANOMALY = "Suspicious Anomaly"
CATEGORY_BENIGN             = "Benign"
CATEGORY_UNKNOWN            = "Unknown"

ALL_CATEGORIES = [
    CATEGORY_CONFIRMED_ATTACK,
    CATEGORY_SUSPECTED_ATTACK,
    CATEGORY_SUSPICIOUS_ANOMALY,
    CATEGORY_BENIGN,
    CATEGORY_UNKNOWN,
]

# ---------------------------------------------------------------------------
# Severity Levels
# ---------------------------------------------------------------------------
SEVERITY_HIGH          = "HIGH"
SEVERITY_MEDIUM        = "MEDIUM"
SEVERITY_LOW           = "LOW"
SEVERITY_INFORMATIONAL = "INFORMATIONAL"

ALL_SEVERITIES = [
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_INFORMATIONAL,
]

# ---------------------------------------------------------------------------
# Logging & Storage Paths
# ---------------------------------------------------------------------------
LOG_DIR = PROJECT_ROOT / "logs"
THREAT_LOG_FILE = LOG_DIR / "threat_assessments.json"
THREAT_RUNTIME_LOG = LOG_DIR / "threat_runtime.log"
