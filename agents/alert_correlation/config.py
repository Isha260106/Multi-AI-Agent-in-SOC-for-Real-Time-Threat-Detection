"""
Configuration for the Alert Correlation Agent (Stage 7).
"""
import pathlib
import sys

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

AGENT_NAME = "Alert Correlation Agent"

# Sliding Window Configuration
DEFAULT_WINDOW_SECONDS = 600  # 10 minutes temporal correlation window

# MITRE ATT&CK Stages
STAGE_RECONNAISSANCE = "Reconnaissance"
STAGE_INITIAL_ACCESS = "Initial Access"
STAGE_PRIVILEGE_ESCALATION = "Privilege Escalation"
STAGE_DATA_STAGING = "Data Staging"
STAGE_EXFILTRATION = "Exfiltration"

# MITRE Technique Mappings
STAGE_TECHNIQUES = {
    STAGE_RECONNAISSANCE: ["T1046", "T1595"],
    STAGE_INITIAL_ACCESS: ["T1110", "T1078"],
    STAGE_PRIVILEGE_ESCALATION: ["T1548", "T1068"],
    STAGE_DATA_STAGING: ["T1003", "T1074"],
    STAGE_EXFILTRATION: ["T1048", "T1041", "T1020"],
}
