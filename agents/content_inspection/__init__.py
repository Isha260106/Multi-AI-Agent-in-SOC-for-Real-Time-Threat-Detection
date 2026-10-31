"""
agents/content_inspection/__init__.py
=====================================
Content & Context Inspection Agent package.
"""

from agents.content_inspection.agent import ContentInspectionAgent
from agents.content_inspection.config import (
    AGENT_NAME,
    VERDICT_BENIGN_ROUTINE,
    VERDICT_EXFILTRATION_CRITICAL,
    VERDICT_GENUINE_USER_HIGH_VOLUME,
    VERDICT_SUSPICIOUS_UNVERIFIED,
)

__all__ = [
    "ContentInspectionAgent",
    "AGENT_NAME",
    "VERDICT_EXFILTRATION_CRITICAL",
    "VERDICT_GENUINE_USER_HIGH_VOLUME",
    "VERDICT_SUSPICIOUS_UNVERIFIED",
    "VERDICT_BENIGN_ROUTINE",
]
