"""
agents/threat_assessment
========================
Unified Threat Assessment Engine Package (Stage 9A)
"""

from agents.threat_assessment.agent import (
    ThreatAssessmentEngine,
    DECISION_TABLE_RULES,
)
from agents.threat_assessment.config import (
    AGENT_NAME,
    CATEGORY_CONFIRMED_ATTACK,
    CATEGORY_SUSPECTED_ATTACK,
    CATEGORY_SUSPICIOUS_ANOMALY,
    CATEGORY_BENIGN,
    CATEGORY_UNKNOWN,
    ALL_CATEGORIES,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_INFORMATIONAL,
    ALL_SEVERITIES,
)

__all__ = [
    "ThreatAssessmentEngine",
    "DECISION_TABLE_RULES",
    "AGENT_NAME",
    "CATEGORY_CONFIRMED_ATTACK",
    "CATEGORY_SUSPECTED_ATTACK",
    "CATEGORY_SUSPICIOUS_ANOMALY",
    "CATEGORY_BENIGN",
    "CATEGORY_UNKNOWN",
    "ALL_CATEGORIES",
    "SEVERITY_HIGH",
    "SEVERITY_MEDIUM",
    "SEVERITY_LOW",
    "SEVERITY_INFORMATIONAL",
    "ALL_SEVERITIES",
]
