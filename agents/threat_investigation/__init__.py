"""
agents/threat_investigation/__init__.py
======================================
Module exports for Stage 10: Multi-Agent Threat Investigation
"""

from agents.threat_investigation.coordinator import (
    ThreatInvestigationCoordinator,
    NetworkEvidenceModule,
    AnomalyExplanationModule,
    AlertCorrelationModule,
    InvestigationSummaryModule,
)
from agents.threat_investigation.config import (
    AGENT_NAME,
    TRIGGER_CATEGORIES,
    TRIGGER_SEVERITIES,
    STATUS_OPEN,
    STATUS_IN_PROGRESS,
    STATUS_COMPLETED,
    STATUS_REQUIRES_TIER2,
    STATUS_INCONCLUSIVE,
    STATUS_CLOSED_BENIGN,
    ALL_INVESTIGATION_STATUSES,
)

__all__ = [
    "ThreatInvestigationCoordinator",
    "NetworkEvidenceModule",
    "AnomalyExplanationModule",
    "AlertCorrelationModule",
    "InvestigationSummaryModule",
    "AGENT_NAME",
    "TRIGGER_CATEGORIES",
    "TRIGGER_SEVERITIES",
    "STATUS_OPEN",
    "STATUS_IN_PROGRESS",
    "STATUS_COMPLETED",
    "STATUS_REQUIRES_TIER2",
    "STATUS_INCONCLUSIVE",
    "STATUS_CLOSED_BENIGN",
    "ALL_INVESTIGATION_STATUSES",
]
