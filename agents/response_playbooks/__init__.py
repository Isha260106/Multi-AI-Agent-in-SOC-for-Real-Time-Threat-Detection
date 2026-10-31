"""
agents/response_playbooks/__init__.py
=====================================
Multi-Agent SOC Response Playbooks (Stage 12).
"""

from agents.response_playbooks.config import (
    ACTION_FLAG_ANALYST_REVIEW,
    ACTION_GATHER_EVIDENCE,
    ACTION_INCREASE_MONITORING,
    ACTION_LOG_BASELINE,
    ACTION_RECOMMEND_CONTAINMENT,
    AGENT_NAME,
    AGENT_VERSION,
    STATUS_APPROVED,
    STATUS_EXECUTED_DRY_RUN,
    STATUS_PENDING_APPROVAL,
    STATUS_RECOMMENDED,
    STATUS_REJECTED,
)
from agents.response_playbooks.engine import ResponsePlaybookEngine

__all__ = [
    "ResponsePlaybookEngine",
    "ACTION_GATHER_EVIDENCE",
    "ACTION_INCREASE_MONITORING",
    "ACTION_FLAG_ANALYST_REVIEW",
    "ACTION_RECOMMEND_CONTAINMENT",
    "ACTION_LOG_BASELINE",
    "STATUS_RECOMMENDED",
    "STATUS_PENDING_APPROVAL",
    "STATUS_APPROVED",
    "STATUS_REJECTED",
    "STATUS_EXECUTED_DRY_RUN",
    "AGENT_NAME",
    "AGENT_VERSION",
]
