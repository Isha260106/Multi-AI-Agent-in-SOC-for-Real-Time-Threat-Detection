"""
agents/response_playbooks/engine.py
===================================
Safe Response Playbook Recommendation Engine (Stage 12).

Multi-Agent SOC Project -- Stage 12: Response Playbooks

KEY PRINCIPLES:
  - ZERO AUTOMATIC MUTATION: Operates strictly in recommendation / dry-run mode.
    Never blocks IP addresses, modifies firewall rules, or terminates processes automatically.
  - TRANSPARENT EVIDENCE CITATIONS: Links every recommendation to concrete model
    predictions, anomaly scores, and threat intelligence findings.
  - IDEMPOTENCY: Deterministic UUID5 identifiers prevent duplicate playbooks for the same event.
  - COMPLETE AUDIT LOGGING: Records triggering signals, recommended actions,
    analyst approval state, and execution timestamps.
"""

import copy
import datetime
import json
import logging
import os
import pathlib
import sys
import uuid
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.response_playbooks.config import (
    ACTION_FLAG_ANALYST_REVIEW,
    ACTION_GATHER_EVIDENCE,
    ACTION_INCREASE_MONITORING,
    ACTION_LOG_BASELINE,
    ACTION_RECOMMEND_CONTAINMENT,
    AGENT_NAME,
    AGENT_VERSION,
    PLAYBOOK_LOG_FILE,
    PLAYBOOK_RUNTIME_LOG,
    RULE_BENIGN_BASELINE,
    RULE_ELEVATED_THREAT,
    RULE_HIGH_CONFIDENCE_INFILTRATION,
    RULE_PORT_SWEEP_RECON,
    RULE_SUSPICIOUS_ANOMALY,
    STATUS_APPROVED,
    STATUS_EXECUTED_DRY_RUN,
    STATUS_PENDING_APPROVAL,
    STATUS_RECOMMENDED,
    STATUS_REJECTED,
)

logger = logging.getLogger("SOC.ResponsePlaybooks")
if not logger.handlers:
    PLAYBOOK_RUNTIME_LOG.parent.mkdir(parents=True, exist_ok=True)
    _fh = logging.FileHandler(PLAYBOOK_RUNTIME_LOG, encoding="utf-8")
    _fh.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    logger.addHandler(_fh)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False


# Canonical allowlisted action names
ALLOWLISTED_ACTIONS = {
    ACTION_RECOMMEND_CONTAINMENT,
    ACTION_FLAG_ANALYST_REVIEW,
    ACTION_INCREASE_MONITORING,
    ACTION_GATHER_EVIDENCE,
    ACTION_LOG_BASELINE,
}

# Normalization map for LLM output variations
ACTION_ALIASES = {
    "RECOMMEND_CONTAINMENT": ACTION_RECOMMEND_CONTAINMENT,
    "ACTION_RECOMMEND_CONTAINMENT": ACTION_RECOMMEND_CONTAINMENT,
    "RECOMMEND_CONTAINMENT_MANUAL_APPROVAL": ACTION_RECOMMEND_CONTAINMENT,
    "CONTAIN_HOST": ACTION_RECOMMEND_CONTAINMENT,
    "FLAG_FOR_ANALYST_REVIEW": ACTION_FLAG_ANALYST_REVIEW,
    "ACTION_FLAG_ANALYST_REVIEW": ACTION_FLAG_ANALYST_REVIEW,
    "ANALYST_REVIEW": ACTION_FLAG_ANALYST_REVIEW,
    "INCREASE_MONITORING": ACTION_INCREASE_MONITORING,
    "ACTION_INCREASE_MONITORING": ACTION_INCREASE_MONITORING,
    "GATHER_ADDITIONAL_EVIDENCE": ACTION_GATHER_EVIDENCE,
    "ACTION_GATHER_EVIDENCE": ACTION_GATHER_EVIDENCE,
    "GATHER_EVIDENCE": ACTION_GATHER_EVIDENCE,
    "LOG_BASELINE_ACTIVITY": ACTION_LOG_BASELINE,
    "ACTION_LOG_BASELINE": ACTION_LOG_BASELINE,
    "LOG_BASELINE": ACTION_LOG_BASELINE,
}


class ResponsePlaybookEngine:
    """
    Deterministic Response Playbook Recommendation Engine.
    Generates structured, non-destructive incident response plans.
    Validates LLM reasoning proposals against strict SOC policy allowlists.
    """

    def __init__(self, log_to_file: bool = True):
        self.log_to_file = log_to_file

    @staticmethod
    def generate_playbook_id(event_id: str) -> str:
        """Deterministic UUID5 generation from event_id."""
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"soc-response-playbook:{event_id}"))

    def evaluate(
        self,
        event: Dict[str, Any],
        threat_assessment: Optional[Dict[str, Any]] = None,
        threat_investigation: Optional[Dict[str, Any]] = None,
        threat_intel: Optional[Dict[str, Any]] = None,
        llm_reasoning: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Evaluate event context and multi-agent outputs to synthesize a safe response playbook.
        Validates any LLM reasoning recommendations against strict allowlists and policy bounds.
        """
        event_id = event.get("event_id") or str(uuid.uuid4())
        playbook_id = self.generate_playbook_id(event_id)
        now_iso = datetime.datetime.now().isoformat()
        audit_trail: List[Dict[str, Any]] = []

        # Extract indicators & context
        src_ip = event.get("src_ip")
        dst_ip = event.get("dst_ip")
        dst_port = event.get("dst_port")
        protocol = event.get("protocol")

        # Threat Assessment telemetry
        category = "Benign"
        severity = "LOW"
        explanation = "Traffic categorized as benign baseline."
        if threat_assessment:
            category = threat_assessment.get("category", "Benign")
            severity = threat_assessment.get("severity", "LOW")
            explanation = threat_assessment.get("explanation", explanation)

        # Threat Intel telemetry
        intel_verdict = "UNKNOWN"
        if threat_intel:
            intel_verdict = threat_intel.get("aggregate_verdict") or threat_intel.get("verdict", "UNKNOWN")

        # Rule evaluation
        recommended_actions: List[Dict[str, Any]] = []
        triggering_evidence: List[str] = []
        rule_id = RULE_BENIGN_BASELINE
        requires_approval = False

        is_critical_attack = (
            category.lower() in ("infilteration", "infiltration")
            or severity.upper() in ("HIGH", "CRITICAL")
            or intel_verdict.upper() == "MALICIOUS"
        )
        is_suspicious_anomaly = (
            category.lower() in ("suspicious anomaly", "anomaly")
            or severity.upper() == "MEDIUM"
            or intel_verdict.upper() == "SUSPICIOUS"
        )

        if is_critical_attack:
            rule_id = RULE_HIGH_CONFIDENCE_INFILTRATION
            requires_approval = True
            triggering_evidence.append(f"Threat category '{category}' with severity '{severity}'.")
            triggering_evidence.append(f"Assessment summary: {explanation}")
            if threat_investigation and "summary" in threat_investigation:
                triggering_evidence.append(f"Forensic investigation: {threat_investigation['summary']}")

            target_host = src_ip or dst_ip or "Identified Attacker Host"

            recommended_actions.append({
                "action": ACTION_RECOMMEND_CONTAINMENT,
                "target": target_host,
                "rationale": "High-severity network threat pattern identified. Containment isolation recommended.",
                "requires_manual_approval": True,
                "execution_mode": "DRY_RUN_ONLY",
                "simulated_command": f"isolate-host --ip {target_host} --reason 'SOC-Incident-{event_id[:8]}'",
            })
            recommended_actions.append({
                "action": ACTION_FLAG_ANALYST_REVIEW,
                "target": "SOC Tier-2 Security Operations Queue",
                "rationale": "High-priority incident escalation for human verification and approval.",
                "requires_manual_approval": False,
                "execution_mode": "ACTIVE",
            })
            recommended_actions.append({
                "action": ACTION_INCREASE_MONITORING,
                "target": f"Flows targeting port {dst_port or 'all'}",
                "rationale": "Capture detailed packet headers and flow metrics for lateral movement detection.",
                "requires_manual_approval": False,
                "execution_mode": "DRY_RUN_ONLY",
            })

        elif is_suspicious_anomaly:
            rule_id = RULE_SUSPICIOUS_ANOMALY
            triggering_evidence.append(f"Statistical anomaly or medium severity: Category='{category}', Severity='{severity}'.")
            triggering_evidence.append(f"Assessment details: {explanation}")

            target_host = src_ip or "Observed Flow"

            recommended_actions.append({
                "action": ACTION_INCREASE_MONITORING,
                "target": target_host,
                "rationale": "Elevated anomaly score in flow statistics. Tighten observation window.",
                "requires_manual_approval": False,
                "execution_mode": "DRY_RUN_ONLY",
            })
            recommended_actions.append({
                "action": ACTION_GATHER_EVIDENCE,
                "target": "Surrounding 60-Minute Flow Records",
                "rationale": "Compile historical flow baseline for source host to evaluate periodicity.",
                "requires_manual_approval": False,
                "execution_mode": "DRY_RUN_ONLY",
            })
            recommended_actions.append({
                "action": ACTION_FLAG_ANALYST_REVIEW,
                "target": "SOC Tier-1 Triage Queue",
                "rationale": "Review anomalous flow parameters against scheduled batch jobs or maintenance.",
                "requires_manual_approval": False,
                "execution_mode": "ACTIVE",
            })

        else:
            rule_id = RULE_BENIGN_BASELINE
            triggering_evidence.append("Flow metrics conform to normal baseline distribution. No active threat indicators.")
            recommended_actions.append({
                "action": ACTION_LOG_BASELINE,
                "target": "Central SQLite Event Storage",
                "rationale": "Record benign flow observation for rolling statistical baseline update.",
                "requires_manual_approval": False,
                "execution_mode": "ACTIVE",
            })

        # ------------------------------------------------------------------
        # LLM Reasoning Integration & Policy Allowlist Enforcement
        # ------------------------------------------------------------------
        llm_metadata: Dict[str, Any] = {}
        if llm_reasoning:
            llm_output = llm_reasoning.get("output")
            if hasattr(llm_output, "model_dump"):
                llm_output = llm_output.model_dump()
            elif not isinstance(llm_output, dict):
                llm_output = {}

            llm_summary = llm_output.get("summary")
            llm_model = llm_reasoning.get("model_name", "gemini-2.5-flash")
            mitre_techs = llm_output.get("mitre_techniques", [])

            if llm_summary:
                triggering_evidence.append(f"Gemini Reasoning ({llm_model}): {llm_summary}")
            if mitre_techs:
                triggering_evidence.append(f"MITRE ATT&CK: {', '.join(mitre_techs)}")

            llm_metadata = {
                "reasoning_id": llm_reasoning.get("reasoning_id"),
                "model_name": llm_model,
                "status": llm_reasoning.get("status"),
                "mitre_techniques": mitre_techs,
                "uncertainties": llm_output.get("uncertainties", []),
            }

            # Validate each candidate recommendation from the LLM
            llm_actions = llm_output.get("recommended_actions", [])
            for cand in llm_actions:
                if hasattr(cand, "model_dump"):
                    cand = cand.model_dump()
                if not isinstance(cand, dict):
                    continue

                raw_action = str(cand.get("action", "")).strip()
                canonical_action = ACTION_ALIASES.get(raw_action.upper())

                if not canonical_action or canonical_action not in ALLOWLISTED_ACTIONS:
                    # Policy violation: LLM suggested an unsupported or dangerous action!
                    audit_trail.append({
                        "timestamp": now_iso,
                        "action": "LLM_ACTION_REJECTED",
                        "actor": f"{AGENT_NAME} Policy Gatekeeper",
                        "rejected_action": raw_action,
                        "target": cand.get("target"),
                        "reason": f"Action '{raw_action}' is not in SOC allowlist catalog. Autonomous execution prevented.",
                    })
                    continue

                # Ensure strict dry-run & approval invariants
                cand_requires_approval = bool(
                    cand.get("requires_approval")
                    or canonical_action == ACTION_RECOMMEND_CONTAINMENT
                    or is_critical_attack
                )
                if cand_requires_approval:
                    requires_approval = True

                # Check if action already exists in recommended_actions
                existing = next((a for a in recommended_actions if a["action"] == canonical_action), None)
                if existing:
                    if cand.get("reason") and cand["reason"] not in existing["rationale"]:
                        existing["rationale"] += f" | LLM Insight: {cand['reason']}"
                else:
                    new_action = {
                        "action": canonical_action,
                        "target": cand.get("target") or (src_ip or "Identified Host"),
                        "rationale": cand.get("reason") or "Recommended by Gemini Flash reasoning agent.",
                        "requires_manual_approval": cand_requires_approval,
                        "execution_mode": "DRY_RUN_ONLY",
                    }
                    if canonical_action == ACTION_RECOMMEND_CONTAINMENT:
                        new_action["simulated_command"] = f"isolate-host --ip {new_action['target']} --reason 'SOC-Incident-{event_id[:8]}'"
                    recommended_actions.append(new_action)

                audit_trail.append({
                    "timestamp": now_iso,
                    "action": "LLM_ACTION_VALIDATED",
                    "actor": f"{AGENT_NAME} Policy Gatekeeper",
                    "validated_action": canonical_action,
                    "target": cand.get("target"),
                    "requires_approval": cand_requires_approval,
                    "notes": "Action passed schema validation and allowlist policy checks.",
                })

        approval_status = STATUS_PENDING_APPROVAL if requires_approval else STATUS_RECOMMENDED

        audit_entry = {
            "timestamp": now_iso,
            "action": "PLAYBOOK_EVALUATED",
            "actor": f"{AGENT_NAME} v{AGENT_VERSION}",
            "rule_id": rule_id,
            "status": approval_status,
            "notes": "Automated non-destructive response recommendation generated.",
        }
        audit_trail.insert(0, audit_entry)

        playbook_record = {
            "playbook_id": playbook_id,
            "event_id": event_id,
            "threat_category": category,
            "severity": severity,
            "status": approval_status,
            "dry_run": True,
            "rule_id": rule_id,
            "recommended_actions": recommended_actions,
            "triggering_evidence": triggering_evidence,
            "approval_status": approval_status,
            "analyst_notes": None,
            "llm_metadata": llm_metadata,
            "audit_trail": audit_trail,
            "created_at": now_iso,
            "updated_at": now_iso,
        }

        if self.log_to_file:
            self._log_playbook(playbook_record)

        return playbook_record

    def apply_approval(
        self,
        playbook: Dict[str, Any],
        approved: bool,
        analyst_id: str = "analyst",
        notes: str = "",
    ) -> Dict[str, Any]:
        """
        Record a human analyst approval or rejection decision.
        Idempotent and safe: Updates audit trail without executing external destructive commands.
        """
        updated = copy.deepcopy(playbook)
        now_iso = datetime.datetime.now().isoformat()
        new_status = STATUS_APPROVED if approved else STATUS_REJECTED

        updated["approval_status"] = new_status
        updated["status"] = new_status
        updated["analyst_notes"] = notes
        updated["updated_at"] = now_iso

        audit_entry = {
            "timestamp": now_iso,
            "action": f"MANUAL_DECISION_{new_status}",
            "actor": analyst_id,
            "approved": approved,
            "notes": notes or ("Approved for containment execution (dry-run)." if approved else "Rejected by analyst."),
        }
        updated.setdefault("audit_trail", []).append(audit_entry)

        if self.log_to_file:
            self._log_playbook(updated)

        return updated

    def _log_playbook(self, playbook: Dict[str, Any]) -> None:
        """Append playbook to local JSON log."""
        try:
            PLAYBOOK_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(PLAYBOOK_LOG_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(playbook, ensure_ascii=False) + "\n")
        except Exception as exc:
            logger.error("Failed to append to response playbooks log: %s", exc)
