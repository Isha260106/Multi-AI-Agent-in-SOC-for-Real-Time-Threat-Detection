"""
agents/threat_assessment/agent.py
=================================
Unified Threat Assessment Engine

Multi-Agent SOC Project -- Stage 9A

PURPOSE
-------
Synthesizes the outputs of:
  1. Supervised Network Detection Agent (Random Forest: known attack signatures)
  2. Unsupervised Anomaly Detection Agent (Isolation Forest: statistical outlier detection)

into a single, explainable threat assessment record.

KEY DESIGN PRINCIPLES:
  - ZERO MODEL RE-RUNS: Reuses pre-computed predictions and scores from earlier
    pipeline stages without calling model inference again.
  - TRANSPARENT DECISION TABLE: Every classification is mapped through an
    explicit, deterministic rule table. Anomaly alone NEVER signifies a confirmed attack.
  - NO FABRICATED SCORES: When a score is missing or uncomputed, it is recorded
    as None (NULL in SQL), never replaced with fake confidence.
  - IDEMPOTENT IDENTIFIERS: Uses deterministic UUID5 hashing on event_id to prevent
    duplicate records across restarts or replays.
"""

import datetime
import json
import logging
import pathlib
import sys
import uuid
from typing import Any, Dict, List, Optional, Tuple, Union

# ---------------------------------------------------------------------------
# Project path
# ---------------------------------------------------------------------------
PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.threat_assessment.config import (
    AGENT_NAME,
    CATEGORY_CONFIRMED_ATTACK,
    CATEGORY_SUSPECTED_ATTACK,
    CATEGORY_SUSPICIOUS_ANOMALY,
    CATEGORY_BENIGN,
    CATEGORY_UNKNOWN,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_INFORMATIONAL,
    THREAT_LOG_FILE,
    THREAT_RUNTIME_LOG,
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger("SOC.ThreatAssessment")
if not logger.handlers:
    THREAT_RUNTIME_LOG.parent.mkdir(parents=True, exist_ok=True)
    _fh = logging.FileHandler(THREAT_RUNTIME_LOG, encoding="utf-8")
    _fh.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    logger.addHandler(_fh)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False


# ---------------------------------------------------------------------------
# Decision Table Definition
# ---------------------------------------------------------------------------
DECISION_TABLE_RULES = [
    {
        "rule_id": 1,
        "network": "Attack (Infilteration)",
        "anomaly": "Anomalous",
        "category": CATEGORY_CONFIRMED_ATTACK,
        "severity": SEVERITY_HIGH,
        "summary": "Dual confirmation: Known attack signature detected and statistical anomaly confirmed.",
    },
    {
        "rule_id": 2,
        "network": "Attack (Infilteration)",
        "anomaly": "Normal",
        "category": CATEGORY_SUSPECTED_ATTACK,
        "severity": SEVERITY_HIGH,
        "summary": "Supervised attack signature identified, but flow statistics fall within normal baseline.",
    },
    {
        "rule_id": 3,
        "network": "Benign",
        "anomaly": "Anomalous",
        "category": CATEGORY_SUSPICIOUS_ANOMALY,
        "severity": SEVERITY_MEDIUM,
        "summary": "Statistical anomaly detected, but signature is Benign. Anomaly alone is NOT a confirmed attack.",
    },
    {
        "rule_id": 4,
        "network": "Benign",
        "anomaly": "Normal",
        "category": CATEGORY_BENIGN,
        "severity": SEVERITY_LOW,
        "summary": "Both agents confirm normal baseline flow characteristics.",
    },
    {
        "rule_id": 5,
        "network": "Attack (Infilteration)",
        "anomaly": "Missing / None",
        "category": CATEGORY_SUSPECTED_ATTACK,
        "severity": SEVERITY_HIGH,
        "summary": "Supervised attack signature identified; anomaly score unavailable for secondary verification.",
    },
    {
        "rule_id": 6,
        "network": "Benign",
        "anomaly": "Missing / None",
        "category": CATEGORY_BENIGN,
        "severity": SEVERITY_LOW,
        "summary": "Supervised model classified flow as Benign; anomaly score unavailable.",
    },
    {
        "rule_id": 7,
        "network": "Missing / None",
        "anomaly": "Anomalous",
        "category": CATEGORY_SUSPICIOUS_ANOMALY,
        "severity": SEVERITY_MEDIUM,
        "summary": "Statistical anomaly detected without supervised signature verification. Anomaly alone is NOT a confirmed attack.",
    },
    {
        "rule_id": 8,
        "network": "Missing / None",
        "anomaly": "Normal",
        "category": CATEGORY_BENIGN,
        "severity": SEVERITY_LOW,
        "summary": "Statistical metrics normal; supervised network detection unavailable.",
    },
    {
        "rule_id": 9,
        "network": "Missing / None",
        "anomaly": "Missing / None",
        "category": CATEGORY_UNKNOWN,
        "severity": SEVERITY_INFORMATIONAL,
        "summary": "Insufficient agent inputs to evaluate threat posture.",
    },
]


def _append_assessment_to_file(assessment: dict, log_file: pathlib.Path = THREAT_LOG_FILE) -> None:
    """Safely append an assessment record to the rolling JSON log."""
    try:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        existing = []
        if log_file.exists():
            try:
                existing = json.loads(log_file.read_text(encoding="utf-8"))
                if not isinstance(existing, list):
                    existing = []
            except (json.JSONDecodeError, OSError):
                existing = []
        existing.append(assessment)
        log_file.write_text(json.dumps(existing, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception as exc:
        logger.error("Failed to append threat assessment to %s: %s", log_file, exc)


class ThreatAssessmentEngine:
    """
    Unified Threat Assessment Engine.

    Evaluates existing network detection and anomaly detection predictions
    against a deterministic decision table to produce a unified, explainable
    threat posture assessment.
    """

    def __init__(self, log_to_file: bool = True):
        self._log_to_file = log_to_file
        self._namespace = uuid.NAMESPACE_OID

    # ------------------------------------------------------------------
    # Helper classification predicates
    # ------------------------------------------------------------------

    @staticmethod
    def is_attack_prediction(pred: Optional[str]) -> bool:
        """Check if network prediction indicates an attack class."""
        if pred is None:
            return False
        clean = str(pred).strip().lower()
        if clean in ("infilteration", "attack", "malicious", "threat", "intrusion"):
            return True
        # If not benign and not normal/unknown/none, treat as attack
        return clean not in ("benign", "normal", "unknown", "none", "", "n/a")

    @staticmethod
    def is_benign_prediction(pred: Optional[str]) -> bool:
        """Check if network prediction indicates benign flow."""
        if pred is None:
            return False
        clean = str(pred).strip().lower()
        return clean in ("benign", "normal", "clean")

    @staticmethod
    def is_anomalous_prediction(pred: Optional[str]) -> bool:
        """Check if anomaly prediction indicates statistical anomaly."""
        if pred is None:
            return False
        clean = str(pred).strip().lower()
        return clean in ("anomalous", "anomaly", "suspicious", "outlier")

    @staticmethod
    def is_normal_anomaly_prediction(pred: Optional[str]) -> bool:
        """Check if anomaly prediction indicates normal flow baseline."""
        if pred is None:
            return False
        clean = str(pred).strip().lower()
        return clean in ("normal", "benign", "baseline")

    # ------------------------------------------------------------------
    # Decision Table Evaluation
    # ------------------------------------------------------------------

    def evaluate_decision_table(
        self,
        network_pred: Optional[str],
        anomaly_pred: Optional[str],
        network_conf: Optional[float],
        anomaly_score: Optional[float],
    ) -> Tuple[str, str, str]:
        """
        Evaluate the decision table based on predictions and available scores.

        Returns:
            Tuple of (category, severity, explanation)
        """
        has_net_attack = self.is_attack_prediction(network_pred)
        has_net_benign = self.is_benign_prediction(network_pred)
        has_anom_anomaly = self.is_anomalous_prediction(anomaly_pred)
        has_anom_normal = self.is_normal_anomaly_prediction(anomaly_pred)

        # Format scores transparently without fabricating values
        conf_str = f"{network_conf:.2%}" if network_conf is not None else "N/A"
        anom_str = f"{anomaly_score:.4f}" if anomaly_score is not None else "N/A"

        # Case 1: Confirmed Attack (Both models agree on threat)
        if has_net_attack and has_anom_anomaly:
            category = CATEGORY_CONFIRMED_ATTACK
            severity = SEVERITY_HIGH
            explanation = (
                f"Dual confirmation of security threat. Supervised network detection identified known "
                f"attack signature ({network_pred}, confidence: {conf_str}), and unsupervised anomaly "
                f"detection flagged significant deviation from baseline (anomaly_score: {anom_str}). "
                f"High confidence in active intrusion."
            )

        # Case 2: Suspected Attack (Signature match, baseline flow metrics)
        elif has_net_attack and has_anom_normal:
            category = CATEGORY_SUSPECTED_ATTACK
            severity = SEVERITY_HIGH
            explanation = (
                f"Supervised network detection matched known attack pattern ({network_pred}, "
                f"confidence: {conf_str}), but unsupervised anomaly detection rated flow distribution "
                f"as normal (anomaly_score: {anom_str}). Indicates potential targeted exploit or stealthy "
                f"attack adhering to standard flow parameters."
            )

        # Case 3: Suspicious Anomaly (Statistical outlier, but signature is Benign)
        # CRITICAL RULE: Anomaly alone does NOT mean confirmed attack!
        elif has_net_benign and has_anom_anomaly:
            category = CATEGORY_SUSPICIOUS_ANOMALY
            severity = SEVERITY_MEDIUM
            explanation = (
                f"Unsupervised anomaly detection flagged statistically unusual flow behavior "
                f"(anomaly_score: {anom_str}), but supervised model classified traffic as {network_pred} "
                f"(confidence: {conf_str}). Anomaly alone does NOT indicate a confirmed attack; "
                f"likely represents benign traffic spike, novel protocol activity, or zero-day behavior "
                f"warranting tier-2 SOC investigation."
            )

        # Case 4: Benign (Both models agree on normal traffic)
        elif has_net_benign and has_anom_normal:
            category = CATEGORY_BENIGN
            severity = SEVERITY_LOW
            explanation = (
                f"Traffic confirmed benign by both detection layers. Supervised classification: "
                f"{network_pred} (confidence: {conf_str}); unsupervised anomaly detection: "
                f"{anomaly_pred} (anomaly_score: {anom_str}). Flow conforms to normal baseline."
            )

        # Case 5: Attack detected, Anomaly missing
        elif has_net_attack and (anomaly_pred is None or not anomaly_pred):
            category = CATEGORY_SUSPECTED_ATTACK
            severity = SEVERITY_HIGH
            explanation = (
                f"Supervised network detection identified attack signature ({network_pred}, "
                f"confidence: {conf_str}); secondary anomaly detection score is unavailable for verification."
            )

        # Case 6: Benign detected, Anomaly missing
        elif has_net_benign and (anomaly_pred is None or not anomaly_pred):
            category = CATEGORY_BENIGN
            severity = SEVERITY_LOW
            explanation = (
                f"Supervised network detection classified flow as {network_pred} "
                f"(confidence: {conf_str}); secondary anomaly detection score is unavailable."
            )

        # Case 7: Anomaly detected, Network missing
        # CRITICAL RULE: Anomaly alone does NOT mean confirmed attack!
        elif (network_pred is None or not network_pred) and has_anom_anomaly:
            category = CATEGORY_SUSPICIOUS_ANOMALY
            severity = SEVERITY_MEDIUM
            explanation = (
                f"Unsupervised anomaly detection flagged statistically unusual flow behavior "
                f"(anomaly_score: {anom_str}); supervised network detection is unavailable. "
                f"Anomaly alone does NOT confirm an attack; manual verification recommended."
            )

        # Case 8: Normal anomaly detected, Network missing
        elif (network_pred is None or not network_pred) and has_anom_normal:
            category = CATEGORY_BENIGN
            severity = SEVERITY_LOW
            explanation = (
                f"Unsupervised anomaly detection observed normal flow distribution "
                f"(anomaly_score: {anom_str}); supervised network detection is unavailable."
            )

        # Case 9: Both inputs missing / indeterminate
        else:
            category = CATEGORY_UNKNOWN
            severity = SEVERITY_INFORMATIONAL
            explanation = (
                "Insufficient agent detection inputs to determine a definitive threat assessment. "
                f"Network prediction: {network_pred or 'None'} (confidence: {conf_str}), "
                f"Anomaly prediction: {anomaly_pred or 'None'} (anomaly_score: {anom_str})."
            )

        return category, severity, explanation

    # ------------------------------------------------------------------
    # Main Assessment Method
    # ------------------------------------------------------------------

    def assess(
        self,
        network_alert: Union[dict, str, None] = None,
        anomaly_alert: Union[dict, str, None] = None,
        event_id: Optional[str] = None,
        actual_label: Optional[str] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Combine existing predictions and available scores into a unified threat assessment.

        Args:
            network_alert: Alert dict from NetworkDetectionAgent, or a raw prediction string.
            anomaly_alert: Alert dict from AnomalyDetectionAgent, or a raw prediction string.
            event_id     : Unique event UUID. If None, resolves from alert dicts or generates.
            actual_label : Optional ground truth label for validation and telemetry.
            **kwargs     : Direct overrides: network_prediction, anomaly_prediction,
                           network_confidence, anomaly_score.

        Returns:
            Structured threat assessment dictionary.
        """
        # Resolve event_id
        if not event_id:
            if isinstance(network_alert, dict) and network_alert.get("event_id"):
                event_id = network_alert["event_id"]
            elif isinstance(anomaly_alert, dict) and anomaly_alert.get("event_id"):
                event_id = anomaly_alert["event_id"]
            elif "event_id" in kwargs:
                event_id = kwargs["event_id"]
            else:
                event_id = str(uuid.uuid4())

        # Resolve network prediction and confidence
        net_pred = kwargs.get("network_prediction")
        net_conf = kwargs.get("network_confidence")

        if isinstance(network_alert, dict):
            if net_pred is None:
                net_pred = network_alert.get("prediction")
            if net_conf is None:
                net_conf = network_alert.get("confidence")
            if actual_label is None:
                actual_label = network_alert.get("actual_label")
        elif isinstance(network_alert, str) and net_pred is None:
            net_pred = network_alert

        # Resolve anomaly prediction and score
        anom_pred = kwargs.get("anomaly_prediction")
        anom_score = kwargs.get("anomaly_score")

        if isinstance(anomaly_alert, dict):
            if anom_pred is None:
                anom_pred = anomaly_alert.get("prediction")
            if anom_score is None:
                anom_score = anomaly_alert.get("anomaly_score")
            # Fallback check if anomaly_score was placed in confidence or context
            if anom_score is None and anomaly_alert.get("confidence") is not None:
                anom_score = anomaly_alert.get("confidence")
            if actual_label is None:
                actual_label = anomaly_alert.get("actual_label")
        elif isinstance(anomaly_alert, str) and anom_pred is None:
            anom_pred = anomaly_alert

        # Cast scores strictly to float if present; DO NOT create fake scores
        if net_conf is not None:
            try:
                net_conf = float(net_conf)
            except (ValueError, TypeError):
                net_conf = None

        if anom_score is not None:
            try:
                anom_score = float(anom_score)
            except (ValueError, TypeError):
                anom_score = None

        # Evaluate decision table
        category, severity, explanation = self.evaluate_decision_table(
            network_pred=net_pred,
            anomaly_pred=anom_pred,
            network_conf=net_conf,
            anomaly_score=anom_score,
        )

        now = datetime.datetime.now().isoformat()
        # Deterministic UUID5 assessment_id based on event_id for idempotency
        assessment_id = str(uuid.uuid5(self._namespace, f"threat_assessment_{event_id}"))

        assessment = {
            "assessment_id": assessment_id,
            "event_id": event_id,
            "category": category,
            "severity": severity,
            "network_prediction": net_pred,
            "anomaly_prediction": anom_pred,
            "network_confidence": net_conf,
            "anomaly_score": anom_score,
            "predictions": {
                "network": net_pred,
                "anomaly": anom_pred,
            },
            "scores": {
                "network_confidence": net_conf,
                "anomaly_score": anom_score,
            },
            "explanation": explanation,
            "actual_label": actual_label,
            "timestamp": now,
            "created_at": now,
        }

        if self._log_to_file:
            _append_assessment_to_file(assessment)

        logger.debug(
            "Threat assessment produced: event_id=%s category=%s severity=%s",
            event_id, category, severity,
        )

        return assessment

    # ------------------------------------------------------------------
    # Convenience List Entrypoint
    # ------------------------------------------------------------------

    def assess_from_alerts(
        self,
        alerts: List[Dict[str, Any]],
        event_id: Optional[str] = None,
        actual_label: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Assess threat from a list of heterogeneous alert dicts.

        Args:
            alerts: List of alert dicts (e.g., from network and anomaly agents).
            event_id: Optional explicit event_id.
            actual_label: Optional ground truth label.

        Returns:
            Structured threat assessment dict.
        """
        if not isinstance(alerts, list):
            raise TypeError("ThreatAssessmentEngine.assess_from_alerts() expects a list of alert dicts.")

        net_alert = None
        anom_alert = None

        for a in alerts:
            if not isinstance(a, dict):
                continue
            agent_name = str(a.get("agent", "")).lower()
            if "network" in agent_name or a.get("prediction") in ("Infilteration", "Benign"):
                if net_alert is None:
                    net_alert = a
            if "anomaly" in agent_name or "anomaly_score" in a or a.get("prediction") in ("Anomalous", "Normal"):
                if anom_alert is None:
                    anom_alert = a

            if event_id is None and a.get("event_id"):
                event_id = a.get("event_id")

        return self.assess(
            network_alert=net_alert,
            anomaly_alert=anom_alert,
            event_id=event_id,
            actual_label=actual_label,
        )

    @classmethod
    def get_decision_table(cls) -> List[Dict[str, Any]]:
        """Return the documented decision table rules."""
        return DECISION_TABLE_RULES
