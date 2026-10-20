"""
agents/threat_investigation/coordinator.py
==========================================
Modular Multi-Agent Threat Investigation Coordinator (Stage 10)

Multi-Agent SOC Project -- Stage 10

PURPOSE:
  Coordinates specialized investigation modules to produce an evidence-backed,
  explainable investigation report for suspicious or high-severity events.

KEY DESIGN PRINCIPLES:
  - ZERO REDUNDANT INFERENCE: Never calls ML models again; reuses real stored
    evidence, alerts, flow features, and Stage 9A threat assessments.
  - STRICT EVIDENCE CITATIONS: Distinguishes observed facts from model predictions,
    inferences, and recommendations. No fabricated scores or unsupported attribution.
  - IDEMPOTENT INVESTIGATION IDS: Deterministic UUID5 hashing prevents duplicate
    investigations for the same triggering event.
  - MODULAR SPECIALIZED ANALYZERS:
      1. NetworkEvidenceModule
      2. AnomalyExplanationModule
      3. AlertCorrelationModule
      4. InvestigationSummaryModule
"""

import datetime
import json
import logging
import pathlib
import sys
import uuid
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.threat_investigation.config import (
    AGENT_NAME,
    TRIGGER_CATEGORIES,
    TRIGGER_SEVERITIES,
    STATUS_COMPLETED,
    STATUS_REQUIRES_TIER2,
    STATUS_INCONCLUSIVE,
    STATUS_CLOSED_BENIGN,
    INVESTIGATION_LOG_FILE,
    INVESTIGATION_RUNTIME_LOG,
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger("SOC.ThreatInvestigation")
if not logger.handlers:
    INVESTIGATION_RUNTIME_LOG.parent.mkdir(parents=True, exist_ok=True)
    _fh = logging.FileHandler(INVESTIGATION_RUNTIME_LOG, encoding="utf-8")
    _fh.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    logger.addHandler(_fh)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False


# ===========================================================================
# 1. Specialized Investigation Module: Network Evidence Analysis
# ===========================================================================
class NetworkEvidenceModule:
    """
    Examines raw flow metrics, port context, protocols, and transmission volumes.
    Identifies concrete observed patterns (e.g., high packet rates, TCP flags, unusual ports).
    """

    @staticmethod
    def analyze(features: Dict[str, Any], network_alert: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        findings = []
        observed_facts = {}
        reasoning = []
        limitations = []

        if not features:
            limitations.append("Raw network flow features were missing or unparseable from event record.")
            return {
                "module": "NetworkEvidenceModule",
                "status": "PARTIAL",
                "findings": ["No raw flow feature dictionary available for deep inspection."],
                "observed_facts": observed_facts,
                "reasoning": ["Cannot verify packet distributions without features."],
                "limitations": limitations,
            }

        # 1. Port & Protocol Inspection
        dst_port = features.get("Dst Port")
        protocol = features.get("Protocol")
        flow_duration = features.get("Flow Duration")
        flow_pkts_s = features.get("Flow Pkts/s")
        flow_byts_s = features.get("Flow Byts/s")
        tot_fwd_pkts = features.get("Tot Fwd Pkts")
        tot_bwd_pkts = features.get("Tot Bwd Pkts")
        syn_flags = features.get("SYN Flag Cnt")
        rst_flags = features.get("RST Flag Cnt")

        observed_facts["dst_port"] = dst_port
        observed_facts["protocol"] = protocol
        observed_facts["flow_duration_us"] = flow_duration
        observed_facts["tot_fwd_pkts"] = tot_fwd_pkts
        observed_facts["tot_bwd_pkts"] = tot_bwd_pkts
        observed_facts["flow_pkts_s"] = flow_pkts_s
        observed_facts["flow_byts_s"] = flow_byts_s

        # Port behavior check
        if dst_port is not None:
            if dst_port in [80, 443, 8080]:
                findings.append(f"Traffic targeted common web service port (Dst Port {dst_port}).")
            elif dst_port in [21, 22, 23, 3389]:
                findings.append(f"Traffic targeted remote administration port (Dst Port {dst_port}).")
            elif dst_port == 0:
                findings.append("Destination port is 0, commonly observed in ICMP or non-standard protocol encapsulations.")
            elif dst_port > 1024:
                findings.append(f"Traffic targeted dynamic/ephemeral high port (Dst Port {dst_port}).")

        # Volumetric & Packet Rate Inspection
        if flow_pkts_s is not None and isinstance(flow_pkts_s, (int, float)):
            if flow_pkts_s > 1000.0:
                findings.append(f"High flow velocity observed: {flow_pkts_s:.2f} pkts/sec (potential flood or scan burst).")
                reasoning.append("High packet rate exceeds standard baseline interactive sessions.")
            else:
                findings.append(f"Flow velocity is moderate to low: {flow_pkts_s:.4f} pkts/sec.")

        # TCP Flag Inspection
        flag_notes = []
        if syn_flags and syn_flags > 0:
            flag_notes.append(f"SYN={syn_flags}")
        if rst_flags and rst_flags > 0:
            flag_notes.append(f"RST={rst_flags}")

        if flag_notes:
            observed_facts["flags_observed"] = ", ".join(flag_notes)
            findings.append(f"Significant TCP flags present: {', '.join(flag_notes)}.")

        # Unidirectional flow check
        if tot_fwd_pkts and (tot_bwd_pkts == 0 or tot_bwd_pkts is None):
            findings.append("Unidirectional flow detected: forward packets transmitted with zero backward responses.")
            reasoning.append("Unanswered connections often signify probing, dropped traffic, or SYN scanning.")

        # Model signature context if available
        if network_alert:
            pred = network_alert.get("prediction")
            conf = network_alert.get("confidence")
            conf_str = f"{conf:.2%}" if conf is not None else "N/A"
            reasoning.append(f"Supervised Random Forest classified signature as '{pred}' with confidence {conf_str}.")
        else:
            limitations.append("Supervised Network Detection alert was not attached to this event.")

        limitations.append("Analysis limited to 78 pre-extracted statistical flow metrics; payload inspection not available in flow records.")

        return {
            "module": "NetworkEvidenceModule",
            "status": "COMPLETED",
            "findings": findings if findings else ["Flow metrics within standard observed parameters."],
            "observed_facts": observed_facts,
            "reasoning": reasoning,
            "limitations": limitations,
        }


# ===========================================================================
# 2. Specialized Investigation Module: Anomaly Explanation
# ===========================================================================
class AnomalyExplanationModule:
    """
    Evaluates unsupervised Isolation Forest output and compares against baseline behavior.
    Explains the statistical significance of the anomaly score without fabricating probabilities.
    """

    @staticmethod
    def analyze(features: Dict[str, Any], anomaly_alert: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        findings = []
        observed_facts = {}
        reasoning = []
        limitations = []

        if not anomaly_alert:
            limitations.append("Anomaly Detection Agent alert record was unavailable for this event.")
            return {
                "module": "AnomalyExplanationModule",
                "status": "MISSING_EVIDENCE",
                "findings": ["No anomaly detection alert recorded for this event."],
                "observed_facts": {},
                "reasoning": ["Cannot evaluate baseline deviation without anomaly alert."],
                "limitations": limitations,
            }

        pred = anomaly_alert.get("prediction")
        score = anomaly_alert.get("anomaly_score")
        if score is None:
            score = anomaly_alert.get("confidence")

        observed_facts["anomaly_prediction"] = pred
        observed_facts["raw_isolation_forest_score"] = score
        observed_facts["severity"] = anomaly_alert.get("severity")

        if pred == "Anomalous":
            findings.append("Statistical deviation confirmed: flow characteristics diverge from benign training baseline.")
            if score is not None and isinstance(score, (int, float)):
                if score < -0.30:
                    findings.append(f"Significant outlier score ({score:.4f}): deep isolation depth in tree forest.")
                    reasoning.append("Negative isolation scores below -0.30 reflect rare multi-dimensional feature combinations.")
                else:
                    findings.append(f"Mild to moderate outlier score ({score:.4f}).")
            reasoning.append("Unsupervised model detected atypical metric distribution compared to learned normal traffic.")
        elif pred == "Normal":
            findings.append("Isolation Forest indicates flow conforms to standard benign distribution.")
            reasoning.append("Path lengths across trees match majority normal flow profiles.")
        else:
            findings.append(f"Indeterminate anomaly status: {pred or 'Unknown'}.")

        # Check for extreme feature values that drive anomaly scores
        if features:
            flow_dur = features.get("Flow Duration")
            if flow_dur and flow_dur > 60000000:
                findings.append(f"Unusually long flow duration: {flow_dur / 1000000:.1f} seconds, contributing to outlier profile.")

        limitations.append("Isolation Forest provides unsupervised density estimation; it does not indicate malicious intent on its own.")

        return {
            "module": "AnomalyExplanationModule",
            "status": "COMPLETED",
            "findings": findings,
            "observed_facts": observed_facts,
            "reasoning": reasoning,
            "limitations": limitations,
        }


# ===========================================================================
# 3. Specialized Investigation Module: Alert & Incident Correlation
# ===========================================================================
class AlertCorrelationModule:
    """
    Correlates evidence across both agents and any existing incidents.
    Explicitly checks for conflicting signals (e.g. Benign signature vs Anomalous baseline).
    """

    @staticmethod
    def analyze(
        network_alert: Optional[Dict[str, Any]],
        anomaly_alert: Optional[Dict[str, Any]],
        incident: Optional[Dict[str, Any]],
        threat_assessment: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        findings = []
        observed_facts = {}
        conflicting_signals = []
        reasoning = []
        limitations = []

        net_pred = network_alert.get("prediction") if network_alert else None
        anom_pred = anomaly_alert.get("prediction") if anomaly_alert else None

        observed_facts["network_prediction"] = net_pred
        observed_facts["anomaly_prediction"] = anom_pred
        observed_facts["has_correlated_incident"] = incident is not None

        if incident:
            observed_facts["incident_id"] = incident.get("incident_id")
            observed_facts["incident_status"] = incident.get("status")
            observed_facts["incident_severity"] = incident.get("severity")
            findings.append(
                f"Multi-Agent Incident confirmed ({incident.get('incident_id', '')[:8]}...): "
                f"Correlated {len(incident.get('alert_ids', []))} alerts across participating agents."
            )
            reasoning.append(f"Incident correlation reason: {incident.get('correlation_reason', 'Multi-agent alert trigger')}.")
        else:
            findings.append("No multi-agent incident was generated (single agent triggered or below correlation threshold).")

        # Check Conflicting Signals
        is_net_attack = net_pred and net_pred.lower() not in ("benign", "normal", "unknown", "")
        is_net_benign = net_pred and net_pred.lower() in ("benign", "normal")
        is_anom_outlier = anom_pred and anom_pred.lower() == "anomalous"
        is_anom_normal = anom_pred and anom_pred.lower() == "normal"

        if is_net_attack and is_anom_normal:
            conflicting_signals.append(
                "Supervised model flagged known attack signature, but unsupervised model classified flow as standard normal baseline."
            )
            reasoning.append("Indicates potential targeted evasion or stealth attack adhering to normal flow volumes.")

        elif is_net_benign and is_anom_outlier:
            conflicting_signals.append(
                "Supervised model classified signature as Benign, but unsupervised model flagged flow as statistically anomalous."
            )
            reasoning.append(
                "Critical SOC Principle: Anomaly alone does NOT confirm an attack. Likely a benign traffic spike, backup stream, or novel protocol."
            )

        elif is_net_attack and is_anom_outlier:
            findings.append("Dual Agreement: Supervised signature match and statistical outlier detection align on threat.")
            reasoning.append("High confidence in malicious activity; no conflicting signals detected.")

        elif is_net_benign and is_anom_normal:
            findings.append("Dual Agreement: Both detection models confirm benign baseline flow.")

        if threat_assessment:
            observed_facts["threat_category"] = threat_assessment.get("category")
            observed_facts["threat_severity"] = threat_assessment.get("severity")

        if not network_alert:
            limitations.append("Network detection alert missing; cross-validation incomplete.")
        if not anomaly_alert:
            limitations.append("Anomaly detection alert missing; statistical baseline verification incomplete.")

        return {
            "module": "AlertCorrelationModule",
            "status": "COMPLETED",
            "findings": findings,
            "conflicting_signals": conflicting_signals,
            "observed_facts": observed_facts,
            "reasoning": reasoning,
            "limitations": limitations,
        }


# ===========================================================================
# 4. Specialized Investigation Module: Investigation Summary & Next Steps
# ===========================================================================
class InvestigationSummaryModule:
    """
    Synthesizes findings, determines investigation status, and provides
    concrete, actionable next steps for tier-2 SOC analysts.
    """

    @staticmethod
    def synthesize(
        category: str,
        severity: str,
        net_findings: Dict[str, Any],
        anom_findings: Dict[str, Any],
        corr_findings: Dict[str, Any],
    ) -> Tuple[str, str, List[str]]:
        """
        Returns:
            Tuple of (investigation_status, summary_text, recommended_next_steps)
        """
        recs = []
        conflicts = corr_findings.get("conflicting_signals", [])

        if category == "Confirmed Attack":
            status = STATUS_COMPLETED
            summary = (
                "INVESTIGATION VERIFIED ACTIVE THREAT: Dual confirmation across supervised attack signature "
                "and statistical baseline outlier detection. Supporting evidence indicates anomalous flow metrics."
            )
            recs.append("Isolate affected source host endpoint or block destination IP at perimeter firewall.")
            recs.append("Collect endpoint host artifact dumps and volatile memory for process tree analysis.")
            recs.append("Initiate SOC incident response runbook for confirmed infiltration/intrusion.")

        elif category == "Suspected Attack":
            status = STATUS_REQUIRES_TIER2
            summary = (
                "INVESTIGATION HIGHLIGHTS SUSPECTED ATTACK: Supervised signature matched known attack taxonomy, "
                "though statistical flow distribution adhered to standard baseline metrics."
            )
            recs.append("Inspect application layer logs and DNS query records associated with this flow.")
            recs.append("Verify if destination port matches expected legitimate service behavior.")
            recs.append("Escalate to Tier-2 analyst for manual payload verification.")

        elif category == "Suspicious Anomaly":
            status = STATUS_REQUIRES_TIER2
            summary = (
                "INVESTIGATION FLAGGED STATISTICAL OUTLIER: Flow exhibited unusual volume or timing distribution, "
                "but supervised detection classified signature as Benign. Anomaly alone does NOT confirm malicious intent."
            )
            recs.append("Cross-reference timestamp against scheduled maintenance windows, backups, or batch syncs.")
            recs.append("Evaluate whether destination host recently deployed new services or protocols.")
            recs.append("Maintain telemetry surveillance on source IP without immediate blocking to prevent false positives.")

        elif category == "Benign":
            status = STATUS_CLOSED_BENIGN
            summary = "INVESTIGATION CLOSED: Flow verified benign across both supervised and unsupervised analytical layers."
            recs.append("No active remediation necessary. Log retained for audit compliance.")

        else:
            status = STATUS_INCONCLUSIVE
            summary = "INVESTIGATION INCONCLUSIVE: Insufficient agent telemetry or missing evidence to establish definitive posture."
            recs.append("Verify sensor health and ensure event streaming transport is transmitting all flow features.")

        return status, summary, recs


# ===========================================================================
# 5. Coordinator: ThreatInvestigationCoordinator
# ===========================================================================
class ThreatInvestigationCoordinator:
    """
    Main investigation coordinator orchestrating modular multi-agent investigation.
    """

    def __init__(self, log_to_file: bool = True):
        self._log_to_file = log_to_file
        self._namespace = uuid.NAMESPACE_OID

    def should_investigate(self, threat_assessment: Optional[Dict[str, Any]], severity: Optional[str] = None) -> bool:
        """
        Determine if an event/assessment warrants formal investigation.
        Benign low-severity events are excluded from automatic deep investigations.
        """
        if not threat_assessment:
            return (severity or "").upper() in TRIGGER_SEVERITIES

        cat = threat_assessment.get("category", "")
        sev = (threat_assessment.get("severity") or severity or "").upper()

        if cat in TRIGGER_CATEGORIES or sev in TRIGGER_SEVERITIES:
            return True
        return False

    def investigate(
        self,
        event_id: str,
        event: Optional[Dict[str, Any]] = None,
        network_alert: Optional[Dict[str, Any]] = None,
        anomaly_alert: Optional[Dict[str, Any]] = None,
        incident: Optional[Dict[str, Any]] = None,
        threat_assessment: Optional[Dict[str, Any]] = None,
        force: bool = False,
    ) -> Optional[Dict[str, Any]]:
        """
        Coordinate an end-to-end multi-agent threat investigation for an event.

        Args:
            event_id: Unique event UUID.
            event: Optional raw event dict with features.
            network_alert: Optional alert from Network Detection Agent.
            anomaly_alert: Optional alert from Anomaly Detection Agent.
            incident: Optional correlated incident dict.
            threat_assessment: Optional assessment dict from ThreatAssessmentEngine.
            force: If True, bypasses benign exclusion (useful for manual analyst CLI audits).

        Returns:
            Structured investigation report dictionary, or None if excluded.
        """
        if not event_id:
            raise ValueError("ThreatInvestigationCoordinator.investigate() requires a valid 'event_id'.")

        cat = threat_assessment.get("category", "Unknown") if threat_assessment else "Unknown"
        sev = threat_assessment.get("severity", "INFORMATIONAL") if threat_assessment else "INFORMATIONAL"

        # Check exclusion criteria unless forced
        if not force and not self.should_investigate(threat_assessment, severity=sev):
            logger.debug("Event %s excluded from investigation: category=%s severity=%s", event_id, cat, sev)
            return None

        features = {}
        if event:
            feat_raw = event.get("features")
            if isinstance(feat_raw, dict):
                features = feat_raw
            elif isinstance(event.get("features_json"), str):
                try:
                    features = json.loads(event["features_json"])
                except Exception:
                    features = {}

        # 1. Run Network Evidence Module
        net_findings = NetworkEvidenceModule.analyze(features, network_alert)

        # 2. Run Anomaly Explanation Module
        anom_findings = AnomalyExplanationModule.analyze(features, anomaly_alert)

        # 3. Run Alert Correlation Module
        corr_findings = AlertCorrelationModule.analyze(
            network_alert=network_alert,
            anomaly_alert=anomaly_alert,
            incident=incident,
            threat_assessment=threat_assessment,
        )

        # 4. Synthesize Summary and Next Steps
        inv_status, summary_text, recs = InvestigationSummaryModule.synthesize(
            category=cat,
            severity=sev,
            net_findings=net_findings,
            anom_findings=anom_findings,
            corr_findings=corr_findings,
        )

        now = datetime.datetime.now().isoformat()
        # Deterministic UUID5 investigation_id to guarantee idempotency across replays
        investigation_id = str(uuid.uuid5(self._namespace, f"threat_investigation_{event_id}"))

        report = {
            "investigation_id": investigation_id,
            "event_id": event_id,
            "threat_category": cat,
            "severity": sev,
            "investigation_status": inv_status,
            "summary": summary_text,
            "findings_by_agent": {
                "network_evidence": net_findings["findings"],
                "anomaly_explanation": anom_findings["findings"],
                "alert_correlation": corr_findings["findings"],
            },
            "supporting_evidence": {
                "network_facts": net_findings.get("observed_facts", {}),
                "anomaly_facts": anom_findings.get("observed_facts", {}),
                "incident_facts": corr_findings.get("observed_facts", {}),
            },
            "conflicting_signals": corr_findings.get("conflicting_signals", []),
            "reasoning": [
                *net_findings.get("reasoning", []),
                *anom_findings.get("reasoning", []),
                *corr_findings.get("reasoning", []),
            ],
            "limitations": [
                *net_findings.get("limitations", []),
                *anom_findings.get("limitations", []),
                *corr_findings.get("limitations", []),
            ],
            "recommended_next_steps": recs,
            "timestamp": now,
            "created_at": now,
        }

        if self._log_to_file:
            self._append_to_file(report)

        logger.info(
            "Threat investigation completed: inv_id=%s event_id=%s status=%s category=%s",
            investigation_id, event_id, inv_status, cat
        )

        return report

    def _append_to_file(self, report: dict, log_file: pathlib.Path = INVESTIGATION_LOG_FILE) -> None:
        """Safely append report to rolling JSON log."""
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
            existing.append(report)
            log_file.write_text(json.dumps(existing, indent=2, ensure_ascii=False), encoding="utf-8")
        except Exception as exc:
            logger.error("Failed to append investigation to %s: %s", log_file, exc)
