"""
agents/alert_correlation/agent.py
=================================
Alert Correlation Agent

Logically correlates multiple independent alerts and multi-source telemetry
into unified security incidents and multi-stage attack sequences.

Supports:
  1. Single-event multi-agent correlation (exact event_id grouping)
  2. Stateful rolling-window attack progression correlation (MITRE ATT&CK stages)
"""

import copy
import datetime
import logging
import re
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple

from agents.alert_correlation.config import (
    AGENT_NAME,
    DEFAULT_WINDOW_SECONDS,
    STAGE_DATA_STAGING,
    STAGE_EXFILTRATION,
    STAGE_INITIAL_ACCESS,
    STAGE_PRIVILEGE_ESCALATION,
    STAGE_RECONNAISSANCE,
    STAGE_TECHNIQUES,
)

logger = logging.getLogger("SOC.AlertCorrelation")


class AlertCorrelationAgent:
    """
    Rule-based and Stateful Alert Correlation Agent.
    Evaluates alerts and telemetry to:
      1. Determine if multiple detections relate to the same underlying network event.
      2. Correlate multi-stage attack sequences across time (Recon -> Access -> PrivEsc -> Staging -> Exfil).
    """

    def __init__(self, window_seconds: int = DEFAULT_WINDOW_SECONDS):
        self._namespace = uuid.NAMESPACE_OID
        self.window_seconds = window_seconds
        # Entity sliding state store: entity_key -> list of telemetry records
        self._entity_windows: Dict[str, List[Dict[str, Any]]] = {}
        # Active sequence incidents: incident_id -> incident dict
        self._sequence_incidents: Dict[str, Dict[str, Any]] = {}

    # -----------------------------------------------------------------------
    # 1. Single-Event Alert Correlation (Backward-Compatible API)
    # -----------------------------------------------------------------------

    def correlate(self, alerts: list[dict]) -> list[dict]:
        """
        Evaluate a list of alert dictionaries and group them into structured incidents
        based on exact event_id matching.

        Args:
            alerts: A list of dicts representing alerts.

        Returns:
            A list of Incident dictionaries. Returns an empty list if no correlations occur.
        """
        if not alerts:
            return []

        if not isinstance(alerts, list):
            raise TypeError("AlertCorrelationAgent.correlate() expects a list of alert dictionaries.")

        # Group by event_id
        grouped: dict[str, list[dict]] = {}
        for alert in alerts:
            if not isinstance(alert, dict):
                raise TypeError("Alert items must be dictionaries.")

            event_id = alert.get("event_id")
            alert_id = alert.get("alert_id")

            if not event_id:
                raise ValueError("Encountered alert missing 'event_id'. Correlation is impossible.")
            if not alert_id:
                raise ValueError(f"Encountered alert missing 'alert_id' (event_id: {event_id}).")

            grouped.setdefault(event_id, []).append(alert)

        incidents = []

        for event_id, event_alerts in grouped.items():
            # Rule 1, 2 & 3: We only correlate if 2 or more alerts exist for the same event
            if len(event_alerts) < 2:
                continue

            # Remove potential duplicate alert copies within the input list
            unique_alerts = {a["alert_id"]: a for a in event_alerts}
            if len(unique_alerts) < 2:
                continue

            deduped_alerts = list(unique_alerts.values())

            # Rule 4 & 5: Build the incident
            incident = self._build_incident(event_id, deduped_alerts)
            incidents.append(incident)

        return incidents

    def _build_incident(self, event_id: str, alerts: list[dict]) -> dict[str, Any]:
        """Apply correlation rules to formulate the incident dictionary."""
        alert_ids = sorted(a["alert_id"] for a in alerts)
        agents = sorted(set(a.get("agent", "Unknown Agent") for a in alerts))

        # Idempotency handling: Hash the sorted alert_ids to ensure deterministic incident_ids
        stable_hash = "".join(alert_ids)
        incident_id = str(uuid.uuid5(self._namespace, stable_hash))

        # Severity Logic Calculation
        high_count = 0
        med_count = 0

        for a in alerts:
            sev = a.get("severity", "LOW").upper()
            if sev == "HIGH":
                high_count += 1
            elif sev == "MEDIUM":
                med_count += 1

        if high_count >= 2:
            severity = "HIGH"
        elif high_count == 1:
            severity = "MEDIUM"
        elif med_count > 0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        # Determine incident status
        if severity in ("HIGH", "MEDIUM"):
            status = "CORRELATED_THREAT"
            prediction = "Potential Threat"
        else:
            status = "CORRELATED_NORMAL"
            prediction = "Normal"

        now = datetime.datetime.now().isoformat()
        reason = (
            f"Correlated {len(alerts)} alerts targeting event_id {event_id}. "
            f"Agents involved: {', '.join(agents)}."
        )

        return {
            "incident_id": incident_id,
            "event_id": event_id,
            "timestamp": now,
            "correlated_agents": agents,
            "alert_ids": alert_ids,
            "correlation_reason": reason,
            "prediction": prediction,
            "severity": severity,
            "status": status,
            "created_at": now,
        }

    # -----------------------------------------------------------------------
    # 2. Stateful Sliding-Window Attack Progression Correlator
    # -----------------------------------------------------------------------

    def ingest_telemetry(
        self,
        event: Optional[Dict[str, Any]] = None,
        alerts: Optional[List[Dict[str, Any]]] = None,
        system_log: Optional[Dict[str, Any]] = None,
        content_report: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Ingest a telemetry item into the stateful temporal sliding window and evaluate
        for multi-stage MITRE ATT&CK progression.

        Args:
            event: Network flow event dictionary.
            alerts: Detection alerts (Network Detection, Anomaly Detection).
            system_log: Normalized host system log dictionary.
            content_report: Content & Context Inspection report.

        Returns:
            A Coordinated Attack Sequence Incident dict if >= 2 stages are correlated,
            or None if no multi-stage progression is observed.
        """
        now_dt = datetime.datetime.now()
        now_ts = now_dt.timestamp()
        now_iso = now_dt.isoformat()

        # 1. Determine entity key(s)
        entity_keys = self._extract_entity_keys(event, alerts, system_log, content_report)
        if not entity_keys:
            return None

        # 2. Classify MITRE stages
        stages_found = self._classify_stages(event, alerts, system_log, content_report)
        if not stages_found:
            return None

        # Build telemetry record
        record_id = (
            (event and event.get("event_id"))
            or (system_log and system_log.get("log_id"))
            or (content_report and content_report.get("inspection_id"))
            or str(uuid.uuid4())
        )
        record = {
            "record_id": record_id,
            "timestamp": now_iso,
            "epoch": now_ts,
            "stages": stages_found,
            "event": event,
            "alerts": alerts or [],
            "system_log": system_log,
            "content_report": content_report,
        }

        # 3. Ingest into each entity window and prune
        resulting_incident = None
        for key in entity_keys:
            window = self._entity_windows.setdefault(key, [])
            window.append(record)
            self._prune_window(key, now_ts)

            # 4. Check for multi-stage attack sequence
            seq_incident = self._evaluate_sequence(key)
            if seq_incident:
                if resulting_incident is None or seq_incident.get("stage_count", 0) > resulting_incident.get("stage_count", 0):
                    resulting_incident = seq_incident

        return resulting_incident

    def _extract_entity_keys(
        self,
        event: Optional[Dict[str, Any]],
        alerts: Optional[List[Dict[str, Any]]],
        system_log: Optional[Dict[str, Any]],
        content_report: Optional[Dict[str, Any]],
    ) -> List[str]:
        """Extract indexing entity keys (IP addresses, hostname, user)."""
        keys = set()

        if event:
            if event.get("src_ip"):
                keys.add(event["src_ip"])
            if event.get("dst_ip"):
                keys.add(event["dst_ip"])

        if system_log:
            if system_log.get("source_host"):
                keys.add(system_log["source_host"])
            if system_log.get("user"):
                keys.add(f"user:{system_log['user']}")
            msg = system_log.get("message", "")
            # Extract any IP from log message
            ip_matches = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", msg)
            for ip in ip_matches:
                keys.add(ip)

        if content_report:
            dest = content_report.get("destination_evaluation", {}).get("destination")
            if dest:
                keys.add(dest)
            user = content_report.get("process_evaluation", {}).get("user")
            if user:
                keys.add(f"user:{user}")

        if alerts:
            for a in alerts:
                ctx = a.get("network_context", {})
                if ctx.get("src_ip"):
                    keys.add(ctx["src_ip"])
                if ctx.get("dst_ip"):
                    keys.add(ctx["dst_ip"])

        return [k for k in keys if k and k not in ("unknown", "127.0.0.1", "none", "")]

    def _classify_stages(
        self,
        event: Optional[Dict[str, Any]],
        alerts: Optional[List[Dict[str, Any]]],
        system_log: Optional[Dict[str, Any]],
        content_report: Optional[Dict[str, Any]],
    ) -> List[str]:
        """Determine which MITRE kill-chain stages are represented in this telemetry."""
        stages = set()

        # Check Host System Logs
        if system_log:
            service = (system_log.get("service") or "").lower()
            log_type = (system_log.get("log_type") or "").lower()
            msg = (system_log.get("message") or "").lower()

            # Stage 2: Initial Access / Brute Force
            if "sshd" in service or "auth" in log_type or "failed password" in msg or "invalid user" in msg:
                stages.add(STAGE_INITIAL_ACCESS)

            # Stage 3: Privilege Escalation
            if "sudo" in service or "sudo" in msg or "command=" in msg or "privesc" in log_type:
                stages.add(STAGE_PRIVILEGE_ESCALATION)

            # Stage 4: Data Staging
            if any(f in msg for f in [".env", "id_rsa", "/etc/shadow", "tar -czf", "zip -r", ".bash_history"]):
                stages.add(STAGE_DATA_STAGING)

        # Check Content Inspection Report
        if content_report:
            verdict = content_report.get("verdict")
            sensitive = content_report.get("sensitive_matches") or []

            if sensitive:
                stages.add(STAGE_DATA_STAGING)

            if verdict == "EXFILTRATION_CRITICAL":
                stages.add(STAGE_EXFILTRATION)

        # Check Network Flow & Alerts
        if alerts:
            for a in alerts:
                pred = (a.get("prediction") or "").lower()
                sev = (a.get("severity") or "").upper()
                if "infilteration" in pred or "attack" in pred or sev == "HIGH":
                    stages.add(STAGE_EXFILTRATION)

        if event:
            features = event.get("features", {})
            if isinstance(features, dict):
                # Reconnaissance indicators: High SYN flags with RST or 0 ACK, port 0, high packet rate
                syn_cnt = features.get("SYN Flag Cnt", 0)
                rst_cnt = features.get("RST Flag Cnt", 0)
                dst_port = features.get("Dst Port")
                tot_fwd = features.get("Tot Fwd Pkts", 0)
                tot_bwd = features.get("Tot Bwd Pkts", 0)

                if (syn_cnt > 0 and tot_bwd == 0) or dst_port == 0 or (tot_fwd > 50 and tot_bwd == 0):
                    stages.add(STAGE_RECONNAISSANCE)

        return sorted(list(stages))

    def _prune_window(self, entity_key: str, current_epoch: float) -> None:
        """Remove telemetry older than sliding window threshold."""
        if entity_key not in self._entity_windows:
            return
        cutoff = current_epoch - self.window_seconds
        self._entity_windows[entity_key] = [
            r for r in self._entity_windows[entity_key] if r.get("epoch", 0) >= cutoff
        ]

    def _evaluate_sequence(self, entity_key: str) -> Optional[Dict[str, Any]]:
        """
        Examine entity history for multi-stage progression.
        Returns a Coordinated Attack Sequence Incident if >= 2 distinct stages are present.
        """
        records = self._entity_windows.get(entity_key, [])
        if not records:
            return None

        # Collect distinct stages observed across all records in window
        stage_records: Dict[str, List[Dict[str, Any]]] = {}
        for r in records:
            for st in r.get("stages", []):
                stage_records.setdefault(st, []).append(r)

        distinct_stages = sorted(list(stage_records.keys()))
        if len(distinct_stages) < 2:
            return None

        # Build chronological timeline
        timeline = []
        for r in sorted(records, key=lambda x: x["epoch"]):
            for st in r["stages"]:
                detail = ""
                if r["system_log"]:
                    detail = f"System log: {r['system_log'].get('service')}: {r['system_log'].get('message', '')[:60]}"
                elif r["content_report"]:
                    detail = f"Content inspection: {r['content_report'].get('verdict')}"
                elif r["alerts"]:
                    detail = f"Alert: {r['alerts'][0].get('prediction')}"
                timeline.append({
                    "stage": st,
                    "timestamp": r["timestamp"],
                    "record_id": r["record_id"],
                    "detail": detail,
                })

        # MITRE techniques mapped
        techniques = []
        for st in distinct_stages:
            techniques.extend(STAGE_TECHNIQUES.get(st, []))
        techniques = sorted(list(set(techniques)))

        # Severity elevation: >= 3 stages or Exfiltration present -> CRITICAL
        has_exfil = STAGE_EXFILTRATION in distinct_stages
        if len(distinct_stages) >= 3 or has_exfil:
            severity = "CRITICAL"
        else:
            severity = "HIGH"

        stage_str = " -> ".join(distinct_stages)
        narrative = (
            f"Coordinated Multi-Stage Attack detected for entity '{entity_key}'. "
            f"Observed kill-chain sequence across {len(records)} events: {stage_str}. "
            f"Mapped MITRE ATT&CK techniques: {', '.join(techniques)}."
        )

        # Stable incident ID based on entity and stages
        stable_seed = f"seq:{entity_key}:{'-'.join(distinct_stages)}"
        incident_id = str(uuid.uuid5(self._namespace, stable_seed))

        now_iso = datetime.datetime.now().isoformat()
        incident = {
            "incident_id": incident_id,
            "incident_type": "ATTACK_SEQUENCE",
            "entity": entity_key,
            "timestamp": now_iso,
            "stages_detected": distinct_stages,
            "mitre_techniques": techniques,
            "stage_count": len(distinct_stages),
            "events_count": len(records),
            "severity": severity,
            "status": "CORRELATED_THREAT",
            "prediction": "Coordinated Multi-Stage Attack",
            "correlation_reason": narrative,
            "timeline": timeline,
            "is_coordinated_attack": True,
            "created_at": now_iso,
        }

        self._sequence_incidents[incident_id] = incident
        logger.warning(
            "ALERT: Coordinated Attack Sequence identified for %s: %s (Severity: %s)",
            entity_key, stage_str, severity,
        )
        return incident

    def has_preceding_compromise(self, entity_key: str) -> bool:
        """
        Check if an entity has observed initial access, brute force, or privilege escalation
        within its active sliding window.
        """
        if not entity_key:
            return False

        records = self._entity_windows.get(entity_key, [])
        for r in records:
            stages = r.get("stages", [])
            if STAGE_INITIAL_ACCESS in stages or STAGE_PRIVILEGE_ESCALATION in stages:
                return True
        return False

    def get_entity_state(self, entity_key: str) -> Dict[str, Any]:
        """Fetch current temporal window state and observed stages for an entity."""
        records = self._entity_windows.get(entity_key, [])
        stages = set()
        for r in records:
            stages.update(r.get("stages", []))
        return {
            "entity": entity_key,
            "active_events_count": len(records),
            "stages_observed": sorted(list(stages)),
            "has_compromise": self.has_preceding_compromise(entity_key),
        }

    def get_active_sequences(self) -> List[Dict[str, Any]]:
        """Return all currently active multi-stage sequence incidents."""
        return list(self._sequence_incidents.values())

    def clear_windows(self) -> None:
        """Reset temporal state memory (useful between test runs)."""
        self._entity_windows.clear()
        self._sequence_incidents.clear()
