"""
agent.py
========
Alert Correlation Agent

Logically correlates multiple independent alerts into a single unified security incident.
"""

import copy
import datetime
import uuid
from typing import Any

from agents.alert_correlation.config import AGENT_NAME


class AlertCorrelationAgent:
    """
    Rule-based Alert Correlation Agent.
    Evaluates alerts to determine if multiple detections relate to the same
    underlying network event, outputting a correlated incident.
    """

    def __init__(self):
        # We use a deterministic namespace for UUID generation to ensure idempotency
        self._namespace = uuid.NAMESPACE_OID

    def correlate(self, alerts: list[dict]) -> list[dict]:
        """
        Evaluate a list of alert dictionaries and group them into structured incidents.

        Args:
            alerts: A list of dicts representing alerts (e.g. from SQLite or streaming).

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
                # After deduplication, if only one alert remains, skip (Rule 3)
                continue
                
            deduped_alerts = list(unique_alerts.values())

            # Rule 4 & 5: Build the incident
            incident = self._build_incident(event_id, deduped_alerts)
            incidents.append(incident)

        return incidents

    def _build_incident(self, event_id: str, alerts: list[dict]) -> dict[str, Any]:
        """Apply correlation rules to formulate the incident dictionary."""
        alert_ids = sorted(a["alert_id"] for a in alerts)
        agents    = sorted(set(a.get("agent", "Unknown Agent") for a in alerts))
        
        # Idempotency handling: Hash the sorted alert_ids to ensure deterministic incident_ids
        stable_hash = "".join(alert_ids)
        incident_id = str(uuid.uuid5(self._namespace, stable_hash))

        # Severity Logic Calculation
        high_count = 0
        med_count  = 0
        
        for a in alerts:
            sev = a.get("severity", "LOW").upper()
            if sev == "HIGH":
                high_count += 1
            elif sev == "MEDIUM":
                med_count += 1

        if high_count >= 2:
            severity = "HIGH"
        elif high_count == 1:
            # e.g., Network=HIGH, Anomaly=LOW (or vice-versa) -> Medium overall Incident severity
            # Alternatively, Network Detection is strongly supervised, so wait... the prompt suggests:
            # "HIGH: A Network Detection Agent alert is HIGH and the related anomaly alert is Anomalous"
            # Actually, both AD and ND output "HIGH" for their anomalous/suspicious predictions.
            # So if one is HIGH and one is LOW, the suggestion is MEDIUM.
            severity = "MEDIUM"
        elif med_count > 0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        # Predictions mapping
        predictions = {a.get("prediction", "Unknown") for a in alerts}
        
        # Determine incident status
        if severity in ("HIGH", "MEDIUM"):
            status = "CORRELATED_THREAT"
            prediction = "Potential Threat"
        else:
            status = "CORRELATED_NORMAL"
            prediction = "Normal"

        now = datetime.datetime.now().isoformat()

        reason = (f"Correlated {len(alerts)} alerts targeting event_id {event_id}. "
                  f"Agents involved: {', '.join(agents)}.")

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
            "created_at": now
        }
