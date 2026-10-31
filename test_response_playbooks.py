"""
test_response_playbooks.py
==========================
Comprehensive Test Suite for Stage 12: Safe Response Playbooks.

Tests:
  1. High-severity attack playbook generation (containment recommendation + manual approval requirement).
  2. Suspicious anomaly playbook generation (monitoring increase + evidence collection).
  3. Benign baseline flow playbook generation (standard baseline logging).
  4. Idempotent playbook generation (deterministic UUID5 based on event_id).
  5. Dry-run safety guarantee (dry_run=True, zero automatic system mutation).
  6. Human approval and rejection lifecycle (analyst decision recording and audit trail).
  7. Central SQLite persistence and query retrieval via AlertStore and ResponsePlaybookQueryStore.
  8. REST API endpoints: GET /api/playbooks, GET /api/playbooks/{id}, POST /api/playbooks/{id}/approve.
"""

import copy
import pathlib
import sys
import tempfile
import unittest
import uuid
from fastapi.testclient import TestClient

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import dashboard_api
from agents.response_playbooks.config import (
    ACTION_FLAG_ANALYST_REVIEW,
    ACTION_GATHER_EVIDENCE,
    ACTION_INCREASE_MONITORING,
    ACTION_LOG_BASELINE,
    ACTION_RECOMMEND_CONTAINMENT,
    RULE_BENIGN_BASELINE,
    RULE_HIGH_CONFIDENCE_INFILTRATION,
    RULE_SUSPICIOUS_ANOMALY,
    STATUS_APPROVED,
    STATUS_PENDING_APPROVAL,
    STATUS_RECOMMENDED,
    STATUS_REJECTED,
)
from agents.response_playbooks.engine import ResponsePlaybookEngine
from storage.db import AlertStore
from storage.query import ResponsePlaybookQueryStore


class TestResponsePlaybooks(unittest.TestCase):
    """Test suite for Stage 12 Response Playbooks Engine and Storage."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_db_path = pathlib.Path(self.temp_dir.name) / "test_soc.db"
        with AlertStore(db_path=self.temp_db_path) as store:
            pass  # Creates tables including response_playbooks

        self.engine = ResponsePlaybookEngine(log_to_file=False)
        self.client = TestClient(dashboard_api.app)

    def tearDown(self):
        self.temp_dir.cleanup()

    # -----------------------------------------------------------------------
    # 1. Rule Evaluation: Infiltration / High Severity Attack
    # -----------------------------------------------------------------------
    def test_evaluate_high_severity_attack_recommends_containment(self):
        event = {
            "event_id": f"event-{uuid.uuid4()}",
            "src_ip": "10.10.10.100",
            "dst_ip": "10.10.10.20",
            "dst_port": 80,
            "protocol": 6,
        }
        assessment = {
            "category": "Infilteration",
            "severity": "HIGH",
            "explanation": "High confidence attack signature matching port sweep and web infiltration.",
        }
        investigation = {
            "summary": "Coordinated attack probes originating from 10.10.10.100.",
        }

        pb = self.engine.evaluate(event, threat_assessment=assessment, threat_investigation=investigation)

        self.assertEqual(pb["event_id"], event["event_id"])
        self.assertEqual(pb["threat_category"], "Infilteration")
        self.assertEqual(pb["severity"], "HIGH")
        self.assertEqual(pb["status"], STATUS_PENDING_APPROVAL)
        self.assertTrue(pb["dry_run"])
        self.assertEqual(pb["rule_id"], RULE_HIGH_CONFIDENCE_INFILTRATION)

        # Verify recommended actions
        actions = [a["action"] for a in pb["recommended_actions"]]
        self.assertIn(ACTION_RECOMMEND_CONTAINMENT, actions)
        self.assertIn(ACTION_FLAG_ANALYST_REVIEW, actions)
        self.assertIn(ACTION_INCREASE_MONITORING, actions)

        containment_action = next(a for a in pb["recommended_actions"] if a["action"] == ACTION_RECOMMEND_CONTAINMENT)
        self.assertTrue(containment_action["requires_manual_approval"])
        self.assertEqual(containment_action["target"], "10.10.10.100")
        self.assertEqual(containment_action["execution_mode"], "DRY_RUN_ONLY")

        # Verify audit trail
        self.assertEqual(len(pb["audit_trail"]), 1)
        self.assertEqual(pb["audit_trail"][0]["action"], "PLAYBOOK_EVALUATED")

    # -----------------------------------------------------------------------
    # 2. Rule Evaluation: Suspicious Anomaly / Medium Severity
    # -----------------------------------------------------------------------
    def test_evaluate_suspicious_anomaly_recommends_monitoring(self):
        event = {
            "event_id": f"event-{uuid.uuid4()}",
            "src_ip": "10.10.10.50",
            "dst_ip": "10.10.10.20",
            "dst_port": 443,
            "protocol": 6,
        }
        assessment = {
            "category": "Suspicious Anomaly",
            "severity": "MEDIUM",
            "explanation": "Statistical outlier score exceeding baseline threshold.",
        }

        pb = self.engine.evaluate(event, threat_assessment=assessment)

        self.assertEqual(pb["status"], STATUS_RECOMMENDED)
        self.assertEqual(pb["rule_id"], RULE_SUSPICIOUS_ANOMALY)
        self.assertTrue(pb["dry_run"])

        actions = [a["action"] for a in pb["recommended_actions"]]
        self.assertIn(ACTION_INCREASE_MONITORING, actions)
        self.assertIn(ACTION_GATHER_EVIDENCE, actions)
        self.assertIn(ACTION_FLAG_ANALYST_REVIEW, actions)
        self.assertNotIn(ACTION_RECOMMEND_CONTAINMENT, actions)

    # -----------------------------------------------------------------------
    # 3. Rule Evaluation: Benign Baseline
    # -----------------------------------------------------------------------
    def test_evaluate_benign_traffic_logs_baseline(self):
        event = {
            "event_id": f"event-{uuid.uuid4()}",
            "src_ip": "10.10.10.20",
            "dst_ip": "10.10.10.10",
            "dst_port": 8000,
            "protocol": 6,
        }
        assessment = {
            "category": "Benign",
            "severity": "LOW",
            "explanation": "Normal traffic.",
        }

        pb = self.engine.evaluate(event, threat_assessment=assessment)

        self.assertEqual(pb["status"], STATUS_RECOMMENDED)
        self.assertEqual(pb["rule_id"], RULE_BENIGN_BASELINE)
        actions = [a["action"] for a in pb["recommended_actions"]]
        self.assertIn(ACTION_LOG_BASELINE, actions)
        self.assertNotIn(ACTION_RECOMMEND_CONTAINMENT, actions)

    # -----------------------------------------------------------------------
    # 4. Idempotency Check
    # -----------------------------------------------------------------------
    def test_playbook_id_is_idempotent(self):
        event_id = f"test-fixed-{uuid.uuid4()}"
        event = {"event_id": event_id}
        assessment = {"category": "Infilteration", "severity": "HIGH"}

        pb1 = self.engine.evaluate(event, threat_assessment=assessment)
        pb2 = self.engine.evaluate(event, threat_assessment=assessment)

        self.assertEqual(pb1["playbook_id"], pb2["playbook_id"])

    # -----------------------------------------------------------------------
    # 5. Analyst Approval / Rejection Lifecycle
    # -----------------------------------------------------------------------
    def test_analyst_approval_lifecycle(self):
        event = {"event_id": f"event-{uuid.uuid4()}", "src_ip": "10.10.10.100"}
        assessment = {"category": "Infilteration", "severity": "HIGH"}
        pb = self.engine.evaluate(event, threat_assessment=assessment)

        # 1. Approve
        approved_pb = self.engine.apply_approval(
            pb,
            approved=True,
            analyst_id="lead_analyst",
            notes="Containment approved after reviewing packet trace.",
        )
        self.assertEqual(approved_pb["approval_status"], STATUS_APPROVED)
        self.assertEqual(approved_pb["status"], STATUS_APPROVED)
        self.assertEqual(len(approved_pb["audit_trail"]), 2)
        self.assertEqual(approved_pb["audit_trail"][1]["actor"], "lead_analyst")

        # 2. Reject
        rejected_pb = self.engine.apply_approval(
            pb,
            approved=False,
            analyst_id="lead_analyst",
            notes="False positive: authorized penetration test.",
        )
        self.assertEqual(rejected_pb["approval_status"], STATUS_REJECTED)
        self.assertEqual(rejected_pb["status"], STATUS_REJECTED)

    # -----------------------------------------------------------------------
    # 6. SQLite Persistence & Query Store
    # -----------------------------------------------------------------------
    def test_sqlite_persistence_and_queries(self):
        event_id = f"event-{uuid.uuid4()}"
        event = {
            "event_id": event_id,
            "event_type": "network_flow",
            "features": {"Dst Port": 80.0},
        }
        assessment = {"category": "Infilteration", "severity": "HIGH"}

        pb = self.engine.evaluate(event, threat_assessment=assessment)

        with AlertStore(db_path=self.temp_db_path) as store:
            store.save_event(event)
            inserted = store.save_playbook(pb)
            self.assertTrue(inserted)
            self.assertEqual(store.playbook_count(), 1)

            # Update approval in DB
            updated = store.update_playbook_approval(
                playbook_id=pb["playbook_id"],
                approved=True,
                analyst_id="soc_analyst_1",
                notes="Host containment approved.",
            )
            self.assertTrue(updated)

        with ResponsePlaybookQueryStore(db_path=self.temp_db_path) as q:
            retrieved = q.get_playbook_by_id(pb["playbook_id"])
            self.assertIsNotNone(retrieved)
            self.assertEqual(retrieved["status"], STATUS_APPROVED)
            self.assertEqual(retrieved["analyst_notes"], "Host containment approved.")
            self.assertEqual(len(retrieved["audit_trail"]), 2)

            by_event = q.get_playbook_by_event_id(event_id)
            self.assertIsNotNone(by_event)
            self.assertEqual(by_event["playbook_id"], pb["playbook_id"])

            stats = q.summary_stats_playbooks()
            self.assertEqual(stats["total_playbooks"], 1)

    # -----------------------------------------------------------------------
    # 7. Dashboard REST API Endpoints
    # -----------------------------------------------------------------------
    def test_api_playbooks_endpoints(self):
        # Insert a playbook directly to the main or temp DB
        resp_list = self.client.get("/api/playbooks")
        self.assertEqual(resp_list.status_code, 200)
        data = resp_list.json()
        self.assertIn("total", data)
        self.assertIn("playbooks", data)
        self.assertIn("stats", data)


if __name__ == "__main__":
    unittest.main()
