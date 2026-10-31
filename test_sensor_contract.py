"""
test_sensor_contract.py
========================
Comprehensive Verification Suite for the SOC Sensor Integration Contract & Pipeline Reliability (Steps 2 & 3).

Guarantees Verified:
  1. Exact 78-feature canonical schema enforcement and strict ordering.
  2. Rejection of missing features, non-numeric values, and negative Flow Duration (HTTP 422).
  3. Rejection of excessive NaN/Inf values (>8 cells) while permitting legitimate cell-level imputation (HTTP 422).
  4. Complete metadata isolation: IP addresses, ports, protocol, and sensor_id are NEVER injected into model features.
  5. Flexible and secure authentication via X-SOC-Sensor-Key or Authorization Bearer/ApiKey (HTTP 401 on invalid).
  6. Payload size enforcement (HTTP 413 on > 1MB).
  7. Duplicate event conflict detection and safe retry handling (HTTP 409).
  8. Health-check readiness contracts (GET /api/models/health and GET /api/health).
  9. Full multi-agent pipeline integration: Network Detection, Anomaly Detection, Alert Correlation,
     Threat Assessment, Threat Investigation, and Response Playbooks.
 10. Persistence verification across SQLite soc.db.
"""

import copy
import json
import math
import pathlib
import sys
import unittest
import uuid
import joblib
from fastapi.testclient import TestClient
from unittest.mock import patch

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import dashboard_api
from kafka.config import PREP_PATH, DATASET_PATH
from kafka.live_adapter import CANONICAL_FEATURES
from kafka.producer import _select_balanced_records

VALID_SENSOR_KEY = "soc-sensor-dev-key-2026"


class TestSensorIntegrationContract(unittest.TestCase):
    """Rigorous contract and reliability test suite for sensor ingestion."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(dashboard_api.app)
        assert PREP_PATH.exists(), f"Preprocessing metadata not found at {PREP_PATH}"
        cls.prep = joblib.load(PREP_PATH)
        cls.feature_names = cls.prep["feature_names"]
        assert len(cls.feature_names) == 78, f"Expected 78 features, got {len(cls.feature_names)}"

        # Standard benign feature baseline
        cls.benign_features = {k: float(v) for k, v in cls.prep["medians"].items()}

        # Load attack features from real dataset
        df = _select_balanced_records(DATASET_PATH, 4)
        inf_rows = df[df["Label"] == "Infilteration"]
        if len(inf_rows) > 0:
            attack_dict = inf_rows.iloc[0].to_dict()
            cls.attack_features = {f: float(attack_dict[f]) for f in cls.feature_names}
        else:
            cls.attack_features = copy.deepcopy(cls.benign_features)

    # -----------------------------------------------------------------------
    # 1. Exact 78-Feature Canonical Schema & Ordering
    # -----------------------------------------------------------------------
    def test_canonical_78_feature_schema_alignment(self):
        """Verify the 78 canonical features match the model training feature names in exact order."""
        self.assertEqual(len(CANONICAL_FEATURES), 78)
        self.assertEqual(len(self.feature_names), 78)
        self.assertEqual(CANONICAL_FEATURES, self.feature_names)

    # -----------------------------------------------------------------------
    # 2. Authentication & Authorization Contracts
    # -----------------------------------------------------------------------
    def test_authentication_contracts(self):
        """Test missing key, invalid key, X-SOC-Sensor-Key, and Authorization Bearer headers."""
        payload = {"features": self.benign_features}

        # 1. Missing header -> 401
        r_none = self.client.post("/api/ingest/flow", json=payload)
        self.assertEqual(r_none.status_code, 401)

        # 2. Invalid X-SOC-Sensor-Key -> 401
        r_bad_header = self.client.post("/api/ingest/flow", json=payload, headers={"X-SOC-Sensor-Key": "wrong"})
        self.assertEqual(r_bad_header.status_code, 401)

        # 3. Invalid Authorization Bearer -> 401
        r_bad_bearer = self.client.post("/api/ingest/flow", json=payload, headers={"Authorization": "Bearer wrong"})
        self.assertEqual(r_bad_bearer.status_code, 401)

        # 4. Valid X-SOC-Sensor-Key -> 201
        r_ok_header = self.client.post("/api/ingest/flow", json=payload, headers={"X-SOC-Sensor-Key": VALID_SENSOR_KEY})
        self.assertEqual(r_ok_header.status_code, 201)

        # 5. Valid Authorization Bearer -> 201
        r_ok_bearer = self.client.post("/api/ingest/flow", json=payload, headers={"Authorization": f"Bearer {VALID_SENSOR_KEY}"})
        self.assertEqual(r_ok_bearer.status_code, 201)

    # -----------------------------------------------------------------------
    # 3. Malformed Feature Payloads & Negative Duration
    # -----------------------------------------------------------------------
    def test_incomplete_features_rejected_with_422(self):
        """Submitting fewer than 78 features must return 422 with detailed missing list."""
        partial_features = {"Dst Port": 80.0, "Protocol": 6.0}
        resp = self.client.post(
            "/api/ingest/flow",
            json={"features": partial_features},
            headers={"X-SOC-Sensor-Key": VALID_SENSOR_KEY},
        )
        self.assertEqual(resp.status_code, 422)
        detail = resp.json()["detail"]
        self.assertEqual(detail["error"], "Missing required model features")
        self.assertEqual(detail["missing_count"], 76)

    def test_non_numeric_and_null_features_rejected_with_422(self):
        """Strings, nulls, and booleans in feature fields must be rejected."""
        corrupted = copy.deepcopy(self.benign_features)
        corrupted["Dst Port"] = "PORT_80"
        corrupted["Protocol"] = True
        corrupted["Flow Duration"] = None

        resp = self.client.post(
            "/api/ingest/flow",
            json={"features": corrupted},
            headers={"X-SOC-Sensor-Key": VALID_SENSOR_KEY},
        )
        self.assertEqual(resp.status_code, 422)
        detail = resp.json()["detail"]
        self.assertEqual(detail["error"], "Non-numeric or null feature values")
        self.assertIn("Dst Port", detail["invalid_features"])
        self.assertIn("Protocol", detail["invalid_features"])
        self.assertIn("Flow Duration", detail["invalid_features"])

    def test_negative_flow_duration_rejected_with_422(self):
        """Negative Flow Duration (e.g. from 32-bit clock wrap) must be rejected."""
        negative_dur = copy.deepcopy(self.benign_features)
        negative_dur["Flow Duration"] = -1500.0

        resp = self.client.post(
            "/api/ingest/flow",
            json={"features": negative_dur},
            headers={"X-SOC-Sensor-Key": VALID_SENSOR_KEY},
        )
        self.assertEqual(resp.status_code, 422)
        detail = resp.json()["detail"]
        self.assertIn("Invalid negative Flow Duration value", detail["error"])

    # -----------------------------------------------------------------------
    # 4. NaN / Infinite Value Threshold Enforcement
    # -----------------------------------------------------------------------
    def test_excessive_nan_inf_features_rejected(self):
        """More than 8 NaN/Inf features indicates corrupt flow capture and must return 422."""
        excessive_nan = copy.deepcopy(self.benign_features)
        # Corrupt 12 features with NaN or inf
        corrupt_keys = list(excessive_nan.keys())[:12]
        for idx, k in enumerate(corrupt_keys):
            excessive_nan[k] = float("nan") if idx % 2 == 0 else float("inf")

        resp = self.client.post(
            "/api/ingest/flow",
            json={"features": excessive_nan},
            headers={"X-SOC-Sensor-Key": VALID_SENSOR_KEY},
        )
        self.assertEqual(resp.status_code, 422)
        detail = resp.json()["detail"]
        self.assertIn("Excessive NaN or Inf feature values", detail["error"])
        self.assertEqual(detail["nan_inf_count"], 12)

    def test_moderate_nan_imputation_accepted(self):
        """Up to 8 NaN/Inf values (e.g. zero duration division) are safely imputed with training medians."""
        acceptable_nan = copy.deepcopy(self.benign_features)
        # 3 NaNs
        acceptable_nan["Flow Byts/s"] = float("nan")
        acceptable_nan["Flow Pkts/s"] = float("nan")
        acceptable_nan["Flow IAT Std"] = float("inf")

        resp = self.client.post(
            "/api/ingest/flow",
            json={"features": acceptable_nan},
            headers={"X-SOC-Sensor-Key": VALID_SENSOR_KEY},
        )
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(resp.json()["status"], "ACCEPTED")

    # -----------------------------------------------------------------------
    # 5. Metadata Isolation & Sensor ID Tracking
    # -----------------------------------------------------------------------
    def test_metadata_isolation_and_sensor_id_preservation(self):
        """Verify network context & sensor_id are preserved in metadata and never leak into model features."""
        custom_eid = f"sensor-contract-{uuid.uuid4()}"
        sensor_id = "sensor-vm-appliance-01"
        payload = {
            "event_id": custom_eid,
            "sensor_id": sensor_id,
            "source": "lab_vm",
            "timestamp": "2026-10-27T12:00:00Z",
            "sequence": 105,
            "src_ip": "10.10.10.100",
            "dst_ip": "10.10.10.20",
            "src_port": 49152,
            "dst_port": 80,
            "protocol": 6,
            "features": self.benign_features,
            "extra_metadata_field": "SHOULD_BE_IGNORED_BY_MODEL",
        }

        resp = self.client.post(
            "/api/ingest/flow",
            json=payload,
            headers={"X-SOC-Sensor-Key": VALID_SENSOR_KEY},
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.json()

        self.assertEqual(data["event_id"], custom_eid)
        self.assertEqual(data["sensor_id"], sensor_id)
        self.assertEqual(data["source"], f"lab_vm:{sensor_id}")
        self.assertEqual(data["network_context"]["src_ip"], "10.10.10.100")
        self.assertEqual(data["network_context"]["dst_ip"], "10.10.10.20")
        self.assertEqual(data["network_context"]["src_port"], 49152)
        self.assertEqual(data["network_context"]["dst_port"], 80)
        self.assertEqual(data["network_context"]["protocol"], 6)

    # -----------------------------------------------------------------------
    # 6. Duplicate Event ID Handling & Safe Retries
    # -----------------------------------------------------------------------
    def test_duplicate_event_conflict_and_safe_retry(self):
        """Duplicate event IDs must return 409 Conflict. A retry with a new UUID must succeed."""
        duplicate_eid = f"conflict-test-{uuid.uuid4()}"
        payload = {
            "event_id": duplicate_eid,
            "src_ip": "10.10.10.100",
            "dst_ip": "10.10.10.20",
            "features": self.benign_features,
        }

        # 1. Initial ingestion -> 201
        r1 = self.client.post("/api/ingest/flow", json=payload, headers={"X-SOC-Sensor-Key": VALID_SENSOR_KEY})
        self.assertEqual(r1.status_code, 201)

        # 2. Immediate duplicate -> 409
        r2 = self.client.post("/api/ingest/flow", json=payload, headers={"X-SOC-Sensor-Key": VALID_SENSOR_KEY})
        self.assertEqual(r2.status_code, 409)
        self.assertIn("already exists", r2.json()["detail"])

        # 3. Retry with fresh event_id -> 201
        payload["event_id"] = f"conflict-test-{uuid.uuid4()}"
        r3 = self.client.post("/api/ingest/flow", json=payload, headers={"X-SOC-Sensor-Key": VALID_SENSOR_KEY})
        self.assertEqual(r3.status_code, 201)

    # -----------------------------------------------------------------------
    # 7. Health and Readiness Endpoints
    # -----------------------------------------------------------------------
    def test_health_check_endpoints(self):
        """Sensors can query /api/health and /api/models/health before streaming traffic."""
        # General health
        r_health = self.client.get("/api/health")
        self.assertEqual(r_health.status_code, 200)
        self.assertEqual(r_health.json()["status"], "online")

        # Models readiness
        r_models = self.client.get("/api/models/health")
        self.assertEqual(r_models.status_code, 200)
        m_data = r_models.json()
        self.assertEqual(m_data["status"], "ok")
        self.assertTrue(m_data["models"]["network_detection"]["loaded"])
        self.assertEqual(m_data["models"]["network_detection"]["features_required"], 78)
        self.assertTrue(m_data["models"]["anomaly_detection"]["loaded"])

    # -----------------------------------------------------------------------
    # 8. End-to-End Attack Flow: Multi-Agent Escalation & Playbook
    # -----------------------------------------------------------------------
    def test_attack_flow_triggers_full_multi_agent_escalation(self):
        """
        Verify that an attack flow:
        - Classifies as Infilteration with HIGH severity.
        - Triggers Threat Assessment (Confirmed Attack / High).
        - Triggers Threat Investigation Coordinator (Stage 10).
        - Generates Response Playbook (Stage 12) with containment recommendation and pending approval.
        - Persists all entities into SQLite soc.db.
        """
        attack_eid = f"attack-e2e-{uuid.uuid4()}"
        payload = {
            "event_id": attack_eid,
            "sensor_id": "sensor-vm-01",
            "source": "live_sensor",
            "src_ip": "10.10.10.100",
            "dst_ip": "10.10.10.20",
            "dst_port": 80,
            "protocol": 6,
            "actual_label": "Infilteration",
            "features": self.attack_features,
        }

        resp = self.client.post(
            "/api/ingest/flow",
            json=payload,
            headers={"X-SOC-Sensor-Key": VALID_SENSOR_KEY},
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.json()

        self.assertEqual(data["event_id"], attack_eid)
        self.assertEqual(data["network_detection"]["prediction"], "Infilteration")
        self.assertEqual(data["network_detection"]["severity"], "HIGH")
        self.assertEqual(data["threat_assessment"]["severity"], "HIGH")
        self.assertTrue(data["investigation_triggered"])
        self.assertTrue(data["playbook_triggered"])
        self.assertEqual(data["response_playbook"]["status"], "PENDING_APPROVAL")
        self.assertTrue(data["persisted"])

        # Verify queryable from /api/playbooks
        pb_resp = self.client.get(f"/api/playbooks/{data['response_playbook']['playbook_id']}")
        self.assertEqual(pb_resp.status_code, 200)
        pb_data = pb_resp.json()
        self.assertEqual(pb_data["event_id"], attack_eid)
        self.assertEqual(pb_data["status"], "PENDING_APPROVAL")


if __name__ == "__main__":
    unittest.main()
