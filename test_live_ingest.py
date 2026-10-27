"""
test_live_ingest.py
===================
Comprehensive Test Suite for Phase 1 Live Sensor Flow Ingestion.

Tests:
1. Sensor authentication (401 on missing/invalid key; success on PSK & Bearer).
2. Request size limits (413 on payload > 1MB).
3. Schema validation (422 on missing features, non-numeric values, or empty body).
4. Duplicate event ID handling (409 Conflict).
5. Full pipeline execution:
   - Network Detection (RF)
   - Anomaly Detection (IF)
   - Alert Correlation
   - Threat Assessment
   - Threat Investigation Coordinator (Stage 10)
   - SQLite Persistence
6. Data preservation (source='live_sensor', src_ip, dst_ip, ports, protocol, 78 model features).
"""

import copy
import json
import pathlib
import sys
import unittest
import uuid
import joblib
from fastapi.testclient import TestClient

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

import dashboard_api
from kafka.config import PREP_PATH, DATASET_PATH
from kafka.producer import _select_balanced_records

VALID_SENSOR_KEY = "soc-sensor-dev-key-2026"


class TestLiveFlowIngestion(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(dashboard_api.app)
        assert PREP_PATH.exists(), f"Preprocessing metadata not found at {PREP_PATH}"
        cls.prep = joblib.load(PREP_PATH)
        cls.feature_names = cls.prep["feature_names"]
        cls.base_benign_features = {k: float(v) for k, v in cls.prep["medians"].items()}

        # Load one confirmed Infilteration row from dataset for attack test
        df_attack = _select_balanced_records(DATASET_PATH, 4)
        inf_rows = df_attack[df_attack["Label"] == "Infilteration"]
        if len(inf_rows) > 0:
            attack_row = inf_rows.iloc[0].to_dict()
            cls.attack_features = {f: float(attack_row[f]) for f in cls.feature_names}
        else:
            cls.attack_features = copy.deepcopy(cls.base_benign_features)

    # -----------------------------------------------------------------------
    # 1. Authentication Tests
    # -----------------------------------------------------------------------

    def test_unauthenticated_request_rejected(self):
        """Requests without sensor key must return 401 Unauthorized."""
        payload = {"features": self.base_benign_features}
        resp = self.client.post("/api/ingest/flow", json=payload)
        self.assertEqual(resp.status_code, 401)
        self.assertIn("Unauthorized", resp.json()["detail"])

    def test_invalid_api_key_rejected(self):
        """Requests with an invalid sensor key must return 401 Unauthorized."""
        payload = {"features": self.base_benign_features}
        # Via X-SOC-Sensor-Key
        resp = self.client.post(
            "/api/ingest/flow",
            json=payload,
            headers={"X-SOC-Sensor-Key": "invalid-secret-key"},
        )
        self.assertEqual(resp.status_code, 401)

        # Via Authorization Bearer
        resp_bearer = self.client.post(
            "/api/ingest/flow",
            json=payload,
            headers={"Authorization": "Bearer wrong-token-123"},
        )
        self.assertEqual(resp_bearer.status_code, 401)

    # -----------------------------------------------------------------------
    # 2. Request Size Limits (1MB)
    # -----------------------------------------------------------------------

    def test_payload_too_large_content_length(self):
        """Requests declaring Content-Length > 1MB must return 413 Payload Too Large."""
        payload = {"features": self.base_benign_features}
        resp = self.client.post(
            "/api/ingest/flow",
            json=payload,
            headers={
                "X-SOC-Sensor-Key": VALID_SENSOR_KEY,
                "Content-Length": "2097152",  # 2MB
            },
        )
        self.assertEqual(resp.status_code, 413)
        self.assertIn("Payload too large", resp.json()["detail"])

    def test_payload_too_large_actual_body(self):
        """Requests with body > 1MB must return 413 Payload Too Large."""
        large_features = copy.deepcopy(self.base_benign_features)
        # Add massive padding in features
        large_features["_padding"] = "X" * 1_200_000
        payload = {"features": large_features}
        resp = self.client.post(
            "/api/ingest/flow",
            json=payload,
            headers={"X-SOC-Sensor-Key": VALID_SENSOR_KEY},
        )
        self.assertEqual(resp.status_code, 413)

    # -----------------------------------------------------------------------
    # 3. Schema & Feature Validation
    # -----------------------------------------------------------------------

    def test_missing_features_key_rejected(self):
        """Payload missing 'features' dict must return 422."""
        payload = {
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.1",
        }
        resp = self.client.post(
            "/api/ingest/flow",
            json=payload,
            headers={"X-SOC-Sensor-Key": VALID_SENSOR_KEY},
        )
        self.assertEqual(resp.status_code, 422)

    def test_incomplete_features_rejected(self):
        """Payload missing any of the 78 model features must return 422 with details."""
        partial_features = {
            "Dst Port": 80.0,
            "Protocol": 6.0,
            "Flow Duration": 12345.0,
        }
        payload = {"features": partial_features}
        resp = self.client.post(
            "/api/ingest/flow",
            json=payload,
            headers={"X-SOC-Sensor-Key": VALID_SENSOR_KEY},
        )
        self.assertEqual(resp.status_code, 422)
        data = resp.json()["detail"]
        self.assertEqual(data["error"], "Missing required model features")
        self.assertEqual(data["missing_count"], 78 - 3)
        self.assertTrue(len(data["missing_features"]) > 0)

    def test_non_numeric_features_rejected(self):
        """Payload with non-numeric or null feature values must return 422."""
        bad_features = copy.deepcopy(self.base_benign_features)
        bad_features["Flow Duration"] = "NOT_A_NUMBER"
        bad_features["Tot Fwd Pkts"] = None
        payload = {"features": bad_features}
        resp = self.client.post(
            "/api/ingest/flow",
            json=payload,
            headers={"X-SOC-Sensor-Key": VALID_SENSOR_KEY},
        )
        self.assertEqual(resp.status_code, 422)
        data = resp.json()["detail"]
        self.assertEqual(data["error"], "Non-numeric or null feature values")
        self.assertIn("Flow Duration", data["invalid_features"])
        self.assertIn("Tot Fwd Pkts", data["invalid_features"])

    # -----------------------------------------------------------------------
    # 4. Duplicate Event ID Conflict
    # -----------------------------------------------------------------------

    def test_duplicate_event_id_returns_409(self):
        """Submitting an event with an already persisted event_id must return 409 Conflict."""
        test_eid = f"sensor-test-{uuid.uuid4()}"
        payload = {
            "event_id": test_eid,
            "src_ip": "192.168.10.5",
            "dst_ip": "10.0.0.50",
            "src_port": 50000,
            "dst_port": 443,
            "protocol": 6,
            "features": self.base_benign_features,
        }
        # First submission succeeds (201)
        resp1 = self.client.post(
            "/api/ingest/flow",
            json=payload,
            headers={"X-SOC-Sensor-Key": VALID_SENSOR_KEY},
        )
        self.assertEqual(resp1.status_code, 201)
        self.assertEqual(resp1.json()["event_id"], test_eid)

        # Second submission with same event_id must fail (409)
        resp2 = self.client.post(
            "/api/ingest/flow",
            json=payload,
            headers={"X-SOC-Sensor-Key": VALID_SENSOR_KEY},
        )
        self.assertEqual(resp2.status_code, 409)
        self.assertIn("already exists", resp2.json()["detail"])

    # -----------------------------------------------------------------------
    # 5. Full SOC Pipeline & Persistence: Benign Flow
    # -----------------------------------------------------------------------

    def test_ingest_benign_flow_full_pipeline(self):
        """
        Verify end-to-end processing of a benign flow event:
        - Validates PSK via Authorization Bearer header.
        - Preserves source='live_sensor' and IP/port context.
        - Runs Network Detection (Benign), Anomaly Detection, Threat Assessment.
        - Persists all entities to SQLite soc.db.
        """
        test_eid = f"sensor-benign-{uuid.uuid4()}"
        payload = {
            "event_id": test_eid,
            "src_ip": "172.16.0.4",
            "dst_ip": "172.16.0.1",
            "src_port": 52400,
            "dst_port": 80,
            "protocol": 6,
            "actual_label": "Benign",
            "features": self.base_benign_features,
        }

        resp = self.client.post(
            "/api/ingest/flow",
            json=payload,
            headers={"Authorization": f"Bearer {VALID_SENSOR_KEY}"},
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.json()

        # Response schema verification
        self.assertEqual(data["status"], "ACCEPTED")
        self.assertEqual(data["event_id"], test_eid)
        self.assertEqual(data["source"], "live_sensor")
        self.assertTrue(data["persisted"])
        self.assertIsInstance(data["processing_time_s"], float)

        # Context preservation
        ctx = data["network_context"]
        self.assertEqual(ctx["src_ip"], "172.16.0.4")
        self.assertEqual(ctx["dst_ip"], "172.16.0.1")
        self.assertEqual(ctx["src_port"], 52400)
        self.assertEqual(ctx["dst_port"], 80)
        self.assertEqual(ctx["protocol"], 6)

        # Agent inference outputs
        self.assertIn("network_detection", data)
        self.assertEqual(data["network_detection"]["prediction"], "Benign")
        self.assertIn("confidence", data["network_detection"])

        self.assertIn("anomaly_detection", data)
        self.assertIn("prediction", data["anomaly_detection"])

        self.assertIn("threat_assessment", data)
        self.assertIn("category", data["threat_assessment"])

        # Database verification via GET /api/events/{event_id}
        db_resp = self.client.get(f"/api/events/{test_eid}")
        self.assertEqual(db_resp.status_code, 200)
        db_data = db_resp.json()
        self.assertEqual(db_data["event"]["event_id"], test_eid)
        self.assertEqual(db_data["event"]["source"], "live_sensor")
        self.assertEqual(len(db_data["event"]["features"]), 78)
        self.assertTrue(len(db_data["alerts"]) >= 1)

    # -----------------------------------------------------------------------
    # 6. Full SOC Pipeline & Persistence: Attack Flow (Triggers Investigation)
    # -----------------------------------------------------------------------

    def test_ingest_attack_flow_triggers_investigation(self):
        """
        Verify end-to-end processing of an attack flow event:
        - Network detection predicts 'Infilteration'.
        - Triggers Stage 10 Threat Investigation Coordinator.
        - Persists incident, assessment, and investigation in SQLite.
        """
        test_eid = f"sensor-attack-{uuid.uuid4()}"
        payload = {
            "event_id": test_eid,
            "src_ip": "13.58.225.34",
            "dst_ip": "172.31.69.25",
            "src_port": 443,
            "dst_port": 443,
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

        self.assertEqual(data["status"], "ACCEPTED")
        self.assertEqual(data["event_id"], test_eid)
        self.assertEqual(data["network_detection"]["prediction"], "Infilteration")
        self.assertEqual(data["network_detection"]["severity"], "HIGH")

        # Threat Assessment verification
        self.assertIsNotNone(data["threat_assessment"])
        self.assertIn(data["threat_assessment"]["severity"], ["HIGH", "MEDIUM"])

        # Automated Stage 10 Threat Investigation verification
        self.assertTrue(data["investigation_triggered"])
        self.assertIsNotNone(data["investigation"])
        self.assertTrue(len(data["investigation"]["investigation_id"]) > 0)
        self.assertIn("investigation_status", data["investigation"])

        # Database verification via GET /api/events/{event_id}
        db_resp = self.client.get(f"/api/events/{test_eid}")
        self.assertEqual(db_resp.status_code, 200)
        db_data = db_resp.json()
        self.assertIsNotNone(db_data["threat_assessment"])
        self.assertIsNotNone(db_data["threat_investigation"])
        self.assertEqual(
            db_data["threat_investigation"]["investigation_id"],
            data["investigation"]["investigation_id"],
        )


if __name__ == "__main__":
    unittest.main()
