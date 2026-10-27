"""
test_dashboard_api.py
=====================
Test Suite for Dashboard API and SQLite Integration.

Multi-Agent SOC Project -- Real-Time Dashboard Tests
"""

import pathlib
import sys
import tempfile
import unittest
from fastapi.testclient import TestClient

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

import dashboard_api
from storage.db import AlertStore


class TestDashboardAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(dashboard_api.app)

    def test_health_endpoint(self):
        resp = self.client.get("/api/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "online")
        self.assertIn("database_exists", data)

    def test_agents_status_endpoint(self):
        resp = self.client.get("/api/agents/status")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("agents", data)
        self.assertEqual(data["is_live_packet_capture"], False)
        agent_names = [a["name"] for a in data["agents"]]
        self.assertIn("Network Detection Agent", agent_names)
        self.assertIn("Anomaly Detection Agent", agent_names)
        self.assertIn("Unified Threat Assessment Engine", agent_names)
        self.assertIn("Live Sensor Ingestion Endpoint", agent_names)

        agent_map = {a["name"]: a for a in data["agents"]}
        self.assertEqual(agent_map["Network Detection Agent"]["status"], "ACTIVE")
        self.assertEqual(agent_map["Anomaly Detection Agent"]["status"], "ACTIVE")

    def test_overview_statistics(self):
        resp = self.client.get("/api/overview")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        for field in [
            "total_events", "benign_events", "threat_events",
            "anomalous_events", "critical_alerts", "open_incidents",
            "total_assessments"
        ]:
            self.assertIn(field, data)
            self.assertIsInstance(data[field], int)

    def test_events_stream_and_filtering(self):
        resp = self.client.get("/api/events?limit=10")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIsInstance(data, list)

        # Test with non-existent UUID filter
        resp_filtered = self.client.get("/api/events?event_id=non-existent-uuid")
        self.assertEqual(resp_filtered.status_code, 200)
        self.assertEqual(len(resp_filtered.json()), 0)

    def test_threat_assessments_endpoint(self):
        resp = self.client.get("/api/threats?limit=10")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIsInstance(data, list)

    def test_alerts_endpoint(self):
        resp = self.client.get("/api/alerts?limit=10")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIsInstance(data, list)

    def test_incidents_endpoint(self):
        resp = self.client.get("/api/incidents?limit=10")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIsInstance(data, list)

    def test_analytics_endpoint(self):
        resp = self.client.get("/api/analytics")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("categories", data)
        self.assertIn("severities", data)
        self.assertIn("latency_stats", data)

    def test_event_not_found(self):
        resp = self.client.get("/api/events/00000000-0000-0000-0000-000000000000")
        self.assertEqual(resp.status_code, 404)

    def test_threat_intel_endpoints(self):
        # 1. Cache endpoint
        resp = self.client.get("/api/intel/cache")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("items", data)
        self.assertIn("stats", data)

        # 2. Lookup endpoint with mock provider
        resp_lookup = self.client.get("/api/intel/lookup?indicator=198.51.100.1&provider=mock")
        self.assertEqual(resp_lookup.status_code, 200)
        lk_data = resp_lookup.json()
        self.assertEqual(lk_data["verdict"], "MALICIOUS")
        self.assertEqual(lk_data["is_mock"], True)
        self.assertEqual(lk_data["indicator_value"], "198.51.100.1")

    def test_agents_status_includes_threat_intelligence(self):
        resp = self.client.get("/api/agents/status")
        self.assertEqual(resp.status_code, 200)
        names = [a["name"] for a in resp.json().get("agents", [])]
        self.assertIn("Threat Intelligence Agent", names)


if __name__ == "__main__":
    unittest.main()

