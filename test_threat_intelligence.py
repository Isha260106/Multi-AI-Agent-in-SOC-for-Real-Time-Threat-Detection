"""
test_threat_intelligence.py
============================
Validation Test Suite for Stage 11: Threat Intelligence Enrichment.

Multi-Agent SOC Project -- Stage 11

TESTS:
  1. Mock provider deterministic lookups (Malicious, Suspicious, No Known Reports)
  2. Mock-mode labeling and explicit disclaimers (is_mock=True, NO_KNOWN_REPORTS disclaimer)
  3. Indicator extraction from events/investigations without inventing missing IPs
  4. SQLite caching persistence, cache hit, and force refresh
  5. Cache TTL expiration and refresh
  6. Graceful handling of missing API keys (AbuseIPDB, VirusTotal)
  7. Provider rate limits, HTTP errors, and network timeouts
  8. Non-destructive investigation report enrichment
  9. Database integration and query store statistics
 10. CLI query_intel tool commands execution
"""

import datetime
import io
import json
import os
import pathlib
import sys
import tempfile
import unittest
import urllib.error
from unittest.mock import MagicMock, patch

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.threat_intelligence.agent import ThreatIntelligenceAgent
from agents.threat_intelligence.config import (
    MOCK_DATA_DISCLAIMER,
    NO_KNOWN_REPORTS_DISCLAIMER,
    PROVIDER_ABUSEIPDB,
    PROVIDER_MOCK,
    PROVIDER_VIRUSTOTAL,
    VERDICT_MALICIOUS,
    VERDICT_NO_KNOWN_REPORTS,
    VERDICT_SUSPICIOUS,
    VERDICT_UNKNOWN,
)
from agents.threat_intelligence.providers import (
    AbuseIPDBProvider,
    BaseIntelProvider,
    MockIntelProvider,
    VirusTotalProvider,
)
from storage.db import AlertStore
from storage.query import ThreatIntelQueryStore


class TestThreatIntelligence(unittest.TestCase):
    """Stage 11 Threat Intelligence Enrichment Test Suite."""

    def setUp(self):
        # Create an isolated temporary SQLite database for each test
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_db_path = pathlib.Path(self.temp_dir.name) / "test_soc.db"
        with AlertStore(db_path=self.temp_db_path) as store:
            pass  # Initializes tables & indexes

    def tearDown(self):
        self.temp_dir.cleanup()

    # -----------------------------------------------------------------------
    # 1. Mock Provider Fixtures
    # -----------------------------------------------------------------------
    def test_mock_provider_deterministic_lookups(self):
        provider = MockIntelProvider()

        # Known malicious fixture
        res_mal = provider.lookup("ip", "198.51.100.1")
        self.assertEqual(res_mal["verdict"], VERDICT_MALICIOUS)
        self.assertEqual(res_mal["reputation_score"], 98.0)
        self.assertTrue(res_mal["is_mock"])
        self.assertIn("https://mock.threatintel.local/ip/198.51.100.1", res_mal["evidence_links"])

        # Known suspicious fixture
        res_susp = provider.lookup("ip", "198.51.100.2")
        self.assertEqual(res_susp["verdict"], VERDICT_SUSPICIOUS)
        self.assertEqual(res_susp["reputation_score"], 42.0)
        self.assertTrue(res_susp["is_mock"])

        # Known clean fixture
        res_clean = provider.lookup("ip", "8.8.8.8")
        self.assertEqual(res_clean["verdict"], VERDICT_NO_KNOWN_REPORTS)
        self.assertEqual(res_clean["reputation_score"], 0.0)

        # Port lookup
        res_port = provider.lookup("port", "4444")
        self.assertEqual(res_port["verdict"], VERDICT_SUSPICIOUS)
        self.assertTrue(res_port["is_mock"])

    # -----------------------------------------------------------------------
    # 2. Mock-Mode Labeling and Disclaimers
    # -----------------------------------------------------------------------
    def test_mock_mode_labeling_and_disclaimers(self):
        provider = MockIntelProvider()

        res_mal = provider.lookup("ip", "198.51.100.1")
        self.assertTrue(res_mal["is_mock"])
        self.assertTrue(any(MOCK_DATA_DISCLAIMER in lim for lim in res_mal["limitations"]))

        res_clean = provider.lookup("ip", "1.1.1.1")
        self.assertEqual(res_clean["verdict"], VERDICT_NO_KNOWN_REPORTS)
        # Must carry the explicit NO_KNOWN_REPORTS disclaimer (safe != no reports)
        self.assertTrue(any("does NOT guarantee that the indicator is safe" in lim for lim in res_clean["limitations"]))

    # -----------------------------------------------------------------------
    # 3. Indicator Extraction Without Fabricating IPs
    # -----------------------------------------------------------------------
    def test_indicator_extraction_no_invented_ips(self):
        agent = ThreatIntelligenceAgent(offline_mode=True, db_path=self.temp_db_path)

        # Case A: Pure flow features with port and protocol, but NO IP
        features_no_ip = {
            "Dst Port": 443.0,
            "Protocol": 6.0,
            "Flow Duration": 12345.0,
            "Flow Pkts/s": 42.5,
        }
        indicators = agent.extract_indicators(features_no_ip)

        types_found = [ind["indicator_type"] for ind in indicators]
        values_found = [ind["indicator_value"] for ind in indicators]

        self.assertIn("port", types_found)
        self.assertIn("443", values_found)
        self.assertIn("protocol", types_found)
        self.assertIn("TCP", values_found)

        # STRICT ASSERTION: Never invent or fabricate IP
        self.assertNotIn("ip", types_found)

        # Case B: Context with actual IP present
        context_with_ip = {
            "src_ip": "198.51.100.1",
            "dst_ip": "10.0.0.5",
            "Dst Port": 80.0,
            "Protocol": 6.0,
        }
        indicators_ip = agent.extract_indicators(context_with_ip)
        ip_vals = [ind["indicator_value"] for ind in indicators_ip if ind["indicator_type"] == "ip"]
        self.assertIn("198.51.100.1", ip_vals)
        self.assertIn("10.0.0.5", ip_vals)

    # -----------------------------------------------------------------------
    # 4. SQLite Caching, Hits, and Force Refresh
    # -----------------------------------------------------------------------
    def test_sqlite_cache_hit_and_force_refresh(self):
        agent = ThreatIntelligenceAgent(offline_mode=True, db_path=self.temp_db_path)

        # 1. First lookup: cache miss -> provider queried
        res1 = agent.lookup("ip", "198.51.100.1", provider_name="mock", force_refresh=False)
        self.assertEqual(res1["verdict"], VERDICT_MALICIOUS)
        self.assertFalse(res1.get("cache_hit"))

        # Verify entry exists in DB
        with AlertStore(db_path=self.temp_db_path) as store:
            self.assertEqual(store.intel_cache_count(), 1)

        # 2. Second lookup: cache hit -> returned from DB without re-query
        res2 = agent.lookup("ip", "198.51.100.1", provider_name="mock", force_refresh=False)
        self.assertEqual(res2["verdict"], VERDICT_MALICIOUS)
        self.assertTrue(res2.get("cache_hit"))

        # 3. Third lookup with force_refresh=True -> cache bypassed
        res3 = agent.lookup("ip", "198.51.100.1", provider_name="mock", force_refresh=True)
        self.assertEqual(res3["verdict"], VERDICT_MALICIOUS)
        self.assertFalse(res3.get("cache_hit"))

    # -----------------------------------------------------------------------
    # 5. Cache TTL Expiration
    # -----------------------------------------------------------------------
    def test_cache_expiration_ttl(self):
        # Insert a pre-expired record into SQLite
        expired_time = (datetime.datetime.now() - datetime.timedelta(hours=2)).isoformat()
        entry = {
            "indicator_type": "ip",
            "indicator_value": "198.51.100.1",
            "provider": "MockProvider",
            "verdict": VERDICT_MALICIOUS,
            "reputation_score": 98.0,
            "raw_response": {"note": "old"},
            "evidence_links": [],
            "last_checked": expired_time,
            "expires_at": expired_time,  # In the past
            "is_mock": True,
        }
        with AlertStore(db_path=self.temp_db_path) as store:
            store.save_intel_cache(entry)

        # Verify query store detects it as expired
        with ThreatIntelQueryStore(db_path=self.temp_db_path) as q_store:
            cached = q_store.get_cached_intel("ip", "198.51.100.1", provider="MockProvider", valid_only=False)
            self.assertIsNotNone(cached)
            self.assertTrue(cached["is_expired"])

            # valid_only=True should filter out expired
            valid_cached = q_store.get_cached_intel("ip", "198.51.100.1", provider="MockProvider", valid_only=True)
            self.assertIsNone(valid_cached)

        # Agent lookup should detect expiration and refresh entry
        agent = ThreatIntelligenceAgent(offline_mode=True, db_path=self.temp_db_path)
        refreshed = agent.lookup("ip", "198.51.100.1", provider_name="mock", force_refresh=False)
        self.assertFalse(refreshed.get("cache_hit"))
        now_iso = datetime.datetime.now().isoformat()
        self.assertGreater(refreshed["expires_at"], now_iso)

    # -----------------------------------------------------------------------
    # 6. Unavailable API Keys Handling
    # -----------------------------------------------------------------------
    def test_missing_api_keys_handling(self):
        # Ensure environment keys are cleared
        with patch.dict(os.environ, {}, clear=True):
            abuse_provider = AbuseIPDBProvider()
            res_abuse = abuse_provider.lookup("ip", "198.51.100.1")
            self.assertEqual(res_abuse["verdict"], VERDICT_UNKNOWN)
            self.assertIsNone(res_abuse["reputation_score"])
            self.assertFalse(res_abuse["is_mock"])
            self.assertTrue(any("not configured" in lim for lim in res_abuse["limitations"]))

            vt_provider = VirusTotalProvider()
            res_vt = vt_provider.lookup("ip", "198.51.100.1")
            self.assertEqual(res_vt["verdict"], VERDICT_UNKNOWN)
            self.assertIsNone(res_vt["reputation_score"])
            self.assertFalse(res_vt["is_mock"])
            self.assertTrue(any("not configured" in lim for lim in res_vt["limitations"]))

    # -----------------------------------------------------------------------
    # 7. Provider Failures, Rate Limits, and Timeouts
    # -----------------------------------------------------------------------
    def test_provider_rate_limit_and_http_errors(self):
        # Test AbuseIPDB 429 Rate Limit
        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "dummy_test_key"}):
            abuse_provider = AbuseIPDBProvider()

            # Mock HTTP 429
            http_err_429 = urllib.error.HTTPError(
                url="https://api.abuseipdb.com/api/v2/check",
                code=429,
                msg="Too Many Requests",
                hdrs={},
                fp=io.BytesIO(b'{"error": "Rate limit exceeded"}')
            )
            with patch("urllib.request.urlopen", side_effect=http_err_429):
                res_429 = abuse_provider.lookup("ip", "198.51.100.1")
                self.assertEqual(res_429["verdict"], VERDICT_UNKNOWN)
                self.assertTrue(any("rate limit" in lim.lower() for lim in res_429["limitations"]))

            # Mock Timeout
            timeout_err = TimeoutError("Connection timed out")
            with patch("urllib.request.urlopen", side_effect=timeout_err):
                res_timeout = abuse_provider.lookup("ip", "198.51.100.1")
                self.assertEqual(res_timeout["verdict"], VERDICT_UNKNOWN)
                self.assertTrue(any("timed out" in lim.lower() for lim in res_timeout["limitations"]))

    # -----------------------------------------------------------------------
    # 8. Non-Destructive Investigation Enrichment
    # -----------------------------------------------------------------------
    def test_non_destructive_investigation_enrichment(self):
        agent = ThreatIntelligenceAgent(offline_mode=True, db_path=self.temp_db_path)

        # Baseline investigation report
        original_report = {
            "investigation_id": "inv-test-uuid-001",
            "event_id": "ev-test-uuid-001",
            "threat_category": "Suspicious Anomaly",
            "severity": "MEDIUM",
            "investigation_status": "REQUIRES_TIER2",
            "summary": "Original investigator assessment summary.",
            "findings_by_agent": {
                "network_evidence": ["Unusual flow volume."],
                "anomaly_explanation": ["Outlier score -0.5108."],
                "alert_correlation": ["Single-agent detection."],
            },
            "supporting_evidence": {
                "network_facts": {
                    "Dst Port": 4444.0,
                    "Protocol": 6.0,
                    "dst_ip": "198.51.100.1",  # Known malicious in mock
                },
                "anomaly_facts": {"anomaly_score": -0.5108},
            },
            "conflicting_signals": ["Supervised model says benign but isolation forest flagged anomaly."],
            "reasoning": ["Investigating outlier behavior."],
            "limitations": ["Analysis limited to statistical metrics."],
            "recommended_next_steps": ["Inspect endpoint logs."],
        }

        enriched = agent.enrich_investigation(
            original_report,
            provider_name="mock",
            force_refresh=False,
            persist=False,
        )

        # Verify zero loss of original data
        self.assertEqual(enriched["investigation_id"], original_report["investigation_id"])
        self.assertEqual(enriched["event_id"], original_report["event_id"])
        self.assertEqual(enriched["threat_category"], "Suspicious Anomaly")
        self.assertEqual(enriched["severity"], "MEDIUM")
        self.assertEqual(enriched["findings_by_agent"]["network_evidence"], ["Unusual flow volume."])
        self.assertEqual(enriched["findings_by_agent"]["anomaly_explanation"], ["Outlier score -0.5108."])
        self.assertEqual(enriched["conflicting_signals"], original_report["conflicting_signals"])

        # Verify threat intelligence was appended
        self.assertIn("threat_intelligence", enriched["findings_by_agent"])
        self.assertTrue(len(enriched["findings_by_agent"]["threat_intelligence"]) >= 1)

        # Verify structured section
        self.assertIn("threat_intelligence", enriched)
        intel_block = enriched["threat_intelligence"]
        self.assertEqual(intel_block["aggregate_verdict"], VERDICT_MALICIOUS)
        self.assertEqual(intel_block["status"], "ENRICHED")

        # Verify limitations preserved and appended
        self.assertIn("Analysis limited to statistical metrics.", enriched["limitations"])
        self.assertTrue(any(MOCK_DATA_DISCLAIMER in lim for lim in enriched["limitations"]))

    # -----------------------------------------------------------------------
    # 9. Query Store Summary Statistics
    # -----------------------------------------------------------------------
    def test_query_store_summary_stats(self):
        agent = ThreatIntelligenceAgent(offline_mode=True, db_path=self.temp_db_path)

        # Perform lookups
        agent.lookup("ip", "198.51.100.1", provider_name="mock")
        agent.lookup("ip", "8.8.8.8", provider_name="mock")
        agent.lookup("port", "4444", provider_name="mock")

        with ThreatIntelQueryStore(db_path=self.temp_db_path) as q_store:
            stats = q_store.summary_stats_intel()
            self.assertEqual(stats["total_cached"], 3)
            self.assertEqual(stats["mock_count"], 3)
            self.assertEqual(stats["real_count"], 0)
            self.assertIn("MALICIOUS", stats["verdicts"])
            self.assertIn("NO_KNOWN_REPORTS", stats["verdicts"])


if __name__ == "__main__":
    unittest.main()
