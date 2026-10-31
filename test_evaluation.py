"""
test_evaluation.py
==================
Test suite for Stage 13 Evaluation and Benchmarking Suite.
"""

import pathlib
import sys
import unittest

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.evaluate_soc import (
    evaluate_offline_models,
    benchmark_pipeline_performance,
    verify_database_persistence,
)


class TestEvaluationSuite(unittest.TestCase):
    """Test suite ensuring Stage 13 evaluation scripts produce valid metrics."""

    def test_offline_evaluation_metrics_validity(self):
        """Verify that offline ML evaluation computes valid mathematical rates and metrics."""
        report = evaluate_offline_models(sample_size=20)
        self.assertEqual(report["evaluation_context"], "HISTORICAL_OFFLINE_BENCHMARK")
        self.assertIn("disclaimer", report)
        self.assertEqual(report["sample_size"], 20)

        rf = report["network_detection"]
        self.assertGreaterEqual(rf["accuracy"], 0.0)
        self.assertLessEqual(rf["accuracy"], 1.0)
        self.assertGreaterEqual(rf["macro_f1"], 0.0)
        self.assertLessEqual(rf["macro_f1"], 1.0)
        self.assertGreaterEqual(rf["false_positive_rate"], 0.0)
        self.assertLessEqual(rf["false_positive_rate"], 1.0)

        cm = rf["confusion_matrix"]
        total_cm = cm["true_positives"] + cm["false_positives"] + cm["true_negatives"] + cm["false_negatives"]
        self.assertEqual(total_cm, 20)

        # Infilteration class
        inf_metrics = rf["per_class_metrics"]["Infilteration"]
        self.assertIn("precision", inf_metrics)
        self.assertIn("recall", inf_metrics)
        self.assertIn("f1_score", inf_metrics)

        # Anomaly detection metrics
        anom = report["anomaly_detection"]
        self.assertGreaterEqual(anom["anomaly_rate_on_attacks"], 0.0)
        self.assertLessEqual(anom["anomaly_rate_on_attacks"], 1.0)

    def test_pipeline_benchmark_execution(self):
        """Verify that pipeline benchmarking runs and returns timing statistics."""
        bench = benchmark_pipeline_performance(n_events=5)
        self.assertEqual(bench["total_events_attempted"], 5)
        self.assertEqual(bench["successful_events"], 5)
        self.assertEqual(bench["failed_events"], 0)
        self.assertGreater(bench["throughput_events_per_second"], 0.0)

        lat = bench["latency_stats_ms"]
        self.assertGreater(lat["average"], 0.0)
        self.assertGreater(lat["p95"], 0.0)

    def test_database_persistence_verification(self):
        """Verify that database persistence check validates SQLite tables."""
        db_rep = verify_database_persistence()
        self.assertEqual(db_rep["status"], "ONLINE")
        counts = db_rep["row_counts"]
        self.assertIn("events", counts)
        self.assertIn("alerts", counts)
        self.assertIn("response_playbooks", counts)


if __name__ == "__main__":
    unittest.main()
