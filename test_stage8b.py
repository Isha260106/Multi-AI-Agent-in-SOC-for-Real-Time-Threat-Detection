import sys
import unittest
import sqlite3
import tempfile
import pathlib
from unittest.mock import patch
from io import StringIO
import time

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from realtime_monitor import get_event_data, format_output, LiveStats, run_monitor


class TestStage8B(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = pathlib.Path(self.tmp_dir.name) / "test_soc.db"
        self._init_db()

    def tearDown(self):
        try:
            self.tmp_dir.cleanup()
        except OSError:
            pass

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE NOT NULL,
                    source TEXT,
                    ingested_at TEXT
                )
            ''')
            conn.execute('''
                CREATE TABLE alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT UNIQUE NOT NULL,
                    event_id TEXT,
                    agent TEXT,
                    timestamp TEXT,
                    prediction TEXT,
                    confidence REAL,
                    severity TEXT,
                    status TEXT,
                    processing_time_s REAL,
                    network_context_json TEXT
                )
            ''')
            conn.execute('''
                CREATE TABLE incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id TEXT UNIQUE NOT NULL,
                    event_id TEXT,
                    prediction TEXT,
                    severity TEXT,
                    status TEXT
                )
            ''')
            conn.commit()

    def test_live_stats_accumulation(self):
        """Test LiveStats tracks event counts, benign, attack, anomalies, alerts, incidents, and latencies."""
        stats = LiveStats()
        stats.process_event('BENIGN', 'NORMAL', 0, False, 0.05)
        stats.process_event('ATTACK', 'ANOMALOUS', 2, True, 0.07)

        self.assertEqual(stats.events_processed, 2)
        self.assertEqual(stats.benign, 1)
        self.assertEqual(stats.attacks, 1)
        self.assertEqual(stats.normal, 1)
        self.assertEqual(stats.anomalous, 1)
        self.assertEqual(stats.alerts, 2)
        self.assertEqual(stats.incidents, 1)
        self.assertEqual(len(stats.latencies), 2)

    def test_get_event_data(self):
        """Test get_event_data fetches network detection, anomaly detection, alerts, incident, and metadata."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("INSERT INTO events (event_id, source, ingested_at) VALUES ('evt-1', 'replay', '2026-10-06')")
            conn.execute('''
                INSERT INTO alerts (alert_id, event_id, agent, timestamp, prediction, confidence, severity, status, processing_time_s) 
                VALUES ('alt-1', 'evt-1', 'Network Detection Agent', '2026-10-06 22:15:01', 'Infilteration', 0.9118, 'HIGH', 'SUSPICIOUS', 0.073)
            ''')
            conn.execute('''
                INSERT INTO alerts (alert_id, event_id, agent, timestamp, prediction, confidence, severity, status, processing_time_s) 
                VALUES ('alt-2', 'evt-1', 'Anomaly Detection Agent', '2026-10-06 22:15:01', 'Anomalous', 0.85, 'MEDIUM', 'SUSPICIOUS', 0.01)
            ''')
            conn.execute('''
                INSERT INTO incidents (incident_id, event_id, prediction, severity, status) 
                VALUES ('inc-1', 'evt-1', 'THREAT', 'HIGH', 'OPEN')
            ''')
            conn.commit()
            
            conn.row_factory = sqlite3.Row
            nd_a, ad_a, alerts_gen, inc, ts, pt, src = get_event_data(conn, 'evt-1')

            self.assertIsNotNone(nd_a)
            self.assertEqual(nd_a['prediction'], 'Infilteration')
            self.assertIsNotNone(ad_a)
            self.assertEqual(ad_a['prediction'], 'Anomalous')
            self.assertIsNotNone(inc)
            self.assertEqual(inc['incident_id'], 'inc-1')
            self.assertEqual(src, 'replay')
            self.assertEqual(len(alerts_gen), 2)

    def test_format_output(self):
        """Test format_output displays all required fields with no fake anomaly confidence."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("INSERT INTO events (event_id, source, ingested_at) VALUES ('evt-2', 'replay', '2026-10-06')")
            conn.execute('''
                INSERT INTO alerts (alert_id, event_id, agent, timestamp, prediction, confidence, severity, status, processing_time_s) 
                VALUES ('alt-3', 'evt-2', 'Network Detection Agent', '2026-10-06 22:15:01', 'Infilteration', 0.9118, 'HIGH', 'SUSPICIOUS', 0.073)
            ''')
            conn.execute('''
                INSERT INTO alerts (alert_id, event_id, agent, timestamp, prediction, confidence, severity, status, processing_time_s) 
                VALUES ('alt-4', 'evt-2', 'Anomaly Detection Agent', '2026-10-06 22:15:01', 'Anomalous', -0.5, 'MEDIUM', 'SUSPICIOUS', 0.02)
            ''')
            conn.execute('''
                INSERT INTO incidents (incident_id, event_id, prediction, severity, status) 
                VALUES ('inc-2', 'evt-2', 'THREAT', 'HIGH', 'OPEN')
            ''')
            conn.commit()
            conn.row_factory = sqlite3.Row
            nd_a, ad_a, alerts_gen, inc, ts, pt, src = get_event_data(conn, 'evt-2')

            output = format_output('evt-2', nd_a, ad_a, alerts_gen, inc, ts, pt, src)
            
            # 1. Classification confidence displayed for Network Detection
            self.assertIn("Confidence     : 91.18%", output)
            # 2. Raw Anomaly score displayed for Isolation Forest without fake confidence
            self.assertIn("Anomaly Score  : -0.500000", output)
            self.assertNotIn("Confidence     : -0.5", output)
            
            # 3. Final status, severity, and incident ID
            self.assertIn("Status         : THREAT", output)
            self.assertIn("Severity       : HIGH", output)
            self.assertIn("Incident ID    : inc-2", output)
            self.assertIn("Prediction     : ATTACK", output)
            self.assertIn("Processing Time: 73 ms", output)

    def test_benign_no_incident_output(self):
        """Test benign event formatting with no alert and no incident."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("INSERT INTO events (event_id, source, ingested_at) VALUES ('evt-benign', 'realtime_dataset_replay', '2026-10-06')")
            conn.execute('''
                INSERT INTO alerts (alert_id, event_id, agent, timestamp, prediction, confidence, severity, status, processing_time_s) 
                VALUES ('alt-b1', 'evt-benign', 'Network Detection Agent', '2026-10-06 22:15:01', 'Benign', 0.9642, 'LOW', 'NORMAL', 0.056)
            ''')
            conn.execute('''
                INSERT INTO alerts (alert_id, event_id, agent, timestamp, prediction, confidence, severity, status, processing_time_s) 
                VALUES ('alt-b2', 'evt-benign', 'Anomaly Detection Agent', '2026-10-06 22:15:01', 'Normal', -0.312, 'LOW', 'NORMAL', 0.012)
            ''')
            conn.commit()
            conn.row_factory = sqlite3.Row
            nd_a, ad_a, alerts_gen, inc, ts, pt, src = get_event_data(conn, 'evt-benign')

            output = format_output('evt-benign', nd_a, ad_a, alerts_gen, inc, ts, pt, src)
            self.assertIn("NETWORK DETECTION\nPrediction     : BENIGN\nConfidence     : 96.42%", output)
            self.assertIn("ANOMALY DETECTION\nPrediction     : NORMAL\nAnomaly Score  : -0.312000", output)
            self.assertIn("FINAL STATUS\nStatus         : BENIGN\nSeverity       : NONE", output)
            self.assertIn("ALERT\nStatus         : No alert generated", output)
            self.assertIn("INCIDENT\nStatus         : No incident created", output)
            self.assertIn("Processing Time: 56 ms", output)

    def test_anomaly_score_from_json_fallback(self):
        """Test extraction of anomaly score when stored inside network_context_json."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("INSERT INTO events (event_id, source, ingested_at) VALUES ('evt-json', 'replay', '2026-10-06')")
            conn.execute('''
                INSERT INTO alerts (alert_id, event_id, agent, timestamp, prediction, confidence, severity, status, processing_time_s, network_context_json) 
                VALUES ('alt-j1', 'evt-json', 'Anomaly Detection Agent', '2026-10-06 22:15:01', 'Anomalous', NULL, 'HIGH', 'SUSPICIOUS', 0.02, '{"anomaly_score": -0.456789}')
            ''')
            conn.commit()
            conn.row_factory = sqlite3.Row
            nd_a, ad_a, alerts_gen, inc, ts, pt, src = get_event_data(conn, 'evt-json')

            output = format_output('evt-json', nd_a, ad_a, alerts_gen, inc, ts, pt, src)
            self.assertIn("Anomaly Score  : -0.456789", output)

    def test_duplicate_suppression_and_poll_advancement(self):
        """Test that the monitor polls new records and advances without duplicating previously displayed events."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("INSERT INTO events (id, event_id, source, ingested_at) VALUES (1, 'evt-first', 'replay', '2026-10-06')")
            conn.execute('''
                INSERT INTO alerts (alert_id, event_id, agent, timestamp, prediction, confidence, severity, status, processing_time_s) 
                VALUES ('alt-f1', 'evt-first', 'Network Detection Agent', '2026-10-06 22:15:01', 'Benign', 0.99, 'LOW', 'NORMAL', 0.02)
            ''')
            conn.commit()

        class DummyArgs:
            pass
        args = DummyArgs()
        args.db_path = self.db_path
        args.interval = 0.001
        args.show_existing = False
        args.once = True

        # First run with show_existing=False should skip event 1
        with patch('sys.stdout', new_callable=StringIO) as out1:
            try:
                run_monitor(args)
            except SystemExit:
                pass
            self.assertNotIn("evt-first", out1.getvalue())

        # Now insert a second event
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("INSERT INTO events (id, event_id, source, ingested_at) VALUES (2, 'evt-second', 'replay', '2026-10-06')")
            conn.execute('''
                INSERT INTO alerts (alert_id, event_id, agent, timestamp, prediction, confidence, severity, status, processing_time_s) 
                VALUES ('alt-f2', 'evt-second', 'Network Detection Agent', '2026-10-06 22:15:02', 'Infilteration', 0.88, 'HIGH', 'SUSPICIOUS', 0.03)
            ''')
            conn.commit()

        # Run with show_existing=True should show both
        args.show_existing = True
        with patch('sys.stdout', new_callable=StringIO) as out2:
            try:
                run_monitor(args)
            except SystemExit:
                pass
            val = out2.getvalue()
            self.assertIn("evt-first", val)
            self.assertIn("evt-second", val)
            # Check sequential order
            self.assertTrue(val.index("evt-first") < val.index("evt-second"))

    @patch('sys.stdout', new_callable=StringIO)
    def test_graceful_shutdown(self, mock_stdout):
        class DummyArgs:
            pass
        args = DummyArgs()
        args.db_path = self.db_path
        args.interval = 0.001
        args.show_existing = True
        args.once = True
        
        try:
            run_monitor(args)
        except SystemExit:
            pass
            
        output = mock_stdout.getvalue()
        self.assertIn("REAL-TIME AI SECURITY OPERATIONS CENTER", output)


if __name__ == '__main__':
    unittest.main()
