import sys
import unittest
import sqlite3
import tempfile
import pathlib
from unittest.mock import patch, MagicMock
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
                    processing_time_s REAL
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

    def test_get_event_data(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("INSERT INTO events (event_id, source, ingested_at) VALUES ('evt-1', 'replay', '2026-10-06')")
            conn.execute('''
                INSERT INTO alerts (alert_id, event_id, agent, timestamp, prediction, confidence, severity, processing_time_s) 
                VALUES ('alt-1', 'evt-1', 'Network Detection Agent', '2026-10-06 22:15:01', 'Infilteration', 0.9118, 'HIGH', 0.073)
            ''')
            conn.execute('''
                INSERT INTO alerts (alert_id, event_id, agent, timestamp, prediction, confidence, severity, processing_time_s) 
                VALUES ('alt-2', 'evt-1', 'Anomaly Detection Agent', '2026-10-06 22:15:01', 'Anomalous', 0.85, 'MEDIUM', 0.01)
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
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("INSERT INTO events (event_id, source, ingested_at) VALUES ('evt-2', 'replay', '2026-10-06')")
            conn.execute('''
                INSERT INTO alerts (alert_id, event_id, agent, timestamp, prediction, confidence, severity, processing_time_s) 
                VALUES ('alt-3', 'evt-2', 'Network Detection Agent', '2026-10-06 22:15:01', 'Infilteration', 0.9118, 'HIGH', 0.073)
            ''')
            conn.execute('''
                INSERT INTO alerts (alert_id, event_id, agent, timestamp, prediction, confidence, severity, processing_time_s) 
                VALUES ('alt-4', 'evt-2', 'Anomaly Detection Agent', '2026-10-06 22:15:01', 'Anomalous', -0.5, 'MEDIUM', 0.02)
            ''')
            conn.execute('''
                INSERT INTO incidents (incident_id, event_id, prediction, severity, status) 
                VALUES ('inc-2', 'evt-2', 'THREAT', 'HIGH', 'OPEN')
            ''')
            conn.commit()
            conn.row_factory = sqlite3.Row
            nd_a, ad_a, alerts_gen, inc, ts, pt, src = get_event_data(conn, 'evt-2')

            output = format_output('evt-2', nd_a, ad_a, alerts_gen, inc, ts, pt, src)
            
            # 6. Anomaly Detection does not incorrectly display a fake confidence percentage.
            # 7. Actual anomaly score is displayed if available.
            self.assertIn("Confidence     : 91.18%", output)
            self.assertIn("Anomaly Score  : -0.500000", output)
            self.assertNotIn("Confidence     : -0.5", output)
            
            # 8. Final status matches. 9. Alert severity matches. 10. Incident ID matches.
            self.assertIn("Status         : THREAT", output)
            self.assertIn("Severity       : HIGH", output)
            self.assertIn("Incident ID    : inc-2", output)
            self.assertIn("Prediction     : ATTACK", output) # Attack not Infilteration matching
            
    
    @patch('sys.stdout', new_callable=StringIO)
    def test_graceful_shutdown(self, mock_stdout):
        class DummyArgs:
            pass
        args = DummyArgs()
        args.db_path = self.db_path
        args.interval = 0.001
        args.show_existing = True
        args.once = True
        
        # 12. Ctrl+C shuts the monitor down cleanly (simulated via KeyboardInterrupt during poll or once=True)
        # We will use once=True to ensure it breaks out correctly
        try:
            run_monitor(args)
        except SystemExit:
            pass
            
        output = mock_stdout.getvalue()
        # Should have initialization print
        self.assertIn("REAL-TIME AI SECURITY OPERATIONS CENTER", output)

if __name__ == '__main__':
    unittest.main()
