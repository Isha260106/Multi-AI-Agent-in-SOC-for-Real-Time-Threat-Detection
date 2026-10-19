"""
test_realtime_monitor.py
========================
Tests for the Real-Time SOC Prediction Monitor.

Multi-Agent SOC Project -- Stage 8A Modification
"""

import sys
import unittest
import time
import sqlite3
import tempfile
import pathlib
from io import StringIO

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from realtime_monitor import parse_args, run_monitor


class TestRealtimeMonitor(unittest.TestCase):
    def setUp(self):
        # Create a temporary database for testing
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix=".db")
        self.temp_db = pathlib.Path(self.temp_db_path)
        
        # Initialize basic mock schema matching the storage/db.py
        from contextlib import closing
        with closing(sqlite3.connect(self.temp_db)) as conn:
            conn.execute("""
                CREATE TABLE events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE,
                    source TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT UNIQUE,
                    event_id TEXT,
                    agent TEXT,
                    prediction TEXT,
                    confidence REAL,
                    severity TEXT,
                    timestamp TEXT,
                    processing_time_s REAL
                )
            """)
            conn.execute("""
                CREATE TABLE incidents (
                    incident_id TEXT UNIQUE,
                    event_id TEXT,
                    prediction TEXT,
                    severity TEXT,
                    status TEXT
                )
            """)
            
            # Insert some mock records
            conn.execute("INSERT INTO events (event_id, source) VALUES ('evt_1', 'test_source')")
            conn.execute("INSERT INTO events (event_id, source) VALUES ('evt_2', 'test_source')")
            conn.execute("""
                INSERT INTO alerts (alert_id, event_id, agent, prediction, confidence, severity, timestamp, processing_time_s)
                VALUES ('al_1', 'evt_1', 'Network Detection Agent', 'ATTACK', 0.95, 'HIGH', '2026-09-17 12:00:00', 0.045)
            """)
            # Second alert without an event mapping
            conn.execute("""
                INSERT INTO alerts (alert_id, event_id, agent, prediction, confidence, severity, timestamp, processing_time_s)
                VALUES ('al_2', 'evt_2', 'Network Detection Agent', 'BENIGN', 0.99, 'LOW', '2026-09-17 12:00:05', 0.015)
            """)
            conn.commit()

    def tearDown(self):
        try:
            import os
            os.close(self.temp_db_fd)
            if self.temp_db.exists():
                self.temp_db.unlink()
        except OSError:
            pass

    def test_format_output(self):
        """Test formatting a SQLite row representation into correct display."""
        from realtime_monitor import get_event_data, format_output
        from contextlib import closing
        with closing(sqlite3.connect(self.temp_db)) as conn:
            conn.row_factory = sqlite3.Row
            nd_a, ad_a, alerts_gen, inc, ts, pt, src = get_event_data(conn, 'evt_1')
            
        output = format_output('evt_1', nd_a, ad_a, alerts_gen, inc, ts, pt, src)
        self.assertIn("[2026-09-17 12:00:00] EVENT RECEIVED", output)
        self.assertIn("Event ID       : evt_1", output)
        self.assertIn("Prediction     : ATTACK", output)
        self.assertIn("Confidence     : 95.00%", output)
        self.assertIn("Severity       : HIGH", output)
        self.assertIn("Processing Time: 45 ms", output)

    def test_missing_database(self):
        """Test gracefully failing on bad database paths."""
        class Args:
            db_path = pathlib.Path("does_not_exist_xyz99.db")
            interval = 0.5
            show_existing = False
            once = True
            
        with self.assertRaises(SystemExit) as cm:
            # We must capture stdout, so it doesn't flood terminal
            old_stdout = sys.stdout
            sys.stdout = StringIO()
            try:
                run_monitor(Args())
            finally:
                sys.stdout = old_stdout
        self.assertEqual(cm.exception.code, 1)

    def test_run_monitor_once_mode(self):
        """Test extracting available logs printing properly in --once mode simulating intervals."""
        class Args:
            db_path = self.temp_db
            interval = 0.1
            show_existing = True
            once = True
            
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        try:
            run_monitor(Args())
        finally:
            output = sys.stdout.getvalue()
            sys.stdout = old_stdout
            
        self.assertIn("evt_1", output)
        self.assertIn("evt_2", output)
        self.assertIn("99.00%", output)

    def test_run_monitor_empty_ignore(self):
        """Test the polling loop securely ignoring previously generated history unless flag is passed."""
        class Args:
            db_path = self.temp_db
            interval = 0.1
            show_existing = False
            once = True
            
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        try:
            run_monitor(Args())
        finally:
            output = sys.stdout.getvalue()
            sys.stdout = old_stdout
            
        # It should ignore al_1 and al_2 because they were pre-existing.
        self.assertNotIn("evt_1", output)
        self.assertNotIn("evt_2", output)

    def test_invalid_interval(self):
        """Test interval configuration validation bounds natively."""
        # Sys.argv patching required realistically testing argparse directly
        old_argv = sys.argv
        sys.argv = ["realtime_monitor.py", "--interval", "-1"]
        
        with self.assertRaises(SystemExit) as cm:
            old_stdout = sys.stdout
            sys.stdout = StringIO()
            try:
                parse_args()
            finally:
                sys.stdout = old_stdout
        
        sys.argv = old_argv
        self.assertEqual(cm.exception.code, 1)


if __name__ == "__main__":
    unittest.main()
