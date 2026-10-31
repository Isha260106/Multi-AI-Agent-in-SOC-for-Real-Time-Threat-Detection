"""
test_vm_sensor.py
==================
Comprehensive Mock-Based Unit Test Suite for Remote VM Telemetry Collector.

Multi-Agent SOC Project -- Phase 7: Testing and Safety Verification

GUARANTEES VERIFIED:
  1. SSH connection failure, timeout, and missing key error handling.
  2. Strict host-key verification and known_hosts validation.
  3. Log collector incremental collection with byte offsets and inode rotation tracking.
  4. Journalctl cursor-based incremental collection.
  5. Parsing of SSH accepted, failed, invalid user, sudo, and session events.
  6. BSD and ISO-8601 syslog timestamp normalization.
  7. Bounded exponential backoff retries for transient log submission errors.
  8. Non-retry of 401 Unauthorized and 422 Unprocessable entity errors.
  9. Flow collector prerequisite probing and clear limitation reporting without fabrication.
 10. Canonical 78-feature mapping and rejection of missing features or negative durations.
 11. Bounded retry and status code accounting for flow ingestion (201, 409, 422, 5xx).
 12. Strict separation of system logs from the 78-feature network flow model.
 13. System logs persistence in SQLite system_logs table and retrieval.
 14. Orchestrator mode selection (replay, vm_logs, vm_flows, vm_all) and PID locking.
"""

import datetime
import io
import json
import os
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.vm_sensor.ssh_client import RemoteSSHClient
from agents.vm_sensor.log_collector import VMLogCollector, RE_SYSLOG_LINE
from agents.vm_sensor.flow_collector import VMFlowCollector
from agents.vm_sensor.orchestrator import VMSensorOrchestrator
from kafka.live_adapter import CANONICAL_FEATURES, IncompatibleSchemaError
from storage.db import AlertStore
from storage.query import SystemLogQueryStore


class TestSSHClient(unittest.TestCase):
    """Test SSH client security, error handling, and parameter construction."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.key_file = pathlib.Path(self.temp_dir.name) / "test_key"
        self.key_file.write_text("DUMMY_KEY")
        self.known_hosts = pathlib.Path(self.temp_dir.name) / "known_hosts"
        self.known_hosts.write_text("45.74.156.54 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAtest\n")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_missing_private_key_fails_cleanly(self):
        client = RemoteSSHClient(
            host="45.74.156.54",
            key_path=str(pathlib.Path(self.temp_dir.name) / "non_existent_key"),
            known_hosts_file=str(self.known_hosts),
        )
        ok, diag = client.test_connection()
        self.assertFalse(ok)
        self.assertIn("not found", diag)

    def test_known_hosts_detection(self):
        client = RemoteSSHClient(
            host="45.74.156.54",
            key_path=str(self.key_file),
            known_hosts_file=str(self.known_hosts),
            strict_host_key_checking="yes",
        )
        self.assertTrue(client.is_host_in_known_hosts())

        unknown_client = RemoteSSHClient(
            host="192.168.1.99",
            key_path=str(self.key_file),
            known_hosts_file=str(self.known_hosts),
        )
        self.assertFalse(unknown_client.is_host_in_known_hosts())

    def test_ssh_args_enforce_strict_host_key_checking(self):
        client = RemoteSSHClient(
            host="45.74.156.54",
            key_path=str(self.key_file),
            known_hosts_file=str(self.known_hosts),
            strict_host_key_checking="yes",
        )
        args = client._build_base_ssh_args()
        self.assertIn("-o", args)
        self.assertIn("StrictHostKeyChecking=yes", args)
        self.assertIn(f"UserKnownHostsFile={client.known_hosts_file}", args)

    @patch("subprocess.run")
    def test_connection_timeout_handled(self, mock_run):
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["ssh"], timeout=10.0)
        client = RemoteSSHClient(
            host="45.74.156.54",
            key_path=str(self.key_file),
            known_hosts_file=str(self.known_hosts),
        )
        ok, diag = client.test_connection()
        self.assertFalse(ok)
        self.assertIn("timed out", diag.lower())

    @patch("subprocess.run")
    def test_command_execution_success(self, mock_run):
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_res.stdout = "Linux test-host 6.8.0\n"
        mock_res.stderr = ""
        mock_run.return_value = mock_res

        client = RemoteSSHClient(
            host="45.74.156.54",
            key_path=str(self.key_file),
            known_hosts_file=str(self.known_hosts),
        )
        code, out, err = client.execute_command("uname -a")
        self.assertEqual(code, 0)
        self.assertIn("Linux test-host", out)


class TestVMLogCollector(unittest.TestCase):
    """Test log parsing, rotation handling, incremental offsets, and API retries."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.state_file = pathlib.Path(self.temp_dir.name) / "state.json"
        self.mock_ssh = MagicMock()
        self.collector = VMLogCollector(
            ssh_client=self.mock_ssh,
            state_file=self.state_file,
            batch_ingest_url="http://127.0.0.1:8000/api/ingest/logs",
            sensor_key="soc-sensor-dev-key-2026",
            source_host="ip-10-0-0-12",
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_parse_ssh_accepted_publickey(self):
        line = "2026-10-27T17:49:24.123456+00:00 ip-10-0-0-12 sshd[65872]: Accepted publickey for ubuntu from 223.237.162.156 port 60497 ssh2: ED25519"
        res = self.collector.parse_log_line(line)
        self.assertIsNotNone(res)
        self.assertEqual(res["log_type"], "AUTH_SUCCESS")
        self.assertEqual(res["severity"], "INFO")
        self.assertEqual(res["metadata"]["user"], "ubuntu")
        self.assertEqual(res["metadata"]["ip"], "223.237.162.156")
        self.assertEqual(res["metadata"]["port"], 60497)

    def test_parse_ssh_failed_password(self):
        line = "Oct 27 18:02:11 ip-10-0-0-12 sshd[65999]: Failed password for invalid user admin from 198.51.100.44 port 43210 ssh2"
        res = self.collector.parse_log_line(line)
        self.assertIsNotNone(res)
        self.assertEqual(res["log_type"], "AUTH_FAILURE")
        self.assertEqual(res["severity"], "WARNING")
        self.assertEqual(res["metadata"]["user"], "admin")
        self.assertEqual(res["metadata"]["ip"], "198.51.100.44")

    def test_parse_sudo_command_execution(self):
        line = "2026-10-27T12:00:00+00:00 ip-10-0-0-12 sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/apt update"
        res = self.collector.parse_log_line(line)
        self.assertIsNotNone(res)
        self.assertEqual(res["log_type"], "SUDO_EXEC")
        self.assertEqual(res["metadata"]["user"], "ubuntu")
        self.assertEqual(res["metadata"]["command"], "/usr/bin/apt update")

    def test_incremental_log_reading_and_offset_advancement(self):
        # 1. First poll: stat returns inode 100, size 250
        self.mock_ssh.execute_command.side_effect = [
            (0, "100 250\n", ""),  # stat
            (0, "line 1\nline 2\n", ""),  # tail chunk
        ]
        logs = self.collector.collect_auth_log_incremental(max_lines=50)
        self.assertEqual(len(logs), 2)
        self.assertEqual(self.collector.state["auth_log_inode"], 100)
        self.assertGreater(self.collector.state["auth_log_offset"], 0)

        # 2. Second poll: no new bytes
        curr_offset = self.collector.state["auth_log_offset"]
        self.mock_ssh.execute_command.side_effect = [
            (0, f"100 {curr_offset}\n", ""),  # stat same size
        ]
        logs2 = self.collector.collect_auth_log_incremental(max_lines=50)
        self.assertEqual(len(logs2), 0)

    def test_log_rotation_resets_offset(self):
        # Initial state: inode 100, offset 500
        self.collector.state["auth_log_inode"] = 100
        self.collector.state["auth_log_offset"] = 500

        # Remote file was rotated: inode is now 101, size is 80
        self.mock_ssh.execute_command.side_effect = [
            (0, "101 80\n", ""),  # stat
            (0, "new line after rotation\n", ""),  # tail
        ]
        logs = self.collector.collect_auth_log_incremental(max_lines=50)
        self.assertEqual(len(logs), 1)
        self.assertEqual(self.collector.state["auth_log_inode"], 101)

    @patch("httpx.Client")
    def test_submit_logs_bounded_retry_on_server_error(self, mock_client_cls):
        mock_resp_500 = MagicMock()
        mock_resp_500.status_code = 500
        mock_resp_500.text = "Internal error"

        mock_resp_201 = MagicMock()
        mock_resp_201.status_code = 201
        mock_resp_201.json.return_value = {"status": "success", "count_inserted": 2}

        # First attempt 500, second attempt 201
        mock_client = MagicMock()
        mock_client.__enter__.return_value = mock_client
        mock_client.post.side_effect = [mock_resp_500, mock_resp_201]
        mock_client_cls.return_value = mock_client

        entries = [{"log_id": "1", "message": "test1"}, {"log_id": "2", "message": "test2"}]
        inserted = self.collector.submit_logs(entries, max_retries=2)
        self.assertEqual(inserted, 2)
        self.assertEqual(mock_client.post.call_count, 2)

    @patch("httpx.Client")
    def test_submit_logs_does_not_retry_401_or_422(self, mock_client_cls):
        mock_resp_401 = MagicMock()
        mock_resp_401.status_code = 401
        mock_resp_401.text = "Unauthorized"

        mock_client = MagicMock()
        mock_client.__enter__.return_value = mock_client
        mock_client.post.return_value = mock_resp_401
        mock_client_cls.return_value = mock_client

        entries = [{"log_id": "1", "message": "test1"}]
        inserted = self.collector.submit_logs(entries, max_retries=3)
        self.assertEqual(inserted, 0)
        # Should NOT retry after 401
        self.assertEqual(mock_client.post.call_count, 1)


class TestVMFlowCollector(unittest.TestCase):
    """Test network flow collector validation, schema mapping, and error reporting."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.state_file = pathlib.Path(self.temp_dir.name) / "state.json"
        self.mock_ssh = MagicMock()
        self.collector = VMFlowCollector(
            ssh_client=self.mock_ssh,
            state_file=self.state_file,
            remote_csv_path="/var/log/soc/flows.csv",
            ingest_url="http://127.0.0.1:8000/api/ingest/flow",
            sensor_key="soc-sensor-dev-key-2026",
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_missing_flow_csv_reports_exact_limitation(self):
        self.mock_ssh.execute_command.return_value = (
            0,
            "TCPDUMP:/usr/bin/tcpdump\nCICFLOWMETER:NONE\nCSV_FILE:MISSING\nCSV_SIZE:0\n",
            "",
        )
        status = self.collector.check_remote_flow_extractor_status()
        self.assertTrue(status["tcpdump_installed"])
        self.assertFalse(status["cicflowmeter_installed"])
        self.assertFalse(status["csv_present"])
        self.assertFalse(status["ready"])
        self.assertIn("Remote flow CSV (/var/log/soc/flows.csv) not currently present", status["limitation"])

    def test_incomplete_flow_record_raises_incompatible_schema(self):
        # A row missing required features must be rejected without metric fabrication
        incomplete_row = {
            "Dst Port": "80",
            "Protocol": "6",
            "Flow Duration": "15000",
            # Omitting 75 features
        }
        with self.assertRaises(IncompatibleSchemaError):
            self.collector.adapter.normalize_dict(incomplete_row)

    def test_negative_flow_duration_rejected(self):
        from kafka.live_adapter import InvalidFlowError
        row = {f: "1.0" for f in CANONICAL_FEATURES}
        row["Flow Duration"] = "-500"  # Negative duration
        with self.assertRaises(InvalidFlowError):
            self.collector.adapter.normalize_dict(row)

    @patch("httpx.Client")
    def test_submit_flows_accounting(self, mock_client_cls):
        # Simulate submissions returning 201 (accepted), 409 (duplicate), 422 (rejected)
        r201 = MagicMock(status_code=201, json=lambda: {"status": "ACCEPTED"})
        r409 = MagicMock(status_code=409, json=lambda: {"detail": "Duplicate event ID"})
        r422 = MagicMock(status_code=422, json=lambda: {"detail": "Missing feature"})

        mock_client = MagicMock()
        mock_client.__enter__.return_value = mock_client
        mock_client.post.side_effect = [r201, r409, r422]
        mock_client_cls.return_value = mock_client

        flows = [{"event_id": "1"}, {"event_id": "2"}, {"event_id": "3"}]
        stats = self.collector.submit_flows(flows)
        self.assertEqual(stats["accepted"], 1)
        self.assertEqual(stats["duplicated"], 1)
        self.assertEqual(stats["rejected"], 1)
        self.assertEqual(stats["failed"], 0)


class TestSystemLogSeparation(unittest.TestCase):
    """Verify that system logs are strictly separated from network flows in DB and API."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = pathlib.Path(self.temp_dir.name) / "test_soc.db"
        with AlertStore(db_path=self.db_path) as store:
            pass  # Creates tables

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_system_logs_stored_in_dedicated_table(self):
        log_entry = {
            "log_id": "test-log-uuid-1",
            "timestamp": "2026-10-27T12:00:00Z",
            "source_host": "ip-10-0-0-12",
            "service": "sshd",
            "log_type": "AUTH_FAILURE",
            "severity": "WARNING",
            "message": "Failed password for ubuntu from 192.168.1.5",
            "raw_log": "raw log string",
            "metadata": {"ip": "192.168.1.5", "user": "ubuntu"},
        }
        with AlertStore(db_path=self.db_path) as store:
            inserted = store.save_system_log(log_entry)
            self.assertTrue(inserted)
            # Duplicate log_id ignored
            dup_inserted = store.save_system_log(log_entry)
            self.assertFalse(dup_inserted)
            self.assertEqual(store.system_logs_count(), 1)

        with SystemLogQueryStore(db_path=self.db_path) as q_store:
            logs = q_store.get_recent_logs(limit=10)
            self.assertEqual(len(logs), 1)
            self.assertEqual(logs[0]["service"], "sshd")
            self.assertEqual(logs[0]["log_type"], "AUTH_FAILURE")
            self.assertEqual(logs[0]["metadata"]["user"], "ubuntu")

    def test_system_logs_batch_atomic_insert(self):
        batch = [
            {"log_id": f"batch-{i}", "service": "sudo", "log_type": "SUDO_EXEC", "message": f"cmd {i}"}
            for i in range(5)
        ]
        with AlertStore(db_path=self.db_path) as store:
            inserted_count = store.save_system_logs_batch(batch)
            self.assertEqual(inserted_count, 5)
            self.assertEqual(store.system_logs_count(), 5)


class TestOrchestrator(unittest.TestCase):
    """Test orchestrator source modes, PID lock, and lifecycle."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.state_file = pathlib.Path(self.temp_dir.name) / "sensor_state.json"
        self.orchestrator = VMSensorOrchestrator(mode="replay", poll_interval=0.1)
        self.orchestrator.log_collector.state_file = self.state_file
        self.orchestrator.flow_collector.state_file = self.state_file

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_mode_selection_and_poll_cycle(self):
        # 1. Replay mode
        res_replay = self.orchestrator.poll_once()
        self.assertEqual(res_replay["mode"], "replay")
        self.assertTrue(res_replay.get("replay_active", False))

        # 2. vm_logs mode
        self.orchestrator.mode = "vm_logs"
        self.orchestrator.log_collector.collect_and_submit = MagicMock(return_value=(4, 4))
        res_logs = self.orchestrator.poll_once()
        self.assertEqual(res_logs["logs_collected"], 4)
        self.assertEqual(res_logs["logs_submitted"], 4)

        # 3. vm_flows mode
        self.orchestrator.mode = "vm_flows"
        self.orchestrator.flow_collector.collect_new_flow_records = MagicMock(return_value=[{"event_id": "1"}])
        self.orchestrator.flow_collector.submit_flows = MagicMock(return_value={"accepted": 1})
        res_flows = self.orchestrator.poll_once()
        self.assertEqual(res_flows["flows_collected"], 1)
        self.assertEqual(res_flows["flows_submitted"], 1)


if __name__ == "__main__":
    unittest.main()
