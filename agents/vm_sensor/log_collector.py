"""
agents/vm_sensor/log_collector.py
=================================
Incremental Ubuntu system log collector and security event parser.

Multi-Agent SOC Project -- Live Victim VM Telemetry Integration
"""

import datetime
import json
import logging
import os
import pathlib
import re
import sys
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

import httpx

from agents.vm_sensor.config import (
    REMOTE_AUTH_LOG_PATH,
    SENSOR_RUNTIME_LOG,
    SOC_LOGS_BATCH_URL,
    SOC_SENSOR_KEY,
    SOC_VM_HOST,
    STATE_FILE,
)
from agents.vm_sensor.ssh_client import RemoteSSHClient

logger = logging.getLogger("SOC.VMSensor.Logs")
if not logger.handlers:
    _fh = logging.FileHandler(SENSOR_RUNTIME_LOG, encoding="utf-8")
    _fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s - %(message)s"))
    logger.addHandler(_fh)
    logger.setLevel(logging.INFO)

# Regex Patterns for Common Security Log Events in Ubuntu /var/log/auth.log
RE_SSH_ACCEPTED = re.compile(
    r"Accepted\s+(?P<method>publickey|password)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)",
    re.IGNORECASE,
)
RE_SSH_FAILED = re.compile(
    r"Failed\s+(?P<method>password|publickey)\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)",
    re.IGNORECASE,
)
RE_INVALID_USER = re.compile(
    r"Invalid\s+user\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)",
    re.IGNORECASE,
)
RE_SUDO_CMD = re.compile(
    r"(?:sudo:\s+)?(?P<user>\S+)\s+:.*?COMMAND=(?P<command>.*)",
    re.IGNORECASE,
)
RE_SESSION_OPEN = re.compile(
    r"pam_unix\((?P<service>[^:]+):session\):\s+session\s+opened\s+for\s+user\s+(?P<user>\S+)",
    re.IGNORECASE,
)
RE_SESSION_CLOSE = re.compile(
    r"pam_unix\((?P<service>[^:]+):session\):\s+session\s+closed\s+for\s+user\s+(?P<user>\S+)",
    re.IGNORECASE,
)
RE_SYSLOG_LINE = re.compile(
    r"^(?:(?P<iso_ts>\d{4}-\d{2}-\d{2}T\S+)|(?P<bsd_ts>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}))\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[^:\[\s]+)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)


class VMLogCollector:
    """
    Collects, normalizes, and submits security logs from the remote victim VM.
    Tracks state (cursors, byte offsets) to ensure zero duplicate submissions across runs.
    """

    def __init__(
        self,
        ssh_client: RemoteSSHClient,
        state_file: pathlib.Path = STATE_FILE,
        batch_ingest_url: str = SOC_LOGS_BATCH_URL,
        sensor_key: str = SOC_SENSOR_KEY,
        source_host: str = SOC_VM_HOST,
    ):
        self.ssh = ssh_client
        self.state_file = pathlib.Path(state_file)
        self.batch_ingest_url = batch_ingest_url
        self.sensor_key = sensor_key
        self.source_host = source_host
        self.state = self._load_state()

    def _load_state(self) -> Dict[str, Any]:
        """Load persistent cursor and offset tracking state."""
        if self.state_file.exists():
            try:
                with open(self.state_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as exc:
                logger.warning("Error reading state file %s: %s. Initializing fresh state.", self.state_file, exc)
        return {
            "auth_log_offset": 0,
            "auth_log_inode": 0,
            "journal_cursor": "",
            "total_logs_collected": 0,
            "total_logs_submitted": 0,
            "last_collected_at": None,
            "last_log_summary": None,
        }

    def _save_state(self) -> None:
        """Persist state atomically."""
        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            temp_file = self.state_file.with_suffix(".tmp")
            with open(temp_file, "w", encoding="utf-8") as f:
                json.dump(self.state, f, indent=2)
            temp_file.replace(self.state_file)
        except Exception as exc:
            logger.error("Failed to save state file %s: %s", self.state_file, exc)

    def parse_log_line(self, raw_line: str, default_service: str = "auth") -> Optional[Dict[str, Any]]:
        """
        Normalize a raw Ubuntu log line into a validated system log dictionary.
        Supports both RFC3339/ISO-8601 and traditional BSD syslog timestamps.
        """
        line = raw_line.strip()
        if not line:
            return None

        # Parse syslog timestamp, host, process, pid, message
        ts_str = datetime.datetime.now().isoformat()
        host = self.source_host
        service = default_service
        pid = None
        message = line

        m_sys = RE_SYSLOG_LINE.match(line)
        if m_sys:
            raw_iso = m_sys.group("iso_ts")
            raw_bsd = m_sys.group("bsd_ts")
            if raw_iso:
                try:
                    ts_str = datetime.datetime.fromisoformat(raw_iso).isoformat()
                except Exception:
                    ts_str = raw_iso
            elif raw_bsd:
                try:
                    year = datetime.date.today().year
                    ts_dt = datetime.datetime.strptime(f"{year} {raw_bsd}", "%Y %b %d %H:%M:%S")
                    ts_str = ts_dt.isoformat()
                except Exception:
                    ts_str = raw_bsd

            host = m_sys.group("host") or self.source_host
            service = m_sys.group("process") or default_service
            pid = m_sys.group("pid")
            message = m_sys.group("message")

        log_type = "GENERAL"
        severity = "INFO"
        meta: Dict[str, Any] = {}
        if pid:
            meta["pid"] = pid

        # Classify security semantics
        m_acc = RE_SSH_ACCEPTED.search(message)
        if m_acc:
            log_type = "AUTH_SUCCESS"
            severity = "INFO"
            meta.update({
                "method": m_acc.group("method"),
                "user": m_acc.group("user"),
                "ip": m_acc.group("ip"),
                "port": int(m_acc.group("port")),
            })
        elif (m_fail := RE_SSH_FAILED.search(message)):
            log_type = "AUTH_FAILURE"
            severity = "WARNING"
            meta.update({
                "method": m_fail.group("method"),
                "user": m_fail.group("user"),
                "ip": m_fail.group("ip"),
                "port": int(m_fail.group("port")),
            })
        elif (m_inv := RE_INVALID_USER.search(message)):
            log_type = "INVALID_USER"
            severity = "WARNING"
            meta.update({
                "user": m_inv.group("user"),
                "ip": m_inv.group("ip"),
                "port": int(m_inv.group("port")),
            })
        elif (m_sudo := RE_SUDO_CMD.search(message)):
            log_type = "SUDO_EXEC"
            severity = "INFO"
            meta.update({
                "user": m_sudo.group("user"),
                "command": m_sudo.group("command"),
            })
        elif (m_open := RE_SESSION_OPEN.search(message)):
            log_type = "SESSION_OPENED"
            severity = "INFO"
            meta.update({
                "service": m_open.group("service"),
                "user": m_open.group("user"),
            })
        elif (m_close := RE_SESSION_CLOSE.search(message)):
            log_type = "SESSION_CLOSED"
            severity = "INFO"
            meta.update({
                "service": m_close.group("service"),
                "user": m_close.group("user"),
            })
        elif "error" in message.lower() or "failed" in message.lower():
            log_type = "SERVICE_ERROR"
            severity = "WARNING"

        return {
            "log_id": str(uuid.uuid4()),
            "timestamp": ts_str,
            "source_host": f"{host} (Victim VM)",
            "service": service,
            "log_type": log_type,
            "severity": severity,
            "message": message,
            "raw_log": line,
            "metadata": meta,
        }

    def collect_auth_log_incremental(self, max_lines: int = 100) -> List[Dict[str, Any]]:
        """
        Incrementally read new lines from /var/log/auth.log over SSH using byte offset tracking.
        Handles file rotation (when file inode changes or file size decreases).
        """
        # Check current inode and size of /var/log/auth.log
        stat_cmd = f"stat -c '%i %s' {REMOTE_AUTH_LOG_PATH} 2>/dev/null || echo '0 0'"
        code, out, _ = self.ssh.execute_command(stat_cmd, timeout=6.0)
        if code != 0:
            logger.warning("Could not stat %s on remote victim", REMOTE_AUTH_LOG_PATH)
            return []

        parts = out.strip().split()
        if len(parts) < 2:
            return []

        try:
            curr_inode = int(parts[0])
            curr_size = int(parts[1])
        except ValueError:
            return []

        prev_offset = int(self.state.get("auth_log_offset", 0))
        prev_inode = int(self.state.get("auth_log_inode", 0))

        # Detect log rotation or truncation
        if curr_inode != prev_inode or curr_size < prev_offset:
            logger.info("Log rotation detected for %s (inode: %d -> %d). Resetting offset to 0.",
                        REMOTE_AUTH_LOG_PATH, prev_inode, curr_inode)
            prev_offset = 0
            self.state["auth_log_inode"] = curr_inode

        if curr_size <= prev_offset:
            # No new data
            return []

        # Read only new bytes using tail -c +<offset+1>
        read_cmd = f"tail -c +{prev_offset + 1} {REMOTE_AUTH_LOG_PATH} | head -n {max_lines}"
        code, chunk, _ = self.ssh.execute_command(read_cmd, timeout=10.0)
        if code != 0 or not chunk:
            return []

        # Find the last newline in the chunk to prevent partial line reads
        last_nl = chunk.rfind("\n")
        if last_nl == -1:
            # No complete line written yet; wait for next cycle
            return []

        valid_chunk = chunk[: last_nl + 1]
        bytes_consumed = len(valid_chunk.encode("utf-8"))
        new_offset = prev_offset + bytes_consumed

        raw_lines = valid_chunk.splitlines()
        parsed_logs = []
        for line in raw_lines:
            entry = self.parse_log_line(line, default_service="auth")
            if entry:
                parsed_logs.append(entry)

        self.state["auth_log_offset"] = new_offset
        self.state["auth_log_inode"] = curr_inode
        self._save_state()

        logger.debug("Read %d new lines from %s (offset: %d -> %d)", len(parsed_logs), REMOTE_AUTH_LOG_PATH, prev_offset, new_offset)
        return parsed_logs

    def collect_journalctl_incremental(self, max_entries: int = 50) -> List[Dict[str, Any]]:
        """
        Incrementally collect security events using systemd journalctl cursor tracking.
        """
        cursor = self.state.get("journal_cursor", "")
        cursor_arg = f"--after-cursor='{cursor}'" if cursor else "-n 15"

        journal_cmd = f"journalctl {cursor_arg} -u ssh -u sudo -u systemd-logind -o json -n {max_entries} --no-pager"
        code, out, _ = self.ssh.execute_command(journal_cmd, timeout=10.0)
        if code != 0 or not out.strip():
            return []

        logs = []
        last_cursor = cursor
        for line in out.strip().splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue

            entry_cursor = rec.get("__CURSOR")
            if entry_cursor:
                last_cursor = entry_cursor

            # Extract fields
            msg = rec.get("MESSAGE", "")
            unit = rec.get("_SYSTEMD_UNIT", rec.get("SYSLOG_IDENTIFIER", "systemd"))
            service = unit.replace(".service", "")
            raw_ts = rec.get("__REALTIME_TIMESTAMP")
            if raw_ts:
                try:
                    ts = datetime.datetime.fromtimestamp(int(raw_ts) / 1_000_000.0).isoformat()
                except Exception:
                    ts = datetime.datetime.now().isoformat()
            else:
                ts = datetime.datetime.now().isoformat()

            parsed = self.parse_log_line(f"{ts} {self.source_host} {service}: {msg}", default_service=service)
            if parsed:
                logs.append(parsed)

        if last_cursor and last_cursor != cursor:
            self.state["journal_cursor"] = last_cursor
            self._save_state()

        return logs

    def submit_logs(self, log_entries: List[Dict[str, Any]], max_retries: int = 3) -> int:
        """
        Submit normalized system log entries to the SOC backend via POST /api/ingest/logs.
        Uses bounded retries with exponential backoff for transient network or 5xx errors.
        Never retries authentication (401) or unprocessable (422) failures.
        """
        if not log_entries:
            return 0

        headers = {
            "Content-Type": "application/json",
            "X-SOC-Sensor-Key": self.sensor_key,
        }
        payload = {"logs": log_entries}

        for attempt in range(1, max_retries + 1):
            try:
                with httpx.Client(timeout=8.0) as client:
                    resp = client.post(self.batch_ingest_url, json=payload, headers=headers)
                    if resp.status_code in (200, 201):
                        res_data = resp.json()
                        inserted = res_data.get("count_inserted", len(log_entries))
                        self.state["total_logs_submitted"] = self.state.get("total_logs_submitted", 0) + inserted
                        if log_entries:
                            self.state["last_log_summary"] = {
                                "timestamp": log_entries[-1].get("timestamp"),
                                "service": log_entries[-1].get("service"),
                                "log_type": log_entries[-1].get("log_type"),
                                "message": (log_entries[-1].get("message") or "")[:80],
                            }
                        self._save_state()
                        logger.info("Successfully submitted %d system logs to SOC backend", inserted)
                        return inserted
                    elif resp.status_code == 401:
                        logger.error("Authentication failed submitting system logs: HTTP 401 Unauthorized")
                        return 0
                    elif resp.status_code == 422:
                        logger.error("Schema validation failed submitting system logs: HTTP 422 Unprocessable: %s", resp.text[:200])
                        return 0
                    else:
                        logger.warning("SOC backend responded with HTTP %d (attempt %d/%d): %s",
                                       resp.status_code, attempt, max_retries, resp.text[:150])
            except Exception as exc:
                logger.warning("Network error on attempt %d/%d submitting system logs to %s: %s",
                               attempt, max_retries, self.batch_ingest_url, exc)

            if attempt < max_retries:
                time.sleep(0.5 * (2 ** (attempt - 1)))

        logger.error("Failed to submit system logs after %d attempts", max_retries)
        return 0

    def collect_and_submit(self) -> Tuple[int, int]:
        """
        Execute one poll cycle: collects both auth.log and journalctl, normalizes,
        and submits to the SOC backend. Returns (total_collected, total_submitted).
        """
        auth_logs = self.collect_auth_log_incremental(max_lines=50)
        journal_logs = self.collect_journalctl_incremental(max_entries=30)

        # Merge and deduplicate by raw_log/timestamp
        all_logs = auth_logs + journal_logs
        seen = set()
        deduped = []
        for l in all_logs:
            k = (l["timestamp"], l["service"], l["message"])
            if k not in seen:
                seen.add(k)
                deduped.append(l)

        collected_cnt = len(deduped)
        submitted_cnt = 0
        if collected_cnt > 0:
            submitted_cnt = self.submit_logs(deduped)
            self.state["total_logs_collected"] = self.state.get("total_logs_collected", 0) + collected_cnt
            self.state["last_collected_at"] = datetime.datetime.now().isoformat()
            self._save_state()

        return collected_cnt, submitted_cnt
