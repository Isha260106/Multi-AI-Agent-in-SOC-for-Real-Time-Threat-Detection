"""
agents/vm_sensor/flow_collector.py
==================================
Network flow collector and schema normalizer for remote Ubuntu victim VM.

Multi-Agent SOC Project -- Live Victim VM Telemetry Integration
"""

import csv
import datetime
import io
import json
import logging
import os
import pathlib
import sys
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

import httpx

from agents.vm_sensor.config import (
    REMOTE_FLOW_CSV_PATH,
    SENSOR_RUNTIME_LOG,
    SOC_INGEST_URL,
    SOC_MODELS_HEALTH_URL,
    SOC_SENSOR_KEY,
    SOC_VM_HOST,
    STATE_FILE,
)
from agents.vm_sensor.ssh_client import RemoteSSHClient
from kafka.live_adapter import CANONICAL_FEATURES, LiveFlowAdapter

logger = logging.getLogger("SOC.VMSensor.Flows")
if not logger.handlers:
    _fh = logging.FileHandler(SENSOR_RUNTIME_LOG, encoding="utf-8")
    _fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s - %(message)s"))
    logger.addHandler(_fh)
    logger.setLevel(logging.INFO)


class VMFlowCollector:
    """
    Manages collection, canonical 78-feature normalization, and API submission
    of live network flows from the remote victim VM.
    
    GUARANTEES:
      - Strictly validates all 78 numeric flow features.
      - NEVER fabricates missing statistical metrics or replaces missing features with arbitrary zeros.
      - Enforces microsecond duration and IAT units.
      - Rejects incomplete or incompatible sensor schemas.
      - Submits valid flows to POST /api/ingest/flow with X-SOC-Sensor-Key.
    """

    def __init__(
        self,
        ssh_client: RemoteSSHClient,
        remote_csv_path: str = REMOTE_FLOW_CSV_PATH,
        ingest_url: str = SOC_INGEST_URL,
        sensor_key: str = SOC_SENSOR_KEY,
        state_file: pathlib.Path = STATE_FILE,
    ):
        self.ssh = ssh_client
        self.remote_csv_path = remote_csv_path
        self.ingest_url = ingest_url
        self.sensor_key = sensor_key
        self.state_file = pathlib.Path(state_file)
        self.adapter = LiveFlowAdapter()
        self.state = self._load_state()

    def _load_state(self) -> Dict[str, Any]:
        """Load persistent offset and count tracking state."""
        if self.state_file.exists():
            try:
                with open(self.state_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def _update_state(self, key: str, val: Any) -> None:
        """Update and save state dictionary."""
        self.state[key] = val
        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.state_file, "w", encoding="utf-8") as f:
                json.dump(self.state, f, indent=2)
        except Exception as exc:
            logger.error("Failed to update state file: %s", exc)

    def check_remote_flow_extractor_status(self) -> Dict[str, Any]:
        """
        Probe the victim VM for flow collection prerequisites (CICFlowMeter, CSV output, tcpdump).
        Reports exact capabilities and limitations without guessing.
        """
        probe_cmd = (
            "echo TCPDUMP:$(which tcpdump 2>/dev/null || echo NONE); "
            "echo CICFLOWMETER:$(which cicflowmeter 2>/dev/null || echo NONE); "
            f"echo CSV_FILE:$([ -f {self.remote_csv_path} ] && echo PRESENT || echo MISSING); "
            f"echo CSV_SIZE:$(stat -c %s {self.remote_csv_path} 2>/dev/null || echo 0)"
        )
        code, out, _ = self.ssh.execute_command(probe_cmd, timeout=8.0)
        
        status_info = {
            "tcpdump_installed": False,
            "cicflowmeter_installed": False,
            "csv_present": False,
            "csv_size_bytes": 0,
            "limitation": None,
            "ready": False,
        }

        if code == 0:
            for line in out.strip().splitlines():
                line = line.strip()
                if line.startswith("TCPDUMP:") and "NONE" not in line:
                    status_info["tcpdump_installed"] = True
                elif line.startswith("CICFLOWMETER:") and "NONE" not in line:
                    status_info["cicflowmeter_installed"] = True
                elif line.startswith("CSV_FILE:") and "PRESENT" in line:
                    status_info["csv_present"] = True
                elif line.startswith("CSV_SIZE:"):
                    try:
                        status_info["csv_size_bytes"] = int(line.replace("CSV_SIZE:", "").strip())
                    except ValueError:
                        pass


        if not status_info["csv_present"]:
            status_info["limitation"] = (
                f"Remote flow CSV ({self.remote_csv_path}) not currently present on victim VM. "
                "Packet capture alone (via tcpdump) captures raw PCAP frames; statistical flow metric extraction "
                "(such as 78-feature CICFlowMeter) must process packets into completed bidirectional flow records "
                "before legitimate model ingestion."
            )
        else:
            status_info["ready"] = True

        return status_info

    def check_soc_models_health(self) -> bool:
        """Verify the local SOC backend Random Forest and Isolation Forest models are loaded."""
        try:
            with httpx.Client(timeout=4.0) as client:
                res = client.get(SOC_MODELS_HEALTH_URL)
                if res.status_code == 200:
                    data = res.json()
                    return data.get("status") == "ok"
        except Exception:
            pass
        return False

    def collect_new_flow_records(self, max_records: int = 50) -> List[Dict[str, Any]]:
        """
        Incrementally read new flow CSV records from the remote victim VM over SSH.
        Normalizes extracted rows into the canonical 78-feature schema without fabricating metrics.
        """
        extractor_status = self.check_remote_flow_extractor_status()
        if not extractor_status["ready"]:
            logger.debug("Remote flow capture is not ready: %s", extractor_status.get("limitation"))
            return []

        # Read CSV incrementally using byte offsets
        prev_offset = int(self.state.get("flow_csv_offset", 0))
        read_cmd = f"tail -c +{prev_offset + 1} {self.remote_csv_path} | head -n {max_records + 1}"
        code, chunk, _ = self.ssh.execute_command(read_cmd, timeout=12.0)
        if code != 0 or not chunk.strip():
            return []

        # Find last newline
        last_nl = chunk.rfind("\n")
        if last_nl == -1:
            return []

        valid_chunk = chunk[: last_nl + 1]
        bytes_consumed = len(valid_chunk.encode("utf-8"))

        # Parse CSV
        reader = csv.DictReader(io.StringIO(valid_chunk))
        flows = []
        for raw_row in reader:
            try:
                # Use LiveFlowAdapter for strict schema alignment, metadata isolation, and unit scaling
                payload = self.adapter.normalize_dict(raw_row)
                flows.append(payload)
            except Exception as exc:
                logger.warning("Rejected incompatible or malformed sensor flow record: %s", exc)

        new_offset = prev_offset + bytes_consumed
        self._update_state("flow_csv_offset", new_offset)
        return flows

    def submit_flow(self, flow_payload: Dict[str, Any], max_retries: int = 3) -> Tuple[int, Dict[str, Any]]:
        """
        Submit a single canonical 78-feature flow record to POST /api/ingest/flow.
        Uses bounded retries with exponential backoff for transient network or 5xx server errors.
        Does not retry 401 (auth), 409 (duplicate conflict), or 422 (validation error).
        Returns (http_status_code, response_data).
        """
        headers = {
            "Content-Type": "application/json",
            "X-SOC-Sensor-Key": self.sensor_key,
        }
        data = {}
        for attempt in range(1, max_retries + 1):
            try:
                with httpx.Client(timeout=15.0) as client:
                    res = client.post(self.ingest_url, json=flow_payload, headers=headers)
                    try:
                        data = res.json()
                    except Exception:
                        data = {"text": res.text}

                    # Do not retry definitive outcomes
                    if res.status_code in (201, 401, 409, 413, 422):
                        return res.status_code, data

                    logger.warning("SOC flow ingest returned HTTP %d (attempt %d/%d)", res.status_code, attempt, max_retries)
            except Exception as exc:
                logger.warning("Network error on attempt %d/%d submitting flow to %s: %s",
                               attempt, max_retries, self.ingest_url, exc)
                data = {"error": str(exc)}

            if attempt < max_retries:
                time.sleep(0.5 * (2 ** (attempt - 1)))

        return 500, data

    def submit_flows(self, flow_payloads: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Submit a batch of normalized flow records with duplicate and error accounting.
        """
        stats = {"accepted": 0, "duplicated": 0, "rejected": 0, "failed": 0}
        for flow in flow_payloads:
            code, resp = self.submit_flow(flow)
            if code == 201:
                stats["accepted"] += 1
            elif code == 409:
                stats["duplicated"] += 1
            elif code in (422, 400):
                stats["rejected"] += 1
            else:
                stats["failed"] += 1

        total_accepted = self.state.get("total_flows_accepted", 0) + stats["accepted"]
        total_duplicated = self.state.get("total_flows_duplicated", 0) + stats["duplicated"]
        total_rejected = self.state.get("total_flows_rejected", 0) + stats["rejected"]

        self._update_state("total_flows_accepted", total_accepted)
        self._update_state("total_flows_duplicated", total_duplicated)
        self._update_state("total_flows_rejected", total_rejected)
        self._update_state("last_flow_time", datetime.datetime.now().isoformat())

        return stats
