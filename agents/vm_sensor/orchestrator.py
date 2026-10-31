"""
agents/vm_sensor/orchestrator.py
================================
Live Telemetry Orchestrator & Dual-Source Coordinator.

Multi-Agent SOC Project -- Live Victim VM Telemetry Integration
"""

import argparse
import datetime
import json
import logging
import os
import pathlib
import signal
import sys
import time
from typing import Any, Dict, Optional

import httpx

from agents.vm_sensor.config import (
    LOG_DIR,
    SENSOR_RUNTIME_LOG,
    SOC_HEALTH_URL,
    SOC_MODELS_HEALTH_URL,
    SOC_VM_HOST,
    SOC_VM_POLL_INTERVAL,
    SOC_VM_TELEMETRY_MODE,
    SOC_VM_USER,
    STATE_FILE,
)
from agents.vm_sensor.flow_collector import VMFlowCollector
from agents.vm_sensor.log_collector import VMLogCollector
from agents.vm_sensor.ssh_client import RemoteSSHClient

logger = logging.getLogger("SOC.VMSensor.Orchestrator")
if not logger.handlers:
    _fh = logging.FileHandler(SENSOR_RUNTIME_LOG, encoding="utf-8")
    _fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s - %(message)s"))
    logger.addHandler(_fh)
    logger.setLevel(logging.INFO)

PID_FILE = LOG_DIR / "vm_sensor.pid"


class VMSensorOrchestrator:
    """
    Coordinates remote victim VM telemetry collection and mode switching.
    Supports dual-source operation:
      1. 'replay'   : Historical dataset replay
      2. 'vm_logs'  : Live Ubuntu system logs (SSH, auth, journalctl)
      3. 'vm_flows' : Live network flow records (78 features)
      4. 'vm_all'   : Both live system logs and network flows
    """

    def __init__(
        self,
        mode: str = SOC_VM_TELEMETRY_MODE,
        poll_interval: float = SOC_VM_POLL_INTERVAL,
    ):
        self.mode = mode.lower()
        self.poll_interval = poll_interval
        self._running = False
        self.ssh_client = RemoteSSHClient()
        self.log_collector = VMLogCollector(self.ssh_client)
        self.flow_collector = VMFlowCollector(self.ssh_client)
        self._last_poll_time: Optional[str] = None
        self._errors_count = 0
        self._last_error: Optional[str] = None

    def _acquire_pid_lock(self) -> bool:
        """Prevent spawning duplicate collector processes."""
        if PID_FILE.exists():
            try:
                with open(PID_FILE, "r") as f:
                    old_pid = int(f.read().strip())
                # Check if process is still alive on Windows
                import ctypes
                kernel32 = ctypes.windll.kernel32
                SYNCHRONIZE = 0x00100000
                process = kernel32.OpenProcess(SYNCHRONIZE, False, old_pid)
                if process != 0:
                    kernel32.CloseHandle(process)
                    logger.warning("Collector already running with PID %d. Refusing duplicate.", old_pid)
                    return False
            except Exception:
                pass

        PID_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(PID_FILE, "w") as f:
            f.write(str(os.getpid()))
        return True

    def _release_pid_lock(self) -> None:
        """Remove PID lock file on shutdown."""
        try:
            if PID_FILE.exists():
                os.remove(PID_FILE)
        except Exception:
            pass

    def check_soc_health(self) -> bool:
        """Verify the local SOC backend is online."""
        try:
            with httpx.Client(timeout=4.0) as client:
                res = client.get(SOC_HEALTH_URL)
                return res.status_code == 200
        except Exception:
            return False

    def verify_prerequisites(self) -> Dict[str, Any]:
        """
        Verify all system prerequisites before starting collection:
          1. Local SOC backend readiness
          2. Machine learning models readiness
          3. Remote SSH connection to victim VM
          4. Reverse SSH tunnel connectivity
        """
        soc_online = self.check_soc_health()
        models_ready = self.flow_collector.check_soc_models_health()
        ssh_ok, ssh_diag = self.ssh_client.test_connection()
        tunnel_ok = self.ssh_client.ensure_reverse_tunnel() if ssh_ok else False
        flow_status = self.flow_collector.check_remote_flow_extractor_status() if ssh_ok else {"ready": False}

        status = {
            "soc_backend_online": soc_online,
            "models_ready": models_ready,
            "ssh_connected": ssh_ok,
            "ssh_diagnostic": ssh_diag,
            "tunnel_healthy": tunnel_ok,
            "flow_extractor_status": flow_status,
            "telemetry_mode": self.mode,
            "ready_to_start": soc_online and (self.mode == "replay" or ssh_ok),
        }
        return status

    def poll_once(self) -> Dict[str, Any]:
        """
        Execute a single telemetry polling cycle based on the active mode.
        """
        self._last_poll_time = datetime.datetime.now().isoformat()
        cycle_result = {
            "timestamp": self._last_poll_time,
            "mode": self.mode,
            "logs_collected": 0,
            "logs_submitted": 0,
            "flows_collected": 0,
            "flows_submitted": 0,
            "error": None,
        }

        try:
            # 1. System Logs Collection
            if self.mode in ("vm_logs", "vm_all"):
                collected, submitted = self.log_collector.collect_and_submit()
                cycle_result["logs_collected"] = collected
                cycle_result["logs_submitted"] = submitted

            # 2. Network Flow Collection
            if self.mode in ("vm_flows", "vm_all"):
                flows = self.flow_collector.collect_new_flow_records(max_records=30)
                cycle_result["flows_collected"] = len(flows)
                if flows:
                    stats = self.flow_collector.submit_flows(flows)
                    cycle_result["flows_submitted"] = stats.get("accepted", 0)

            # 3. Simulated Replay Mode
            if self.mode == "replay":
                # In replay mode, telemetry is provided by the historical dataset generator
                cycle_result["replay_active"] = True

        except Exception as exc:
            self._errors_count += 1
            self._last_error = str(exc)
            cycle_result["error"] = str(exc)
            logger.error("Error during telemetry poll cycle: %s", exc)

        # Update orchestrator state file for API & dashboard visibility
        try:
            current_state = {}
            if STATE_FILE.exists():
                try:
                    with open(STATE_FILE, "r", encoding="utf-8") as f:
                        current_state = json.load(f)
                except Exception:
                    current_state = {}
            current_state.update({
                "mode": self.mode,
                "last_poll_time": self._last_poll_time,
                "errors_count": self._errors_count,
                "last_error": self._last_error,
                "last_poll_result": cycle_result,
                "is_running": True,
            })
            STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
            temp_file = STATE_FILE.with_suffix(".tmp")
            with open(temp_file, "w", encoding="utf-8") as f:
                json.dump(current_state, f, indent=2)
            temp_file.replace(STATE_FILE)
        except Exception as exc:
            logger.warning("Could not persist orchestrator state to %s: %s", STATE_FILE, exc)

        return cycle_result

    def run(self, max_cycles: Optional[int] = None) -> None:
        """
        Run continuous collection loop until interrupted or max_cycles reached.
        """
        if not self._acquire_pid_lock():
            print(f"[!] Another VM sensor collector is already running. Exiting.")
            return

        def _handle_exit(sig, frame):
            print("\n[+] Graceful shutdown signal received. Stopping collector...")
            self._running = False

        signal.signal(signal.SIGINT, _handle_exit)
        signal.signal(signal.SIGTERM, _handle_exit)

        print("=" * 70)
        print("  MULTI-AGENT AI SOC: LIVE VICTIM VM TELEMETRY COLLECTOR")
        print("=" * 70)
        print(f"  Target Victim : {SOC_VM_USER}@{SOC_VM_HOST} (Private IP: 10.0.0.12)")
        print(f"  Selected Mode : {self.mode.upper()}")
        print(f"  Poll Interval : {self.poll_interval}s")
        print("-" * 70)

        prereqs = self.verify_prerequisites()
        print(f"  SOC Backend   : {'ONLINE' if prereqs['soc_backend_online'] else 'OFFLINE (Start uvicorn dashboard_api:app)'}")
        print(f"  Models Ready  : {'YES' if prereqs['models_ready'] else 'DEGRADED'}")
        print(f"  SSH Host      : {'CONNECTED' if prereqs['ssh_connected'] else 'FAILED'}")
        print(f"  Reverse Tunnel: {'OPERATIONAL' if prereqs['tunnel_healthy'] else 'DEGRADED'}")
        print("=" * 70)

        if not prereqs["ready_to_start"]:
            print("[!] Prerequisites verification failed. Check logs/vm_sensor_runtime.log for details.")
            self._release_pid_lock()
            return

        self._running = True
        cycle = 0

        try:
            while self._running:
                cycle += 1
                res = self.poll_once()

                # Terminal telemetry feedback
                if self.mode in ("vm_logs", "vm_all") and res["logs_collected"] > 0:
                    print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Ingested {res['logs_submitted']} new Ubuntu system logs.")
                if self.mode in ("vm_flows", "vm_all") and res["flows_collected"] > 0:
                    print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Ingested {res['flows_submitted']} new network flow events.")

                if max_cycles and cycle >= max_cycles:
                    break

                time.sleep(self.poll_interval)
        finally:
            self._running = False
            self.ssh_client.close()
            self._release_pid_lock()
            try:
                if STATE_FILE.exists():
                    with open(STATE_FILE, "r", encoding="utf-8") as f:
                        curr = json.load(f)
                    curr["is_running"] = False
                    with open(STATE_FILE, "w", encoding="utf-8") as f:
                        json.dump(curr, f, indent=2)
            except Exception:
                pass
            print("[+] Collector shut down cleanly.")

    def get_status(self) -> Dict[str, Any]:
        """Return comprehensive live status for API and React dashboard integration."""
        state = self.log_collector.state
        return {
            "mode": self.mode,
            "victim_host": SOC_VM_HOST,
            "victim_user": SOC_VM_USER,
            "last_poll_time": self._last_poll_time,
            "total_logs_collected": state.get("total_logs_collected", 0),
            "total_logs_submitted": state.get("total_logs_submitted", 0),
            "total_flows_accepted": state.get("total_flows_accepted", 0),
            "total_flows_duplicated": state.get("total_flows_duplicated", 0),
            "total_flows_rejected": state.get("total_flows_rejected", 0),
            "last_log_summary": state.get("last_log_summary"),
            "errors_count": self._errors_count,
            "last_error": self._last_error,
        }
