"""
agents/vm_sensor/ssh_client.py
==============================
Secure OpenSSH client wrapper for remote Ubuntu victim VM communication.

Multi-Agent SOC Project -- Live Victim VM Telemetry Integration
"""

import logging
import os
import pathlib
import subprocess
import time
from typing import Optional, Tuple

from agents.vm_sensor.config import (
    KNOWN_HOSTS_FILE,
    SENSOR_RUNTIME_LOG,
    SOC_LOCAL_BACKEND_PORT,
    SOC_REMOTE_TUNNEL_PORT,
    SOC_STRICT_HOST_KEY_CHECKING,
    SOC_VM_CONNECT_TIMEOUT,
    SOC_VM_HOST,
    SOC_VM_PORT,
    SOC_VM_SSH_KEY,
    SOC_VM_USER,
)

logger = logging.getLogger("SOC.VMSensor.SSH")
if not logger.handlers:
    _fh = logging.FileHandler(SENSOR_RUNTIME_LOG, encoding="utf-8")
    _fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s - %(message)s"))
    logger.addHandler(_fh)
    logger.setLevel(logging.INFO)


class RemoteSSHClient:
    """
    Manages secure remote execution, log extraction, and reverse tunneling
    to the authorized remote Ubuntu victim VM via standard OpenSSH.
    """

    def __init__(
        self,
        host: str = SOC_VM_HOST,
        user: str = SOC_VM_USER,
        key_path: str = SOC_VM_SSH_KEY,
        port: int = SOC_VM_PORT,
        connect_timeout: float = SOC_VM_CONNECT_TIMEOUT,
        known_hosts_file: str = KNOWN_HOSTS_FILE,
        strict_host_key_checking: str = SOC_STRICT_HOST_KEY_CHECKING,
    ):
        self.host = host
        self.user = user
        self.key_path = str(pathlib.Path(key_path).expanduser().resolve())
        self.port = port
        self.connect_timeout = connect_timeout
        self.known_hosts_file = str(pathlib.Path(known_hosts_file).expanduser().resolve())
        self.strict_host_key_checking = strict_host_key_checking
        self._tunnel_process: Optional[subprocess.Popen] = None

    def is_host_in_known_hosts(self) -> bool:
        """Check if the target host IP or name exists in the trusted known_hosts file."""
        if not os.path.exists(self.known_hosts_file):
            return False
        try:
            with open(self.known_hosts_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        hosts_part = line.split()[0] if line.split() else ""
                        if self.host in hosts_part:
                            return True
        except Exception as exc:
            logger.warning("Error reading known_hosts file: %s", exc)
        return False

    def _build_base_ssh_args(self) -> list[str]:
        """Construct standard security-hardened OpenSSH CLI arguments."""
        args = [
            "ssh",
            "-i", self.key_path,
            "-p", str(self.port),
            "-o", "BatchMode=yes",
            "-o", f"ConnectTimeout={int(self.connect_timeout)}",
            "-o", "ServerAliveInterval=15",
            "-o", "ServerAliveCountMax=3",
        ]
        if os.path.exists(self.known_hosts_file):
            args.extend(["-o", f"UserKnownHostsFile={self.known_hosts_file}"])
        # In production, strict verification requires the host key to be in known_hosts
        args.extend(["-o", f"StrictHostKeyChecking={self.strict_host_key_checking}"])
        return args

    def test_connection(self) -> Tuple[bool, str]:
        """
        Verify SSH connectivity and host identity against the remote victim.
        Returns (success: bool, diagnostic_message: str).
        """
        if not os.path.isfile(self.key_path):
            msg = f"SSH private key file not found: {self.key_path}"
            logger.error(msg)
            return False, msg

        cmd = self._build_base_ssh_args() + [
            f"{self.user}@{self.host}",
            "uname -s -r; whoami; hostname -I",
        ]

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.connect_timeout + 5,
            )
            if res.returncode == 0:
                output = res.stdout.strip().replace("\n", " | ")
                logger.info("SSH connection verified to %s@%s: %s", self.user, self.host, output)
                return True, f"Connected: {output}"
            else:
                err_clean = res.stderr.strip() or f"exit code {res.returncode}"
                logger.warning("SSH connection failed to %s@%s: %s", self.user, self.host, err_clean)
                return False, f"Connection failed: {err_clean}"
        except subprocess.TimeoutExpired:
            msg = f"SSH connection timed out after {self.connect_timeout}s connecting to {self.host}"
            logger.warning(msg)
            return False, msg
        except Exception as exc:
            msg = f"SSH execution error: {exc}"
            logger.error(msg)
            return False, msg

    def execute_command(self, remote_command: str, timeout: float = 15.0) -> Tuple[int, str, str]:
        """
        Execute a command on the remote victim VM and return (exit_code, stdout, stderr).
        """
        cmd = self._build_base_ssh_args() + [
            f"{self.user}@{self.host}",
            remote_command,
        ]

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return res.returncode, res.stdout, res.stderr
        except subprocess.TimeoutExpired:
            logger.warning("Remote command timed out after %ss: %s", timeout, remote_command[:60])
            return -1, "", f"Command timed out after {timeout} seconds"
        except Exception as exc:
            logger.error("Failed to execute remote command: %s", exc)
            return -1, "", str(exc)

    def test_reverse_tunnel(self, remote_port: int = SOC_REMOTE_TUNNEL_PORT) -> bool:
        """
        Test if the victim VM can reach the Windows SOC backend through the reverse tunnel.
        """
        test_cmd = f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 4 http://127.0.0.1:{remote_port}/api/health"
        code, stdout, _ = self.execute_command(test_cmd, timeout=8.0)
        return code == 0 and stdout.strip() == "200"

    def ensure_reverse_tunnel(
        self,
        remote_port: int = SOC_REMOTE_TUNNEL_PORT,
        local_port: int = SOC_LOCAL_BACKEND_PORT,
    ) -> bool:
        """
        Ensure that the reverse SSH tunnel (remote:18000 -> local:8000) is operational.
        Recovers gracefully if the tunnel has broken or the remote port is hung.
        """
        if self.test_reverse_tunnel(remote_port):
            return True

        logger.info("Reverse tunnel test failed. Attempting recovery for port %d -> %d...", remote_port, local_port)

        # 1. Kill stale listeners on the victim side
        self.execute_command(f"sudo fuser -k {remote_port}/tcp 2>/dev/null || true", timeout=6.0)
        time.sleep(1.0)

        # 2. Terminate previous local tunnel process if owned by us
        if self._tunnel_process and self._tunnel_process.poll() is None:
            try:
                self._tunnel_process.terminate()
                self._tunnel_process.wait(timeout=3)
            except Exception:
                pass

        # 3. Launch fresh reverse tunnel in the background
        tunnel_cmd = self._build_base_ssh_args() + [
            "-N",
            "-R", f"127.0.0.1:{remote_port}:127.0.0.1:{local_port}",
            "-o", "ExitOnForwardFailure=yes",
            f"{self.user}@{self.host}",
        ]

        try:
            self._tunnel_process = subprocess.Popen(
                tunnel_cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
            time.sleep(2.5)

            if self._tunnel_process.poll() is not None:
                _, err = self._tunnel_process.communicate()
                logger.error("Failed to establish reverse tunnel: %s", err.strip())
                return False

            if self.test_reverse_tunnel(remote_port):
                logger.info("Reverse tunnel successfully re-established on port %d -> %d", remote_port, local_port)
                return True
            else:
                logger.warning("Tunnel process running but health check did not return 200 on port %d", remote_port)
                return False
        except Exception as exc:
            logger.error("Error creating reverse tunnel: %s", exc)
            return False

    def close(self) -> None:
        """Clean up background tunnel process if managed."""
        if self._tunnel_process and self._tunnel_process.poll() is None:
            try:
                self._tunnel_process.terminate()
                self._tunnel_process.wait(timeout=3)
            except Exception:
                pass
            self._tunnel_process = None
