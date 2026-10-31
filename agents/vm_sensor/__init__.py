"""
agents/vm_sensor
================
Remote Ubuntu Victim VM Telemetry Collector Package.

Multi-Agent SOC Project -- Live Victim VM Telemetry Integration
"""

from agents.vm_sensor.config import (
    SOC_VM_HOST,
    SOC_VM_POLL_INTERVAL,
    SOC_VM_SSH_KEY,
    SOC_VM_TELEMETRY_MODE,
    SOC_VM_USER,
)
from agents.vm_sensor.flow_collector import VMFlowCollector
from agents.vm_sensor.log_collector import VMLogCollector
from agents.vm_sensor.orchestrator import VMSensorOrchestrator
from agents.vm_sensor.ssh_client import RemoteSSHClient

__all__ = [
    "VMSensorOrchestrator",
    "RemoteSSHClient",
    "VMLogCollector",
    "VMFlowCollector",
    "SOC_VM_HOST",
    "SOC_VM_USER",
    "SOC_VM_SSH_KEY",
    "SOC_VM_TELEMETRY_MODE",
    "SOC_VM_POLL_INTERVAL",
]
