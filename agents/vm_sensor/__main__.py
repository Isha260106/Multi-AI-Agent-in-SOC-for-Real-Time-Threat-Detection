"""
agents/vm_sensor/__main__.py
============================
CLI Entrypoint for Remote Victim VM Telemetry Collector.

Usage:
    python -m agents.vm_sensor --mode vm_logs
    python -m agents.vm_sensor --mode vm_flows
    python -m agents.vm_sensor --mode vm_all
    python -m agents.vm_sensor --mode replay
    python -m agents.vm_sensor --check-only
"""

import argparse
import os
import sys

from agents.vm_sensor.config import SOC_VM_POLL_INTERVAL, SOC_VM_TELEMETRY_MODE
from agents.vm_sensor.orchestrator import VMSensorOrchestrator


def main():
    parser = argparse.ArgumentParser(
        description="Multi-Agent SOC: Remote Ubuntu Victim VM Telemetry Collector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--mode",
        choices=["replay", "vm_logs", "vm_flows", "vm_all"],
        default=SOC_VM_TELEMETRY_MODE,
        help="Telemetry collection mode (default: from env or vm_all)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=SOC_VM_POLL_INTERVAL,
        help=f"Polling interval in seconds (default: {SOC_VM_POLL_INTERVAL})",
    )
    parser.add_argument(
        "--max-cycles",
        type=int,
        default=None,
        help="Optional maximum polling cycles to execute before exiting (useful for testing)",
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Verify SSH connectivity, reverse tunnel, and local SOC health, then exit",
    )

    args = parser.parse_args()

    orchestrator = VMSensorOrchestrator(mode=args.mode, poll_interval=args.interval)

    if args.check_only:
        print("=" * 70)
        print("  VERIFYING REMOTE VICTIM VM TELEMETRY PREREQUISITES")
        print("=" * 70)
        prereqs = orchestrator.verify_prerequisites()
        for k, v in prereqs.items():
            print(f"  {k:25}: {v}")
        print("=" * 70)
        sys.exit(0 if prereqs["ready_to_start"] else 1)

    orchestrator.run(max_cycles=args.max_cycles)


if __name__ == "__main__":
    main()
