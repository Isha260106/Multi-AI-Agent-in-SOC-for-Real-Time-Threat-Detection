"""
query_incidents.py
==================
Command-line interface to search and retrieve correlated incidents from the soc.db.

Multi-Agent SOC Project -- Stage 7
"""

import argparse
import sys
import json
import pathlib

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from storage.query import IncidentQueryStore

# ---------------------------------------------------------------------------
# ANSI Colours
# ---------------------------------------------------------------------------
ANSI   = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
GREEN  = "\033[92m" if ANSI else ""
RED    = "\033[91m" if ANSI else ""
YELLOW = "\033[93m" if ANSI else ""
CYAN   = "\033[96m" if ANSI else ""
BOLD   = "\033[1m"  if ANSI else ""
DIM    = "\033[2m"  if ANSI else ""
RESET  = "\033[0m"  if ANSI else ""

DIV  = "=" * 78
DIV2 = "-" * 78


def print_incident(inc: dict, verbose: bool = False) -> None:
    """Pretty-print a single incident record."""
    status = inc.get("status", "UNKNOWN")
    sev    = inc.get("severity", "LOW")

    # Status colour mapping
    status_fmt = f"{RED}{status}{RESET}" if "THREAT" in status else f"{GREEN}{status}{RESET}"
    sev_fmt    = f"{RED}{sev}{RESET}"    if sev == "HIGH" else (
                 f"{YELLOW}{sev}{RESET}" if sev == "MEDIUM" else f"{GREEN}{sev}{RESET}")

    print(f"\n{BOLD}{CYAN}=== INCIDENT: {inc.get('incident_id')} ==={RESET}")
    print(f"  {BOLD}Event ID   :{RESET} {DIM}{inc.get('event_id')}{RESET}")
    print(f"  {BOLD}Timestamp  :{RESET} {inc.get('timestamp')}")
    print(f"  {BOLD}Prediction :{RESET} {inc.get('prediction')}")
    print(f"  {BOLD}Severity   :{RESET} {sev_fmt}")
    print(f"  {BOLD}Status     :{RESET} {status_fmt}")
    print(f"  {BOLD}Agents     :{RESET} {', '.join(inc.get('correlated_agents', []))}")
    print(f"  {BOLD}Alerts     :{RESET} {len(inc.get('alert_ids', []))}")
    print(f"  {BOLD}Reason     :{RESET} {inc.get('correlation_reason')}")

    if verbose:
        print(DIV2)
        print(f"  {BOLD}Alert IDs  :{RESET} {', '.join(inc.get('alert_ids', []))}")
        print(f"  {BOLD}Created At :{RESET} {inc.get('created_at')}")


def main():
    parser = argparse.ArgumentParser(description="Query Correlated Incidents in the SOC database.")

    # Mutual exclusion group for primary query types
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--recent", type=int, metavar="N",
                       help="Return the N most recent incidents")
    group.add_argument("--severity", type=str, choices=["HIGH", "MEDIUM", "LOW"],
                       help="Return incidents matching this severity")
    group.add_argument("--status", type=str, choices=["CORRELATED_NORMAL", "CORRELATED_THREAT"],
                       help="Return incidents matching this status")
    group.add_argument("--event-id", type=str,
                       help="Return incidents linked to this exact event UUID")
    group.add_argument("--agent", type=str,
                       help="Return incidents involving this agent (e.g. 'Anomaly Detection Agent')")
    group.add_argument("--summary", action="store_true",
                       help="Show summary statistics only (no individual records)")

    parser.add_argument("--verbose", action="store_true", default=False,
                        help="Include extensive metadata in output")

    args = parser.parse_args()

    # Need db existence check
    from storage.config import DB_PATH
    if not DB_PATH.exists():
        print(f"{RED}Database not found: {DB_PATH}{RESET}")
        print("Run the data ingestion or streaming demo first.")
        sys.exit(1)

    try:
        with IncidentQueryStore() as qs:
            print(f"\n{DIV}")
            
            if args.summary:
                stats = qs.summary_stats_incidents()
                print(f"  {BOLD}SOC INCIDENTS SUMMARY{RESET}")
                print(DIV2)
                print(f"  Total Incidents : {stats['total_incidents']}")
                print(f"  First Incident  : {stats['earliest_incident']}")
                print(f"  Last Incident   : {stats['latest_incident']}")
                
                print(f"\n  {BOLD}By Prediction:{RESET}")
                for p, c in stats['prediction_counts'].items():
                    print(f"    - {p:20}: {c}")
                    
                print(f"\n  {BOLD}By Severity:{RESET}")
                for s, c in stats['severity_counts'].items():
                    print(f"    - {s:20}: {c}")
                print(DIV)
                return

            # Route standard queries
            print(f"  {BOLD}INCIDENT QUERY RESULTS{RESET}")
            results = []
            
            if args.recent:
                results = qs.get_recent_incidents(args.recent)
            elif args.severity:
                results = qs.get_incidents_by_severity(args.severity)
            elif args.status:
                results = qs.get_incidents_by_status(args.status)
            elif args.event_id:
                results = qs.get_incidents_by_event_id(args.event_id)
            elif args.agent:
                results = qs.get_incidents_by_agent(args.agent)

            print(f"  {DIM}Matching records: {len(results)}{RESET}")
            print(DIV)
            
            for inc in results:
                print_incident(inc, getattr(args, "verbose", False))

            print(f"\n{DIV}")

    except Exception as e:
        print(f"\n{RED}Query failed: {str(e)}{RESET}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
