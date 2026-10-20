"""
query_investigations.py
=======================
Command-line interface to coordinate, inspect, and query Multi-Agent Threat Investigations.

Multi-Agent SOC Project -- Stage 10: Multi-Agent Threat Investigation
"""

import argparse
import json
import pathlib
import sys

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from storage.config import DB_PATH
from storage.db import AlertStore
from storage.query import (
    ThreatInvestigationQueryStore,
    AlertQueryStore,
    ThreatAssessmentQueryStore,
    IncidentQueryStore,
)
from agents.threat_investigation.coordinator import ThreatInvestigationCoordinator
from agents.threat_investigation.config import ALL_INVESTIGATION_STATUSES

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


def format_status(status: str) -> str:
    if "TIER2" in status:
        return f"{YELLOW}{BOLD}{status}{RESET}"
    elif "COMPLETED" in status:
        return f"{RED}{BOLD}{status}{RESET}"
    elif "BENIGN" in status:
        return f"{GREEN}{status}{RESET}"
    return f"{CYAN}{status}{RESET}"


def format_category(cat: str) -> str:
    if cat == "Confirmed Attack":
        return f"{RED}{BOLD}{cat}{RESET}"
    elif cat == "Suspected Attack":
        return f"{RED}{cat}{RESET}"
    elif cat == "Suspicious Anomaly":
        return f"{YELLOW}{cat}{RESET}"
    elif cat == "Benign":
        return f"{GREEN}{cat}{RESET}"
    return f"{DIM}{cat}{RESET}"


def format_severity(sev: str) -> str:
    if sev == "HIGH":
        return f"{RED}{BOLD}{sev}{RESET}"
    elif sev == "MEDIUM":
        return f"{YELLOW}{sev}{RESET}"
    elif sev == "LOW":
        return f"{GREEN}{sev}{RESET}"
    return f"{DIM}{sev}{RESET}"


def print_investigation_report(inv: dict, verbose: bool = False) -> None:
    """Pretty-print an investigation report."""
    inv_id = inv.get("investigation_id", "N/A")
    event_id = inv.get("event_id", "N/A")
    cat = inv.get("threat_category", "Unknown")
    sev = inv.get("severity", "INFORMATIONAL")
    status = inv.get("investigation_status", "OPEN")

    print(f"\n{BOLD}{CYAN}=== THREAT INVESTIGATION: {inv_id} ==={RESET}")
    print(f"  {BOLD}Event ID    :{RESET} {DIM}{event_id}{RESET}")
    print(f"  {BOLD}Timestamp   :{RESET} {inv.get('timestamp')}")
    print(f"  {BOLD}Status      :{RESET} {format_status(status)}")
    print(f"  {BOLD}Threat Post :{RESET} {format_category(cat)} | Severity: {format_severity(sev)}")
    print(f"  {BOLD}Summary     :{RESET} {inv.get('summary')}")

    # Findings by Agent
    findings = inv.get("findings_by_agent", {})
    if findings:
        print(f"\n  {BOLD}FINDINGS BY AGENT:{RESET}")
        for agent_mod, f_list in findings.items():
            mod_title = agent_mod.replace("_", " ").title()
            print(f"    - {CYAN}{mod_title}{RESET}:")
            if isinstance(f_list, list):
                for f in f_list:
                    print(f"        * {f}")

    # Supporting Evidence
    evidence = inv.get("supporting_evidence", {})
    if evidence and verbose:
        print(f"\n  {BOLD}SUPPORTING EVIDENCE (FACTS):{RESET}")
        for ev_key, facts in evidence.items():
            if isinstance(facts, dict) and facts:
                print(f"    - {DIM}{ev_key}{RESET}: {json.dumps(facts, ensure_ascii=False)}")

    # Conflicting Signals
    conflicts = inv.get("conflicting_signals", [])
    if conflicts:
        print(f"\n  {BOLD}{YELLOW}CONFLICTING SIGNALS DETECTED:{RESET}")
        for c in conflicts:
            print(f"    * {YELLOW}{c}{RESET}")

    # Recommended Next Steps
    steps = inv.get("recommended_next_steps", [])
    if steps:
        print(f"\n  {BOLD}{GREEN}RECOMMENDED NEXT STEPS (TIER-2 ACTION):{RESET}")
        for idx, step in enumerate(steps, 1):
            print(f"    {idx}. {step}")

    # Limitations
    limitations = inv.get("limitations", [])
    if limitations and verbose:
        print(f"\n  {BOLD}{DIM}INVESTIGATION LIMITATIONS:{RESET}")
        for lim in limitations:
            print(f"    * {DIM}{lim}{RESET}")

    if verbose:
        print(DIV2)
        print(f"  {BOLD}Created At  :{RESET} {inv.get('created_at')}")


def investigate_event(event_id: str, force: bool = False) -> None:
    """Coordinate an investigation for a specific event UUID using existing database evidence."""
    if not DB_PATH.exists():
        print(f"{RED}Database not found: {DB_PATH}{RESET}")
        sys.exit(1)

    with AlertStore() as store, AlertQueryStore() as aqs, ThreatAssessmentQueryStore() as tqs:
        # Check existing investigation report
        with ThreatInvestigationQueryStore() as iqs:
            existing_inv = iqs.get_investigation_by_event_id(event_id)
            if existing_inv and not force:
                print(f"{YELLOW}Investigation already exists for event {event_id}. Use --force to re-investigate.{RESET}")
                print_investigation_report(existing_inv, verbose=True)
                return

        # Fetch evidence
        row_ev = store._conn.execute("SELECT * FROM events WHERE event_id = ?", (event_id,)).fetchone()
        if not row_ev:
            print(f"{RED}Event {event_id} not found in soc.db events table.{RESET}")
            sys.exit(1)

        event_dict = dict(row_ev)
        if event_dict.get("features_json"):
            try:
                event_dict["features"] = json.loads(event_dict["features_json"])
            except Exception:
                event_dict["features"] = {}

        # Fetch alerts
        alerts = aqs.get_alert_by_event_id(event_id)
        net_alert = next((a for a in alerts if "Network" in a.get("agent", "")), None)
        anom_alert = next((a for a in alerts if "Anomaly" in a.get("agent", "")), None)

        # Fetch incident
        inc_row = store._conn.execute("SELECT * FROM incidents WHERE event_id = ?", (event_id,)).fetchone()
        incident = dict(inc_row) if inc_row else None

        # Fetch assessment
        ta_list = tqs.get_assessments_by_event_id(event_id)
        assessment = ta_list[0] if ta_list else None

        coord = ThreatInvestigationCoordinator(log_to_file=True)
        report = coord.investigate(
            event_id=event_id,
            event=event_dict,
            network_alert=net_alert,
            anomaly_alert=anom_alert,
            incident=incident,
            threat_assessment=assessment,
            force=force,
        )

        if not report:
            print(f"{YELLOW}Event {event_id} does not meet investigation criteria (Benign / Low Severity). Use --force to override.{RESET}")
            return

        store.save_investigation(report)
        print(f"{GREEN}Investigation completed and persisted to soc.db.{RESET}")
        print_investigation_report(report, verbose=True)


def main():
    parser = argparse.ArgumentParser(
        description="Query and Coordinate Multi-Agent Threat Investigations in the SOC database (Stage 10)."
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--investigate", type=str, metavar="EVENT_ID",
        help="Run multi-agent investigation on a specific event UUID"
    )
    group.add_argument(
        "--recent", type=int, metavar="N",
        help="Return the N most recent investigation reports"
    )
    group.add_argument(
        "--id", type=str, dest="investigation_id",
        help="Retrieve an investigation report by its UUID"
    )
    group.add_argument(
        "--event-id", type=str,
        help="Retrieve an investigation report linked to this exact event UUID"
    )
    group.add_argument(
        "--status", type=str, choices=ALL_INVESTIGATION_STATUSES,
        help="Filter investigations by status ('COMPLETED', 'REQUIRES_TIER2', 'CLOSED_BENIGN')"
    )
    group.add_argument(
        "--category", type=str,
        help="Filter investigations by threat category ('Confirmed Attack', 'Suspicious Anomaly')"
    )
    group.add_argument(
        "--summary", action="store_true",
        help="Show summary statistics across all threat investigations"
    )

    parser.add_argument(
        "--force", action="store_true", default=False,
        help="Force investigation even for benign flows, or re-run existing investigation"
    )
    parser.add_argument(
        "--verbose", action="store_true", default=False,
        help="Include full evidence facts and limitations in output"
    )

    args = parser.parse_args()

    if not DB_PATH.exists():
        print(f"{RED}Database not found: {DB_PATH}{RESET}")
        sys.exit(1)

    if args.investigate:
        investigate_event(args.investigate, force=args.force)
        return

    try:
        with ThreatInvestigationQueryStore() as qs:
            print(f"\n{DIV}")

            if args.summary:
                stats = qs.summary_stats_investigations()
                print(f"  {BOLD}SOC THREAT INVESTIGATIONS SUMMARY (Stage 10){RESET}")
                print(DIV2)
                print(f"  Total Investigations : {stats['total_investigations']}")
                print(f"  Earliest Record      : {stats['earliest_investigation'] or 'None'}")
                print(f"  Latest Record        : {stats['latest_investigation'] or 'None'}")
                print("\n  By Status:")
                if stats["status_counts"]:
                    for stat, count in stats["status_counts"].items():
                        print(f"    - {format_status(stat)}: {count}")
                else:
                    print(f"    {DIM}(None recorded){RESET}")

                print("\n  By Threat Category:")
                if stats["category_counts"]:
                    for cat, count in stats["category_counts"].items():
                        print(f"    - {format_category(cat)}: {count}")
                else:
                    print(f"    {DIM}(None recorded){RESET}")
                print(DIV)
                return

            records = []
            if args.recent is not None:
                records = qs.get_recent_investigations(args.recent)
                print(f"  {BOLD}Recent Threat Investigations (Limit: {args.recent}){RESET}")
            elif args.investigation_id:
                rec = qs.get_investigation_by_id(args.investigation_id)
                records = [rec] if rec else []
                print(f"  {BOLD}Threat Investigation: {args.investigation_id}{RESET}")
            elif args.event_id:
                rec = qs.get_investigation_by_event_id(args.event_id)
                records = [rec] if rec else []
                print(f"  {BOLD}Threat Investigation for Event: {args.event_id}{RESET}")
            elif args.status:
                records = qs.get_investigations_by_status(args.status)
                print(f"  {BOLD}Threat Investigations by Status: {args.status}{RESET}")
            elif args.category:
                records = qs.get_investigations_by_category(args.category)
                print(f"  {BOLD}Threat Investigations by Category: {args.category}{RESET}")

            print(DIV2)
            if not records:
                print(f"  {DIM}No investigation reports found matching the criteria.{RESET}")
            else:
                for r in records:
                    print_investigation_report(r, verbose=args.verbose)
                print(f"\n  Found {len(records)} matching investigation report(s).")
            print(DIV)

    except Exception as exc:
        print(f"{RED}[ERROR] Query failed: {exc}{RESET}")
        sys.exit(1)


if __name__ == "__main__":
    main()
