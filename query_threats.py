"""
query_threats.py
================
Command-line interface to search and retrieve Unified Threat Assessments from soc.db.

Multi-Agent SOC Project -- Stage 9A: Unified Threat Assessment Engine
"""

import argparse
import json
import pathlib
import sys

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from storage.config import DB_PATH
from storage.query import ThreatAssessmentQueryStore
from agents.threat_assessment.config import ALL_CATEGORIES, ALL_SEVERITIES

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


def print_assessment(asm: dict, verbose: bool = False) -> None:
    """Pretty-print a single threat assessment record."""
    cat = asm.get("category", "Unknown")
    sev = asm.get("severity", "INFORMATIONAL")
    aid = asm.get("assessment_id", "N/A")
    eid = asm.get("event_id", "N/A")

    net_pred = asm.get("network_prediction") or "N/A"
    anom_pred = asm.get("anomaly_prediction") or "N/A"

    net_conf = asm.get("network_confidence")
    anom_score = asm.get("anomaly_score")

    conf_str = f"{net_conf:.2%}" if net_conf is not None else "N/A"
    anom_str = f"{anom_score:.4f}" if anom_score is not None else "N/A"

    print(f"\n{BOLD}{CYAN}=== THREAT ASSESSMENT: {aid} ==={RESET}")
    print(f"  {BOLD}Event ID    :{RESET} {DIM}{eid}{RESET}")
    print(f"  {BOLD}Timestamp   :{RESET} {asm.get('timestamp')}")
    print(f"  {BOLD}Category    :{RESET} {format_category(cat)}")
    print(f"  {BOLD}Severity    :{RESET} {format_severity(sev)}")
    print(f"  {BOLD}Network Det :{RESET} {net_pred} (confidence: {conf_str})")
    print(f"  {BOLD}Anomaly Det :{RESET} {anom_pred} (anomaly_score: {anom_str})")
    print(f"  {BOLD}Explanation :{RESET} {asm.get('explanation')}")

    if asm.get("actual_label"):
        print(f"  {BOLD}Actual Label:{RESET} {asm.get('actual_label')}")

    if verbose:
        print(DIV2)
        print(f"  {BOLD}Created At  :{RESET} {asm.get('created_at')}")


def main():
    parser = argparse.ArgumentParser(
        description="Query Unified Threat Assessments in the SOC database (Stage 9A)."
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--recent", type=int, metavar="N",
        help="Return the N most recent threat assessments"
    )
    group.add_argument(
        "--category", type=str,
        help="Filter assessments by category (e.g. 'Confirmed Attack', 'Suspicious Anomaly')"
    )
    group.add_argument(
        "--severity", type=str, choices=ALL_SEVERITIES,
        help="Filter assessments by severity ('HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL')"
    )
    group.add_argument(
        "--event-id", type=str,
        help="Search threat assessments linked to this exact event UUID"
    )
    group.add_argument(
        "--id", type=str, dest="assessment_id",
        help="Search single threat assessment by its assessment UUID"
    )
    group.add_argument(
        "--summary", action="store_true",
        help="Show summary statistics across all threat assessments"
    )

    parser.add_argument(
        "--verbose", action="store_true", default=False,
        help="Include full audit metadata"
    )

    args = parser.parse_args()

    if not DB_PATH.exists():
        print(f"{RED}Database not found: {DB_PATH}{RESET}")
        print("Run the data ingestion or streaming demo first.")
        sys.exit(1)

    try:
        with ThreatAssessmentQueryStore() as qs:
            print(f"\n{DIV}")

            if args.summary:
                stats = qs.summary_stats_assessments()
                print(f"  {BOLD}SOC THREAT ASSESSMENTS SUMMARY (Stage 9A){RESET}")
                print(DIV2)
                print(f"  Total Assessments : {stats['total_assessments']}")
                print(f"  Earliest Record   : {stats['earliest_assessment'] or 'None'}")
                print(f"  Latest Record     : {stats['latest_assessment'] or 'None'}")
                print("\n  By Category:")
                if stats["category_counts"]:
                    for cat, count in stats["category_counts"].items():
                        print(f"    - {format_category(cat)}: {count}")
                else:
                    print(f"    {DIM}(None recorded){RESET}")

                print("\n  By Severity:")
                if stats["severity_counts"]:
                    for sev, count in stats["severity_counts"].items():
                        print(f"    - {format_severity(sev)}: {count}")
                else:
                    print(f"    {DIM}(None recorded){RESET}")
                print(DIV)
                return

            records = []
            if args.recent is not None:
                records = qs.get_recent_assessments(args.recent)
                print(f"  {BOLD}Recent Threat Assessments (Limit: {args.recent}){RESET}")
            elif args.category:
                records = qs.get_assessments_by_category(args.category)
                print(f"  {BOLD}Threat Assessments by Category: {args.category}{RESET}")
            elif args.severity:
                records = qs.get_assessments_by_severity(args.severity)
                print(f"  {BOLD}Threat Assessments by Severity: {args.severity}{RESET}")
            elif args.event_id:
                records = qs.get_assessments_by_event_id(args.event_id)
                print(f"  {BOLD}Threat Assessments for Event: {args.event_id}{RESET}")
            elif args.assessment_id:
                rec = qs.get_assessment_by_id(args.assessment_id)
                records = [rec] if rec else []
                print(f"  {BOLD}Threat Assessment: {args.assessment_id}{RESET}")

            print(DIV2)
            if not records:
                print(f"  {DIM}No threat assessments found matching the criteria.{RESET}")
            else:
                for r in records:
                    print_assessment(r, verbose=args.verbose)
                print(f"\n  Found {len(records)} matching assessment(s).")
            print(DIV)

    except Exception as exc:
        print(f"{RED}[ERROR] Query failed: {exc}{RESET}")
        sys.exit(1)


if __name__ == "__main__":
    main()
