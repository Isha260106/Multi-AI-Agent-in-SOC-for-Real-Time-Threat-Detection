"""
query_alerts.py
================
Command-Line Query Tool for the SOC Alert Database

Multi-Agent SOC Project -- Stage 5: Central Event and Alert Storage

Provides a simple CLI to search and retrieve alerts from soc.db.
All queries go through storage/query.py -- no SQL is written here.

USAGE
-----
  python query_alerts.py --recent 20
  python query_alerts.py --severity HIGH
  python query_alerts.py --status SUSPICIOUS
  python query_alerts.py --prediction Infilteration
  python query_alerts.py --summary
  python query_alerts.py --from "2026-09-16T12:00:00" --to "2026-09-16T13:00:00"
  python query_alerts.py --search Infilteration --field prediction
  python query_alerts.py --event-id 3f8a2c1d-...
  python query_alerts.py --recent 5 --counts
"""

import argparse
import pathlib
import sys

# ---------------------------------------------------------------------------
# Project root
# ---------------------------------------------------------------------------
PROJECT_ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from storage.config import DB_PATH
from storage.query import AlertQueryStore

# ---------------------------------------------------------------------------
# ANSI colours
# ---------------------------------------------------------------------------
try:
    if sys.platform == "win32":
        import ctypes
        ctypes.windll.kernel32.SetConsoleMode(
            ctypes.windll.kernel32.GetStdHandle(-11), 7
        )
    ANSI = True
except Exception:
    ANSI = False

RED    = "\033[91m" if ANSI else ""
GREEN  = "\033[92m" if ANSI else ""
YELLOW = "\033[93m" if ANSI else ""
CYAN   = "\033[96m" if ANSI else ""
BOLD   = "\033[1m"  if ANSI else ""
DIM    = "\033[2m"  if ANSI else ""
RESET  = "\033[0m"  if ANSI else ""

DIV  = "=" * 72
DIV2 = "-" * 72


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def _alert_color(pred: str) -> str:
    return RED if pred == "Infilteration" else GREEN


def _print_header(title: str) -> None:
    print(f"\n{BOLD}{DIV}{RESET}")
    print(f"{BOLD}  {title}{RESET}")
    print(f"{BOLD}{DIV}{RESET}")


def _print_alert_table(alerts: list[dict], label: str = "") -> None:
    """Print a compact table of alerts."""
    if not alerts:
        print(f"\n  {YELLOW}No matching alerts found.{RESET}")
        return

    if label:
        print(f"\n  {label}: {len(alerts)} result(s)")

    print(f"\n  {'#':<5} {'Prediction':<18} {'Severity':<8} {'Confidence':>12} "
          f"{'Status':<12} {'Timestamp':<27} {'Event ID'}")
    print("  " + DIV2)

    for i, a in enumerate(alerts, 1):
        pred  = a.get("prediction", "?")
        sev   = a.get("severity", "?")
        conf  = a.get("confidence", 0)
        stat  = a.get("status", "?")
        ts    = a.get("timestamp", "?")[:26]
        eid   = a.get("event_id") or "N/A"
        eid_s = (eid[:16] + "...") if len(eid) > 19 else eid

        color = _alert_color(pred)
        print(
            f"  {i:<5} {color}{pred:<18}{RESET} "
            f"{color}{sev:<8}{RESET} {conf:>12.2%} "
            f"{stat:<12} {DIM}{ts:<27}{RESET} {DIM}{eid_s}{RESET}"
        )


def _print_alert_detail(a: dict) -> None:
    """Print one alert in verbose detail."""
    pred  = a.get("prediction", "?")
    color = _alert_color(pred)

    print(f"\n  {color}{BOLD}{'[SUSPICIOUS]' if pred == 'Infilteration' else '[NORMAL]'}{RESET}")
    for key in ("alert_id", "event_id", "agent", "timestamp", "prediction",
                "confidence", "severity", "status", "actual_label",
                "processing_time_s"):
        val = a.get(key)
        if val is not None:
            print(f"  {key:<28}: {val}")

    ctx = a.get("network_context_json")
    if ctx:
        print(f"  {'network_context':<28}:")
        for k, v in ctx.items():
            print(f"      {k}: {v}")


# ---------------------------------------------------------------------------
# Summary display
# ---------------------------------------------------------------------------

def _print_summary(stats: dict) -> None:
    _print_header("SOC Database Summary")

    pct     = stats.get("attack_pct", 0)
    pct_col = RED if pct > 20 else (YELLOW if pct > 5 else GREEN)

    print(f"\n  {'Total events ingested':<30}: {stats['total_events']}")
    print(f"  {'Total alerts stored':<30}: {stats['total_alerts']}")
    print(f"  {'Benign predictions':<30}: {GREEN}{stats['benign_count']}{RESET}")
    print(f"  {'Attack predictions':<30}: {RED}{stats['attack_count']}{RESET}")
    print(f"  {'Attack percentage':<30}: {pct_col}{pct:.1f}%{RESET}")
    if stats.get("avg_confidence_pct") is not None:
        print(f"  {'Avg confidence':<30}: {stats['avg_confidence_pct']:.1f}%")
    if stats.get("avg_processing_ms") is not None:
        print(f"  {'Avg processing time':<30}: {stats['avg_processing_ms']:.1f} ms")
    if stats.get("earliest_alert"):
        print(f"  {'Earliest alert':<30}: {DIM}{stats['earliest_alert']}{RESET}")
    if stats.get("latest_alert"):
        print(f"  {'Latest alert':<30}: {DIM}{stats['latest_alert']}{RESET}")
    print(f"\n  Database: {DB_PATH}")
    print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args():
    p = argparse.ArgumentParser(
        description=(
            "SOC Alert Query Tool -- Multi-Agent SOC Stage 5.\n\n"
            "Query the central SQLite alert database (data/soc.db)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python query_alerts.py --recent 20\n"
            "  python query_alerts.py --severity HIGH\n"
            "  python query_alerts.py --status SUSPICIOUS\n"
            "  python query_alerts.py --prediction Infilteration\n"
            "  python query_alerts.py --summary\n"
            "  python query_alerts.py --from \"2026-09-16T12:00:00\" --to \"2026-09-16T13:00:00\"\n"
            "  python query_alerts.py --search Infilteration --field prediction\n"
            "  python query_alerts.py --event-id <uuid>\n"
            "  python query_alerts.py --counts\n"
        ),
    )

    # Query modes (mutually exclusive)
    g = p.add_mutually_exclusive_group()
    g.add_argument("--recent",     type=int,   metavar="N",
                   help="Show N most-recent alerts.")
    g.add_argument("--severity",   choices=["HIGH", "LOW"],
                   help="Filter by severity.")
    g.add_argument("--status",     choices=["SUSPICIOUS", "NORMAL"],
                   help="Filter by status.")
    g.add_argument("--prediction", choices=["Infilteration", "Benign"],
                   help="Filter by prediction class.")
    g.add_argument("--summary",    action="store_true",
                   help="Show aggregate statistics.")
    g.add_argument("--counts",     action="store_true",
                   help="Show count breakdowns by prediction and severity.")
    g.add_argument("--event-id",   metavar="UUID",
                   help="Show all alerts linked to a specific event_id.")
    g.add_argument("--search",     metavar="KEYWORD",
                   help="Search using LIKE pattern. Combine with --field.")

    # Supplementary args
    p.add_argument("--from",       dest="ts_from", metavar="ISO_DATETIME",
                   help="Start of time range (ISO-8601). Use with --to.")
    p.add_argument("--to",         dest="ts_to",   metavar="ISO_DATETIME",
                   help="End of time range (ISO-8601). Use with --from.")
    p.add_argument("--field",      default="prediction",
                   help="Field to search with --search. Default: prediction")
    p.add_argument("--verbose", "-v", action="store_true",
                   help="Print full alert details instead of table.")
    return p.parse_args()


def main() -> None:
    args = _parse_args()

    # Check DB exists
    if not DB_PATH.exists():
        print(f"\n{RED}[ERROR] Database not found: {DB_PATH}{RESET}")
        print("Run the demo first:  python kafka/demo.py")
        print("Or ingest logs with: python storage/ingest.py")
        sys.exit(1)

    try:
        store = AlertQueryStore()
    except FileNotFoundError as exc:
        print(f"\n{RED}[ERROR] {exc}{RESET}")
        sys.exit(1)

    with store:
        # ---------------------------------------------------------------- #
        # --summary                                                         #
        # ---------------------------------------------------------------- #
        if args.summary:
            _print_summary(store.summary_stats())

        # ---------------------------------------------------------------- #
        # --counts                                                          #
        # ---------------------------------------------------------------- #
        elif args.counts:
            _print_header("Alert Counts")
            pred_c = store.count_by_prediction()
            sev_c  = store.count_by_severity()
            print(f"\n  By prediction:")
            for k, v in pred_c.items():
                color = RED if k == "Infilteration" else GREEN
                print(f"    {color}{k:<20}{RESET}: {v}")
            print(f"\n  By severity:")
            for k, v in sev_c.items():
                color = RED if k == "HIGH" else GREEN
                print(f"    {color}{k:<20}{RESET}: {v}")
            print()

        # ---------------------------------------------------------------- #
        # --from / --to (time range)                                        #
        # ---------------------------------------------------------------- #
        elif args.ts_from or args.ts_to:
            start = args.ts_from or "1970-01-01T00:00:00"
            end   = args.ts_to   or "9999-12-31T23:59:59"
            _print_header(f"Alerts from {start}  to  {end}")
            alerts = store.get_alerts_in_timerange(start, end)
            if args.verbose:
                for a in alerts:
                    _print_alert_detail(a)
            else:
                _print_alert_table(alerts)
            print(f"\n  Total: {len(alerts)}\n")

        # ---------------------------------------------------------------- #
        # --recent N                                                        #
        # ---------------------------------------------------------------- #
        elif args.recent is not None:
            _print_header(f"Most Recent {args.recent} Alerts")
            alerts = store.get_recent_alerts(args.recent)
            if args.verbose:
                for a in alerts:
                    _print_alert_detail(a)
            else:
                _print_alert_table(alerts)
            print(f"\n  Total shown: {len(alerts)}\n")

        # ---------------------------------------------------------------- #
        # --severity HIGH|LOW                                               #
        # ---------------------------------------------------------------- #
        elif args.severity:
            _print_header(f"Alerts with Severity = {args.severity}")
            alerts = store.get_alerts_by_severity(args.severity)
            if args.verbose:
                for a in alerts:
                    _print_alert_detail(a)
            else:
                _print_alert_table(alerts)
            print(f"\n  Total: {len(alerts)}\n")

        # ---------------------------------------------------------------- #
        # --status SUSPICIOUS|NORMAL                                        #
        # ---------------------------------------------------------------- #
        elif args.status:
            _print_header(f"Alerts with Status = {args.status}")
            alerts = store.get_alerts_by_status(args.status)
            if args.verbose:
                for a in alerts:
                    _print_alert_detail(a)
            else:
                _print_alert_table(alerts)
            print(f"\n  Total: {len(alerts)}\n")

        # ---------------------------------------------------------------- #
        # --prediction Infilteration|Benign                                  #
        # ---------------------------------------------------------------- #
        elif args.prediction:
            _print_header(f"Alerts with Prediction = {args.prediction}")
            alerts = store.get_alerts_by_prediction(args.prediction)
            if args.verbose:
                for a in alerts:
                    _print_alert_detail(a)
            else:
                _print_alert_table(alerts)
            print(f"\n  Total: {len(alerts)}\n")

        # ---------------------------------------------------------------- #
        # --event-id UUID                                                   #
        # ---------------------------------------------------------------- #
        elif args.event_id:
            _print_header(f"Alerts for Event ID: {args.event_id}")
            alerts = store.get_alert_by_event_id(args.event_id)
            if args.verbose:
                for a in alerts:
                    _print_alert_detail(a)
            else:
                _print_alert_table(alerts)
            print(f"\n  Total: {len(alerts)}\n")

        # ---------------------------------------------------------------- #
        # --search KEYWORD --field FIELD                                    #
        # ---------------------------------------------------------------- #
        elif args.search:
            try:
                alerts = store.search_alerts(args.search, args.field)
                _print_header(
                    f"Search: field={args.field!r}  keyword={args.search!r}"
                )
                if args.verbose:
                    for a in alerts:
                        _print_alert_detail(a)
                else:
                    _print_alert_table(alerts)
                print(f"\n  Total: {len(alerts)}\n")
            except ValueError as exc:
                print(f"\n{RED}[ERROR] {exc}{RESET}\n")
                sys.exit(1)

        # ---------------------------------------------------------------- #
        # No mode specified -- show summary by default                      #
        # ---------------------------------------------------------------- #
        else:
            _print_summary(store.summary_stats())

        print(f"  {DIM}Database: {DB_PATH}{RESET}\n")


if __name__ == "__main__":
    main()
