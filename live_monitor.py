"""
Live Network Monitor
=====================
Multi-Agent SOC Project -- Stage 3 (Live Monitoring Extension)

Two operating modes:

  --mode simulate   Replays the cleaned dataset row-by-row with a configurable
                    delay to simulate a live network feed. Works right now with
                    no extra tools required.

  --mode watch      Tails a CSV file written by CICFlowMeter (or any other tool
                    that appends network-flow rows to a CSV). The monitor wakes
                    up on every new row and immediately runs the agent on it.

Usage examples:

  # Simulate -- shuffled (recommended for demos, shows both Benign + Suspicious)
  python live_monitor.py --mode simulate --shuffle

  # Simulate -- default order, 1 second per record
  python live_monitor.py --mode simulate

  # Simulate faster (0.2 sec per record), only print intrusions
  python live_monitor.py --mode simulate --shuffle --delay 0.2 --alerts-only

  # Simulate -- stop after 50 records
  python live_monitor.py --mode simulate --shuffle --max 50

  # Watch mode -- tail a live CSV produced by CICFlowMeter
  python live_monitor.py --mode watch --file "C:/CICFlowMeter/output/flows.csv"

  # Watch mode -- poll every 2 seconds
  python live_monitor.py --mode watch --file flows.csv --poll 2.0

Press Ctrl+C at any time to stop and see a session summary.

Output:
  Terminal    -- clean, color-coded live alert stream
  JSON log    -- <project_root>/logs/live_monitor_alerts.json (appended)
  Agent log   -- <project_root>/logs/agent_runtime.log (agent internals)

NOTE: This script never modifies the model or the dataset.
"""

import argparse
import json
import logging
import os
import pathlib
import sys
import time
import datetime

import pandas as pd

# ---------------------------------------------------------------------------
# Project root
# ---------------------------------------------------------------------------
PROJECT_ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from agents.network_detection.agent import NetworkDetectionAgent

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
DATASET        = PROJECT_ROOT / "data" / "processed" / "cleaned_dataset.csv"
LOG_DIR        = PROJECT_ROOT / "logs"
LIVE_LOG_FILE  = LOG_DIR / "live_monitor_alerts.json"
AGENT_LOG_FILE = LOG_DIR / "agent_runtime.log"

# ---------------------------------------------------------------------------
# Redirect ALL agent/library logging to a file so the terminal stays clean.
# The monitor's own print() calls control what the user sees.
# ---------------------------------------------------------------------------
LOG_DIR.mkdir(parents=True, exist_ok=True)

_file_handler = logging.FileHandler(AGENT_LOG_FILE, encoding="utf-8")
_file_handler.setFormatter(logging.Formatter(
    "%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
))

# Root logger: send everything to file, nothing to console
logging.root.setLevel(logging.DEBUG)
logging.root.handlers = []          # remove any default handlers
logging.root.addHandler(_file_handler)

# ---------------------------------------------------------------------------
# ANSI color support
# ---------------------------------------------------------------------------
try:
    if sys.platform == "win32":
        import ctypes
        ctypes.windll.kernel32.SetConsoleMode(
            ctypes.windll.kernel32.GetStdHandle(-11), 7
        )
        ANSI_SUPPORTED = True
    else:
        ANSI_SUPPORTED = True
except Exception:
    ANSI_SUPPORTED = False

RED    = "\033[91m" if ANSI_SUPPORTED else ""
GREEN  = "\033[92m" if ANSI_SUPPORTED else ""
YELLOW = "\033[93m" if ANSI_SUPPORTED else ""
CYAN   = "\033[96m" if ANSI_SUPPORTED else ""
BOLD   = "\033[1m"  if ANSI_SUPPORTED else ""
RESET  = "\033[0m"  if ANSI_SUPPORTED else ""

# ---------------------------------------------------------------------------
# Session stats
# ---------------------------------------------------------------------------
class SessionStats:
    def __init__(self):
        self.total      = 0
        self.benign     = 0
        self.suspicious = 0
        self.errors     = 0
        self.started    = datetime.datetime.now()

    def record(self, prediction):
        self.total += 1
        if prediction == "Infilteration":
            self.suspicious += 1
        else:
            self.benign += 1

    def record_error(self):
        self.errors += 1
        self.total  += 1

    def summary(self):
        elapsed = datetime.datetime.now() - self.started
        pct = (self.suspicious / max(self.total - self.errors, 1)) * 100
        return (
            "\n" + "=" * 60 + "\n"
            "  SESSION SUMMARY\n"
            + "=" * 60 + "\n"
            "  Duration          : " + str(elapsed).split(".")[0] + "\n"
            "  Records processed : " + str(self.total) + "\n"
            "  Benign            : " + str(self.benign) + "\n"
            "  SUSPICIOUS        : " + str(self.suspicious)
            + " ({:.1f}%)\n".format(pct)
            + "  Errors/skipped    : " + str(self.errors) + "\n"
            "  Agent log         : " + str(AGENT_LOG_FILE) + "\n"
            "  Alert log         : " + str(LIVE_LOG_FILE) + "\n"
            + "=" * 60 + "\n"
        )

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _status_bar(stats):
    """Single-line status shown after each Benign record when alerts_only=True."""
    return (
        "  [Live] Processed: {:<6}  Benign: {:<6}  "
        "SUSPICIOUS: {:<6}  Errors: {}".format(
            stats.total, stats.benign, stats.suspicious, stats.errors
        )
    )


def print_alert(record_num, alert, actual_label=None):
    """Pretty-print a single alert to stdout."""
    pred   = alert["prediction"]
    conf   = alert["confidence"]
    sev    = alert["severity"]
    status = alert["status"]
    ts     = alert["timestamp"]
    ctx    = alert.get("network_context", {})

    if pred == "Infilteration":
        color = RED
        icon  = "[!!] INTRUSION DETECTED"
    else:
        color = GREEN
        icon  = "[ . ] Normal Traffic"

    print("\n" + color + BOLD + icon + RESET
          + "  |  Record #" + str(record_num)
          + "  |  " + ts)

    print("  Prediction  : " + color + BOLD + pred + RESET)
    print("  Confidence  : " + "{:.2%}".format(conf))
    print("  Severity    : " + color + sev + RESET
          + "   Status: " + status)

    if actual_label:
        if actual_label == pred:
            verdict = GREEN + "CORRECT" + RESET
        else:
            verdict = RED + "WRONG" + RESET
        print("  Actual      : " + actual_label + "  (" + verdict + ")")

    if ctx:
        parts = [str(k) + "=" + str(v) for k, v in list(ctx.items())[:5]]
        print("  Context     : " + CYAN + ",  ".join(parts) + RESET)


def append_alert_to_log(alert):
    """Append a single alert dict to the rolling JSON log."""
    if LIVE_LOG_FILE.exists():
        try:
            existing = json.loads(LIVE_LOG_FILE.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            existing = []
    else:
        existing = []

    existing.append(alert)
    LIVE_LOG_FILE.write_text(
        json.dumps(existing, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# MODE A: Simulate
# ---------------------------------------------------------------------------
def run_simulate(agent, delay, alerts_only, max_records, shuffle):
    """
    Replay cleaned_dataset.csv row-by-row as if records arrived live.

    --shuffle  randomises the row order so that Benign and Infilteration
               records are interleaved from the very first record.
               Without --shuffle the dataset plays in original order
               (all Benign rows come first).
    """
    print("\n" + BOLD + CYAN + "=== SIMULATE MODE ===" + RESET)
    print("  Source    : " + str(DATASET))
    print("  Shuffle   : " + ("YES (mixed Benign + Infilteration from start)"
                               if shuffle else "NO  (original CSV order)"))
    print("  Delay     : " + str(delay) + "s per record")
    print("  Filter    : " + ("SUSPICIOUS only" if alerts_only else "all records"))
    if max_records:
        print("  Limit     : " + str(max_records) + " records")
    print("  Alert log : " + str(LIVE_LOG_FILE))
    print("  Agent log : " + str(AGENT_LOG_FILE))
    print("\n  " + YELLOW + "Loading dataset (this may take a moment)..." + RESET)

    df = pd.read_csv(DATASET, low_memory=False)

    if shuffle:
        df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    total_rows = len(df)
    n_infil    = int((df["Label"] == "Infilteration").sum()) if "Label" in df.columns else "?"
    n_benign   = int((df["Label"] == "Benign").sum())        if "Label" in df.columns else "?"

    print("  Rows      : {:,}  (Benign: {:,}  |  Infilteration: {:,})".format(
        total_rows, n_benign, n_infil))
    print("\n  " + BOLD + "Live feed starting -- press Ctrl+C to stop" + RESET)
    print("-" * 60)

    stats = SessionStats()
    i     = 0  # row pointer; wraps when exhausted

    try:
        while True:
            if max_records and stats.total >= max_records:
                print("\n  Reached limit of " + str(max_records) + " records. Stopping.")
                break

            row_df = df.iloc[[i]].copy()
            actual = row_df["Label"].iloc[0] if "Label" in row_df.columns else None

            try:
                alerts = agent.analyze(row_df)
                alert  = alerts[0]
                stats.record(alert["prediction"])

                if actual:
                    alert["actual_label"] = actual

                append_alert_to_log(alert)

                if alerts_only and alert["prediction"] != "Infilteration":
                    # Show a compact status line instead of full alert
                    print("\r" + _status_bar(stats), end="", flush=True)
                else:
                    print_alert(stats.total, alert, actual_label=actual)

            except ValueError as exc:
                stats.record_error()
                print("\n  " + YELLOW + "[SKIP] Row " + str(i) + ": "
                      + str(exc)[:120] + RESET)

            i = (i + 1) % total_rows
            time.sleep(delay)

    except KeyboardInterrupt:
        print("\n\n  " + YELLOW + "Stopped by user (Ctrl+C)" + RESET)

    print(stats.summary())


# ---------------------------------------------------------------------------
# MODE B: Watch
# ---------------------------------------------------------------------------
def run_watch(agent, filepath, poll_interval, alerts_only):
    """
    Tail a CSV file for new rows in real time.

    Any network-flow capture tool that appends rows to a CSV
    (e.g. CICFlowMeter) will work with this mode.

    How it works:
      1. Read the header row once to learn column names.
      2. Remember the current byte offset (end of header).
      3. Every <poll_interval> seconds, seek to the saved offset
         and read any newly appended bytes.
      4. Split on newlines; feed each complete new row to the agent.
      5. Update the offset so the next poll only reads NEW bytes.
    """
    filepath = pathlib.Path(filepath)

    print("\n" + BOLD + CYAN + "=== WATCH MODE ===" + RESET)
    print("  Watching  : " + str(filepath))
    print("  Poll      : every " + str(poll_interval) + "s")
    print("  Filter    : " + ("SUSPICIOUS only" if alerts_only else "all records"))
    print("  Alert log : " + str(LIVE_LOG_FILE))
    print("  Agent log : " + str(AGENT_LOG_FILE))

    # Wait until the file exists (CICFlowMeter may not have started yet)
    while not filepath.exists():
        print("  " + YELLOW + "Waiting for file: " + str(filepath) + RESET)
        time.sleep(poll_interval)

    print("\n  " + BOLD + "File found. Tailing -- press Ctrl+C to stop" + RESET)
    print("-" * 60)

    stats       = SessionStats()
    header_cols = None
    byte_offset = 0
    line_buffer = ""       # holds an incomplete line across poll cycles

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:

            # Read and parse the header row
            header_line = fh.readline()
            if not header_line:
                print("  " + RED + "ERROR: File appears empty (no header row)." + RESET)
                return

            header_cols = [c.strip() for c in header_line.split(",")]
            byte_offset = fh.tell()
            print("  Columns   : " + str(len(header_cols))
                  + "  (first 5: " + ", ".join(header_cols[:5]) + " ...)")
            print()

            while True:
                fh.seek(byte_offset)
                new_text  = fh.read()
                byte_offset = fh.tell()

                if new_text:
                    line_buffer += new_text
                    lines          = line_buffer.split("\n")
                    line_buffer    = lines[-1]          # keep incomplete tail
                    complete_lines = lines[:-1]

                    for line in complete_lines:
                        line = line.strip()
                        if not line:
                            continue

                        # Simple CSV parse (handles quoted fields minimally)
                        values = [v.strip() for v in line.split(",")]
                        if len(values) != len(header_cols):
                            stats.record_error()
                            print("  " + YELLOW
                                  + "[SKIP] Column count mismatch ("
                                  + str(len(values)) + " vs "
                                  + str(len(header_cols)) + ")" + RESET)
                            continue

                        row_dict = dict(zip(header_cols, values))
                        row_df   = pd.DataFrame([row_dict])
                        actual   = row_dict.get("Label")

                        try:
                            alerts = agent.analyze(row_df)
                            alert  = alerts[0]
                            stats.record(alert["prediction"])

                            if actual:
                                alert["actual_label"] = actual

                            append_alert_to_log(alert)

                            if alerts_only and alert["prediction"] != "Infilteration":
                                print("\r" + _status_bar(stats), end="", flush=True)
                            else:
                                print_alert(stats.total, alert, actual_label=actual)

                        except ValueError as exc:
                            stats.record_error()
                            print("\n  " + YELLOW + "[SKIP] " + str(exc)[:120] + RESET)

                else:
                    # No new data -- show a heartbeat dot so the user knows
                    # the monitor is alive
                    print("\r  [waiting for new records...]  "
                          + _status_bar(stats), end="", flush=True)

                time.sleep(poll_interval)

    except KeyboardInterrupt:
        print("\n\n  " + YELLOW + "Stopped by user (Ctrl+C)" + RESET)

    print(stats.summary())


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="Live network monitor -- Multi-Agent SOC project.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python live_monitor.py --mode simulate --shuffle
  python live_monitor.py --mode simulate --shuffle --delay 0.2 --alerts-only
  python live_monitor.py --mode simulate --shuffle --max 50
  python live_monitor.py --mode watch --file "C:/CICFlowMeter/output/flows.csv"
  python live_monitor.py --mode watch --file flows.csv --poll 2.0
        """,
    )

    parser.add_argument(
        "--mode",
        choices=["simulate", "watch"],
        default="simulate",
        help="'simulate' or 'watch'. Default: simulate",
    )
    parser.add_argument(
        "--shuffle",
        action="store_true",
        help="(simulate) Shuffle the dataset so Benign and Infilteration "
             "records are interleaved. Recommended for demos.",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=1.0,
        help="(simulate) Seconds between records. Default: 1.0",
    )
    parser.add_argument(
        "--file",
        type=str,
        default=None,
        help="(watch) Path to the live CSV file to tail.",
    )
    parser.add_argument(
        "--poll",
        type=float,
        default=1.0,
        help="(watch) Seconds between file-size polls. Default: 1.0",
    )
    parser.add_argument(
        "--alerts-only",
        action="store_true",
        help="Only print SUSPICIOUS records. "
             "Shows a compact status line for Benign traffic.",
    )
    parser.add_argument(
        "--max",
        type=int,
        default=0,
        help="(simulate) Stop after N records. 0 = unlimited. Default: 0",
    )

    return parser.parse_args()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    args = parse_args()

    print("\n" + BOLD + "=" * 60 + RESET)
    print(BOLD + "  Multi-Agent SOC -- Live Network Monitor" + RESET)
    print(BOLD + "=" * 60 + RESET)

    print("\n  " + YELLOW + "Initializing Network Detection Agent..." + RESET)
    try:
        agent = NetworkDetectionAgent()
    except FileNotFoundError as exc:
        print("\n  " + RED + "ERROR: " + str(exc) + RESET)
        sys.exit(1)

    print("  " + GREEN + "Agent ready." + RESET)

    if args.mode == "simulate":
        run_simulate(
            agent       = agent,
            delay       = args.delay,
            alerts_only = args.alerts_only,
            max_records = args.max,
            shuffle     = args.shuffle,
        )
    elif args.mode == "watch":
        if not args.file:
            print("\n  " + RED + "ERROR: --file is required in watch mode." + RESET)
            print("  Example: python live_monitor.py --mode watch --file flows.csv")
            sys.exit(1)
        run_watch(
            agent         = agent,
            filepath      = args.file,
            poll_interval = args.poll,
            alerts_only   = args.alerts_only,
        )


if __name__ == "__main__":
    main()
