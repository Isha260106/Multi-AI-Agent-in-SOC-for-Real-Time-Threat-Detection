"""
kafka/demo.py
==============
End-to-End Real-Time Event Streaming Demonstration

Multi-Agent SOC Project -- Stage 4: Real-Time Event Streaming

This script runs the complete Stage 4 pipeline in a single process:

    Network Flow Dataset
           |
           v
    Event Producer  (replays CSV records as structured events)
           |
           v
    In-Process Event Stream  (Python Queue -- no Kafka broker required)
           |
           v
    Network Detection Consumer  (extracts features, calls agent)
           |
           v
    Network Detection Agent  (preprocess -> Random Forest predict)
           |
           v
    Random Forest Model  (trained in Stage 2)
           |
           v
    Prediction + Confidence
           |
           v
    Security Alert  (structured, severity-rated)
           |
           v
    Streaming Alert Log  (logs/streaming_alerts.json)

NOTE ON LOCAL REAL-TIME SIMULATION
------------------------------------
This demonstration uses historical CICIDS 2017 dataset records replayed as
events.  The dataset is used for controlled simulation / testing purposes.
It is NOT itself a live traffic source.

The system demonstrates near-real-time event processing capability.
On a local Windows machine, typical prediction latency is < 50 ms per event.

USAGE
-----
  # Default: 20 events, 1-second delay, balanced benign/attack selection:
  python kafka/demo.py

  # Custom:
  python kafka/demo.py --count 20 --delay 0.5

  # Fast demo (0.2 second delay):
  python kafka/demo.py --count 20 --delay 0.2

  # With malformed event injection (tests error handling):
  python kafka/demo.py --count 20 --inject-errors

OUTPUTS
-------
  Terminal   -- live event stream with colour-coded alerts
  JSON log   -- <project_root>/logs/streaming_alerts.json
  Runtime log-- <project_root>/logs/streaming_runtime.log
"""

import argparse
import datetime
import sys
import pathlib
import threading
import time
import json
import logging

# ---------------------------------------------------------------------------
# Project root
# ---------------------------------------------------------------------------
PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from kafka.config import (
    KAFKA_TOPIC,
    DEFAULT_TRANSPORT,
    DEFAULT_DELAY,
    DEFAULT_EVENT_COUNT,
    LOG_DIR,
    STREAMING_LOG_FILE,
)
from kafka.stream import _get_topic_queue, make_producer, make_consumer
from kafka.producer import run_producer
from kafka.consumer import consume_events

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOG_DIR.mkdir(parents=True, exist_ok=True)
_log = logging.getLogger("SOC.Demo")
if not _log.handlers:
    _fh = logging.FileHandler(STREAMING_LOG_FILE, encoding="utf-8")
    _fh.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    _log.addHandler(_fh)
    _log.setLevel(logging.DEBUG)
    _log.propagate = False

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
BLUE   = "\033[94m" if ANSI else ""
BOLD   = "\033[1m"  if ANSI else ""
DIM    = "\033[2m"  if ANSI else ""
RESET  = "\033[0m"  if ANSI else ""


# ---------------------------------------------------------------------------
# Malformed event injection (tests error handling)
# ---------------------------------------------------------------------------

def _inject_malformed_events(topic: str, count: int = 3) -> None:
    """
    Push deliberately bad events onto the queue to verify consumer robustness.

    These events test the following error conditions:
      1. Missing 'features' key entirely
      2. Non-numeric feature value
      3. Empty features dict
    """
    import uuid, json, datetime
    from kafka.stream import _get_topic_queue

    q = _get_topic_queue(topic)

    bad_events = [
        # 1. No features key at all
        {
            "event_id":    str(uuid.uuid4()),
            "event_type":  "network_flow",
            "timestamp":   datetime.datetime.now().isoformat(),
            "source":      "malformed_injection",
            "sequence":    9001,
            "actual_label": None,
            # DELIBERATELY MISSING: "features"
        },
        # 2. Features dict present but critical value is a string
        {
            "event_id":    str(uuid.uuid4()),
            "event_type":  "network_flow",
            "timestamp":   datetime.datetime.now().isoformat(),
            "source":      "malformed_injection",
            "sequence":    9002,
            "actual_label": None,
            "features": {
                "Dst Port": "NOT_A_NUMBER",   # string in numeric column
                "Protocol": None,             # null value
            },
            # Only 2 of 78 features present -- agent will fill rest with medians
        },
        # 3. Completely empty features
        {
            "event_id":    str(uuid.uuid4()),
            "event_type":  "network_flow",
            "timestamp":   datetime.datetime.now().isoformat(),
            "source":      "malformed_injection",
            "sequence":    9003,
            "actual_label": None,
            "features":    {},
        },
    ]

    for evt in bad_events[:count]:
        q.put(json.dumps(evt, ensure_ascii=False))


# ---------------------------------------------------------------------------
# Pipeline helper that runs producer + consumer in the same thread
# (simpler than threading for a demo -- producer puts N events then stops,
#  consumer drains exactly N events then prints summary)
# ---------------------------------------------------------------------------

def _run_pipeline_sequential(
    count: int,
    delay: float,
    balanced: bool,
    transport: str,
    inject_errors: bool,
) -> None:
    """
    Run producer then consumer sequentially in a single thread.

    This is the simplest approach for a demo:
      1. Producer pushes all events into the queue instantly (delay=0 for fill).
      2. Consumer pops events one-by-one, running detection on each.

    The delay is applied *inside the consumer* between each processing step
    to simulate real-time pacing on the output side.
    """

    print(f"\n{BOLD}{CYAN}{'=' * 60}{RESET}")
    print(f"{BOLD}{CYAN}  Multi-Agent SOC -- Stage 4: Real-Time Event Streaming{RESET}")
    print(f"{BOLD}{CYAN}  Local Real-Time Simulation{RESET}")
    print(f"{BOLD}{CYAN}{'=' * 60}{RESET}")
    print()
    print(f"  {YELLOW}NOTE: Historical dataset records are replayed to simulate{RESET}")
    print(f"  {YELLOW}real-time network events. The dataset is NOT live traffic.{RESET}")
    print()

    _log.info("Demo started. count=%d delay=%.2f balanced=%s transport=%s inject_errors=%s",
              count, delay, balanced, transport, inject_errors)

    # ------------------------------------------------------------------ #
    # PHASE 1 -- Producer: populate the event queue                        #
    # ------------------------------------------------------------------ #
    print(f"{BOLD}  PHASE 1 -- EVENT PRODUCER{RESET}")
    print("  " + "-" * 56)
    print(f"  Replaying {count} records from cleaned_dataset.csv")
    print(f"  Selection: {'Balanced (Benign + Infilteration)' if balanced else 'Sequential'}")
    print()

    sent = run_producer(
        count=count,
        delay=0.0,          # fill queue instantly; real pacing happens in consumer
        balanced=balanced,
        transport=transport,
        topic=KAFKA_TOPIC,
        silent=False,
    )

    # ------------------------------------------------------------------ #
    # PHASE 1b -- Inject malformed events (optional)                       #
    # ------------------------------------------------------------------ #
    if inject_errors:
        print(f"\n  {YELLOW}[Error Injection] Adding 3 malformed events to test "
              f"consumer robustness...{RESET}")
        _inject_malformed_events(KAFKA_TOPIC, count=3)
        total_events = count + 3
        print(f"  Total events in queue: {total_events}")
    else:
        total_events = count

    # ------------------------------------------------------------------ #
    # PHASE 2 -- Consumer: drain the queue and run detection               #
    # ------------------------------------------------------------------ #
    print(f"\n{BOLD}  PHASE 2 -- NETWORK DETECTION CONSUMER{RESET}")
    print("  " + "-" * 56)

    stats = consume_events(
        count=total_events,
        transport=transport,
        topic=KAFKA_TOPIC,
        poll_timeout=5.0,
        silent=False,
    )

    # ------------------------------------------------------------------ #
    # PHASE 3 -- Session summary                                           #
    # ------------------------------------------------------------------ #
    print(f"\n{BOLD}  PHASE 3 -- SESSION SUMMARY{RESET}")
    print(stats.summary())

    _log.info("Demo completed. benign=%d suspicious=%d errors=%d",
              stats.benign, stats.suspicious, stats.errors)


def _run_pipeline_threaded(
    count: int,
    delay: float,
    balanced: bool,
    transport: str,
    inject_errors: bool,
) -> None:
    """
    Run producer in a background thread while the consumer processes in the
    main thread, simulating two separate terminals.

    The delay is applied in the PRODUCER so events arrive at the rate
    specified by --delay.
    """

    print(f"\n{BOLD}{CYAN}{'=' * 60}{RESET}")
    print(f"{BOLD}{CYAN}  Multi-Agent SOC -- Stage 4: Real-Time Event Streaming{RESET}")
    print(f"{BOLD}{CYAN}  Live Simulation Mode (Producer + Consumer Concurrent){RESET}")
    print(f"{BOLD}{CYAN}{'=' * 60}{RESET}")
    print()
    print(f"  {YELLOW}NOTE: Historical dataset records are replayed to simulate{RESET}")
    print(f"  {YELLOW}real-time network events. The dataset is NOT live traffic.{RESET}")
    print()

    _log.info("Threaded demo started. count=%d delay=%.2f balanced=%s",
              count, delay, balanced)

    total_events = count + (3 if inject_errors else 0)

    # Start producer in background thread
    def _producer_thread():
        run_producer(
            count=count,
            delay=delay,
            balanced=balanced,
            transport=transport,
            topic=KAFKA_TOPIC,
            silent=True,    # producer output suppressed; consumer drives the display
        )
        if inject_errors:
            time.sleep(0.5)
            _inject_malformed_events(KAFKA_TOPIC, count=3)

    t = threading.Thread(target=_producer_thread, daemon=True)
    t.start()

    # Consumer runs in main thread
    stats = consume_events(
        count=total_events,
        transport=transport,
        topic=KAFKA_TOPIC,
        poll_timeout=delay * 3 + 5.0,
        silent=False,
    )

    t.join(timeout=10)

    print(f"\n{BOLD}  SESSION SUMMARY{RESET}")
    print(stats.summary())

    _log.info("Threaded demo completed. benign=%d suspicious=%d errors=%d",
              stats.benign, stats.suspicious, stats.errors)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args():
    p = argparse.ArgumentParser(
        description=(
            "Stage 4 End-to-End Demo -- Multi-Agent SOC.\n\n"
            "Runs the complete Producer → Stream → Consumer → Agent pipeline.\n"
            "Local real-time simulation using historical network-flow data."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python kafka/demo.py\n"
            "  python kafka/demo.py --count 20 --delay 0.5\n"
            "  python kafka/demo.py --count 20 --delay 0.2 --parallel\n"
            "  python kafka/demo.py --count 20 --inject-errors\n"
        ),
    )
    p.add_argument("--count",         type=int,   default=DEFAULT_EVENT_COUNT,
                   help="Number of real events to process. Default: %(default)s")
    p.add_argument("--delay",         type=float, default=DEFAULT_DELAY,
                   help="Seconds between events (--parallel mode). Default: %(default)s")
    p.add_argument("--balanced",      action="store_true",  default=True,
                   help="Select half Benign + half Attack records. Default: True")
    p.add_argument("--sequential",    dest="balanced", action="store_false",
                   help="Read records in CSV order.")
    p.add_argument("--parallel",      action="store_true",  default=False,
                   help="Run producer in background thread (shows true concurrency).")
    p.add_argument("--inject-errors", action="store_true",  default=False,
                   help="Inject 3 malformed events to test consumer error handling.")
    p.add_argument("--transport",     choices=["queue", "kafka"], default=DEFAULT_TRANSPORT,
                   help="Event transport. Default: %(default)s")
    return p.parse_args()


if __name__ == "__main__":
    args = _parse_args()

    if args.parallel:
        _run_pipeline_threaded(
            count=args.count,
            delay=args.delay,
            balanced=args.balanced,
            transport=args.transport,
            inject_errors=args.inject_errors,
        )
    else:
        _run_pipeline_sequential(
            count=args.count,
            delay=args.delay,
            balanced=args.balanced,
            transport=args.transport,
            inject_errors=args.inject_errors,
        )
