"""
kafka/producer.py
==================
Network-Flow Event Producer

Multi-Agent SOC Project -- Stage 4: Real-Time Event Streaming

PURPOSE
-------
Reads historical network-flow records from the cleaned dataset and re-plays
them one at a time as structured events, simulating a live network feed.

IMPORTANT NOTES
---------------
* Historical dataset records are replayed to simulate real-time network events.
  The CSV itself is NOT live traffic -- it is being used for controlled
  simulation / testing purposes only.

* The model input features (78 columns) are transmitted as-is.
  The 'Label' column is NEVER included in the event features sent to the
  consumer / model.  The label is only stored in the event metadata so that
  the end-to-end test can verify prediction accuracy.

* The producer reads the dataset in chunks (CSV_CHUNK_SIZE rows at a time)
  so it never loads the entire ~330k-row file into memory.

EVENT FORMAT
------------
{
    "event_id"   : "<uuid4>",
    "event_type" : "network_flow",
    "timestamp"  : "<ISO-8601>",
    "source"     : "historical_replay",
    "sequence"   : <int>,           # 1-based counter within this session
    "actual_label": "<str> | null", # ground-truth label (for test/demo only)
    "features"   : {
        "Dst Port"      : <float>,
        "Protocol"      : <float>,
        "Flow Duration" : <float>,
        ...                         # all 78 model features
    }
}

USAGE
-----
  # Standalone (queue transport, default 20 events, 1-second delay):
  python kafka/producer.py

  # Custom count and delay:
  python kafka/producer.py --count 20 --delay 0.5

  # Mix benign + attack records regardless of CSV order:
  python kafka/producer.py --balanced --count 20

  # Kafka transport (requires running Kafka broker):
  python kafka/producer.py --transport kafka --count 20

  # When run as part of the end-to-end demo (demo.py), this module is
  # imported directly.
"""

import argparse
import datetime
import json
import logging
import pathlib
import sys
import time
import uuid

import pandas as pd

# ---------------------------------------------------------------------------
# Project root on sys.path so we can import from kafka/ and agents/
# ---------------------------------------------------------------------------
PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from kafka.config import (
    DATASET_PATH,
    LOG_DIR,
    STREAMING_LOG_FILE,
    KAFKA_BOOTSTRAP_SERVERS,
    KAFKA_TOPIC,
    DEFAULT_TRANSPORT,
    DEFAULT_DELAY,
    DEFAULT_EVENT_COUNT,
    CSV_CHUNK_SIZE,
    EVENT_TYPE,
    LABEL_COLUMN,
)
from kafka.stream import make_producer

# ---------------------------------------------------------------------------
# Logging -- file only so terminal stays clean
# ---------------------------------------------------------------------------
LOG_DIR.mkdir(parents=True, exist_ok=True)

_log = logging.getLogger("SOC.Producer")
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
# ANSI colours for Windows terminal
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

CYAN   = "\033[96m" if ANSI else ""
GREEN  = "\033[92m" if ANSI else ""
YELLOW = "\033[93m" if ANSI else ""
BOLD   = "\033[1m"  if ANSI else ""
RESET  = "\033[0m"  if ANSI else ""


# ---------------------------------------------------------------------------
# Record selection helpers
# ---------------------------------------------------------------------------

def _select_balanced_records(dataset_path: pathlib.Path, n_total: int) -> pd.DataFrame:
    """
    Return a near-balanced sample of records: roughly half Benign, half
    Infilteration, with total row count equal to ``n_total``.

    Uses chunked reading so only a small portion of the file is in memory
    at any one time.  Scans the file until both pools have enough rows.

    NOTE: The cleaned_dataset.csv is ordered with all Benign records first
    and Infilteration records later.  We cannot stop early after a fixed
    number of rows -- we must scan until both pools are filled.
    Each pool is capped at ``n_attack * 3`` rows to bound memory.
    """
    # Split count evenly; the extra 1 (for odd n_total) goes to Benign.
    n_attack = n_total // 2
    n_benign = n_total - n_attack    # handles odd n_total correctly
    pool_cap  = max(n_attack, n_benign) * 3

    benign_pool: list = []
    attack_pool: list = []

    for chunk in pd.read_csv(dataset_path, chunksize=CSV_CHUNK_SIZE, low_memory=False):
        if LABEL_COLUMN in chunk.columns:
            if len(benign_pool) < pool_cap:
                benign_pool.extend(
                    chunk[chunk[LABEL_COLUMN] == "Benign"].to_dict(orient="records")
                )
            if len(attack_pool) < pool_cap:
                attack_pool.extend(
                    chunk[chunk[LABEL_COLUMN] == "Infilteration"].to_dict(orient="records")
                )
        # Stop when both pools are large enough to sample from
        if len(benign_pool) >= n_benign and len(attack_pool) >= n_attack:
            break

    import random
    random.seed(42)
    sampled_benign = random.sample(benign_pool, min(n_benign, len(benign_pool)))
    sampled_attack = random.sample(attack_pool, min(n_attack, len(attack_pool)))

    combined = sampled_benign + sampled_attack
    random.shuffle(combined)
    return pd.DataFrame(combined)


def _select_sequential_records(
    dataset_path: pathlib.Path, n_total: int
) -> pd.DataFrame:
    """
    Return the first ``n_total`` records from the CSV using chunked reading.
    """
    rows: list = []
    for chunk in pd.read_csv(dataset_path, chunksize=CSV_CHUNK_SIZE, low_memory=False):
        rows.extend(chunk.to_dict(orient="records"))
        if len(rows) >= n_total:
            break
    return pd.DataFrame(rows[:n_total])


# ---------------------------------------------------------------------------
# Event builder
# ---------------------------------------------------------------------------

def build_event(row: dict, feature_names: list, sequence: int) -> dict:
    """
    Construct a structured network-flow event dict from a raw CSV row.

    The Label column is captured separately and stored in ``actual_label``
    (used only for test/demo accuracy verification).  It is NEVER placed
    inside ``features`` -- the model never sees the label.

    Args:
        row           : dict of column -> value from the CSV row
        feature_names : ordered list of the 78 model feature names
        sequence      : 1-based event counter in this session

    Returns:
        A fully-formed event dict ready to send to the stream.
    """
    actual_label = row.get(LABEL_COLUMN)   # may be None if column absent

    features = {}
    for feat in feature_names:
        val = row.get(feat)
        if val is not None:
            try:
                features[feat] = float(val)
            except (TypeError, ValueError):
                features[feat] = None   # consumer will handle this gracefully

    event = {
        "event_id":     str(uuid.uuid4()),
        "event_type":   EVENT_TYPE,
        "timestamp":    datetime.datetime.now().isoformat(),
        "source":       "historical_replay",
        "sequence":     sequence,
        "actual_label": actual_label,   # ground-truth for validation only
        "features":     features,
    }
    return event


# ---------------------------------------------------------------------------
# Main producer function
# ---------------------------------------------------------------------------

def run_producer(
    count: int = DEFAULT_EVENT_COUNT,
    delay: float = DEFAULT_DELAY,
    balanced: bool = True,
    transport: str = DEFAULT_TRANSPORT,
    topic: str = KAFKA_TOPIC,
    bootstrap_servers: str = KAFKA_BOOTSTRAP_SERVERS,
    feature_names: list | None = None,
    silent: bool = False,
) -> list:
    """
    Load records from the cleaned dataset and publish them as events.

    Args:
        count             : Number of events to send.
        delay             : Seconds to wait between events (simulation speed).
        balanced          : If True, selects half Benign + half Infilteration.
        transport         : "queue" or "kafka".
        topic             : Event topic / queue name.
        bootstrap_servers : Kafka bootstrap address (ignored for queue transport).
        feature_names     : Explicit list of 78 feature names.  If None, the
                            producer derives them from the preprocessing metadata.
        silent            : If True, suppress all print() output (used in demo.py).

    Returns:
        List of sent event dicts (useful for the end-to-end demo).
    """

    def _print(*args, **kwargs):
        if not silent:
            print(*args, **kwargs)

    # ------------------------------------------------------------------ #
    # Resolve the 78 feature names from preprocessing metadata             #
    # ------------------------------------------------------------------ #
    if feature_names is None:
        import joblib
        from kafka.config import PREP_PATH
        if not PREP_PATH.exists():
            raise FileNotFoundError(
                f"Preprocessing metadata not found: {PREP_PATH}\n"
                "Ensure Stage 3 is complete and the .pkl files exist."
            )
        prep = joblib.load(PREP_PATH)
        feature_names = prep["feature_names"]   # ordered list of 78 names

    # ------------------------------------------------------------------ #
    # Load records                                                         #
    # ------------------------------------------------------------------ #
    _print(f"\n{BOLD}{CYAN}=== NETWORK-FLOW EVENT PRODUCER ==={RESET}")
    _print(f"  Transport : {transport.upper()}")
    _print(f"  Topic     : {topic}")
    _print(f"  Events    : {count}")
    _print(f"  Delay     : {delay}s per event")
    _print(f"  Selection : {'Balanced (Benign + Attack)' if balanced else 'Sequential'}")
    _print(f"  Dataset   : {DATASET_PATH}")
    _print()
    _print(f"  {YELLOW}NOTE: Historical dataset records are replayed to simulate")
    _print(f"  real-time network events. The CSV is NOT itself live traffic.{RESET}")
    _print()

    _log.info("Producer started. transport=%s topic=%s count=%d delay=%.2fs",
              transport, topic, count, delay)

    if balanced:
        df = _select_balanced_records(DATASET_PATH, count)
    else:
        df = _select_sequential_records(DATASET_PATH, count)

    if df.empty:
        _print(f"  {YELLOW}[WARN] Dataset is empty or not found.{RESET}")
        _log.warning("Dataset empty or could not be read: %s", DATASET_PATH)
        return []

    # ------------------------------------------------------------------ #
    # Create producer                                                       #
    # ------------------------------------------------------------------ #
    producer = make_producer(transport, topic, bootstrap_servers)

    # ------------------------------------------------------------------ #
    # Send events                                                           #
    # ------------------------------------------------------------------ #
    sent_events: list = []
    rows = df.to_dict(orient="records")

    _print(f"  {BOLD}Sending {len(rows)} event(s) -- press Ctrl+C to stop{RESET}")
    _print("  " + "-" * 56)

    try:
        for i, row in enumerate(rows, start=1):
            event = build_event(row, feature_names, sequence=i)
            producer.send(event)
            sent_events.append(event)

            # Print concise event summary (not all 78 features)
            label_info = (
                f"Actual={event['actual_label']}" if event["actual_label"] else "no label"
            )
            _print(
                f"  {GREEN}[Sent]{RESET} "
                f"Event #{i:>3}  |  ID: {event['event_id'][:8]}...  |  {label_info}"
            )
            _log.info("Event sent: seq=%d event_id=%s actual_label=%s",
                      i, event["event_id"], event.get("actual_label"))

            if i < len(rows):
                time.sleep(delay)

    except KeyboardInterrupt:
        _print(f"\n  {YELLOW}[Producer] Stopped by user (Ctrl+C){RESET}")
        _log.info("Producer stopped by user after %d events.", len(sent_events))

    producer.flush()
    producer.close()

    _print(f"\n  {GREEN}Producer finished. {len(sent_events)} event(s) sent.{RESET}")
    _log.info("Producer finished. sent=%d", len(sent_events))

    return sent_events


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _parse_args():
    p = argparse.ArgumentParser(
        description=(
            "Network-Flow Event Producer -- Multi-Agent SOC Stage 4.\n\n"
            "Replays historical network-flow records as real-time events.\n"
            "Historical dataset records are replayed to simulate real-time\n"
            "network events. The CSV is NOT itself live traffic."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python kafka/producer.py\n"
            "  python kafka/producer.py --count 20 --delay 0.5\n"
            "  python kafka/producer.py --count 20 --balanced\n"
            "  python kafka/producer.py --transport kafka --count 20\n"
        ),
    )
    p.add_argument("--count",     type=int,   default=DEFAULT_EVENT_COUNT,
                   help="Number of events to send. Default: %(default)s")
    p.add_argument("--delay",     type=float, default=DEFAULT_DELAY,
                   help="Seconds between events. Default: %(default)s")
    p.add_argument("--balanced",  action="store_true", default=True,
                   help="Select half Benign + half Attack records. Default: True")
    p.add_argument("--sequential", dest="balanced", action="store_false",
                   help="Read records in CSV order instead of balanced selection.")
    p.add_argument("--transport", choices=["queue", "kafka"], default=DEFAULT_TRANSPORT,
                   help="Event transport. Default: %(default)s")
    p.add_argument("--topic",     default=KAFKA_TOPIC,
                   help="Topic/queue name. Default: %(default)s")
    p.add_argument("--broker",    default=KAFKA_BOOTSTRAP_SERVERS,
                   help="Kafka broker address (kafka transport only).")
    return p.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    run_producer(
        count=args.count,
        delay=args.delay,
        balanced=args.balanced,
        transport=args.transport,
        topic=args.topic,
        bootstrap_servers=args.broker,
    )
