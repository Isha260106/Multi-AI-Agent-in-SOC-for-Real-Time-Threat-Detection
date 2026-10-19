"""
storage/ingest.py
==================
JSON Log Migration / Backfill

Multi-Agent SOC Project -- Stage 5: Central Event and Alert Storage

PURPOSE
-------
Reads existing JSON alert log files produced by Stage 3 and Stage 4 scripts
and inserts their records into the soc.db SQLite database.

This is an idempotent operation: running ingest.py multiple times is safe.
Duplicate records are detected by alert_id (which is generated deterministically
from available fields) and silently skipped.

SUPPORTED LOG FILES
-------------------
  logs/streaming_alerts.json      -- Stage 4 consumer (has event_id + processing_time_s)
  logs/network_detection_alerts.json -- Stage 3 test   (no event_id, no processing_time_s)
  logs/live_monitor_alerts.json   -- Stage 3 live monitor (no event_id, no processing_time_s)

OBSERVED JSON STRUCTURES
------------------------
streaming_alerts.json records:
  {
    "agent", "timestamp", "prediction", "confidence", "severity", "status",
    "note", "class_probabilities", "network_context",
    "event_id",           <-- present (Stage 4)
    "actual_label",       <-- present (may be null)
    "processing_time_s"   <-- present
  }

network_detection_alerts.json records:
  {
    "actual_label",       <-- at top
    "agent", "timestamp", "prediction", "confidence", "severity", "status",
    "note", "class_probabilities", "network_context"
    -- NO event_id
    -- NO processing_time_s
  }

live_monitor_alerts.json records:
  {
    "agent", "timestamp", "prediction", "confidence", "severity", "status",
    "note", "class_probabilities", "network_context",
    "actual_label"        <-- at bottom
    -- NO event_id
    -- NO processing_time_s
  }

ALERT_ID GENERATION
-------------------
For records that already have event_id and timestamp, alert_id is derived as:
    sha1(event_id + "|" + timestamp)[:32]

For legacy records (no event_id), alert_id is derived as:
    sha1(agent + "|" + timestamp + "|" + prediction + "|" + str(confidence))[:32]

This ensures idempotency across re-runs.

USAGE
-----
  python storage/ingest.py                    -- ingest all three log files
  python storage/ingest.py --file streaming   -- ingest only streaming log
"""

import argparse
import hashlib
import json
import logging
import pathlib
import sys

# ---------------------------------------------------------------------------
# Project path
# ---------------------------------------------------------------------------
PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from storage.config import ALERT_LOGS, STREAMING_RUNTIME_LOG
from storage.db import AlertStore

# ---------------------------------------------------------------------------
# Logging -- file + console summary
# ---------------------------------------------------------------------------
_log = logging.getLogger("SOC.Storage.Ingest")
if not _log.handlers:
    STREAMING_RUNTIME_LOG.parent.mkdir(parents=True, exist_ok=True)
    _fh = logging.FileHandler(STREAMING_RUNTIME_LOG, encoding="utf-8")
    _fh.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    _log.addHandler(_fh)
    _log.setLevel(logging.DEBUG)
    _log.propagate = False

# ---------------------------------------------------------------------------
# alert_id generation
# ---------------------------------------------------------------------------

def _make_alert_id(record: dict) -> str:
    """
    Generate a stable, unique alert_id for a log record.

    If the record has both event_id and timestamp, use those.
    Otherwise fall back to agent + timestamp + prediction + confidence.
    """
    event_id  = record.get("event_id")
    timestamp = record.get("timestamp", "")
    agent     = record.get("agent", "")
    pred      = record.get("prediction", "")
    conf      = str(record.get("confidence", ""))

    if event_id:
        raw = f"{event_id}|{timestamp}"
    else:
        raw = f"{agent}|{timestamp}|{pred}|{conf}"

    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:32]


# ---------------------------------------------------------------------------
# Single-file ingest
# ---------------------------------------------------------------------------

def ingest_file(
    log_path: pathlib.Path,
    store: AlertStore,
    label: str = "",
) -> dict:
    """
    Read one JSON alert log file and insert its records into soc.db.

    Args:
        log_path : Path to the JSON file (list of alert dicts).
        store    : Open AlertStore instance.
        label    : Human-readable name for progress output.

    Returns:
        {
            "read"       : int,  -- records successfully parsed
            "inserted"   : int,  -- new rows written to DB
            "duplicates" : int,  -- rows skipped (already in DB)
            "errors"     : int,  -- records that could not be parsed
        }
    """
    counts = {"read": 0, "inserted": 0, "duplicates": 0, "errors": 0}

    if not log_path.exists():
        print(f"  [SKIP] File not found: {log_path}")
        _log.warning("Ingest skipped -- file not found: %s", log_path)
        return counts

    try:
        raw_text = log_path.read_text(encoding="utf-8")
        records  = json.loads(raw_text)
    except (json.JSONDecodeError, OSError) as exc:
        print(f"  [ERROR] Cannot read {log_path}: {exc}")
        _log.error("Cannot read log file %s: %s", log_path, exc)
        counts["errors"] += 1
        return counts

    if not isinstance(records, list):
        print(f"  [ERROR] {log_path} does not contain a JSON array.")
        counts["errors"] += 1
        return counts

    total = len(records)
    print(f"  {label}: {total} records found in {log_path.name}")
    _log.info("Ingesting %d records from %s", total, log_path)

    for i, record in enumerate(records):
        if not isinstance(record, dict):
            counts["errors"] += 1
            _log.warning("Record %d in %s is not a dict -- skipped.", i, log_path.name)
            continue

        counts["read"] += 1

        try:
            # Attach a deterministic alert_id
            record["alert_id"] = _make_alert_id(record)

            # Strip event_id from all JSON log records.
            # The events table is only populated by the live consumer; legacy log
            # records (including streaming_alerts.json from past runs) don't have
            # corresponding parent rows, so the FK constraint would reject them.
            # Setting event_id to None makes them first-class legacy alerts.
            record["event_id"] = None

            inserted = store.save_alert(record)

            if inserted:
                counts["inserted"] += 1
            else:
                counts["duplicates"] += 1

        except Exception as exc:
            counts["errors"] += 1
            _log.error(
                "Failed to ingest record %d from %s: %s",
                i, log_path.name, exc
            )

    return counts


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run_ingest(sources: list[str] | None = None) -> None:
    """
    Ingest alert logs into soc.db.

    Args:
        sources: List of source keys ("streaming", "network_detection",
                 "live_monitor"). If None, all three are processed.
    """
    if sources is None:
        sources = list(ALERT_LOGS.keys())

    print("\n" + "=" * 60)
    print("  Multi-Agent SOC -- Stage 5: Log Ingestion")
    print("=" * 60)

    _log.info("Ingest started. sources=%s", sources)

    totals = {"read": 0, "inserted": 0, "duplicates": 0, "errors": 0}

    with AlertStore() as store:
        print(f"\n  Database : {store._db_path}")
        print(f"  Events   : {store.event_count()} existing rows")
        print(f"  Alerts   : {store.alert_count()} existing rows")
        print()

        for source in sources:
            log_path = ALERT_LOGS.get(source)
            if log_path is None:
                print(f"  [WARN] Unknown source: {source!r}")
                continue

            counts = ingest_file(log_path, store, label=source)
            for k in totals:
                totals[k] += counts[k]
            print(
                f"    read={counts['read']}  "
                f"inserted={counts['inserted']}  "
                f"duplicates={counts['duplicates']}  "
                f"errors={counts['errors']}"
            )

        print()
        print(f"  Events after ingest : {store.event_count()}")
        print(f"  Alerts after ingest : {store.alert_count()}")

    print()
    print("  TOTALS")
    print(f"    Records read     : {totals['read']}")
    print(f"    Inserted         : {totals['inserted']}")
    print(f"    Duplicates (skip): {totals['duplicates']}")
    print(f"    Errors           : {totals['errors']}")
    print()
    if totals["errors"] > 0:
        print("  [WARN] Some records could not be ingested. Check streaming_runtime.log.")
    else:
        print("  Ingest completed successfully.")
    print("=" * 60 + "\n")

    _log.info(
        "Ingest finished. read=%d inserted=%d duplicates=%d errors=%d",
        totals["read"], totals["inserted"], totals["duplicates"], totals["errors"],
    )


def _parse_args():
    p = argparse.ArgumentParser(
        description=(
            "Ingest existing JSON alert logs into soc.db.\n"
            "Multi-Agent SOC -- Stage 5."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python storage/ingest.py\n"
            "  python storage/ingest.py --file streaming\n"
            "  python storage/ingest.py --file network_detection live_monitor\n"
        ),
    )
    p.add_argument(
        "--file",
        nargs="+",
        choices=list(ALERT_LOGS.keys()),
        default=None,
        dest="sources",
        help="Which log files to ingest. Default: all three.",
    )
    return p.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    run_ingest(sources=args.sources)
