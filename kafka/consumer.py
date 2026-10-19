"""
kafka/consumer.py
==================
Network-Flow Event Consumer  /  Network Detection Agent integration

Multi-Agent SOC Project -- Stage 4: Real-Time Event Streaming
                            Stage 5: Central Event and Alert Storage

PURPOSE
-------
Receives network-flow events from the event stream, passes each event's
78 features to the existing Network Detection Agent (agents/network_detection/
agent.py), then generates a structured security alert, saves it to the
rolling JSON log, AND persists both the raw event and the alert to soc.db.

The consumer does NOT:
  * Duplicate model-loading logic (the Agent owns that).
  * Duplicate preprocessing logic (the Agent owns that).
  * Make any blocking / response decisions (later stages).

PROCESSING PIPELINE
-------------------
  Incoming Event (JSON)
       |
       v  extract + validate 78 features
  pandas DataFrame (1 row)
       |
       v  agent.analyze(df)
  NetworkDetectionAgent
       |
       v  Random Forest predict + predict_proba
  Prediction + Confidence
       |
       v  agent.generate_alert(...)
  Structured Alert dict
       |
       v  print to terminal + append to JSON log

ERROR HANDLING
--------------
The consumer is designed to be fault-tolerant.  A single badly-formed event
will be logged and skipped; subsequent events continue to be processed.

Handled error conditions:
  * Missing event_id          -> warning, processing continues with a generated ID
  * Unexpected event_type     -> warning, still attempts processing
  * Missing ``features`` key  -> error logged, event skipped
  * Missing individual feature -> agent fills with training median (logged)
  * Non-numeric feature value  -> agent fills with training median (logged)
  * Model prediction error     -> error logged, event skipped
  * JSON decode error (Kafka)  -> error logged, event skipped

ALERT FORMAT (preserved from Stage 3)
--------------------------------------
{
    "agent"              : "Network Detection Agent",
    "timestamp"          : "...",
    "prediction"         : "Infilteration" | "Benign",
    "confidence"         : 0.84,
    "severity"           : "HIGH" | "LOW",
    "status"             : "SUSPICIOUS" | "NORMAL",
    "note"               : "...",
    "class_probabilities": {...},
    "network_context"    : {...},
    "event_id"           : "...",      # added by consumer for cross-reference
    "actual_label"       : "..." | null,
    "processing_time_s"  : 0.034
}

USAGE
-----
  # Standalone (queue transport, waits for events from producer.py):
  python kafka/consumer.py

  # With explicit event count:
  python kafka/consumer.py --count 20

  # Kafka transport:
  python kafka/consumer.py --transport kafka --count 20

  # When run as part of the end-to-end demo (demo.py), this module is
  # imported directly via consume_events().
"""

import argparse
import datetime
import json
import logging
import pathlib
import sys
import time

import pandas as pd

# ---------------------------------------------------------------------------
# Project root on sys.path
# ---------------------------------------------------------------------------
PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from kafka.config import (
    LOG_DIR,
    STREAMING_LOG_FILE,
    STREAMING_ALERT_FILE,
    KAFKA_BOOTSTRAP_SERVERS,
    KAFKA_TOPIC,
    KAFKA_GROUP_ID,
    DEFAULT_TRANSPORT,
    DEFAULT_EVENT_COUNT,
    LABEL_COLUMN,
)
from kafka.stream import make_consumer
from agents.network_detection.agent import NetworkDetectionAgent

# Stage 5: SQLite storage (imported lazily)
try:
    from storage.db import AlertStore as _AlertStore
    _STORAGE_AVAILABLE = True
except ImportError:
    _STORAGE_AVAILABLE = False

# Stage 6: Anomaly Detection Agent (imported lazily so Stage 4 remains
# fully functional even if anomaly model is not yet trained)
try:
    from agents.anomaly_detection.agent import AnomalyDetectionAgent as _AnomalyAgent
    _ANOMALY_AVAILABLE = True
except ImportError:
    _ANOMALY_AVAILABLE = False

# Stage 7: Alert Correlation Agent
try:
    from agents.alert_correlation.agent import AlertCorrelationAgent as _CorrelationAgent
    _CORRELATION_AVAILABLE = True
except ImportError:
    _CORRELATION_AVAILABLE = False

# ---------------------------------------------------------------------------
# Logging -- file only so terminal stays clean during demos
# ---------------------------------------------------------------------------
LOG_DIR.mkdir(parents=True, exist_ok=True)

_log = logging.getLogger("SOC.Consumer")
if not _log.handlers:
    _fh = logging.FileHandler(STREAMING_LOG_FILE, encoding="utf-8")
    _fh.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    _log.addHandler(_fh)
    _log.setLevel(logging.DEBUG)
    _log.propagate = False

# agent logger also goes to the same file
_agent_log = logging.getLogger("NetworkDetectionAgent")
if not _agent_log.handlers:
    _agent_log.addHandler(logging.FileHandler(STREAMING_LOG_FILE, encoding="utf-8"))
    _agent_log.setLevel(logging.DEBUG)
    _agent_log.propagate = False

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


# ---------------------------------------------------------------------------
# Alert persistence
# ---------------------------------------------------------------------------

def _append_alert_to_file(alert: dict, log_file: pathlib.Path) -> None:
    """Append a single alert dict to any rolling JSON log file."""
    log_file.parent.mkdir(parents=True, exist_ok=True)
    if log_file.exists():
        try:
            existing = json.loads(log_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            existing = []
    else:
        existing = []

    existing.append(alert)
    log_file.write_text(
        json.dumps(existing, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def _append_alert(alert: dict) -> None:
    """Append a single alert dict to the streaming rolling JSON log file."""
    _append_alert_to_file(alert, STREAMING_ALERT_FILE)


# ---------------------------------------------------------------------------
# Terminal display
# ---------------------------------------------------------------------------

def _print_alert(seq: int, total: int, alert: dict, processing_time: float) -> None:
    """Pretty-print one alert result to stdout."""
    pred   = alert["prediction"]
    conf   = alert["confidence"]
    sev    = alert["severity"]
    status = alert["status"]
    actual = alert.get("actual_label")
    event_id = alert.get("event_id", "unknown")

    color = RED if pred == "Infilteration" else GREEN
    icon  = "[!!] INTRUSION DETECTED" if pred == "Infilteration" else "[ . ] Normal Traffic"

    print(f"\n  {color}{BOLD}{icon}{RESET}  |  Event {seq}/{total}")
    print(f"  {'Event ID':12}: {DIM}{event_id[:16]}...{RESET}")
    print(f"  {'Prediction':12}: {color}{BOLD}{pred}{RESET}")
    print(f"  {'Confidence':12}: {conf:.2%}")
    print(f"  {'Severity':12}: {color}{sev}{RESET}   Status: {status}")

    if actual is not None:
        match_color = GREEN if actual == pred else RED
        match_word  = "CORRECT" if actual == pred else "WRONG"
        print(f"  {'Actual Label':12}: {actual}  ({match_color}{match_word}{RESET})")

    print(f"  {'Process time':12}: {processing_time * 1000:.1f} ms")

    ctx = alert.get("network_context", {})
    if ctx:
        parts = [f"{k}={v}" for k, v in list(ctx.items())[:4]]
        print(f"  {'Context':12}: {CYAN}{',  '.join(parts)}{RESET}")


# ---------------------------------------------------------------------------
# Event → DataFrame conversion
# ---------------------------------------------------------------------------

def _event_to_dataframe(
    event: dict, feature_names: list
) -> tuple[pd.DataFrame, str]:
    """
    Extract the 78 model features from an event dict into a 1-row DataFrame.

    Args:
        event        : Parsed event dict from the stream.
        feature_names: Ordered list of the 78 required feature names.

    Returns:
        (df, event_id)  -- 1-row DataFrame ready for agent.analyze()

    Raises:
        ValueError: If the event is missing the 'features' key entirely.
        KeyError  : If the event dict is structurally broken.
    """
    event_id = event.get("event_id", f"unknown-{datetime.datetime.now().isoformat()}")

    features = event.get("features")
    if features is None:
        raise ValueError(f"Event {event_id} is missing the 'features' key.")

    # Build a row dict using only the 78 model feature names.
    # Missing features are set to None; the agent will fill them with medians.
    row = {feat: features.get(feat) for feat in feature_names}

    df = pd.DataFrame([row])
    return df, event_id


# ---------------------------------------------------------------------------
# Session summary
# ---------------------------------------------------------------------------

class _SessionStats:
    def __init__(self):
        self.total      = 0
        self.benign     = 0
        self.suspicious = 0
        self.errors     = 0
        self.correct    = 0
        self.labelled   = 0
        self.proc_times: list = []
        self.started    = datetime.datetime.now()

    def record(self, prediction: str, actual: str | None, proc_t: float):
        self.total += 1
        self.proc_times.append(proc_t)
        if prediction == "Infilteration":
            self.suspicious += 1
        else:
            self.benign += 1
        if actual is not None:
            self.labelled += 1
            if prediction == actual:
                self.correct += 1

    def record_error(self):
        self.errors += 1

    def summary(self) -> str:
        elapsed = datetime.datetime.now() - self.started
        avg_ms  = (sum(self.proc_times) / len(self.proc_times) * 1000) if self.proc_times else 0
        pct_sus = (self.suspicious / max(self.total - self.errors, 1)) * 100
        acc     = (self.correct / max(self.labelled, 1)) * 100

        lines = [
            "\n" + "=" * 60,
            "  STREAMING SESSION SUMMARY (Local real-time simulation)",
            "=" * 60,
            f"  Duration              : {str(elapsed).split('.')[0]}",
            f"  Events received       : {self.total}",
            f"  Benign                : {self.benign}",
            f"  SUSPICIOUS            : {self.suspicious}  ({pct_sus:.1f}%)",
            f"  Errors / Skipped      : {self.errors}",
        ]
        if self.labelled:
            lines.append(
                f"  Prediction accuracy   : {self.correct}/{self.labelled}  ({acc:.1f}%)"
            )
        if self.proc_times:
            lines.append(
                f"  Avg processing time   : {avg_ms:.1f} ms per event"
            )
        from storage.config import DB_PATH as _DB_PATH
        lines += [
            f"  Alert log             : {STREAMING_ALERT_FILE}",
            f"  SQLite database       : {_DB_PATH}",
            f"  Runtime log           : {STREAMING_LOG_FILE}",
            "=" * 60 + "\n",
        ]
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main consumer function
# ---------------------------------------------------------------------------

def consume_events(
    count: int = DEFAULT_EVENT_COUNT,
    transport: str = DEFAULT_TRANSPORT,
    topic: str = KAFKA_TOPIC,
    bootstrap_servers: str = KAFKA_BOOTSTRAP_SERVERS,
    group_id: str = KAFKA_GROUP_ID,
    poll_timeout: float = 10.0,
    silent: bool = False,
    event_queue=None,            # optional pre-built QueueConsumer/KafkaConsumer
) -> _SessionStats:
    """
    Listen to the event stream and pass each event to the Network Detection Agent.

    Args:
        count            : Expected number of events to process before exiting.
        transport        : "queue" or "kafka".
        topic            : Topic/queue name.
        bootstrap_servers: Kafka broker address.
        group_id         : Kafka consumer group ID.
        poll_timeout     : Seconds to wait for an event before each poll cycle.
        silent           : Suppress terminal output (used in unit tests).
        event_queue      : Optional pre-constructed consumer object (for demo.py).

    Returns:
        _SessionStats object with processing results.
    """

    def _print(*args, **kwargs):
        if not silent:
            print(*args, **kwargs)

    # ------------------------------------------------------------------ #
    # Initialise agent (loads model once, reused for all events)           #
    # ------------------------------------------------------------------ #
    _print(f"\n{BOLD}{CYAN}=== NETWORK-FLOW EVENT CONSUMER ==={RESET}")
    _print(f"  Transport  : {transport.upper()}")
    _print(f"  Topic      : {topic}")
    _print(f"  Expecting  : {count} event(s)")
    _print()

    _log.info("Consumer started. transport=%s topic=%s expecting=%d", transport, topic, count)

    try:
        agent = NetworkDetectionAgent()
    except FileNotFoundError as exc:
        _print(f"\n  {RED}[ERROR] Cannot load agent: {exc}{RESET}")
        _log.error("Agent init failed: %s", exc)
        return _SessionStats()

    feature_names = agent._feature_names       # 78-element list from preprocessing metadata
    _print(f"  {GREEN}Network Detection Agent ready. Features: {agent._n_features}{RESET}")

    # ------------------------------------------------------------------ #
    # Initialise Anomaly Detection Agent (Stage 6)                         #
    # ------------------------------------------------------------------ #
    _anomaly_agent = None
    if _ANOMALY_AVAILABLE:
        try:
            _anomaly_agent = _AnomalyAgent()
            _print(f"  {GREEN}Anomaly Detection Agent ready.  "
                   f"Threshold: {_anomaly_agent._threshold:.6f}{RESET}")
        except FileNotFoundError:
            _print(f"  {YELLOW}[Stage 6] Anomaly model not found -- "
                   f"run: python agents/anomaly_detection/train.py{RESET}")
        except Exception as _ae:
            _print(f"  {YELLOW}[Stage 6] Anomaly agent init failed: {str(_ae)[:80]}{RESET}")

    # ------------------------------------------------------------------ #
    # Initialise Alert Correlation Agent (Stage 7)                         #
    # ------------------------------------------------------------------ #
    _correlation_agent = None
    if _CORRELATION_AVAILABLE:
        try:
            _correlation_agent = _CorrelationAgent()
            _print(f"  {GREEN}Alert Correlation Agent ready.{RESET}")
        except Exception as _cae:
            _print(f"  {YELLOW}[Stage 7] Correlation agent init failed: {str(_cae)[:80]}{RESET}")

    from agents.anomaly_detection.config import ANOMALY_ALERT_FILE as _ANOMALY_ALERT_FILE
    _print(f"  {BOLD}Waiting for events -- press Ctrl+C to stop{RESET}")
    _print("  " + "-" * 56)

    # ------------------------------------------------------------------ #
    # Create consumer (or reuse pre-built one)                             #
    # ------------------------------------------------------------------ #
    consumer = event_queue if event_queue is not None else make_consumer(
        transport=transport,
        topic=topic,
        bootstrap_servers=bootstrap_servers,
        group_id=group_id,
        timeout_s=poll_timeout,
    )

    stats     = _SessionStats()
    processed = 0

    try:
        while processed < count:
            event = consumer.poll(timeout_s=poll_timeout)

            if event is None:
                # Timeout -- heartbeat
                _print(f"\r  {DIM}[waiting for events...]  "
                       f"Processed: {processed}/{count}{RESET}", end="", flush=True)
                continue

            # ---------------------------------------------------------- #
            # Process event                                                #
            # ---------------------------------------------------------- #
            seq       = event.get("sequence", processed + 1)
            actual    = event.get("actual_label")
            event_id  = event.get("event_id", "unknown")

            _log.info("Event received: seq=%d event_id=%s", seq, event_id)

            t_start = time.perf_counter()

            try:
                # Convert event features -> 1-row DataFrame
                df, eid = _event_to_dataframe(event, feature_names)

                # Run agent (preprocess → predict → generate_alert)
                alerts = agent.analyze(df)
                alert  = alerts[0]

                t_elapsed = time.perf_counter() - t_start

                # Enrich alert with streaming metadata
                alert["event_id"]        = eid
                alert["actual_label"]    = actual
                alert["processing_time_s"] = round(t_elapsed, 6)

                # Stage 4: append to rolling JSON log (unchanged)
                _append_alert(alert)

                # Stage 6: Run Anomaly Detection Agent on the same event
                if _anomaly_agent is not None:
                    try:
                        t_a_start       = time.perf_counter()
                        anomaly_alerts  = _anomaly_agent.analyze(df)
                        t_a_elapsed     = time.perf_counter() - t_a_start
                        anomaly_alert   = anomaly_alerts[0]

                        # Enrich anomaly alert with streaming metadata
                        anomaly_alert["event_id"]          = eid
                        anomaly_alert["actual_label"]      = actual
                        anomaly_alert["processing_time_s"] = round(t_a_elapsed, 6)

                        # Append to Anomaly Detection JSON log
                        _append_alert_to_file(anomaly_alert, _ANOMALY_ALERT_FILE)

                        # Print compact anomaly line
                        a_pred  = anomaly_alert.get("prediction", "?")
                        a_score = anomaly_alert.get("anomaly_score", 0.0)
                        a_sev   = anomaly_alert.get("severity", "?")
                        a_color = RED if a_pred == "Anomalous" else GREEN
                        _print(
                            f"  {'Anomaly':12}: {a_color}{a_pred}{RESET}  "
                            f"score={a_score:.4f}  sev={a_color}{a_sev}{RESET}  "
                            f"({t_a_elapsed*1000:.1f} ms)"
                        )
                        _log.info(
                            "Anomaly result: event_id=%s prediction=%s score=%.6f",
                            eid, a_pred, a_score,
                        )

                    except Exception as _ae:
                        _log.error(
                            "[Stage 6] Anomaly agent failed for event_id=%s: %s",
                            eid, _ae,
                        )
                        anomaly_alert = None
                else:
                    anomaly_alert = None

                # Stage 7: Run Alert Correlation Agent
                incident = None
                if _correlation_agent is not None:
                    try:
                        # Collect all alerts created for this event
                        current_alerts = [alert]
                        if anomaly_alert:
                            current_alerts.append(anomaly_alert)
                        
                        incidents_out = _correlation_agent.correlate(current_alerts)
                        if incidents_out:
                            incident = incidents_out[0]
                            i_sev = incident.get("severity", "?")
                            i_color = RED if i_sev == "HIGH" else (YELLOW if i_sev == "MEDIUM" else GREEN)
                            _print(f"  {'Incident':12}: {i_color}{incident.get('status')}{RESET}  "
                                   f"sev={i_color}{i_sev}{RESET}  (Agents: {len(incident.get('alert_ids', []))})")
                            
                    except Exception as _cae:
                        _log.error("[Stage 7] Correlation failed for event_id=%s: %s", eid, _cae)

                # Stage 5, 6 & 7: persist event + alerts + incident to SQLite
                if _STORAGE_AVAILABLE:
                    try:
                        with _AlertStore() as _store:
                            _store.save_event(event) # FK parent goes first
                            _store.save_alert(alert) # ND alert
                            if anomaly_alert:
                                _store.save_alert(anomaly_alert) # Anomaly alert
                            if incident:
                                _store.save_incident(incident) # Correlated incident
                        _log.debug("Saved to soc.db: event_id=%s", eid)
                    except Exception as _db_exc:
                        _log.error(
                            "[Storage] Failed to save event_id=%s to soc.db: %s",
                            eid, _db_exc,
                        )
                        _print(
                            f"\n  {YELLOW}[Storage WARNING] Could not write to "
                            f"soc.db: {str(_db_exc)[:100]}{RESET}"
                        )

                stats.record(alert["prediction"], actual, t_elapsed)
                processed += 1

                _print_alert(processed, count, alert, t_elapsed)

                _log.info(
                    "Prediction complete: seq=%d event_id=%s prediction=%s "
                    "confidence=%.4f severity=%s time=%.4fs",
                    seq, eid, alert["prediction"], alert["confidence"],
                    alert["severity"], t_elapsed,
                )

                if alert["prediction"] == "Infilteration":
                    _log.warning(
                        "SUSPICIOUS traffic detected: event_id=%s confidence=%.4f",
                        eid, alert["confidence"],
                    )

            except ValueError as exc:
                t_elapsed = time.perf_counter() - t_start
                stats.record_error()
                processed += 1
                _print(f"\n  {YELLOW}[SKIP] Event {seq}: {str(exc)[:120]}{RESET}")
                _log.error("Processing error for event_id=%s: %s", event_id, exc)

            except Exception as exc:
                t_elapsed = time.perf_counter() - t_start
                stats.record_error()
                processed += 1
                _print(f"\n  {RED}[ERROR] Event {seq} ({type(exc).__name__}): "
                       f"{str(exc)[:120]}{RESET}")
                _log.error("Unexpected error for event_id=%s: %s", event_id, exc, exc_info=True)

    except KeyboardInterrupt:
        _print(f"\n\n  {YELLOW}[Consumer] Stopped by user (Ctrl+C){RESET}")
        _log.info("Consumer stopped by user after %d events.", processed)

    consumer.close()

    _print(f"\n  {GREEN}Consumer finished. {processed} event(s) processed.{RESET}")
    _log.info("Consumer finished. processed=%d errors=%d", processed, stats.errors)

    return stats


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _parse_args():
    p = argparse.ArgumentParser(
        description=(
            "Network-Flow Event Consumer -- Multi-Agent SOC Stage 4.\n\n"
            "Listens to the event stream and passes each event to the "
            "Network Detection Agent for classification."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python kafka/consumer.py\n"
            "  python kafka/consumer.py --count 20\n"
            "  python kafka/consumer.py --transport kafka --count 20\n"
        ),
    )
    p.add_argument("--count",     type=int,   default=DEFAULT_EVENT_COUNT,
                   help="Number of events to process. Default: %(default)s")
    p.add_argument("--transport", choices=["queue", "kafka"], default=DEFAULT_TRANSPORT,
                   help="Event transport. Default: %(default)s")
    p.add_argument("--topic",     default=KAFKA_TOPIC,
                   help="Topic/queue name. Default: %(default)s")
    p.add_argument("--broker",    default=KAFKA_BOOTSTRAP_SERVERS,
                   help="Kafka broker address (kafka transport only).")
    p.add_argument("--group",     default=KAFKA_GROUP_ID,
                   help="Kafka consumer group ID.")
    p.add_argument("--timeout",   type=float, default=10.0,
                   help="Seconds to wait for each event before polling again. Default: 10")
    return p.parse_args()


if __name__ == "__main__":
    args   = _parse_args()
    stats  = consume_events(
        count=args.count,
        transport=args.transport,
        topic=args.topic,
        bootstrap_servers=args.broker,
        group_id=args.group,
        poll_timeout=args.timeout,
    )
    print(stats.summary())
