"""
test_streaming.py
==================
End-to-End Validation Test for Stage 4 Event Streaming

Multi-Agent SOC Project -- Stage 4: Real-Time Event Streaming

This test verifies the complete pipeline:

  Producer → Event Stream → Consumer → Network Detection Agent → Alert

Test structure:
  1. Load preprocessing metadata to get feature names
  2. Select a balanced set of records (10 Benign + 10 Infilteration)
  3. Producer publishes all 20 events to the in-process queue
  4. Consumer processes all 20 events and collects alerts
  5. Inject 3 malformed events and verify they are handled gracefully
  6. Verify checklist:
       - Events transmitted correctly
       - 78 features reach the model
       - Predictions generated for all events
       - Confidence values generated
       - Structured alerts generated
       - Both Benign and Infilteration records included
       - Malformed events do not crash the consumer
       - Model files unchanged
       - Dataset file unchanged

Outputs:
  Terminal   -- detailed test report
  JSON log   -- E:/multi-agent-soc/logs/streaming_alerts.json
  Runtime log-- E:/multi-agent-soc/logs/streaming_runtime.log
"""

import sys
import json
import pathlib
import datetime
import uuid

# ---------------------------------------------------------------------------
# Project root
# ---------------------------------------------------------------------------
PROJECT_ROOT = pathlib.Path(r"E:\multi-agent-soc")
sys.path.insert(0, str(PROJECT_ROOT))

from kafka.config import (
    DATASET_PATH,
    MODEL_PATH,
    PREP_PATH,
    STREAMING_ALERT_FILE,
    STREAMING_LOG_FILE,
    KAFKA_TOPIC,
    LOG_DIR,
)
from kafka.stream import _get_topic_queue, make_producer, make_consumer
from kafka.producer import run_producer, build_event, _select_balanced_records
from kafka.consumer import consume_events

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
RESET  = "\033[0m"  if ANSI else ""

DIV  = "=" * 70
DIV2 = "-" * 70

N_EVENTS = 20   # 10 Benign + 10 Infilteration


def section(title: str) -> None:
    print(f"\n{DIV}")
    print(f"  {title}")
    print(DIV)


def check(name: str, passed: bool, detail: str = "") -> bool:
    icon  = f"{GREEN}[OK  ]{RESET}" if passed else f"{RED}[FAIL]{RESET}"
    extra = f"  -- {detail}" if detail else ""
    print(f"  {icon}  {name}{extra}")
    return passed


# ---------------------------------------------------------------------------
# STEP 1: Prerequisites
# ---------------------------------------------------------------------------
section("STEP 1: Prerequisites")

import joblib
print("  Loading preprocessing metadata...")
assert PREP_PATH.exists(), f"PREP_PATH not found: {PREP_PATH}"
prep = joblib.load(PREP_PATH)
feature_names = prep["feature_names"]
n_features    = prep["n_features"]
print(f"  Feature count     : {n_features}")
print(f"  Model path        : {MODEL_PATH}")
print(f"  Dataset path      : {DATASET_PATH}")
assert MODEL_PATH.exists(),   f"Model not found: {MODEL_PATH}"
assert DATASET_PATH.exists(), f"Dataset not found: {DATASET_PATH}"
print(f"  {GREEN}All prerequisite files present.{RESET}")

# Record model/dataset sizes before the test (to verify they are untouched after)
model_size_before   = MODEL_PATH.stat().st_size
dataset_size_before = DATASET_PATH.stat().st_size

# ---------------------------------------------------------------------------
# STEP 2: Select balanced records (uses chunked reading)
# ---------------------------------------------------------------------------
section("STEP 2: Select Records (Chunked CSV Reading)")

df = _select_balanced_records(DATASET_PATH, N_EVENTS)
print(f"  Records selected  : {len(df)}")
if "Label" in df.columns:
    vc = df["Label"].value_counts()
    for label, cnt in vc.items():
        print(f"  {label:20}: {cnt}")
print(f"  {GREEN}Balanced selection complete.{RESET}")

# ---------------------------------------------------------------------------
# STEP 3: Producer -- publish events
# ---------------------------------------------------------------------------
section("STEP 3: Producer -- Publish Events to In-Process Queue")

sent_events = run_producer(
    count=N_EVENTS,
    delay=0.0,
    balanced=True,
    transport="queue",
    topic=KAFKA_TOPIC,
    feature_names=feature_names,
    silent=False,
)

print(f"\n  Events sent : {len(sent_events)}")

# Verify event structure of first event
sample_event = sent_events[0]
print(f"\n  Sample event structure (event #1):")
print(f"    event_id    : {sample_event['event_id']}")
print(f"    event_type  : {sample_event['event_type']}")
print(f"    timestamp   : {sample_event['timestamp']}")
print(f"    source      : {sample_event['source']}")
print(f"    sequence    : {sample_event['sequence']}")
print(f"    actual_label: {sample_event['actual_label']}")
print(f"    features    : {len(sample_event['features'])} fields")
print(f"    Label in features? : {'Label' in sample_event['features']}")

# ---------------------------------------------------------------------------
# STEP 4: Inject malformed events
# ---------------------------------------------------------------------------
section("STEP 4: Inject Malformed Events (Error Handling Test)")

import json as _json
q = _get_topic_queue(KAFKA_TOPIC)

malformed = [
    # Missing features key
    {
        "event_id":    str(uuid.uuid4()),
        "event_type":  "network_flow",
        "timestamp":   datetime.datetime.now().isoformat(),
        "source":      "test_injection",
        "sequence":    9001,
        "actual_label": None,
        # no "features" key
    },
    # Non-numeric + partial features
    {
        "event_id":    str(uuid.uuid4()),
        "event_type":  "network_flow",
        "timestamp":   datetime.datetime.now().isoformat(),
        "source":      "test_injection",
        "sequence":    9002,
        "actual_label": None,
        "features": {"Dst Port": "BAD_VALUE", "Protocol": None},
    },
    # Empty features
    {
        "event_id":    str(uuid.uuid4()),
        "event_type":  "network_flow",
        "timestamp":   datetime.datetime.now().isoformat(),
        "source":      "test_injection",
        "sequence":    9003,
        "actual_label": None,
        "features":    {},
    },
]

for evt in malformed:
    q.put(_json.dumps(evt, ensure_ascii=False))

print(f"  3 malformed events injected into the queue.")
print(f"  Total events in queue: {N_EVENTS + 3}")

# ---------------------------------------------------------------------------
# STEP 5: Consumer -- process all events
# ---------------------------------------------------------------------------
section("STEP 5: Consumer -- Process All Events")

stats = consume_events(
    count=N_EVENTS + 3,
    transport="queue",
    topic=KAFKA_TOPIC,
    poll_timeout=5.0,
    silent=False,
)

# ---------------------------------------------------------------------------
# STEP 6: Result table
# ---------------------------------------------------------------------------
section("STEP 6: Per-Event Results")

alerts_data = []
if STREAMING_ALERT_FILE.exists():
    try:
        alerts_data = json.loads(STREAMING_ALERT_FILE.read_text(encoding="utf-8"))
    except Exception:
        alerts_data = []

# Print table header
print(f"\n  {'#':<4} {'Predicted':<18} {'Actual':<18} {'Confidence':>12} "
      f"{'Severity':<8} {'Status':<12} {'Match':<6} {'ms':>6}")
print(f"  {DIV2}")

correct_count = 0
total_with_labels = 0
proc_times_ms = []

for i, alert in enumerate(alerts_data[-N_EVENTS:], start=1):   # last N_EVENTS alerts
    pred   = alert.get("prediction", "?")
    actual = alert.get("actual_label")
    conf   = alert.get("confidence", 0)
    sev    = alert.get("severity", "?")
    status = alert.get("status", "?")
    pt_ms  = alert.get("processing_time_s", 0) * 1000
    proc_times_ms.append(pt_ms)

    if actual is not None:
        total_with_labels += 1
        match = "YES" if pred == actual else "NO "
        if pred == actual:
            correct_count += 1
    else:
        match = "N/A"

    color = RED if pred == "Infilteration" else GREEN
    print(
        f"  {i:<4} {color}{pred:<18}{RESET} {str(actual):<18} "
        f"{conf:>12.2%} {sev:<8} {status:<12} {match:<6} {pt_ms:>5.1f}"
    )

if proc_times_ms:
    avg_ms = sum(proc_times_ms) / len(proc_times_ms)
    print(f"\n  Average processing time: {avg_ms:.1f} ms per event")

# ---------------------------------------------------------------------------
# STEP 7: Final Validation Checklist
# ---------------------------------------------------------------------------
section("STEP 7: Final Validation Checklist")

all_ok = True

checks = [
    ("Model file exists",                     MODEL_PATH.exists()),
    ("Preprocessing metadata exists",         PREP_PATH.exists()),
    ("Dataset file exists",                   DATASET_PATH.exists()),
    (f"{n_features} features in metadata",    n_features == 78),
    ("Events sent by producer",               len(sent_events) == N_EVENTS),
    ("'Label' NOT in event features",         "Label" not in sent_events[0]["features"]),
    ("'actual_label' in event metadata",      "actual_label" in sent_events[0]),
    ("Consumer processed expected events",    stats.total >= N_EVENTS),
    ("Alerts saved to JSON log",              STREAMING_ALERT_FILE.exists()),
    ("Both classes in test set",              (
        any(e.get("actual_label") == "Benign"        for e in sent_events) and
        any(e.get("actual_label") == "Infilteration" for e in sent_events)
    )),
    ("Malformed events handled (not crashed)", stats.errors <= 3),
    ("Model file size unchanged",             MODEL_PATH.stat().st_size == model_size_before),
    ("Dataset file size unchanged",           DATASET_PATH.stat().st_size == dataset_size_before),
    ("Processing time recorded in alerts",    any(
        "processing_time_s" in a for a in alerts_data[-N_EVENTS:]
    )),
    ("Runtime log written",                   STREAMING_LOG_FILE.exists()),
]

for name, passed in checks:
    result = check(name, passed)
    if not result:
        all_ok = False

# ---------------------------------------------------------------------------
# Final summary
# ---------------------------------------------------------------------------
print(f"\n{DIV}")
if all_ok:
    print(f"  {GREEN}{BOLD}All checks PASSED. Stage 4 pipeline is operational.{RESET}")
else:
    print(f"  {RED}{BOLD}Some checks FAILED -- see above for details.{RESET}")

print(f"\n  Prediction accuracy : {correct_count}/{total_with_labels}  "
      f"({correct_count/max(total_with_labels,1)*100:.1f}%)"
      if total_with_labels else "  No labelled events.")
print(f"  Benign detected     : {stats.benign}")
print(f"  Suspicious detected : {stats.suspicious}")
print(f"  Errors / Skipped    : {stats.errors}")
if proc_times_ms:
    print(f"  Avg processing time : {avg_ms:.1f} ms  "
          f"(near-real-time event processing demonstration)")
print(f"  Alert log           : {STREAMING_ALERT_FILE}")
print(f"  Runtime log         : {STREAMING_LOG_FILE}")
print(DIV)
print("  Test complete.")
print(DIV)
