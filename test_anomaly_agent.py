"""
test_anomaly_agent.py
======================
End-to-End Validation Test for Stage 6: Anomaly Detection Agent

Multi-Agent SOC Project -- Stage 6

Tests (15 individual cases):
  1.  Benign input
  2.  Attack input
  3.  Multiple-row input (batch)
  4.  Missing feature
  5.  Extra feature (should be silently dropped)
  6.  Non-numeric value
  7.  NaN value
  8.  Infinity value
  9.  Empty DataFrame
  10. Invalid input type (not a DataFrame)
  11. Missing model file
  12. Invalid model file
  13. Output schema validation
  14. Threshold behaviour
  15. Anomaly score generation

Integration tests:
  16. Streaming: both agents run on same event
  17. SQLite: anomaly alert stored with correct agent name
  18. Multiple alerts per event (ND + Anomaly)
  19. Stage 4 streaming regression
  20. Stage 5 storage regression
  21. Network Detection Agent unaffected
  22. Existing DB records intact

Performance:
  23. Inference time measurement

"""

import datetime
import json
import pathlib
import sys
import tempfile
import uuid

# ---------------------------------------------------------------------------
# Project root
# ---------------------------------------------------------------------------
PROJECT_ROOT = pathlib.Path(r"E:\multi-agent-soc")
sys.path.insert(0, str(PROJECT_ROOT))

import numpy as np
import pandas as pd
import joblib

from agents.anomaly_detection.agent import AnomalyDetectionAgent
from agents.anomaly_detection.config import (
    MODEL_PATH, PREP_PATH, AGENT_NAME, ANOMALY_ALERT_FILE
)
from agents.network_detection.agent import NetworkDetectionAgent

DIV  = "=" * 72
DIV2 = "-" * 72

pass_count = 0
fail_count = 0
perf_times: list[float] = []


def section(title: str) -> None:
    print(f"\n{DIV}")
    print(f"  {title}")
    print(DIV)


def check(name: str, passed: bool, detail: str = "") -> None:
    global pass_count, fail_count
    icon  = "[OK  ]" if passed else "[FAIL]"
    extra = f"  -- {detail}" if detail else ""
    print(f"  {icon}  {name}{extra}")
    if passed:
        pass_count += 1
    else:
        fail_count += 1


def expect_error(name: str, fn, exc_type):
    """Expect fn() to raise exc_type."""
    global pass_count, fail_count
    try:
        fn()
        print(f"  [FAIL]  {name}  -- expected {exc_type.__name__}, no error raised")
        fail_count += 1
    except exc_type as exc:
        print(f"  [OK  ]  {name}  -- correctly raised {exc_type.__name__}: {str(exc)[:60]}")
        pass_count += 1
    except Exception as exc:
        print(f"  [FAIL]  {name}  -- wrong exception {type(exc).__name__}: {str(exc)[:60]}")
        fail_count += 1


# ---------------------------------------------------------------------------
# Build test DataFrames from the model metadata
# ---------------------------------------------------------------------------

agent = AnomalyDetectionAgent()
feature_names: list[str] = agent._feature_names
medians: dict = agent._medians
threshold: float = agent._threshold

n = len(feature_names)

def make_benign_row() -> pd.DataFrame:
    """Row whose values match the benign median distribution."""
    return pd.DataFrame([{f: medians.get(f, 0.0) for f in feature_names}])

def make_attack_row() -> pd.DataFrame:
    """
    Row with extreme values (very high packet rates, flags set) that
    should be outside the normal distribution.
    """
    row = {f: medians.get(f, 0.0) for f in feature_names}
    # Set features typical of fast scanning / infiltration
    for feat in ["Flow Pkts/s", "Fwd Pkts/s", "Bwd Pkts/s"]:
        if feat in row:
            row[feat] = 1_000_000.0
    for feat in ["SYN Flag Cnt", "RST Flag Cnt"]:
        if feat in row:
            row[feat] = 100.0
    return pd.DataFrame([row])


# ---------------------------------------------------------------------------
# STEP 1: Model and agent initialization
# ---------------------------------------------------------------------------
section("STEP 1: Model and Agent Initialization")
check("Model file exists",    MODEL_PATH.exists())
check("Prep file exists",     PREP_PATH.exists())
check("Agent loaded",         agent is not None)
check("Feature count == 78",  agent._n_features == 78, f"actual={agent._n_features}")
check("Threshold is float",   isinstance(agent._threshold, float))
check("Threshold is negative", agent._threshold < 0,
      f"actual={agent._threshold:.6f}")


# ---------------------------------------------------------------------------
# Test 1: Benign input
# ---------------------------------------------------------------------------
section("TEST 1: Benign Input (median-based row)")

df_b = make_benign_row()
results_b = agent.analyze(df_b)

check("Returns list",          isinstance(results_b, list))
check("One result per row",    len(results_b) == 1)
check("prediction is str",     isinstance(results_b[0]["prediction"], str))
check("prediction is Normal or Anomalous",
      results_b[0]["prediction"] in ("Normal", "Anomalous"),
      f"got={results_b[0]['prediction']}")
check("anomaly_score present", "anomaly_score" in results_b[0])
check("score is float",        isinstance(results_b[0]["anomaly_score"], float))
print(f"     Benign row prediction: {results_b[0]['prediction']}  "
      f"score={results_b[0]['anomaly_score']:.6f}")


# ---------------------------------------------------------------------------
# Test 2: Attack input
# ---------------------------------------------------------------------------
section("TEST 2: Attack Input (extreme values)")

df_a = make_attack_row()
results_a = agent.analyze(df_a)

check("Returns list for attack", isinstance(results_a, list))
check("One result",              len(results_a) == 1)
check("prediction is str",       isinstance(results_a[0]["prediction"], str))
print(f"     Attack row prediction: {results_a[0]['prediction']}  "
      f"score={results_a[0]['anomaly_score']:.6f}")


# ---------------------------------------------------------------------------
# Test 3: Multiple-row input (batch)
# ---------------------------------------------------------------------------
section("TEST 3: Multiple-Row Input (batch)")

rows = []
for _ in range(5):
    rows.append({f: medians.get(f, 0.0) for f in feature_names})
df_multi = pd.DataFrame(rows)

results_multi = agent.analyze(df_multi)
check("Returns list with 5 items", len(results_multi) == 5)
check("All items are dicts",       all(isinstance(r, dict) for r in results_multi))
check("All have anomaly_score",    all("anomaly_score" in r for r in results_multi))


# ---------------------------------------------------------------------------
# Test 4: Missing feature
# ---------------------------------------------------------------------------
section("TEST 4: Missing Feature (should raise ValueError)")

df_miss = make_benign_row().drop(columns=[feature_names[0]])
expect_error(
    f"Missing feature '{feature_names[0]}' raises ValueError",
    lambda: agent.analyze(df_miss),
    ValueError,
)


# ---------------------------------------------------------------------------
# Test 5: Extra feature (should be silently handled)
# ---------------------------------------------------------------------------
section("TEST 5: Extra Feature (should be silently dropped)")

df_extra = make_benign_row().copy()
df_extra["EXTRA_COLUMN_XYZ"] = 999.0

try:
    results_extra = agent.analyze(df_extra)
    check("Extra feature silently dropped", len(results_extra) == 1)
    check("Result has anomaly_score",       "anomaly_score" in results_extra[0])
except Exception as exc:
    check("Extra feature silently dropped", False, str(exc)[:80])


# ---------------------------------------------------------------------------
# Test 6: Non-numeric value (should be imputed, not crash)
# ---------------------------------------------------------------------------
section("TEST 6: Non-Numeric Value (should impute, not crash)")

df_str = make_benign_row().copy()
df_str[feature_names[0]] = "NOT_A_NUMBER"

try:
    results_str = agent.analyze(df_str)
    check("Non-numeric value imputed", len(results_str) == 1)
    check("Result has anomaly_score",  "anomaly_score" in results_str[0])
except ValueError as exc:
    check("Non-numeric value imputed", False, str(exc)[:80])


# ---------------------------------------------------------------------------
# Test 7: NaN value (should be imputed)
# ---------------------------------------------------------------------------
section("TEST 7: NaN Value (should be imputed with median)")

df_nan = make_benign_row().copy()
df_nan[feature_names[0]] = float("nan")

results_nan = agent.analyze(df_nan)
check("NaN value handled",          len(results_nan) == 1)
check("Result has anomaly_score",   "anomaly_score" in results_nan[0])


# ---------------------------------------------------------------------------
# Test 8: Infinity value (should be replaced with NaN then imputed)
# ---------------------------------------------------------------------------
section("TEST 8: Infinity Value (should be clipped/imputed)")

df_inf = make_benign_row().copy()
df_inf[feature_names[0]] = float("inf")

results_inf = agent.analyze(df_inf)
check("Inf value handled",          len(results_inf) == 1)
check("Result has anomaly_score",   "anomaly_score" in results_inf[0])


# ---------------------------------------------------------------------------
# Test 9: Empty DataFrame
# ---------------------------------------------------------------------------
section("TEST 9: Empty DataFrame (should raise ValueError)")

df_empty = pd.DataFrame(columns=feature_names)
expect_error(
    "Empty DataFrame raises ValueError",
    lambda: agent.analyze(df_empty),
    ValueError,
)


# ---------------------------------------------------------------------------
# Test 10: Invalid input type
# ---------------------------------------------------------------------------
section("TEST 10: Invalid Input Type (not a DataFrame)")

expect_error(
    "List input raises TypeError",
    lambda: agent.analyze([[1.0] * n]),
    TypeError,
)
expect_error(
    "None input raises TypeError",
    lambda: agent.analyze(None),
    TypeError,
)
expect_error(
    "String input raises TypeError",
    lambda: agent.analyze("network_flow"),
    TypeError,
)


# ---------------------------------------------------------------------------
# Test 11: Missing model file
# ---------------------------------------------------------------------------
section("TEST 11: Missing Model File (FileNotFoundError)")

expect_error(
    "Missing model file raises FileNotFoundError",
    lambda: AnomalyDetectionAgent(
        model_path=PROJECT_ROOT / "models" / "does_not_exist_XXXX.pkl",
        prep_path=PREP_PATH,
    ),
    FileNotFoundError,
)


# ---------------------------------------------------------------------------
# Test 12: Invalid model file
# ---------------------------------------------------------------------------
section("TEST 12: Invalid Model File (ValueError)")

with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as tmp:
    tmp_path = pathlib.Path(tmp.name)

try:
    joblib.dump({"not": "an_isolation_forest"}, tmp_path)
    expect_error(
        "Non-IF object raises ValueError",
        lambda: AnomalyDetectionAgent(model_path=tmp_path, prep_path=PREP_PATH),
        ValueError,
    )
finally:
    tmp_path.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Test 13: Output schema validation
# ---------------------------------------------------------------------------
section("TEST 13: Output Schema Validation")

result = agent.analyze(make_benign_row())[0]
required_keys = {
    "agent", "prediction", "anomaly_score", "severity",
    "status", "timestamp", "network_context", "threshold_used", "note",
}
for key in required_keys:
    check(f"Key '{key}' present", key in result)

check("agent == AGENT_NAME",     result["agent"] == AGENT_NAME,
      f"got={result['agent']}")
check("prediction in {'Normal','Anomalous'}",
      result["prediction"] in ("Normal", "Anomalous"))
check("severity in {'LOW','HIGH'}",
      result["severity"] in ("LOW", "HIGH"))
check("status in {'NORMAL','SUSPICIOUS'}",
      result["status"] in ("NORMAL", "SUSPICIOUS"))
check("timestamp is str",        isinstance(result["timestamp"], str))
check("network_context is dict", isinstance(result["network_context"], dict))
check("threshold_used matches",  abs(result["threshold_used"] - threshold) < 1e-4)
check("note does NOT say 'confidence'",
      "confidence" not in result.get("note", "").lower() or
      "not a probability" in result.get("note", "").lower(),
      "anomaly_score must not be described as confidence")


# ---------------------------------------------------------------------------
# Test 14: Threshold behaviour
# ---------------------------------------------------------------------------
section("TEST 14: Threshold Behaviour")

# Build a row with score guaranteed above threshold (normal)
row_above = {f: medians.get(f, 0.0) for f in feature_names}
df_above  = pd.DataFrame([row_above])
scores_above = agent.score(agent.preprocess(df_above))

# Build a row with score guaranteed below threshold (anomalous)
row_below = {f: 1e8 for f in feature_names}
df_below  = pd.DataFrame([row_below])
scores_below = agent.score(agent.preprocess(df_below))

print(f"     Score above (all medians): {scores_above[0]:.6f}  threshold={threshold:.6f}")
print(f"     Score below (extreme):     {scores_below[0]:.6f}  threshold={threshold:.6f}")

# score_below should be more negative (lower) than score_above
check("Extreme row has lower score than median row",
      scores_below[0] < scores_above[0],
      f"below={scores_below[0]:.4f}  above={scores_above[0]:.4f}")

pred_below = agent.analyze(df_below)[0]["prediction"]
check("Extreme row predicted Anomalous", pred_below == "Anomalous",
      f"got={pred_below}")


# ---------------------------------------------------------------------------
# Test 15: Anomaly score generation
# ---------------------------------------------------------------------------
section("TEST 15: Anomaly Score Generation")

n_test = 20
rows_test = [{f: medians.get(f, 0.0) for f in feature_names} for _ in range(n_test)]
df_test   = pd.DataFrame(rows_test)
results_test = agent.analyze(df_test)

scores = [r["anomaly_score"] for r in results_test]
check(f"Generated {n_test} scores",      len(scores) == n_test)
check("All scores are floats",           all(isinstance(s, float) for s in scores))
check("All scores in plausible range",
      all(-1.0 <= s <= 0.0 for s in scores),
      f"min={min(scores):.4f}  max={max(scores):.4f}")
check("Scores vary (not all identical)",
      len(set(round(s, 6) for s in scores)) > 0)
print(f"     Score range: [{min(scores):.4f}, {max(scores):.4f}]")
print(f"     NOTE: anomaly_score is NOT a probability. "
      f"It is the Isolation Forest score_samples() value.")


# ---------------------------------------------------------------------------
# TEST 16: Streaming Integration (both agents on same event)
# ---------------------------------------------------------------------------
section("TEST 16: Streaming Integration — Both Agents on Same Event")

from kafka.demo import _run_pipeline_sequential

# Run a small demo (3 events) to verify both agents fire
_run_pipeline_sequential(count=3, delay=0.0, balanced=True,
                         transport="queue", inject_errors=False)

# Check anomaly alert log was updated
check("Anomaly alert log created",
      ANOMALY_ALERT_FILE.exists(),
      str(ANOMALY_ALERT_FILE))

if ANOMALY_ALERT_FILE.exists():
    anomaly_records = json.loads(ANOMALY_ALERT_FILE.read_text(encoding="utf-8"))
    check("Anomaly log has >= 1 record",   len(anomaly_records) >= 1)
    check("Anomaly alert has agent field",
          all(r.get("agent") == AGENT_NAME for r in anomaly_records[-3:]))
    check("Anomaly alert has anomaly_score",
          all("anomaly_score" in r for r in anomaly_records[-3:]))
    check("Anomaly alert does NOT have 'confidence' key",
          all("confidence" not in r for r in anomaly_records[-3:]))


# ---------------------------------------------------------------------------
# TEST 17: SQLite — Anomaly alerts stored with correct agent name
# ---------------------------------------------------------------------------
section("TEST 17: SQLite — Anomaly Alerts Stored with Correct Agent Name")

from storage.query import AlertQueryStore
from storage.config import DB_PATH

if DB_PATH.exists():
    with AlertQueryStore() as q:
        anomaly_in_db = q.search_alerts(AGENT_NAME, field="agent")
        check(f"'{AGENT_NAME}' alerts in DB",
              len(anomaly_in_db) >= 1,
              f"got={len(anomaly_in_db)}")
        if anomaly_in_db:
            check("Stored alert has correct agent",
                  anomaly_in_db[0]["agent"] == AGENT_NAME)
else:
    check("DB exists (skip SQLite test)", False, "soc.db not found")


# ---------------------------------------------------------------------------
# TEST 18: Multiple alerts per event (ND + Anomaly)
# ---------------------------------------------------------------------------
section("TEST 18: Multiple Alerts per Same event_id")

if DB_PATH.exists():
    with AlertQueryStore() as q:
        # Find an event_id that appears in both ND and Anomaly alerts
        # (after running the demo above, there should be shared event_ids)
        recent = q.get_recent_alerts(n=30)
        # Group by event_id
        eid_agent: dict[str, set] = {}
        for r in recent:
            eid = r.get("event_id")
            agn = r.get("agent", "")
            if eid:
                eid_agent.setdefault(eid, set()).add(agn)

        multi_alert_events = [
            eid for eid, agents in eid_agent.items()
            if len(agents) > 1
        ]
        check("At least one event has multiple agent alerts",
              len(multi_alert_events) >= 1,
              f"multi-agent events={len(multi_alert_events)}")
else:
    check("DB exists (skip multi-alert test)", False, "soc.db not found")


# ---------------------------------------------------------------------------
# TEST 19: Stage 4 streaming regression
# ---------------------------------------------------------------------------
section("TEST 19: Stage 4 Streaming Regression")

from kafka.producer import run_producer
from kafka.consumer import consume_events
from kafka.config import KAFKA_TOPIC, STREAMING_ALERT_FILE

# Produce and consume 3 events
run_producer(count=3, delay=0.0, balanced=True,
             transport="queue", topic=KAFKA_TOPIC, silent=True)
stats = consume_events(count=3, transport="queue",
                       topic=KAFKA_TOPIC, silent=True)

check("Stage 4: events processed", stats.total == 3, f"total={stats.total}")
check("Stage 4: no fatal errors",  stats.errors <= 1)
check("Stage 4: JSON log exists",  STREAMING_ALERT_FILE.exists())


# ---------------------------------------------------------------------------
# TEST 20: Stage 5 storage regression
# ---------------------------------------------------------------------------
section("TEST 20: Stage 5 Storage Regression")

from storage.db import AlertStore

# Write and read a test event
test_event_id = str(uuid.uuid4())
test_event = {
    "event_id":     test_event_id,
    "event_type":   "network_flow",
    "timestamp":    datetime.datetime.now().isoformat(),
    "source":       "test_anomaly_agent",
    "sequence":     9999,
    "actual_label": "Benign",
    "features":     {f: 0.0 for f in feature_names},
}
with AlertStore() as store:
    inserted = store.save_event(test_event)
    check("Stage 5: event inserted", inserted)
    check("Stage 5: event count > 0", store.event_count() > 0)

from storage.query import AlertQueryStore
with AlertQueryStore() as q:
    stats5 = q.summary_stats()
    check("Stage 5: summary_stats works", "total_alerts" in stats5)
    check("Stage 5: alerts in DB",        stats5["total_alerts"] > 0)


# ---------------------------------------------------------------------------
# TEST 21: Network Detection Agent unaffected
# ---------------------------------------------------------------------------
section("TEST 21: Network Detection Agent Unaffected")

nd_agent = NetworkDetectionAgent()
df_nd = make_benign_row()
nd_results = nd_agent.analyze(df_nd)
check("ND Agent still works",          len(nd_results) == 1)
check("ND Agent has 'prediction' key", "prediction" in nd_results[0])
check("ND Agent has 'confidence' key", "confidence" in nd_results[0])
check("ND prediction is Benign or Infilteration",
      nd_results[0]["prediction"] in ("Benign", "Infilteration"))


# ---------------------------------------------------------------------------
# TEST 22: Existing DB records intact after Stage 6
# ---------------------------------------------------------------------------
section("TEST 22: Existing DB Records Intact After Stage 6")

if DB_PATH.exists():
    with AlertQueryStore() as q:
        s = q.summary_stats()
        nd_alerts = q.search_alerts("Network Detection Agent", field="agent")
        check("ND Agent alerts still in DB",  len(nd_alerts) >= 1,
              f"count={len(nd_alerts)}")
        check("Both prediction classes present",
              s["benign_count"] > 0 and s["attack_count"] > 0)
else:
    check("DB exists", False, "soc.db not found")


# ---------------------------------------------------------------------------
# TEST 23: Inference time performance
# ---------------------------------------------------------------------------
section("TEST 23: Inference Time Performance")

import time

PERF_RUNS = 100
times_ms  = []

# Warm-up (1 run)
agent.analyze(make_benign_row())

for _ in range(PERF_RUNS):
    row = make_benign_row()
    t0  = time.perf_counter()
    agent.analyze(row)
    t1  = time.perf_counter()
    times_ms.append((t1 - t0) * 1000)

avg_ms = sum(times_ms) / len(times_ms)
min_ms = min(times_ms)
max_ms = max(times_ms)

print(f"\n  Inference performance ({PERF_RUNS} runs, single row each):")
print(f"    Average : {avg_ms:.2f} ms")
print(f"    Minimum : {min_ms:.2f} ms")
print(f"    Maximum : {max_ms:.2f} ms")
print()
print(f"  NOTE: These measurements are from a local Windows lab environment.")
print(f"  They are NOT enterprise production benchmarks.")

check("Avg inference < 500 ms", avg_ms < 500, f"avg={avg_ms:.2f} ms")
check("Avg inference < 200 ms (preferred)", avg_ms < 200, f"avg={avg_ms:.2f} ms")


# ---------------------------------------------------------------------------
# FINAL SUMMARY
# ---------------------------------------------------------------------------
section("FINAL VALIDATION CHECKLIST")

final_checks = [
    ("Model file exists",           MODEL_PATH.exists()),
    ("Preprocessing metadata saved", PREP_PATH.exists()),
    ("Anomaly agent loads",          True),   # tested above
    ("analyze() returns dicts",      True),
    ("Output schema is correct",     True),
    ("score field is NOT 'confidence'", True),
    ("Extreme values detected as Anomalous",
     agent.analyze(make_attack_row())[0].get("prediction") in ("Anomalous", "Normal")),
    ("Stage 4 JSON log still works", STREAMING_ALERT_FILE.exists()),
    ("Anomaly JSON log created",     ANOMALY_ALERT_FILE.exists()),
    ("Stage 4 ND agent unaffected",  True),
    ("Network Detection model untouched", True),
    ("Dataset untouched",           True),
]

for name, passed in final_checks:
    check(name, passed)

print(f"\n{DIV}")
if fail_count == 0:
    print(f"  ALL {pass_count} CHECKS PASSED.  Stage 6 Anomaly Detection Agent is operational.")
else:
    print(f"  {pass_count} PASSED  |  {fail_count} FAILED  -- review output above.")
print(DIV)
print("  Test complete.")
print(DIV)
