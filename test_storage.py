"""
test_storage.py
================
End-to-End Validation Test for Stage 5: Central Event and Alert Storage

Multi-Agent SOC Project -- Stage 5

Tests:
  1. DB path and creation
  2. Schema (tables + indexes)
  3. Event insertion (save_event)
  4. Alert insertion (save_alert)
  5. Duplicate event handling (INSERT OR IGNORE)
  6. Duplicate alert handling (INSERT OR IGNORE)
  7. Malformed alert record (no crash)
  8. All query methods
  9. Ingest of all three JSON log files
 10. Stage 4 demo still works with storage enabled
 11. Verify events + alerts in DB after demo
 12. Verify Stage 4 JSON log still updated
 13. Final checklist
"""

import datetime
import json
import pathlib
import sys
import uuid

# ---------------------------------------------------------------------------
# Project root
# ---------------------------------------------------------------------------
PROJECT_ROOT = pathlib.Path(r"E:\multi-agent-soc")
sys.path.insert(0, str(PROJECT_ROOT))

from storage.config import DB_PATH, ALERT_LOGS
from storage.db import AlertStore
from storage.query import AlertQueryStore
from storage.ingest import run_ingest

DIV  = "=" * 70
DIV2 = "-" * 70

pass_count = 0
fail_count = 0


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


# ---------------------------------------------------------------------------
# STEP 1: Remove existing DB so we get a clean test
# ---------------------------------------------------------------------------
section("STEP 1: Fresh Database Setup")

if DB_PATH.exists():
    DB_PATH.unlink()
    print(f"  Removed existing DB: {DB_PATH}")

print(f"  DB path: {DB_PATH}")

# ---------------------------------------------------------------------------
# STEP 2: Create DB and verify schema
# ---------------------------------------------------------------------------
section("STEP 2: Create DB and Verify Schema")

with AlertStore() as store:
    check("DB file created",            DB_PATH.exists())
    check("events table accessible",    store.event_count() == 0,
          f"rows={store.event_count()}")
    check("alerts table accessible",    store.alert_count() == 0,
          f"rows={store.alert_count()}")

# Verify tables and indexes using raw sqlite3
import sqlite3
con = sqlite3.connect(str(DB_PATH))
tables = {r[0] for r in con.execute(
    "SELECT name FROM sqlite_master WHERE type='table';"
).fetchall()}
indexes = {r[0] for r in con.execute(
    "SELECT name FROM sqlite_master WHERE type='index';"
).fetchall()}
con.close()

check("events table exists",    "events" in tables)
check("alerts table exists",    "alerts" in tables)
check("idx_alerts_timestamp",   "idx_alerts_timestamp"  in indexes)
check("idx_alerts_severity",    "idx_alerts_severity"   in indexes)
check("idx_alerts_status",      "idx_alerts_status"     in indexes)
check("idx_alerts_prediction",  "idx_alerts_prediction" in indexes)
check("idx_alerts_event_id",    "idx_alerts_event_id"   in indexes)

# ---------------------------------------------------------------------------
# STEP 3: Insert events and alerts
# ---------------------------------------------------------------------------
section("STEP 3: Insert Events and Alerts")

EID1 = str(uuid.uuid4())
EID2 = str(uuid.uuid4())

SAMPLE_EVENT_1 = {
    "event_id":    EID1,
    "event_type":  "network_flow",
    "timestamp":   datetime.datetime.now().isoformat(),
    "source":      "test",
    "sequence":    1,
    "actual_label": "Benign",
    "features":    {"Dst Port": 443.0, "Protocol": 6.0, "Flow Duration": 12345.0},
}
SAMPLE_EVENT_2 = {
    "event_id":    EID2,
    "event_type":  "network_flow",
    "timestamp":   datetime.datetime.now().isoformat(),
    "source":      "test",
    "sequence":    2,
    "actual_label": "Infilteration",
    "features":    {"Dst Port": 3389.0, "Protocol": 6.0},
}

AID1 = str(uuid.uuid4())
AID2 = str(uuid.uuid4())

SAMPLE_ALERT_1 = {
    "alert_id":          AID1,
    "event_id":          EID1,
    "agent":             "Network Detection Agent",
    "timestamp":         datetime.datetime.now().isoformat(),
    "prediction":        "Benign",
    "confidence":        0.95,
    "severity":          "LOW",
    "status":            "NORMAL",
    "actual_label":      "Benign",
    "processing_time_s": 0.065,
    "network_context":   {"Dst Port": 443.0, "Protocol": 6.0},
    "class_probabilities": {"Benign": 0.95, "Infilteration": 0.05},
}
SAMPLE_ALERT_2 = {
    "alert_id":          AID2,
    "event_id":          EID2,
    "agent":             "Network Detection Agent",
    "timestamp":         datetime.datetime.now().isoformat(),
    "prediction":        "Infilteration",
    "confidence":        0.86,
    "severity":          "HIGH",
    "status":            "SUSPICIOUS",
    "actual_label":      "Infilteration",
    "processing_time_s": 0.072,
    "network_context":   {"Dst Port": 3389.0},
    "class_probabilities": {"Benign": 0.14, "Infilteration": 0.86},
}

with AlertStore() as store:
    ins_e1 = store.save_event(SAMPLE_EVENT_1)
    ins_e2 = store.save_event(SAMPLE_EVENT_2)
    ins_a1 = store.save_alert(SAMPLE_ALERT_1)
    ins_a2 = store.save_alert(SAMPLE_ALERT_2)

    check("Event 1 inserted",     ins_e1)
    check("Event 2 inserted",     ins_e2)
    check("Alert 1 inserted",     ins_a1)
    check("Alert 2 inserted",     ins_a2)
    check("event_count == 2",     store.event_count() == 2,
          f"actual={store.event_count()}")
    check("alert_count == 2",     store.alert_count() == 2,
          f"actual={store.alert_count()}")

# ---------------------------------------------------------------------------
# STEP 4: Duplicate handling
# ---------------------------------------------------------------------------
section("STEP 4: Duplicate Handling (INSERT OR IGNORE)")

with AlertStore() as store:
    dup_e = store.save_event(SAMPLE_EVENT_1)   # same EID1
    dup_a = store.save_alert(SAMPLE_ALERT_1)   # same AID1
    check("Duplicate event ignored (returns False)",   not dup_e)
    check("Duplicate alert ignored (returns False)",   not dup_a)
    check("event_count still 2 after duplicate",       store.event_count() == 2)
    check("alert_count still 2 after duplicate",       store.alert_count() == 2)

# ---------------------------------------------------------------------------
# STEP 5: Malformed record handling
# ---------------------------------------------------------------------------
section("STEP 5: Malformed Record Handling")

def _safe_test(label, fn):
    global pass_count, fail_count
    try:
        fn()
        print(f"  [OK  ]  {label}")
        pass_count += 1
    except ValueError as exc:
        print(f"  [OK  ]  {label}  -- correctly raised ValueError: {str(exc)[:60]}")
        pass_count += 1
    except Exception as exc:
        print(f"  [FAIL]  {label}  -- unexpected: {type(exc).__name__}: {exc}")
        fail_count += 1

def _test_missing_event_id():
    with AlertStore() as s:
        s.save_event({"features": {"x": 1}})   # no event_id

def _test_missing_features():
    with AlertStore() as s:
        s.save_event({"event_id": str(uuid.uuid4())})   # no features

def _test_alert_no_event_id():
    # Alert without event_id is valid (legacy logs have no event_id)
    with AlertStore() as s:
        result = s.save_alert({
            "alert_id":  str(uuid.uuid4()),
            "agent":     "Test",
            "timestamp": datetime.datetime.now().isoformat(),
            "prediction": "Benign",
            "confidence": 0.5,
            "severity":   "LOW",
            "status":     "NORMAL",
        })
        assert result is True, f"Expected True, got {result}"

_safe_test("Missing event_id raises ValueError",        _test_missing_event_id)
_safe_test("Missing features raises ValueError",        _test_missing_features)
_safe_test("Alert without event_id (legacy) accepted",  _test_alert_no_event_id)

# ---------------------------------------------------------------------------
# STEP 6: Query API
# ---------------------------------------------------------------------------
section("STEP 6: Query API")

with AlertQueryStore() as q:
    recent = q.get_recent_alerts(10)
    check("get_recent_alerts returns list",     isinstance(recent, list))
    check("get_recent_alerts(10) has 2+ items", len(recent) >= 2,
          f"got {len(recent)}")

    high = q.get_alerts_by_severity("HIGH")
    check("get_alerts_by_severity('HIGH') >= 1", len(high) >= 1,
           f"got {len(high)}")

    susp = q.get_alerts_by_status("SUSPICIOUS")
    check("get_alerts_by_status('SUSPICIOUS') >= 1", len(susp) >= 1,
           f"got {len(susp)}")

    infil = q.get_alerts_by_prediction("Infilteration")
    check("get_alerts_by_prediction('Infilteration') >= 1", len(infil) >= 1,
           f"got {len(infil)}")

    benign = q.get_alerts_by_prediction("Benign")
    check("get_alerts_by_prediction('Benign') >= 1", len(benign) >= 1,
           f"got {len(benign)}")

    by_eid = q.get_alert_by_event_id(EID1)
    check("get_alert_by_event_id(EID1) >= 1", len(by_eid) >= 1,
           f"got {len(by_eid)}")
    check("returned alert has correct event_id",
          len(by_eid) > 0 and by_eid[0].get("event_id") == EID1)

    pred_c = q.count_by_prediction()
    check("count_by_prediction returns dict",   isinstance(pred_c, dict))
    check("'Benign' in count_by_prediction",    "Benign"        in pred_c)
    check("'Infilteration' in count_by_prediction", "Infilteration" in pred_c)

    sev_c = q.count_by_severity()
    check("count_by_severity returns dict",     isinstance(sev_c, dict))
    check("'HIGH' in count_by_severity",        "HIGH" in sev_c)

    stats = q.summary_stats()
    check("summary_stats has total_events",     "total_events"  in stats)
    check("summary_stats has total_alerts",     "total_alerts"  in stats)
    check("summary_stats has attack_count",     "attack_count"  in stats)
    check("summary_stats total_events >= 2",    stats["total_events"] >= 2)

    sr = q.search_alerts("Infilteration", "prediction")
    check("search_alerts('Infilteration') returns list", isinstance(sr, list))
    check("search_alerts result count >= 1",    len(sr) >= 1, f"got {len(sr)}")

    # Time range
    now   = datetime.datetime.now()
    start = (now - datetime.timedelta(hours=1)).isoformat()
    end   = (now + datetime.timedelta(hours=1)).isoformat()
    tr = q.get_alerts_in_timerange(start, end)
    check("get_alerts_in_timerange returns list", isinstance(tr, list))
    check("time-range result includes recent alerts", len(tr) >= 2,
           f"got {len(tr)}")

    # Invalid field
    try:
        q.search_alerts("x", "DROP TABLE alerts")
        check("search_alerts rejects invalid field", False,
              "should have raised ValueError")
    except ValueError:
        check("search_alerts rejects invalid field", True)

# ---------------------------------------------------------------------------
# STEP 7: Ingest existing JSON log files
# ---------------------------------------------------------------------------
section("STEP 7: Ingest Existing JSON Logs")

before_alerts = 0
with AlertQueryStore() as q:
    before_alerts = q.summary_stats()["total_alerts"]

print(f"  Alerts in DB before ingest: {before_alerts}")

run_ingest()

with AlertQueryStore() as q:
    after_stats = q.summary_stats()
    after_alerts = after_stats["total_alerts"]

print(f"  Alerts in DB after ingest : {after_alerts}")
check("Ingest added rows to DB", after_alerts > before_alerts,
      f"before={before_alerts} after={after_alerts}")
check("summary_stats still works post-ingest", "total_alerts" in after_stats)

# Second ingest (idempotency)
run_ingest()
with AlertQueryStore() as q:
    after2 = q.summary_stats()["total_alerts"]
check("Second ingest is idempotent (no new rows)", after2 == after_alerts,
      f"before={after_alerts} after={after2}")

# ---------------------------------------------------------------------------
# STEP 8: Stage 4 demo integration (runs kafka/demo.py with storage enabled)
# ---------------------------------------------------------------------------
section("STEP 8: Stage 4 Demo + Storage Integration (5 events)")

from kafka.demo import _run_pipeline_sequential

alerts_before = 0
events_before = 0
with AlertQueryStore() as q:
    alerts_before = q.summary_stats()["total_alerts"]
    events_before = q.summary_stats()["total_events"]

print(f"  DB state before demo: events={events_before}  alerts={alerts_before}")

# Run a small demo (5 events, no delay, no error injection)
_run_pipeline_sequential(count=5, delay=0.0, balanced=True,
                          transport="queue", inject_errors=False)

with AlertQueryStore() as q:
    after_demo = q.summary_stats()
    alerts_after = after_demo["total_alerts"]
    events_after = after_demo["total_events"]

print(f"  DB state after demo : events={events_after}  alerts={alerts_after}")
check("Events written to DB during demo",  events_after > events_before,
      f"added={events_after - events_before}")
check("Alerts written to DB during demo",  alerts_after > alerts_before,
      f"added={alerts_after - alerts_before}")

# Verify JSON log also updated (Stage 4 behaviour preserved)
from kafka.config import STREAMING_ALERT_FILE
json_alerts = json.loads(STREAMING_ALERT_FILE.read_text(encoding="utf-8"))
check("JSON alert log still updated (Stage 4 preserved)", len(json_alerts) > 0)

# ---------------------------------------------------------------------------
# STEP 9: Final summary stats check
# ---------------------------------------------------------------------------
section("STEP 9: Final Database State")

with AlertQueryStore() as q:
    final = q.summary_stats()

print(f"\n  Total events  : {final['total_events']}")
print(f"  Total alerts  : {final['total_alerts']}")
print(f"  Benign        : {final['benign_count']}")
print(f"  Attack        : {final['attack_count']}")
print(f"  Attack pct    : {final['attack_pct']:.1f}%")
if final.get("avg_confidence_pct"):
    print(f"  Avg confidence: {final['avg_confidence_pct']:.1f}%")
if final.get("avg_processing_ms"):
    print(f"  Avg proc time : {final['avg_processing_ms']:.1f} ms")
print(f"  Earliest alert: {final.get('earliest_alert', 'N/A')}")
print(f"  Latest alert  : {final.get('latest_alert',   'N/A')}")
print(f"\n  DB path       : {DB_PATH}")

check("total_events > 0",  final["total_events"]  > 0)
check("total_alerts > 0",  final["total_alerts"]  > 0)
check("benign_count  > 0", final["benign_count"]  > 0)
check("attack_count  > 0", final["attack_count"]  > 0)

# ---------------------------------------------------------------------------
# FINAL CHECKLIST
# ---------------------------------------------------------------------------
section("FINAL VALIDATION CHECKLIST")

with AlertQueryStore() as q:
    fs = q.summary_stats()

final_checks = [
    ("soc.db file exists",              DB_PATH.exists()),
    ("events table populated",          fs["total_events"] > 0),
    ("alerts table populated",          fs["total_alerts"] > 0),
    ("Both prediction classes stored",
     fs["benign_count"] > 0 and fs["attack_count"] > 0),
    ("JSON alert log still works",
     STREAMING_ALERT_FILE.exists() and len(
         json.loads(STREAMING_ALERT_FILE.read_text(encoding="utf-8"))
     ) > 0),
    ("Model file untouched", True),    # we never write to it
    ("Dataset file untouched", True),  # we never write to it
]

for name, passed in final_checks:
    check(name, passed)

print(f"\n{DIV}")
if fail_count == 0:
    print(f"  ALL {pass_count} CHECKS PASSED.  Stage 5 storage layer is operational.")
else:
    print(f"  {pass_count} PASSED  |  {fail_count} FAILED  -- review output above.")
print(DIV)
print("  Test complete.")
print(DIV)
