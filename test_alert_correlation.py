"""
test_alert_correlation.py
=========================
End-to-End Validation Test for Stage 7: Alert Correlation Agent

Multi-Agent SOC Project -- Stage 7
"""

import datetime
import pathlib
import sys
import tempfile
import time
import uuid

# Project root
PROJECT_ROOT = pathlib.Path(r"E:\multi-agent-soc")
sys.path.insert(0, str(PROJECT_ROOT))

from agents.alert_correlation.agent import AlertCorrelationAgent

DIV  = "=" * 72
DIV2 = "-" * 72

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

def expect_error(name: str, fn, exc_type):
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

agent = AlertCorrelationAgent()

def mock_alert(event_id, agent_name, severity, alert_id=None):
    return {
        "alert_id": alert_id or str(uuid.uuid4()),
        "event_id": event_id,
        "agent": agent_name,
        "prediction": "Attack" if severity == "HIGH" else "Normal",
        "severity": severity
    }

# ---------------------------------------------------------------------------
# Test Scenarios
# ---------------------------------------------------------------------------
section("1. Two alerts from different agents (Same event_id)")
eid1 = str(uuid.uuid4())
alerts1 = [
    mock_alert(eid1, "Network Detection Agent", "HIGH"),
    mock_alert(eid1, "Anomaly Detection Agent", "LOW")
]
res1 = agent.correlate(alerts1)
check("Creates 1 incident", len(res1) == 1)
if res1:
    check("Incident severity is MEDIUM", res1[0]["severity"] == "MEDIUM")
    check("Correlated 2 agents", len(res1[0]["correlated_agents"]) == 2)
    check("Status is THREAT", "THREAT" in res1[0]["status"])

section("2. Two alerts from the same agent (Same event_id)")
eid2 = str(uuid.uuid4())
alerts2 = [
    mock_alert(eid2, "Network Detection Agent", "HIGH"),
    mock_alert(eid2, "Network Detection Agent", "HIGH")
]
res2 = agent.correlate(alerts2)
check("Creates 1 incident", len(res2) == 1)
if res2:
    check("Correlated 1 agent", len(res2[0]["correlated_agents"]) == 1)
    check("Incident severity is HIGH", res2[0]["severity"] == "HIGH")

section("3. Alerts with different event_ids")
alerts3 = [
    mock_alert(str(uuid.uuid4()), "Network Detection Agent", "HIGH"),
    mock_alert(str(uuid.uuid4()), "Anomaly Detection Agent", "HIGH")
]
res3 = agent.correlate(alerts3)
check("Generates no incidents (unrelated events)", len(res3) == 0)

section("4. Only one alert for an event")
alerts4 = [mock_alert(str(uuid.uuid4()), "Network Detection Agent", "HIGH")]
res4 = agent.correlate(alerts4)
check("Generates no incidents (only 1 alert)", len(res4) == 0)

section("5. Missing event_id")
alerts5 = [
    mock_alert(None, "Network Detection Agent", "HIGH"),
    mock_alert(None, "Anomaly Detection Agent", "HIGH")
]
expect_error("Raises ValueError for missing event_id", lambda: agent.correlate(alerts5), ValueError)

section("6. Missing alert_id")
alerts6_eid = str(uuid.uuid4())
alerts6 = [
    mock_alert(alerts6_eid, "Network Detection Agent", "HIGH", alert_id="id1"),
    {"alert_id": "", "event_id": alerts6_eid, "agent": "Anomaly Detection Agent", "prediction": "Attack", "severity": "HIGH"}
]
expect_error("Raises ValueError for missing alert_id", lambda: agent.correlate(alerts6), ValueError)

section("7. Empty alert list")
res7 = agent.correlate([])
check("Empty list returns empty list", len(res7) == 0)

section("8. Duplicate alerts")
eid8 = str(uuid.uuid4())
a_dup = mock_alert(eid8, "ND", "HIGH")
alerts8 = [a_dup, a_dup]
res8 = agent.correlate(alerts8)
check("Duplicate alerts deduped -> leaves 1 -> no incident", len(res8) == 0)

section("9. High-severity network alert plus anomalous alert")
eid9 = str(uuid.uuid4())
alerts9 = [
    mock_alert(eid9, "ND", "HIGH"),
    mock_alert(eid9, "AD", "HIGH")
]
res9 = agent.correlate(alerts9)
check("Creates 1 incident", len(res9) == 1)
if res9:
    check("Incident severity is HIGH", res9[0]["severity"] == "HIGH")
    check("Status is THREAT", "THREAT" in res9[0]["status"])

section("10. Normal network alert plus normal anomaly alert")
eid10 = str(uuid.uuid4())
alerts10 = [
    mock_alert(eid10, "ND", "LOW"),
    mock_alert(eid10, "AD", "LOW")
]
res10 = agent.correlate(alerts10)
check("Creates 1 incident", len(res10) == 1)
if res10:
    check("Incident severity is LOW", res10[0]["severity"] == "LOW")
    check("Status is NORMAL", "NORMAL" in res10[0]["status"])

section("11 & 12. Multiple events & Multiple incidents")
m_eid1 = str(uuid.uuid4())
m_eid2 = str(uuid.uuid4())
alerts_m = [
    mock_alert(m_eid1, "ND", "HIGH"), mock_alert(m_eid1, "AD", "HIGH"),
    mock_alert(m_eid2, "ND", "LOW"),  mock_alert(m_eid2, "AD", "LOW"),
    mock_alert(str(uuid.uuid4()), "ND", "LOW") # Single alert
]
res_m = agent.correlate(alerts_m)
check("Creates exactly 2 incidents", len(res_m) == 2, f"got={len(res_m)}")

section("13 & 14 & 17. DB insertion, Idempotency, and Regression")
from storage.db import AlertStore
from storage.query import IncidentQueryStore, AlertQueryStore
from storage.config import DB_PATH

if not DB_PATH.exists():
    check("DB found", False, f"{DB_PATH} not found")
else:
    test_incident = res9[0]
    with AlertStore() as store:
        # DB needs event first to meet FK constraint safely, though
        # in the DB schema we made event_id NULLABLE in incidents just in case,
        # but wait, we declared `FOREIGN KEY(event_id) REFERENCES events(event_id)`,
        # so we must insert the event first if event_id is not null!
        # Actually in production `consumer.py` does that before incident save.
        
        # Insert mock event for test
        store.save_event({
            "event_id": eid9,
            "event_type": "test_event",
            "timestamp": "2026-09-17",
            "features": {"f1": 1.0}
        })
        
        inserted1 = store.save_incident(test_incident)
        check("Incident inserted successfully", inserted1)
        
        inserted2 = store.save_incident(test_incident)
        check("Duplicate incident safely ignored (Idempotency)", not inserted2)

    with IncidentQueryStore() as qs:
        # 15. Query methods
        q_recent = qs.get_recent_incidents(50)
        check("get_recent_incidents works", len(q_recent) >= 1)
        
        q_eid = qs.get_incidents_by_event_id(eid9)
        check("get_incidents_by_event_id works", len(q_eid) == 1)
        check("fields exist", q_eid[0]["incident_id"] == test_incident["incident_id"])

    with AlertQueryStore() as aqs:
        c = aqs.summary_stats()["total_alerts"]
        check("Existing database alerts preserved (Regression)", c > 0, f"Found {c} alerts")

section("16. Malformed alert data")
expect_error("Raises TypeError for non-dict item", lambda: agent.correlate(["malformed"]), TypeError)

section("Performance")
PERF_RUNS = 1000
test_alerts = alerts9 * 5 # 10 alerts total for same event
t_start = time.perf_counter()
for _ in range(PERF_RUNS):
    agent.correlate(test_alerts)
t_elapsed = time.perf_counter() - t_start

avg_ms = (t_elapsed / PERF_RUNS) * 1000

print(f"\n  Processed {PERF_RUNS} iterations of 10 alerts each.")
print(f"  Average correlation time: {avg_ms:.3f} ms")
print("  Note: Measurement is from a local lab environment.")
check("Performance is < 10ms", avg_ms < 10)

print(f"\n{DIV}")
if fail_count == 0:
    print(f"  ALL {pass_count} CHECKS PASSED. Agent is operational.")
else:
    print(f"  {pass_count} PASSED  |  {fail_count} FAILED")
print(DIV)
