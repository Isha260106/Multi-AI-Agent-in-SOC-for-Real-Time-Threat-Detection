"""
test_threat_assessment.py
=========================
Validation Test Suite for Stage 9A: Unified Threat Assessment Engine

Multi-Agent SOC Project -- Stage 9A
"""

import datetime
import pathlib
import sys
import tempfile
import uuid

# Project root
PROJECT_ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from agents.threat_assessment.agent import ThreatAssessmentEngine, DECISION_TABLE_RULES
from agents.threat_assessment.config import (
    CATEGORY_CONFIRMED_ATTACK,
    CATEGORY_SUSPECTED_ATTACK,
    CATEGORY_SUSPICIOUS_ANOMALY,
    CATEGORY_BENIGN,
    CATEGORY_UNKNOWN,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_INFORMATIONAL,
)
from storage.db import AlertStore
from storage.query import ThreatAssessmentQueryStore, AlertQueryStore

DIV  = "=" * 76
DIV2 = "-" * 76

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


# ---------------------------------------------------------------------------
# Test Execution
# ---------------------------------------------------------------------------

def run_tests():
    engine = ThreatAssessmentEngine(log_to_file=False)

    # ------------------------------------------------------------------
    # 1. Decision Table - All Prediction Combinations
    # ------------------------------------------------------------------
    section("1. Decision Table: Prediction Combinations")

    # Case 1: Attack + Anomalous -> Confirmed Attack (HIGH)
    res1 = engine.assess(
        network_prediction="Infilteration",
        anomaly_prediction="Anomalous",
        network_confidence=0.92,
        anomaly_score=-0.15,
        event_id="e-01"
    )
    check("Dual threat: Confirmed Attack", res1["category"] == CATEGORY_CONFIRMED_ATTACK)
    check("Dual threat: Severity HIGH", res1["severity"] == SEVERITY_HIGH)
    check("Scores preserved", res1["network_confidence"] == 0.92 and res1["anomaly_score"] == -0.15)
    check("Explanation contains dual confirmation", "Dual confirmation" in res1["explanation"])

    # Case 2: Attack + Normal -> Suspected Attack (HIGH)
    res2 = engine.assess(
        network_prediction="Infilteration",
        anomaly_prediction="Normal",
        network_confidence=0.88,
        anomaly_score=0.12,
        event_id="e-02"
    )
    check("Attack + Normal: Suspected Attack", res2["category"] == CATEGORY_SUSPECTED_ATTACK)
    check("Attack + Normal: Severity HIGH", res2["severity"] == SEVERITY_HIGH)

    # Case 3: Benign + Anomalous -> Suspicious Anomaly (MEDIUM)
    # Critical requirement: Anomaly alone MUST NOT mean confirmed attack
    res3 = engine.assess(
        network_prediction="Benign",
        anomaly_prediction="Anomalous",
        network_confidence=0.99,
        anomaly_score=-0.08,
        event_id="e-03"
    )
    check("Benign + Anomalous: Suspicious Anomaly", res3["category"] == CATEGORY_SUSPICIOUS_ANOMALY)
    check("Benign + Anomalous: Severity MEDIUM", res3["severity"] == SEVERITY_MEDIUM)
    check("Rule enforcement: Not confirmed attack", res3["category"] != CATEGORY_CONFIRMED_ATTACK)
    check("Explanation mentions anomaly alone is not confirmed attack", "NOT" in res3["explanation"])

    # Case 4: Benign + Normal -> Benign (LOW)
    res4 = engine.assess(
        network_prediction="Benign",
        anomaly_prediction="Normal",
        network_confidence=0.98,
        anomaly_score=0.25,
        event_id="e-04"
    )
    check("Benign + Normal: Benign", res4["category"] == CATEGORY_BENIGN)
    check("Benign + Normal: Severity LOW", res4["severity"] == SEVERITY_LOW)

    # ------------------------------------------------------------------
    # 2. Missing Scores and Partial Agent Results
    # ------------------------------------------------------------------
    section("2. Partial Agent Results & Missing Scores")

    # Case 5: Attack + Anomaly Missing
    res5 = engine.assess(
        network_prediction="Infilteration",
        anomaly_prediction=None,
        network_confidence=0.85,
        anomaly_score=None,
        event_id="e-05"
    )
    check("Attack + None: Suspected Attack", res5["category"] == CATEGORY_SUSPECTED_ATTACK)
    check("Missing score remains None (no fake score)", res5["anomaly_score"] is None)

    # Case 6: Benign + Anomaly Missing
    res6 = engine.assess(
        network_prediction="Benign",
        anomaly_prediction=None,
        network_confidence=0.95,
        anomaly_score=None,
        event_id="e-06"
    )
    check("Benign + None: Benign", res6["category"] == CATEGORY_BENIGN)

    # Case 7: Network Missing + Anomalous
    res7 = engine.assess(
        network_prediction=None,
        anomaly_prediction="Anomalous",
        network_confidence=None,
        anomaly_score=-0.22,
        event_id="e-07"
    )
    check("None + Anomalous: Suspicious Anomaly", res7["category"] == CATEGORY_SUSPICIOUS_ANOMALY)
    check("None + Anomalous: Not confirmed attack", res7["category"] != CATEGORY_CONFIRMED_ATTACK)
    check("Missing network confidence remains None", res7["network_confidence"] is None)

    # Case 8: Network Missing + Normal
    res8 = engine.assess(
        network_prediction=None,
        anomaly_prediction="Normal",
        network_confidence=None,
        anomaly_score=0.10,
        event_id="e-08"
    )
    check("None + Normal: Benign", res8["category"] == CATEGORY_BENIGN)

    # Case 9: Both Missing
    res9 = engine.assess(
        network_prediction=None,
        anomaly_prediction=None,
        network_confidence=None,
        anomaly_score=None,
        event_id="e-09"
    )
    check("None + None: Unknown", res9["category"] == CATEGORY_UNKNOWN)
    check("None + None: Severity INFORMATIONAL", res9["severity"] == SEVERITY_INFORMATIONAL)

    # ------------------------------------------------------------------
    # 3. Assessment from Heterogeneous Alert Dicts
    # ------------------------------------------------------------------
    section("3. Assessment from Alert Dicts & List API")

    eid_alert = str(uuid.uuid4())
    net_alert = {
        "alert_id": str(uuid.uuid4()),
        "event_id": eid_alert,
        "agent": "Network Detection Agent",
        "prediction": "Infilteration",
        "confidence": 0.912,
        "severity": "HIGH",
    }
    anom_alert = {
        "alert_id": str(uuid.uuid4()),
        "event_id": eid_alert,
        "agent": "Anomaly Detection Agent",
        "prediction": "Anomalous",
        "anomaly_score": -0.185,
        "severity": "HIGH",
    }

    res_dicts = engine.assess(
        network_alert=net_alert,
        anomaly_alert=anom_alert,
    )
    check("Direct dict resolution: event_id matches", res_dicts["event_id"] == eid_alert)
    check("Direct dict resolution: Confirmed Attack", res_dicts["category"] == CATEGORY_CONFIRMED_ATTACK)
    check("Scores extracted without re-running models", res_dicts["network_confidence"] == 0.912)

    res_list = engine.assess_from_alerts([net_alert, anom_alert])
    check("assess_from_alerts(): Category matches", res_list["category"] == CATEGORY_CONFIRMED_ATTACK)
    check("assess_from_alerts(): Scores match", res_list["anomaly_score"] == -0.185)

    expect_error(
        "assess_from_alerts() raises TypeError for non-list",
        lambda: engine.assess_from_alerts("not-a-list"),
        TypeError
    )

    # ------------------------------------------------------------------
    # 4. Storage Persistence and Duplicate Prevention (Idempotency)
    # ------------------------------------------------------------------
    section("4. SQLite Persistence & Duplicate Prevention")

    with tempfile.TemporaryDirectory() as tmpdir:
        test_db = pathlib.Path(tmpdir) / "test_soc.db"
        with AlertStore(db_path=test_db) as store:
            # First save an event (FK parent)
            eid_store = str(uuid.uuid4())
            store.save_event({
                "event_id": eid_store,
                "features": {"f1": 1.0},
                "event_type": "network_flow",
            })

            # Create assessment
            asm1 = engine.assess(
                network_prediction="Infilteration",
                anomaly_prediction="Anomalous",
                network_confidence=0.89,
                anomaly_score=-0.14,
                event_id=eid_store,
            )

            # Insert assessment
            inserted1 = store.save_assessment(asm1)
            check("Initial assessment insertion succeeds", inserted1 is True)
            check("Database count equals 1", store.assessment_count() == 1)

            # Attempt duplicate insertion with same assessment_id (Idempotent)
            inserted2 = store.save_assessment(asm1)
            check("Duplicate assessment insertion safely ignored (INSERT OR IGNORE)", inserted2 is False)
            check("Database count remains 1", store.assessment_count() == 1)

        # Query tests on test database
        with ThreatAssessmentQueryStore(db_path=test_db) as qs:
            recents = qs.get_recent_assessments(10)
            check("get_recent_assessments returns 1 record", len(recents) == 1)
            check("Category query matches", len(qs.get_assessments_by_category("Confirmed Attack")) == 1)
            check("Severity query matches", len(qs.get_assessments_by_severity("HIGH")) == 1)
            check("Event ID query matches", len(qs.get_assessments_by_event_id(eid_store)) == 1)
            check("Assessment ID query matches", qs.get_assessment_by_id(asm1["assessment_id"]) is not None)

            # Summary stats
            stats = qs.summary_stats_assessments()
            check("summary_stats_assessments total", stats["total_assessments"] == 1)
            check("summary_stats_assessments category counts", stats["category_counts"].get("Confirmed Attack") == 1)

    # ------------------------------------------------------------------
    # 5. Production Database Non-Destructive Regression Check
    # ------------------------------------------------------------------
    section("5. Production Database Non-Destructive Regression")

    from storage.config import DB_PATH
    if DB_PATH.exists():
        with AlertStore(db_path=DB_PATH) as prod_store:
            ev_count = prod_store.event_count()
            al_count = prod_store.alert_count()
            inc_count = prod_store.incident_count()
            asm_count = prod_store.assessment_count()

            check(f"Existing events intact ({ev_count} rows)", ev_count >= 0)
            check(f"Existing alerts intact ({al_count} rows)", al_count >= 700)
            check(f"Existing incidents intact ({inc_count} rows)", inc_count >= 0)
            check("Threat assessments table accessible in production soc.db", asm_count >= 0)

        with AlertQueryStore(db_path=DB_PATH) as aqs:
            recent_alerts = aqs.get_recent_alerts(5)
            check("Existing AlertQueryStore remains fully functional", len(recent_alerts) == 5)
    else:
        print("  [SKIP] Production database does not exist yet.")

    # ------------------------------------------------------------------
    # Final Result
    # ------------------------------------------------------------------
    print(f"\n{DIV}")
    print(f"  RESULTS: {pass_count} PASSED, {fail_count} FAILED")
    print(DIV)
    if fail_count > 0:
        sys.exit(1)


if __name__ == "__main__":
    run_tests()
