"""
test_threat_investigation.py
============================
Validation Test Suite for Stage 10: Multi-Agent Threat Investigation

Multi-Agent SOC Project -- Stage 10
"""

import json
import pathlib
import sys
import tempfile
import uuid

# Project root
PROJECT_ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from agents.threat_investigation.coordinator import (
    ThreatInvestigationCoordinator,
    NetworkEvidenceModule,
    AnomalyExplanationModule,
    AlertCorrelationModule,
    InvestigationSummaryModule,
)
from agents.threat_investigation.config import (
    STATUS_COMPLETED,
    STATUS_REQUIRES_TIER2,
    STATUS_INCONCLUSIVE,
    STATUS_CLOSED_BENIGN,
)
from storage.db import AlertStore
from storage.query import ThreatInvestigationQueryStore, ThreatAssessmentQueryStore, AlertQueryStore

DIV = "=" * 76
DIV2 = "-" * 76

pass_count = 0
fail_count = 0


def section(title: str) -> None:
    print(f"\n{DIV}")
    print(f"  {title}")
    print(DIV)


def check(name: str, passed: bool, detail: str = "") -> None:
    global pass_count, fail_count
    icon = "[OK  ]" if passed else "[FAIL]"
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


def run_tests():
    coord = ThreatInvestigationCoordinator(log_to_file=False)

    # ------------------------------------------------------------------
    # 1. Benign Event Exclusion Logic
    # ------------------------------------------------------------------
    section("1. Benign Event Exclusion Logic")

    benign_ta = {
        "category": "Benign",
        "severity": "LOW",
        "network_prediction": "Benign",
        "anomaly_prediction": "Normal",
    }
    check(
        "should_investigate is False for Benign Low",
        coord.should_investigate(benign_ta) is False
    )

    benign_result = coord.investigate(
        event_id="eid-benign-01",
        threat_assessment=benign_ta,
        force=False,
    )
    check("investigate() skips benign event without error", benign_result is None)

    # Force investigation on benign flow
    forced_result = coord.investigate(
        event_id="eid-benign-01",
        threat_assessment=benign_ta,
        force=True,
    )
    check("Forced investigation succeeds on benign flow", forced_result is not None)
    if forced_result:
        check("Forced benign status is CLOSED_BENIGN", forced_result["investigation_status"] == STATUS_CLOSED_BENIGN)

    # ------------------------------------------------------------------
    # 2. Suspicious & High-Severity Threat Investigations
    # ------------------------------------------------------------------
    section("2. Suspicious & High-Severity Threat Investigations")

    # Case A: Confirmed Attack
    confirmed_ta = {
        "category": "Confirmed Attack",
        "severity": "HIGH",
        "network_prediction": "Infilteration",
        "anomaly_prediction": "Anomalous",
        "network_confidence": 0.95,
        "anomaly_score": -0.45,
    }
    ev_attack = {
        "features": {
            "Dst Port": 443,
            "Protocol": 6,
            "Flow Duration": 1200000,
            "Flow Pkts/s": 1500.0,
            "Tot Fwd Pkts": 50,
            "Tot Bwd Pkts": 20,
            "SYN Flag Cnt": 1,
            "RST Flag Cnt": 0,
        }
    }
    net_al = {
        "agent": "Network Detection Agent",
        "prediction": "Infilteration",
        "confidence": 0.95,
        "severity": "HIGH",
    }
    anom_al = {
        "agent": "Anomaly Detection Agent",
        "prediction": "Anomalous",
        "anomaly_score": -0.45,
        "severity": "HIGH",
    }
    inc_sample = {
        "incident_id": "inc-001",
        "status": "CORRELATED_THREAT",
        "severity": "HIGH",
        "alert_ids": ["al-1", "al-2"],
        "correlation_reason": "Dual threat alert correlation",
    }

    inv_confirmed = coord.investigate(
        event_id="eid-confirmed-01",
        event=ev_attack,
        network_alert=net_al,
        anomaly_alert=anom_al,
        incident=inc_sample,
        threat_assessment=confirmed_ta,
    )
    check("Confirmed Attack triggers investigation", inv_confirmed is not None)
    if inv_confirmed:
        check("Investigation status is COMPLETED", inv_confirmed["investigation_status"] == STATUS_COMPLETED)
        check("Network velocity detected", any("velocity" in f.lower() or "flood" in f.lower() for f in inv_confirmed["findings_by_agent"]["network_evidence"]))
        check("Anomaly depth explained", any("deep isolation" in f.lower() or "outlier" in f.lower() for f in inv_confirmed["findings_by_agent"]["anomaly_explanation"]))
        check("No conflicting signals in dual confirmation", len(inv_confirmed["conflicting_signals"]) == 0)
        check("Concrete next steps provided", len(inv_confirmed["recommended_next_steps"]) >= 2)

    # Case B: Suspicious Anomaly (Requires Tier-2 SOC verification)
    suspicious_ta = {
        "category": "Suspicious Anomaly",
        "severity": "MEDIUM",
        "network_prediction": "Benign",
        "anomaly_prediction": "Anomalous",
        "network_confidence": 0.99,
        "anomaly_score": -0.25,
    }
    ev_suspicious = {
        "features": {
            "Dst Port": 0,
            "Protocol": 0,
            "Flow Duration": 62000000,
            "Flow Pkts/s": 0.05,
            "Tot Fwd Pkts": 3,
            "Tot Bwd Pkts": 0,
        }
    }
    net_benign_al = {
        "agent": "Network Detection Agent",
        "prediction": "Benign",
        "confidence": 0.99,
        "severity": "LOW",
    }

    inv_suspicious = coord.investigate(
        event_id="eid-suspicious-01",
        event=ev_suspicious,
        network_alert=net_benign_al,
        anomaly_alert=anom_al,
        incident=None,
        threat_assessment=suspicious_ta,
    )
    check("Suspicious Anomaly triggers investigation", inv_suspicious is not None)
    if inv_suspicious:
        check("Investigation status is REQUIRES_TIER2", inv_suspicious["investigation_status"] == STATUS_REQUIRES_TIER2)
        check("Unidirectional flow detected", any("unidirectional" in f.lower() for f in inv_suspicious["findings_by_agent"]["network_evidence"]))
        check("Conflicting signals flagged (Benign vs Anomalous)", len(inv_suspicious["conflicting_signals"]) > 0)
        check("Limitations clearly state anomaly alone != attack", any("unsupervised density" in lim.lower() for lim in inv_suspicious["limitations"]))

    # ------------------------------------------------------------------
    # 3. Missing Evidence & Partial Telemetry
    # ------------------------------------------------------------------
    section("3. Missing Evidence & Partial Telemetry")

    # Missing all features and alerts
    inv_partial = coord.investigate(
        event_id="eid-partial-01",
        event=None,
        network_alert=None,
        anomaly_alert=None,
        incident=None,
        threat_assessment={"category": "Unknown", "severity": "INFORMATIONAL"},
        force=True,
    )
    check("Graceful handling of missing inputs", inv_partial is not None)
    if inv_partial:
        check("Status is INCONCLUSIVE on missing evidence", inv_partial["investigation_status"] == STATUS_INCONCLUSIVE)
        check("Limitations note missing features", any("missing" in lim.lower() for lim in inv_partial["limitations"]))

    expect_error(
        "investigate() raises ValueError for missing event_id",
        lambda: coord.investigate(event_id=""),
        ValueError
    )

    # ------------------------------------------------------------------
    # 4. Storage Persistence & Duplicate Prevention (Idempotency)
    # ------------------------------------------------------------------
    section("4. Storage Persistence & Duplicate Prevention")

    with tempfile.TemporaryDirectory() as tmpdir:
        test_db = pathlib.Path(tmpdir) / "test_soc.db"
        with AlertStore(db_path=test_db) as store:
            eid_store = str(uuid.uuid4())
            # Save parent event
            store.save_event({
                "event_id": eid_store,
                "features": {"Dst Port": 80},
                "event_type": "network_flow",
            })

            inv_report = coord.investigate(
                event_id=eid_store,
                event={"features": {"Dst Port": 80}},
                threat_assessment={"category": "Confirmed Attack", "severity": "HIGH"},
            )
            assert inv_report is not None

            # 1st insertion
            inserted1 = store.save_investigation(inv_report)
            check("Initial investigation report inserted", inserted1 is True)
            check("Investigation count is 1", store.investigation_count() == 1)

            # 2nd duplicate insertion (same investigation_id / event_id)
            inserted2 = store.save_investigation(inv_report)
            check("Duplicate investigation safely ignored (INSERT OR IGNORE)", inserted2 is False)
            check("Investigation count remains 1", store.investigation_count() == 1)

        # Query Store validation
        with ThreatInvestigationQueryStore(db_path=test_db) as qs:
            recents = qs.get_recent_investigations(10)
            check("get_recent_investigations returns 1 record", len(recents) == 1)
            check("get_investigation_by_id retrieves correct report", qs.get_investigation_by_id(inv_report["investigation_id"]) is not None)
            check("get_investigation_by_event_id retrieves correct report", qs.get_investigation_by_event_id(eid_store) is not None)
            check("get_investigations_by_status matches", len(qs.get_investigations_by_status(STATUS_COMPLETED)) == 1)

            stats = qs.summary_stats_investigations()
            check("summary_stats_investigations count", stats["total_investigations"] == 1)
            check("summary_stats_investigations status count", stats["status_counts"].get(STATUS_COMPLETED) == 1)

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
            inv_count = prod_store.investigation_count()

            check(f"Existing events intact ({ev_count} rows)", ev_count >= 10)
            check(f"Existing alerts intact ({al_count} rows)", al_count >= 700)
            check(f"Existing incidents intact ({inc_count} rows)", inc_count >= 2)
            check(f"Existing assessments intact ({asm_count} rows)", asm_count >= 5)
            check(f"Threat investigations table functional ({inv_count} rows)", inv_count >= 1)

        with ThreatInvestigationQueryStore(db_path=DB_PATH) as prod_qs:
            recent_invs = prod_qs.get_recent_investigations(5)
            check("Production investigation query works", len(recent_invs) >= 1)
    else:
        print("  [SKIP] Production database does not exist.")

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
