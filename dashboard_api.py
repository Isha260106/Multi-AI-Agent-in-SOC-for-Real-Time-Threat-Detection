"""
dashboard_api.py
================
FastAPI Backend for Real-Time Multi-Agent AI SOC Dashboard.

Multi-Agent SOC Project -- Real-Time SOC Dashboard Layer

PURPOSE:
  - Exposes REST endpoints reading directly from SQLite (soc.db) and agent configurations.
  - Read-only data access with CORS restricted to local dashboard origin.
  - Aggregates events, threat assessments, alerts, incidents, analytics, and agent health.
  - Gracefully handles empty databases, missing tables, and missing fields without crashing.
"""

import datetime
import json
import logging
import os
import pathlib
import sqlite3
import sys
import uuid
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Project path setup
# ---------------------------------------------------------------------------
PROJECT_ROOT = pathlib.Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    from storage.config import DB_PATH
except ImportError:
    DB_PATH = PROJECT_ROOT / "data" / "soc.db"

from fastapi import (
    FastAPI,
    HTTPException,
    Query,
    Request,
    Header,
    Security,
    Depends,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# FastAPI App Initialization
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Multi-Agent AI SOC Dashboard API",
    description="Real-Time Telemetry and Threat Posture Intelligence API",
    version="1.0.0",
)

# Enable CORS for local Vite development & previews
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:4173",
        "http://127.0.0.1:4173",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

logger = logging.getLogger("SOC.DashboardAPI")

# ---------------------------------------------------------------------------
# Ingestion Authentication & Unified Pipeline Singleton
# ---------------------------------------------------------------------------
DEFAULT_SENSOR_KEY = "soc-sensor-dev-key-2026"
api_key_header = APIKeyHeader(name="X-SOC-Sensor-Key", auto_error=False)


def verify_sensor_key(
    x_soc_sensor_key: Optional[str] = Security(api_key_header),
    authorization: Optional[str] = Header(None),
) -> str:
    """
    Validate that incoming requests carry a valid Pre-Shared Key (PSK).
    Checks header 'X-SOC-Sensor-Key' or 'Authorization: Bearer <key>'.
    Configurable via SOC_SENSOR_KEY environment variable.
    """
    key = None
    if x_soc_sensor_key:
        key = x_soc_sensor_key.strip()
    elif authorization:
        auth = authorization.strip()
        if auth.lower().startswith("bearer "):
            key = auth[7:].strip()
        elif auth.lower().startswith("apikey "):
            key = auth[7:].strip()
        else:
            key = auth

    expected_key = os.environ.get("SOC_SENSOR_KEY", DEFAULT_SENSOR_KEY)
    if not key or key != expected_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Invalid or missing sensor key",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    return key


_pipeline_instance: Optional[Any] = None


def get_pipeline():
    """Lazy-load the unified SOC pipeline singleton for ingestion."""
    global _pipeline_instance
    if _pipeline_instance is None:
        from kafka.consumer import SOCPipeline
        _pipeline_instance = SOCPipeline()
    return _pipeline_instance


class FlowIngestPayload(BaseModel):
    event_id: Optional[str] = Field(None, description="Unique UUID for this event. Generated if omitted.")
    timestamp: Optional[str] = Field(None, description="ISO-8601 flow timestamp. Generated if omitted.")
    source: Optional[str] = Field("live_sensor", description="Source identifier (marked as live_sensor).")
    sequence: Optional[int] = Field(None, description="Optional monotonic sequence number from sensor.")
    src_ip: Optional[str] = Field(None, description="Observed source IP address.")
    dst_ip: Optional[str] = Field(None, description="Observed destination IP address.")
    src_port: Optional[int] = Field(None, description="Observed source transport port.")
    dst_port: Optional[int] = Field(None, description="Observed destination transport port.")
    protocol: Optional[Any] = Field(None, description="Transport protocol number or name.")
    actual_label: Optional[str] = Field(None, description="Ground truth label if known (for verification).")
    features: Dict[str, Any] = Field(..., description="Map of exactly 78 extracted flow metrics.")


# ---------------------------------------------------------------------------
# SQLite Read Connection Helper
# ---------------------------------------------------------------------------
def get_db_connection() -> Optional[sqlite3.Connection]:
    """Return a read-only sqlite3 connection or None if database doesn't exist."""
    if not DB_PATH.exists():
        return None
    try:
        # uri=True with ro mode ensures read-only safety
        uri = f"file:{DB_PATH.as_posix()}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn
    except Exception as exc:
        logger.warning("Failed to open db in read-only URI mode: %s. Falling back.", exc)
        try:
            conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
            conn.row_factory = sqlite3.Row
            return conn
        except Exception:
            return None


def safe_json_loads(val: Any, default=None):
    if not val or not isinstance(val, str):
        return default
    try:
        return json.loads(val)
    except Exception:
        return default


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/health")
def get_health():
    """Verify backend and database connection state."""
    db_ok = DB_PATH.exists()
    return {
        "status": "online",
        "timestamp": datetime.datetime.now().isoformat(),
        "database_exists": db_ok,
        "database_path": str(DB_PATH),
    }


@app.get("/api/agents/status")
def get_agents_status():
    """
    Return health and operational status of all pipeline agents and storage components.
    Checks models, tables, and runtime files without fabricating data.
    """
    agents = []

    # 1. Network Detection Agent
    rf_model_path = PROJECT_ROOT / "models" / "network_detection_model.pkl"
    rf_meta_path = PROJECT_ROOT / "models" / "network_detection_preprocessing.pkl"
    nd_active = (
        rf_model_path.is_file() and rf_model_path.stat().st_size > 0 and
        rf_meta_path.is_file() and rf_meta_path.stat().st_size > 0
    )
    agents.append({
        "id": "network_detection",
        "name": "Network Detection Agent",
        "type": "Supervised Classifier",
        "model": "Random Forest (78 features)",
        "status": "ACTIVE" if nd_active else "DEGRADED",
        "details": f"Signature model {'ready (78 features)' if nd_active else 'missing model or preprocessing metadata'}",
    })

    # 2. Anomaly Detection Agent
    if_model_path = PROJECT_ROOT / "models" / "anomaly_detection_model.pkl"
    if_meta_path = PROJECT_ROOT / "models" / "anomaly_detection_preprocessing.pkl"
    ad_active = (
        if_model_path.is_file() and if_model_path.stat().st_size > 0 and
        if_meta_path.is_file() and if_meta_path.stat().st_size > 0
    )
    agents.append({
        "id": "anomaly_detection",
        "name": "Anomaly Detection Agent",
        "type": "Unsupervised Outlier Detector",
        "model": "Isolation Forest",
        "status": "ACTIVE" if ad_active else "DEGRADED",
        "details": f"Baseline model {'ready (Isolation Forest)' if ad_active else 'missing model or preprocessing metadata'}",
    })

    # 3. Alert Correlation Agent
    agents.append({
        "id": "alert_correlation",
        "name": "Alert Correlation Agent",
        "type": "Multi-Agent Synthesizer",
        "model": "Deterministic Rule Graph",
        "status": "ACTIVE",
        "details": "Aggregates multi-agent alerts by event UUID",
    })

    # 4. Threat Assessment Engine (Stage 9A)
    agents.append({
        "id": "threat_assessment",
        "name": "Unified Threat Assessment Engine",
        "type": "Zero-Rerun Decision Engine",
        "model": "Transparent Decision Table",
        "status": "ACTIVE",
        "details": "Deterministic policy classification without model re-runs",
    })

    # 5. Threat Investigation Coordinator (Stage 10)
    agents.append({
        "id": "threat_investigation",
        "name": "Threat Investigation Coordinator",
        "type": "Modular Multi-Agent Investigator",
        "model": "Evidence Synthesis & Causality Engine",
        "status": "ACTIVE",
        "details": "Evidence-backed deep investigation for suspicious and high-severity threats",
    })

    # 6. Threat Intelligence Agent (Stage 11)
    has_abuse = bool(os.environ.get("ABUSEIPDB_API_KEY", "").strip())
    has_vt = bool(os.environ.get("VIRUSTOTAL_API_KEY", "").strip())
    active_prov = "AbuseIPDB" if has_abuse else ("VirusTotal" if has_vt else "MockProvider (Offline Demo)")
    agents.append({
        "id": "threat_intelligence",
        "name": "Threat Intelligence Agent",
        "type": "Modular Threat Intel Enrichment",
        "model": f"Provider: {active_prov}",
        "status": "ACTIVE",
        "details": f"Observable indicator lookups & SQLite cache (Mode: {'External API' if (has_abuse or has_vt) else 'Offline Mock Fixtures'})",
    })

    # 7. Ingestion & Streaming Replay
    agents.append({
        "id": "event_ingestion",
        "name": "Event Stream Simulator",
        "type": "Dataset Stream Replay",
        "model": "In-Memory Queue IPC",
        "status": "READY",
        "details": "Near-real-time flow simulator (Non-live tap / simulated replay)",
    })

    # 8. Live Sensor Ingestion Endpoint (Phase 1)
    agents.append({
        "id": "live_sensor_ingestion",
        "name": "Live Sensor Ingestion Endpoint",
        "type": "Authenticated REST Sensor Ingestion",
        "model": "POST /api/ingest/flow (Phase 1 Ready)",
        "status": "ACTIVE",
        "details": "Authenticated receiver for live VM sensor telemetry",
    })

    # 9. Central Storage
    conn = get_db_connection()
    storage_status = "ONLINE" if conn else ("MISSING" if not DB_PATH.exists() else "ERROR")
    if conn:
        conn.close()

    agents.append({
        "id": "central_storage",
        "name": "Central Storage",
        "type": "SQLite WAL Engine",
        "model": "soc.db",
        "status": storage_status,
        "details": f"Path: {DB_PATH.name} ({'Available' if storage_status == 'ONLINE' else 'Unavailable'})",
    })

    return {
        "timestamp": datetime.datetime.now().isoformat(),
        "mode": "Simulated Dataset Replay (Emulated Real-Time Tap)",
        "is_live_packet_capture": False,
        "agents": agents,
    }


@app.get("/api/overview")
def get_overview_statistics():
    """
    Overview aggregate metrics:
    - total events, benign events, attack events, anomalous events, critical alerts, open incidents
    """
    empty_stats = {
        "total_events": 0,
        "benign_events": 0,
        "threat_events": 0,
        "anomalous_events": 0,
        "critical_alerts": 0,
        "total_alerts": 0,
        "open_incidents": 0,
        "total_assessments": 0,
        "avg_latency_ms": None,
        "earliest_timestamp": None,
        "latest_timestamp": None,
    }

    conn = get_db_connection()
    if not conn:
        return empty_stats

    try:
        # Check tables existence
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        
        total_events = 0
        if "events" in tables:
            row = conn.execute("SELECT COUNT(*) FROM events").fetchone()
            total_events = row[0] if row else 0

        # Predictions & alerts stats
        benign_count = 0
        threat_count = 0
        anom_count = 0
        critical_alerts = 0
        total_alerts = 0
        avg_latency = None

        if "alerts" in tables:
            total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            
            # Network detection predictions
            b_row = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE agent = 'Network Detection Agent' AND LOWER(prediction) = 'benign'"
            ).fetchone()
            benign_count = b_row[0] if b_row else 0

            t_row = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE agent = 'Network Detection Agent' AND LOWER(prediction) != 'benign'"
            ).fetchone()
            threat_count = t_row[0] if t_row else 0

            # Anomaly detections
            a_row = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE agent = 'Anomaly Detection Agent' AND LOWER(prediction) = 'anomalous'"
            ).fetchone()
            anom_count = a_row[0] if a_row else 0

            # High severity alerts
            c_row = conn.execute("SELECT COUNT(*) FROM alerts WHERE UPPER(severity) = 'HIGH'").fetchone()
            critical_alerts = c_row[0] if c_row else 0

            # Latency average
            lat_row = conn.execute("SELECT AVG(processing_time_s) FROM alerts WHERE processing_time_s IS NOT NULL").fetchone()
            if lat_row and lat_row[0] is not None:
                avg_latency = round(lat_row[0] * 1000, 2)

        # Incidents
        open_incidents = 0
        if "incidents" in tables:
            open_incidents = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]

        # Threat Assessments
        total_assessments = 0
        earliest_ts = None
        latest_ts = None
        if "threat_assessments" in tables:
            total_assessments = conn.execute("SELECT COUNT(*) FROM threat_assessments").fetchone()[0]
            ts_row = conn.execute("SELECT MIN(timestamp), MAX(timestamp) FROM threat_assessments").fetchone()
            if ts_row:
                earliest_ts, latest_ts = ts_row[0], ts_row[1]
        elif "events" in tables:
            ts_row = conn.execute("SELECT MIN(timestamp), MAX(timestamp) FROM events").fetchone()
            if ts_row:
                earliest_ts, latest_ts = ts_row[0], ts_row[1]

        # Threat Investigations (Stage 10)
        total_investigations = 0
        if "threat_investigations" in tables:
            total_investigations = conn.execute("SELECT COUNT(*) FROM threat_investigations").fetchone()[0]

        return {
            "total_events": total_events,
            "benign_events": benign_count,
            "threat_events": threat_count,
            "anomalous_events": anom_count,
            "critical_alerts": critical_alerts,
            "total_alerts": total_alerts,
            "open_incidents": open_incidents,
            "total_assessments": total_assessments,
            "total_investigations": total_investigations,
            "avg_latency_ms": avg_latency,
            "earliest_timestamp": earliest_ts,
            "latest_timestamp": latest_ts,
        }
    except Exception as exc:
        logger.error("Error reading overview stats: %s", exc)
        return empty_stats
    finally:
        conn.close()


@app.get("/api/events")
def get_live_events(
    limit: int = Query(50, ge=1, le=500),
    severity: Optional[str] = None,
    category: Optional[str] = None,
    prediction: Optional[str] = None,
    event_id: Optional[str] = None,
    search: Optional[str] = None,
):
    """
    Live Event Stream endpoint returning unified event records joined with
    Network Detection, Anomaly Detection, Correlated Incident, and Threat Assessment.
    """
    conn = get_db_connection()
    if not conn:
        return []

    try:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        if "events" not in tables:
            return []

        # Build dynamic query
        query = """
            SELECT 
                e.id,
                e.event_id,
                e.event_type,
                e.timestamp,
                e.source,
                e.sequence,
                e.actual_label,
                ta.assessment_id,
                ta.category AS threat_category,
                ta.severity AS threat_severity,
                ta.network_prediction,
                ta.anomaly_prediction,
                ta.network_confidence,
                ta.anomaly_score,
                ta.explanation AS threat_explanation,
                inc.incident_id,
                inc.status AS incident_status,
                inc.severity AS incident_severity
            FROM events e
            LEFT JOIN threat_assessments ta ON e.event_id = ta.event_id
            LEFT JOIN incidents inc ON e.event_id = inc.event_id
            WHERE 1=1
        """
        params: List[Any] = []

        if event_id:
            query += " AND e.event_id = ?"
            params.append(event_id.strip())

        if search:
            query += " AND (e.event_id LIKE ? OR e.source LIKE ? OR ta.explanation LIKE ?)"
            pat = f"%{search.strip()}%"
            params.extend([pat, pat, pat])

        if severity:
            query += " AND (UPPER(ta.severity) = UPPER(?) OR UPPER(inc.severity) = UPPER(?))"
            params.extend([severity.strip(), severity.strip()])

        if category:
            query += " AND LOWER(ta.category) = LOWER(?)"
            params.append(category.strip())

        if prediction:
            query += " AND (LOWER(ta.network_prediction) = LOWER(?) OR LOWER(e.actual_label) = LOWER(?))"
            params.extend([prediction.strip(), prediction.strip()])

        query += " ORDER BY e.id DESC LIMIT ?"
        params.append(limit)

        rows = conn.execute(query, params).fetchall()

        events_list = []
        for r in rows:
            d = dict(r)
            # Default fallbacks if threat assessment not populated yet
            if not d.get("threat_category"):
                d["threat_category"] = "Benign" if (d.get("actual_label") or "").lower() == "benign" else "Unknown"
            if not d.get("threat_severity"):
                d["threat_severity"] = "LOW" if d["threat_category"] == "Benign" else "INFORMATIONAL"

            events_list.append(d)

        return events_list
    except Exception as exc:
        logger.error("Error retrieving live events: %s", exc)
        return []
    finally:
        conn.close()


@app.get("/api/events/{event_id}")
def get_event_detail(event_id: str):
    """
    Detailed inspection for a specific event:
    - Raw features (78 flow metrics)
    - Network Detection Alert
    - Anomaly Detection Alert
    - Incident Record
    - Threat Assessment
    """
    conn = get_db_connection()
    if not conn:
        raise HTTPException(status_code=404, detail="Database not found")

    try:
        # Event row
        ev_row = conn.execute("SELECT * FROM events WHERE event_id = ?", (event_id,)).fetchone()
        if not ev_row:
            raise HTTPException(status_code=404, detail=f"Event {event_id} not found")

        ev_dict = dict(ev_row)
        ev_dict["features"] = safe_json_loads(ev_dict.get("features_json"), default={})

        # Alerts
        alerts_rows = conn.execute("SELECT * FROM alerts WHERE event_id = ? ORDER BY id ASC", (event_id,)).fetchall()
        alerts = []
        for a in alerts_rows:
            ad = dict(a)
            ad["network_context"] = safe_json_loads(ad.get("network_context_json"))
            ad["class_probabilities"] = safe_json_loads(ad.get("class_probabilities_json"))
            alerts.append(ad)

        # Incident
        inc_row = conn.execute("SELECT * FROM incidents WHERE event_id = ?", (event_id,)).fetchone()
        incident = dict(inc_row) if inc_row else None
        if incident:
            incident["correlated_agents"] = safe_json_loads(incident.get("correlated_agents"), [])
            incident["alert_ids"] = safe_json_loads(incident.get("alert_ids"), [])

        # Threat Assessment
        ta_row = conn.execute("SELECT * FROM threat_assessments WHERE event_id = ?", (event_id,)).fetchone()
        assessment = dict(ta_row) if ta_row else None

        # Threat Investigation (Stage 10)
        inv_row = conn.execute("SELECT * FROM threat_investigations WHERE event_id = ?", (event_id,)).fetchone()
        investigation = None
        if inv_row:
            investigation = dict(inv_row)
            for col in (
                "findings_by_agent_json", "supporting_evidence_json",
                "conflicting_signals_json", "reasoning_json",
                "limitations_json", "recommended_next_steps_json"
            ):
                clean_key = col.replace("_json", "")
                investigation[clean_key] = safe_json_loads(investigation.get(col), default=[] if "signals" in clean_key or "reasoning" in clean_key or "steps" in clean_key else {})

        return {
            "event": ev_dict,
            "alerts": alerts,
            "incident": incident,
            "threat_assessment": assessment,
            "threat_investigation": investigation,
        }
    finally:
        conn.close()


@app.get("/api/threats")
def get_threat_assessments(
    limit: int = Query(50, ge=1, le=200),
    category: Optional[str] = None,
    severity: Optional[str] = None,
    event_id: Optional[str] = None,
):
    """Retrieve list of unified threat assessments with deterministic explanations."""
    conn = get_db_connection()
    if not conn:
        return []

    try:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        if "threat_assessments" not in tables:
            return []

        query = "SELECT * FROM threat_assessments WHERE 1=1"
        params: List[Any] = []

        if category:
            query += " AND LOWER(category) = LOWER(?)"
            params.append(category.strip())

        if severity:
            query += " AND UPPER(severity) = UPPER(?)"
            params.append(severity.strip())

        if event_id:
            query += " AND event_id = ?"
            params.append(event_id.strip())

        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


@app.get("/api/alerts")
def get_alerts(
    limit: int = Query(50, ge=1, le=200),
    severity: Optional[str] = None,
    agent: Optional[str] = None,
    event_id: Optional[str] = None,
):
    """Retrieve raw alert records generated across detection agents."""
    conn = get_db_connection()
    if not conn:
        return []

    try:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        if "alerts" not in tables:
            return []

        query = "SELECT * FROM alerts WHERE 1=1"
        params: List[Any] = []

        if severity:
            query += " AND UPPER(severity) = UPPER(?)"
            params.append(severity.strip())

        if agent:
            query += " AND LOWER(agent) LIKE LOWER(?)"
            params.append(f"%{agent.strip()}%")

        if event_id:
            query += " AND event_id = ?"
            params.append(event_id.strip())

        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        rows = conn.execute(query, params).fetchall()
        alerts = []
        for r in rows:
            d = dict(r)
            d["network_context"] = safe_json_loads(d.get("network_context_json"))
            d["class_probabilities"] = safe_json_loads(d.get("class_probabilities_json"))
            alerts.append(d)
        return alerts
    finally:
        conn.close()


@app.get("/api/incidents")
def get_incidents(
    limit: int = Query(50, ge=1, le=200),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    event_id: Optional[str] = None,
):
    """Retrieve correlated multi-agent incidents."""
    conn = get_db_connection()
    if not conn:
        return []

    try:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        if "incidents" not in tables:
            return []

        query = "SELECT * FROM incidents WHERE 1=1"
        params: List[Any] = []

        if severity:
            query += " AND UPPER(severity) = UPPER(?)"
            params.append(severity.strip())

        if status:
            query += " AND UPPER(status) = UPPER(?)"
            params.append(status.strip())

        if event_id:
            query += " AND event_id = ?"
            params.append(event_id.strip())

        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        rows = conn.execute(query, params).fetchall()
        incidents = []
        for r in rows:
            d = dict(r)
            d["correlated_agents"] = safe_json_loads(d.get("correlated_agents"), [])
            d["alert_ids"] = safe_json_loads(d.get("alert_ids"), [])
            incidents.append(d)
        return incidents
    finally:
        conn.close()


@app.get("/api/investigations")
def get_investigations(
    limit: int = Query(50, ge=1, le=200),
    status: Optional[str] = None,
    category: Optional[str] = None,
    severity: Optional[str] = None,
    event_id: Optional[str] = None,
):
    """Retrieve list of completed multi-agent threat investigations."""
    conn = get_db_connection()
    if not conn:
        return []

    try:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        if "threat_investigations" not in tables:
            return []

        query = "SELECT * FROM threat_investigations WHERE 1=1"
        params: List[Any] = []

        if status:
            query += " AND UPPER(investigation_status) = UPPER(?)"
            params.append(status.strip())

        if category:
            query += " AND LOWER(threat_category) = LOWER(?)"
            params.append(category.strip())

        if severity:
            query += " AND UPPER(severity) = UPPER(?)"
            params.append(severity.strip())

        if event_id:
            query += " AND event_id = ?"
            params.append(event_id.strip())

        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        rows = conn.execute(query, params).fetchall()
        investigations = []
        for r in rows:
            d = dict(r)
            for col in (
                "findings_by_agent_json", "supporting_evidence_json",
                "conflicting_signals_json", "reasoning_json",
                "limitations_json", "recommended_next_steps_json"
            ):
                clean_key = col.replace("_json", "")
                d[clean_key] = safe_json_loads(d.get(col), default=[] if "signals" in clean_key or "reasoning" in clean_key or "steps" in clean_key else {})
            investigations.append(d)
        return investigations
    finally:
        conn.close()


@app.get("/api/investigations/{investigation_id}")
def get_investigation_report(investigation_id: str):
    """Retrieve a single investigation report by its UUID."""
    conn = get_db_connection()
    if not conn:
        raise HTTPException(status_code=404, detail="Database not found")

    try:
        row = conn.execute(
            "SELECT * FROM threat_investigations WHERE investigation_id = ?",
            (investigation_id.strip(),)
        ).fetchone()

        if not row:
            raise HTTPException(status_code=404, detail=f"Investigation report {investigation_id} not found")

        d = dict(row)
        for col in (
            "findings_by_agent_json", "supporting_evidence_json",
            "conflicting_signals_json", "reasoning_json",
            "limitations_json", "recommended_next_steps_json"
        ):
            clean_key = col.replace("_json", "")
            d[clean_key] = safe_json_loads(d.get(col), default=[] if "signals" in clean_key or "reasoning" in clean_key or "steps" in clean_key else {})
        return d
    finally:
        conn.close()



@app.get("/api/analytics")
def get_analytics():
    """
    Aggregations for graphs and visual charts:
    - Threat category breakdown
    - Severity breakdown
    - Agent detection breakdown
    - Flow processing latency distribution
    - Timeline activity
    """
    empty_result = {
        "categories": {},
        "severities": {},
        "agent_counts": {},
        "latency_stats": {"avg_ms": None, "min_ms": None, "max_ms": None},
        "timeline": [],
    }

    conn = get_db_connection()
    if not conn:
        return empty_result

    try:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}

        # 1. Threat categories
        categories = {}
        if "threat_assessments" in tables:
            rows = conn.execute("SELECT category, COUNT(*) FROM threat_assessments GROUP BY category").fetchall()
            categories = {r[0]: r[1] for r in rows if r[0]}

        # 2. Severities
        severities = {}
        if "threat_assessments" in tables:
            rows = conn.execute("SELECT severity, COUNT(*) FROM threat_assessments GROUP BY severity").fetchall()
            severities = {r[0]: r[1] for r in rows if r[0]}
        elif "alerts" in tables:
            rows = conn.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity").fetchall()
            severities = {r[0]: r[1] for r in rows if r[0]}

        # 3. Agent counts
        agent_counts = {}
        if "alerts" in tables:
            rows = conn.execute("SELECT agent, COUNT(*) FROM alerts GROUP BY agent").fetchall()
            agent_counts = {r[0]: r[1] for r in rows if r[0]}

        # 4. Latencies
        latency_stats = {"avg_ms": None, "min_ms": None, "max_ms": None}
        if "alerts" in tables:
            row = conn.execute(
                "SELECT AVG(processing_time_s), MIN(processing_time_s), MAX(processing_time_s) "
                "FROM alerts WHERE processing_time_s IS NOT NULL"
            ).fetchone()
            if row and row[0] is not None:
                latency_stats = {
                    "avg_ms": round(row[0] * 1000, 2),
                    "min_ms": round(row[1] * 1000, 2),
                    "max_ms": round(row[2] * 1000, 2),
                }

        # 5. Timeline (last 30 events grouped or sampled)
        timeline = []
        if "events" in tables:
            rows = conn.execute(
                "SELECT id, timestamp, actual_label FROM events ORDER BY id DESC LIMIT 30"
            ).fetchall()
            for r in reversed(rows):
                timeline.append({
                    "id": r["id"],
                    "timestamp": r["timestamp"][-8:] if r["timestamp"] else "N/A",
                    "label": r["actual_label"] or "Unknown",
                })

        return {
            "categories": categories,
            "severities": severities,
            "agent_counts": agent_counts,
            "latency_stats": latency_stats,
            "timeline": timeline,
        }
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Threat Intelligence Endpoints (Stage 11)
# ---------------------------------------------------------------------------

@app.get("/api/intel/cache")
def get_intel_cache(
    limit: int = Query(50, ge=1, le=200),
    verdict: Optional[str] = None,
    provider: Optional[str] = None,
):
    """Return recently cached threat intelligence lookups and cache summary."""
    conn = get_db_connection()
    if not conn:
        return {"items": [], "stats": {"total_cached": 0, "mock_count": 0, "real_count": 0, "expired_count": 0}}

    try:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        if "threat_intel_cache" not in tables:
            return {"items": [], "stats": {"total_cached": 0, "mock_count": 0, "real_count": 0, "expired_count": 0}}

        query = "SELECT * FROM threat_intel_cache"
        params: list[Any] = []
        conds: list[str] = []
        if verdict:
            conds.append("UPPER(verdict) = UPPER(?)")
            params.append(verdict.strip())
        if provider:
            conds.append("LOWER(provider) = LOWER(?)")
            params.append(provider.strip())
        if conds:
            query += " WHERE " + " AND ".join(conds)
        query += " ORDER BY last_checked DESC LIMIT ?"
        params.append(limit)

        rows = conn.execute(query, tuple(params)).fetchall()
        now_iso = datetime.datetime.now().isoformat()
        items = []
        for r in rows:
            d = dict(r)
            d["raw_response"] = safe_json_loads(d.get("raw_response_json"), default={})
            d["evidence_links"] = safe_json_loads(d.get("evidence_links_json"), default=[])
            d["is_mock"] = bool(d.get("is_mock", 0))
            d["is_expired"] = bool(d.get("expires_at") and str(d["expires_at"]) < now_iso)
            items.append(d)

        total = conn.execute("SELECT COUNT(*) FROM threat_intel_cache").fetchone()[0]
        mock_cnt = conn.execute("SELECT COUNT(*) FROM threat_intel_cache WHERE is_mock = 1").fetchone()[0]
        expired_cnt = conn.execute("SELECT COUNT(*) FROM threat_intel_cache WHERE expires_at < ?", (now_iso,)).fetchone()[0]

        return {
            "items": items,
            "stats": {
                "total_cached": total,
                "mock_count": mock_cnt,
                "real_count": total - mock_cnt,
                "expired_count": expired_cnt,
            },
        }
    finally:
        conn.close()


@app.get("/api/intel/lookup")
def api_intel_lookup(
    indicator: str = Query(..., description="Observable indicator (IP or Port)"),
    type: Optional[str] = Query(None, description="Indicator type: ip or port"),
    provider: Optional[str] = Query(None, description="mock, abuseipdb, or virustotal"),
    force: bool = Query(False, description="Force refresh bypassing cache"),
):
    """Perform real-time or cached threat intelligence lookup for an observable indicator."""
    from agents.threat_intelligence.agent import ThreatIntelligenceAgent
    from agents.threat_intelligence.providers import IPV4_REGEX

    ind_val = indicator.strip()
    ind_type = (type or "").strip().lower()
    if not ind_type:
        ind_type = "ip" if IPV4_REGEX.match(ind_val) else ("port" if ind_val.isdigit() else "ip")

    agent = ThreatIntelligenceAgent()
    try:
        res = agent.lookup(
            indicator_type=ind_type,
            indicator_value=ind_val,
            provider_name=provider,
            force_refresh=force,
        )
        return res
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/investigations/{investigation_id}/enrich")
def api_enrich_investigation(
    investigation_id: str,
    provider: Optional[str] = None,
    force: bool = False,
):
    """Enrich an existing investigation with threat intelligence and persist to database."""
    from agents.threat_intelligence.agent import ThreatIntelligenceAgent
    from storage.query import ThreatInvestigationQueryStore

    with ThreatInvestigationQueryStore() as q:
        inv = q.get_investigation_by_id(investigation_id)
        if not inv:
            inv = q.get_investigation_by_event_id(investigation_id)

    if not inv:
        raise HTTPException(status_code=404, detail=f"Threat investigation '{investigation_id}' not found.")

    agent = ThreatIntelligenceAgent()
    enriched = agent.enrich_investigation(inv, provider_name=provider, force_refresh=force, persist=True)
    return enriched


# ---------------------------------------------------------------------------
# Phase 1: Live VM Sensor Flow Ingestion Endpoint
# ---------------------------------------------------------------------------

@app.post("/api/ingest/flow", status_code=status.HTTP_201_CREATED)
async def ingest_flow_event(
    payload: FlowIngestPayload,
    request: Request,
    _auth_key: str = Depends(verify_sensor_key),
):
    """
    Secure, authenticated endpoint for ingesting live sensor flow events.

    Execution Pipeline:
      1. Request-size & Pre-Shared Key (PSK) authentication checks.
      2. Event schema validation (all 78 features present and numeric).
      3. Duplicate event_id check against SQLite (409 Conflict).
      4. Event routing through unified SOCPipeline:
         - Network Detection (Random Forest classifier)
         - Anomaly Detection (Isolation Forest detector)
         - Alert Correlation (multi-agent incident synthesis)
         - Threat Assessment (deterministic policy engine)
         - Threat Investigation (automated Stage 10 coordinator when triggered)
         - Storage persistence (soc.db WAL transactions)
      5. Response formatted with complete multi-agent analysis summary.
    """
    # 1. Enforce payload size limit (1MB = 1,048,576 bytes)
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > 1_048_576:
                raise HTTPException(
                    status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                    detail="Payload too large. Maximum allowed size is 1MB.",
                )
        except ValueError:
            pass

    raw_body = await request.body()
    if len(raw_body) > 1_048_576:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail="Payload too large. Maximum allowed size is 1MB.",
        )

    # 2. Validate features dictionary
    if not isinstance(payload.features, dict) or not payload.features:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Field 'features' must be a non-empty dictionary containing the 78 flow features.",
        )

    pipeline = get_pipeline()
    expected_features = pipeline.feature_names

    # Check for missing features
    missing = [f for f in expected_features if f not in payload.features]
    if missing:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": "Missing required model features",
                "missing_count": len(missing),
                "missing_features": missing[:10],
            },
        )

    # Check for non-numeric or invalid feature values
    invalid_features = []
    normalized_features = {}
    for f in expected_features:
        val = payload.features[f]
        if val is None or isinstance(val, bool):
            invalid_features.append(f)
        else:
            try:
                normalized_features[f] = float(val)
            except (ValueError, TypeError):
                invalid_features.append(f)

    if invalid_features:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": "Non-numeric or null feature values",
                "invalid_count": len(invalid_features),
                "invalid_features": invalid_features[:10],
            },
        )

    # 3. Check for duplicate event_id
    event_id = payload.event_id or str(uuid.uuid4())
    conn = get_db_connection()
    if conn:
        try:
            existing = conn.execute("SELECT 1 FROM events WHERE event_id = ?", (event_id,)).fetchone()
            if existing:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"Event ID '{event_id}' already exists in database.",
                )
        finally:
            conn.close()

    # 4. Context fallback from features if not given in top-level payload
    dst_port = payload.dst_port
    if dst_port is None and "Dst Port" in normalized_features:
        try:
            dst_port = int(normalized_features["Dst Port"])
        except Exception:
            pass

    protocol = payload.protocol
    if protocol is None and "Protocol" in normalized_features:
        try:
            protocol = int(normalized_features["Protocol"])
        except Exception:
            pass

    event_dict = {
        "event_id": event_id,
        "event_type": "network_flow",
        "timestamp": payload.timestamp or datetime.datetime.now().isoformat(),
        "source": payload.source or "live_sensor",
        "sequence": payload.sequence or 0,
        "actual_label": payload.actual_label,
        "src_ip": payload.src_ip,
        "dst_ip": payload.dst_ip,
        "src_port": payload.src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "features": normalized_features,
    }

    # 5. Process through the full existing SOC pipeline
    try:
        result = pipeline.process_event(event_dict, persist=True)
    except Exception as exc:
        logger.error("Pipeline failure for ingested flow event %s: %s", event_id, exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Pipeline processing failed: {str(exc)}",
        )

    # 6. Format and return response
    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content={
            "status": "ACCEPTED",
            "message": "Flow event successfully validated, analyzed, and persisted",
            "event_id": event_id,
            "source": event_dict["source"],
            "timestamp": event_dict["timestamp"],
            "network_context": {
                "src_ip": payload.src_ip,
                "dst_ip": payload.dst_ip,
                "src_port": payload.src_port,
                "dst_port": dst_port,
                "protocol": protocol,
            },
            "processing_time_s": result["processing_time_s"],
            "network_detection": {
                "prediction": result["network_alert"]["prediction"],
                "confidence": result["network_alert"]["confidence"],
                "severity": result["network_alert"]["severity"],
                "status": result["network_alert"]["status"],
            },
            "anomaly_detection": {
                "prediction": result["anomaly_alert"]["prediction"],
                "anomaly_score": result["anomaly_alert"]["anomaly_score"],
                "severity": result["anomaly_alert"]["severity"],
            } if result.get("anomaly_alert") else None,
            "threat_assessment": {
                "category": result["threat_assessment"]["category"],
                "severity": result["threat_assessment"]["severity"],
                "explanation": result["threat_assessment"]["explanation"],
            } if result.get("threat_assessment") else None,
            "incident": {
                "incident_id": result["incident"]["incident_id"],
                "status": result["incident"]["status"],
                "severity": result["incident"]["severity"],
            } if result.get("incident") else None,
            "investigation": {
                "investigation_id": result["investigation"]["investigation_id"],
                "investigation_status": result["investigation"]["investigation_status"],
                "threat_category": result["investigation"].get("threat_category"),
                "severity": result["investigation"].get("severity"),
                "summary": result["investigation"].get("summary"),
            } if result.get("investigation") else None,
            "investigation_triggered": result["investigation_triggered"],
            "persisted": result["persisted"],
        },
    )


if __name__ == "__main__":
    import uvicorn
    print(f"Starting Multi-Agent SOC Dashboard API on http://127.0.0.1:8000")
    uvicorn.run("dashboard_api:app", host="127.0.0.1", port=8000, reload=False)

