"""
storage/query.py
=================
Search and Retrieval API

Multi-Agent SOC Project -- Stage 5: Central Event and Alert Storage

PURPOSE
-------
Provides all read operations on the soc.db database.

All query methods return plain Python dicts (or lists of dicts) so
callers do not need to know about sqlite3.Row internals.

SUPPORTED QUERIES
-----------------
  get_recent_alerts(n)                  -- latest N alerts (most-recent first)
  get_alerts_by_severity(severity)      -- "HIGH" or "LOW"
  get_alerts_by_status(status)          -- "SUSPICIOUS" or "NORMAL"
  get_alerts_by_prediction(prediction)  -- "Infilteration" or "Benign"
  get_alerts_in_timerange(start, end)   -- ISO-8601 timestamp strings
  get_alert_by_event_id(event_id)       -- all alerts linked to one event
  count_by_prediction()                 -- {"Benign": N, "Infilteration": N}
  count_by_severity()                   -- {"HIGH": N, "LOW": N}
  summary_stats()                       -- aggregate overview dict
  search_alerts(keyword, field)         -- SQL LIKE pattern on a specified column
"""

import datetime
import json
import logging
import pathlib
import sqlite3
import sys
from typing import Any

# ---------------------------------------------------------------------------
# Project path
# ---------------------------------------------------------------------------
PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from storage.config import DB_PATH, SQLITE_PRAGMAS, STREAMING_RUNTIME_LOG

# ---------------------------------------------------------------------------
# Module logger
# ---------------------------------------------------------------------------
_log = logging.getLogger("SOC.Storage.Query")
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
# Allowed columns for search_alerts (prevents SQL injection)
# ---------------------------------------------------------------------------
_SEARCHABLE_FIELDS = {
    "prediction", "severity", "status", "agent",
    "event_id", "alert_id", "actual_label",
}

_INCIDENT_SEARCHABLE_FIELDS = {
    "prediction", "severity", "status", "event_id",
    "incident_id", "correlation_reason"
}


def _row_to_dict(row: sqlite3.Row) -> dict:
    """Convert a sqlite3.Row to a plain Python dict."""
    d = dict(row)
    # Deserialise JSON blob columns
    for col in ("network_context_json", "class_probabilities_json"):
        if col in d and d[col] is not None:
            try:
                d[col] = json.loads(d[col])
            except (json.JSONDecodeError, TypeError):
                pass   # leave as raw string on parse failure
    return d


def _incident_row_to_dict(row: sqlite3.Row) -> dict:
    """Convert an incident sqlite3.Row to a plain Python dict."""
    d = dict(row)
    for col in ("correlated_agents", "alert_ids"):
        if col in d and d[col] is not None:
            try:
                d[col] = json.loads(d[col])
            except (json.JSONDecodeError, TypeError):
                d[col] = [] # Fallback
    return d


# ---------------------------------------------------------------------------
# AlertQueryStore
# ---------------------------------------------------------------------------

class AlertQueryStore:
    """
    Read-only query interface for the soc.db SQLite database.

    Usage (context manager):
        with AlertQueryStore() as q:
            results = q.get_recent_alerts(20)

    Usage (manual):
        q = AlertQueryStore()
        results = q.get_recent_alerts(20)
        q.close()
    """

    def __init__(self, db_path: pathlib.Path = DB_PATH):
        self._db_path = db_path
        if not db_path.exists():
            raise FileNotFoundError(
                f"Database not found: {db_path}\n"
                "Run the demo or ingest.py first to create and populate the database."
            )
        self._conn = sqlite3.connect(
            str(db_path), check_same_thread=False,
            detect_types=sqlite3.PARSE_DECLTYPES,
        )
        self._conn.row_factory = sqlite3.Row
        for pragma in SQLITE_PRAGMAS:
            self._conn.execute(pragma)
        _log.debug("Query connection opened: %s", db_path)

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    # ------------------------------------------------------------------
    # Basic retrieval queries
    # ------------------------------------------------------------------

    def get_recent_alerts(self, n: int = 20) -> list[dict]:
        """Return the N most-recent alerts (by timestamp, descending)."""
        rows = self._conn.execute(
            "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?;", (n,)
        ).fetchall()
        _log.debug("get_recent_alerts(n=%d) -> %d rows", n, len(rows))
        return [_row_to_dict(r) for r in rows]

    def get_alerts_by_severity(self, severity: str) -> list[dict]:
        """Return all alerts with the given severity ('HIGH' or 'LOW')."""
        rows = self._conn.execute(
            "SELECT * FROM alerts WHERE severity = ? ORDER BY timestamp DESC;",
            (severity.upper(),),
        ).fetchall()
        _log.debug("get_alerts_by_severity(%r) -> %d rows", severity, len(rows))
        return [_row_to_dict(r) for r in rows]

    def get_alerts_by_status(self, status: str) -> list[dict]:
        """Return all alerts with the given status ('SUSPICIOUS' or 'NORMAL')."""
        rows = self._conn.execute(
            "SELECT * FROM alerts WHERE status = ? ORDER BY timestamp DESC;",
            (status.upper(),),
        ).fetchall()
        _log.debug("get_alerts_by_status(%r) -> %d rows", status, len(rows))
        return [_row_to_dict(r) for r in rows]

    def get_alerts_by_prediction(self, prediction: str) -> list[dict]:
        """Return all alerts with the given prediction ('Benign' or 'Infilteration')."""
        rows = self._conn.execute(
            "SELECT * FROM alerts WHERE prediction = ? ORDER BY timestamp DESC;",
            (prediction,),
        ).fetchall()
        _log.debug("get_alerts_by_prediction(%r) -> %d rows", prediction, len(rows))
        return [_row_to_dict(r) for r in rows]

    def get_alerts_in_timerange(self, start: str, end: str) -> list[dict]:
        """
        Return alerts whose timestamp falls within [start, end].

        Args:
            start: ISO-8601 string, e.g. "2026-09-16T12:00:00"
            end  : ISO-8601 string, e.g. "2026-09-16T13:00:00"
        """
        rows = self._conn.execute(
            """SELECT * FROM alerts
               WHERE timestamp >= ? AND timestamp <= ?
               ORDER BY timestamp ASC;""",
            (start, end),
        ).fetchall()
        _log.debug(
            "get_alerts_in_timerange(%r, %r) -> %d rows", start, end, len(rows)
        )
        return [_row_to_dict(r) for r in rows]

    def get_alert_by_event_id(self, event_id: str) -> list[dict]:
        """Return all alerts linked to a specific event_id."""
        rows = self._conn.execute(
            "SELECT * FROM alerts WHERE event_id = ? ORDER BY timestamp ASC;",
            (event_id,),
        ).fetchall()
        _log.debug("get_alert_by_event_id(%r) -> %d rows", event_id, len(rows))
        return [_row_to_dict(r) for r in rows]

    def get_event_by_id(self, event_id: str) -> dict | None:
        """Return single raw event record by event_id."""
        row = self._conn.execute(
            "SELECT * FROM events WHERE event_id = ? LIMIT 1;",
            (event_id.strip(),),
        ).fetchone()
        if not row:
            return None
        d = dict(row)
        if "features_json" in d and d["features_json"]:
            try:
                d["features"] = json.loads(d["features_json"])
            except Exception:
                d["features"] = {}
        return d

    # ------------------------------------------------------------------
    # Aggregation / statistics
    # ------------------------------------------------------------------

    def count_by_prediction(self) -> dict[str, int]:
        """Return a dict mapping each prediction class to its count."""
        rows = self._conn.execute(
            "SELECT prediction, COUNT(*) AS cnt FROM alerts GROUP BY prediction;"
        ).fetchall()
        result = {r["prediction"]: r["cnt"] for r in rows}
        _log.debug("count_by_prediction() -> %s", result)
        return result

    def count_by_severity(self) -> dict[str, int]:
        """Return a dict mapping each severity level to its count."""
        rows = self._conn.execute(
            "SELECT severity, COUNT(*) AS cnt FROM alerts GROUP BY severity;"
        ).fetchall()
        result = {r["severity"]: r["cnt"] for r in rows}
        _log.debug("count_by_severity() -> %s", result)
        return result

    def summary_stats(self) -> dict[str, Any]:
        """
        Return an aggregate summary dict:
            total_events      : int
            total_alerts      : int
            benign_count      : int
            attack_count      : int
            attack_pct        : float
            avg_confidence    : float | None
            avg_processing_ms : float | None
            earliest_alert    : str | None
            latest_alert      : str | None
        """
        ev_count = self._conn.execute("SELECT COUNT(*) FROM events;").fetchone()[0]
        al_count = self._conn.execute("SELECT COUNT(*) FROM alerts;").fetchone()[0]

        pred_rows = self._conn.execute(
            "SELECT prediction, COUNT(*) AS cnt FROM alerts GROUP BY prediction;"
        ).fetchall()
        pred_counts = {r["prediction"]: r["cnt"] for r in pred_rows}
        benign  = pred_counts.get("Benign", 0)
        attack  = pred_counts.get("Infilteration", 0)
        total_p = benign + attack
        attack_pct = (attack / total_p * 100) if total_p else 0.0

        agg = self._conn.execute(
            """SELECT AVG(confidence)        AS avg_conf,
                      AVG(processing_time_s) AS avg_proc,
                      MIN(timestamp)         AS earliest,
                      MAX(timestamp)         AS latest
               FROM alerts;"""
        ).fetchone()

        avg_conf = round(agg["avg_conf"] * 100, 2)  if agg["avg_conf"] is not None else None
        avg_proc = round(agg["avg_proc"] * 1000, 1) if agg["avg_proc"] is not None else None

        return {
            "total_events":       ev_count,
            "total_alerts":       al_count,
            "benign_count":       benign,
            "attack_count":       attack,
            "attack_pct":         round(attack_pct, 1),
            "avg_confidence_pct": avg_conf,
            "avg_processing_ms":  avg_proc,
            "earliest_alert":     agg["earliest"],
            "latest_alert":       agg["latest"],
        }

    # ------------------------------------------------------------------
    # Full-text / pattern search
    # ------------------------------------------------------------------

    def search_alerts(self, keyword: str, field: str = "prediction") -> list[dict]:
        """
        Search alerts using SQL LIKE pattern matching on a specified text column.

        Args:
            keyword : Search string. '%' wildcards are supported.
                      If no wildcard is present, the search is an exact match.
            field   : Column to search. Must be one of the allowed fields:
                      prediction, severity, status, agent, event_id,
                      alert_id, actual_label.

        Returns:
            List of matching alert dicts, ordered by timestamp descending.

        Raises:
            ValueError: If field is not in the allowed set (prevents SQL injection).
        """
        if field not in _SEARCHABLE_FIELDS:
            raise ValueError(
                f"Field '{field}' is not searchable. "
                f"Allowed: {sorted(_SEARCHABLE_FIELDS)}"
            )

        # Wrap keyword in % only if no wildcard supplied by caller
        pattern = keyword if "%" in keyword else keyword

        rows = self._conn.execute(
            f"SELECT * FROM alerts WHERE {field} LIKE ? ORDER BY timestamp DESC;",
            (pattern,),
        ).fetchall()
        _log.debug("search_alerts(keyword=%r, field=%r) -> %d rows", keyword, field, len(rows))
        return [_row_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Raw event access
    # ------------------------------------------------------------------

    def get_recent_events(self, n: int = 20) -> list[dict]:
        """Return the N most-recently ingested events."""
        rows = self._conn.execute(
            "SELECT * FROM events ORDER BY ingested_at DESC LIMIT ?;", (n,)
        ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            if d.get("features_json"):
                try:
                    d["features_json"] = json.loads(d["features_json"])
                except (json.JSONDecodeError, TypeError):
                    pass
            result.append(d)
        return result


# ---------------------------------------------------------------------------
# IncidentQueryStore
# ---------------------------------------------------------------------------

class IncidentQueryStore(AlertQueryStore):
    """
    Read-only query interface for the soc.db incidents table.
    Inherits connection logic from AlertQueryStore.
    """

    def get_recent_incidents(self, n: int = 20) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM incidents ORDER BY timestamp DESC LIMIT ?;", (n,)
        ).fetchall()
        return [_incident_row_to_dict(r) for r in rows]

    def get_incidents_by_severity(self, severity: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM incidents WHERE severity = ? ORDER BY timestamp DESC;",
            (severity.upper(),),
        ).fetchall()
        return [_incident_row_to_dict(r) for r in rows]

    def get_incidents_by_status(self, status: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM incidents WHERE status = ? ORDER BY timestamp DESC;",
            (status.upper(),),
        ).fetchall()
        return [_incident_row_to_dict(r) for r in rows]

    def get_incidents_by_event_id(self, event_id: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM incidents WHERE event_id = ? ORDER BY timestamp ASC;",
            (event_id,),
        ).fetchall()
        return [_incident_row_to_dict(r) for r in rows]

    def search_incidents(self, keyword: str, field: str = "prediction") -> list[dict]:
        if field not in _INCIDENT_SEARCHABLE_FIELDS:
            raise ValueError(f"Field '{field}' is not searchable. Allowed: {sorted(_INCIDENT_SEARCHABLE_FIELDS)}")
        pattern = keyword if "%" in keyword else keyword
        rows = self._conn.execute(
            f"SELECT * FROM incidents WHERE {field} LIKE ? ORDER BY timestamp DESC;",
            (pattern,),
        ).fetchall()
        return [_incident_row_to_dict(r) for r in rows]

    def get_incidents_by_agent(self, agent: str) -> list[dict]:
        # JSON string match hack, or LIKE approach
        pattern = f"%{agent}%"
        rows = self._conn.execute(
            "SELECT * FROM incidents WHERE correlated_agents LIKE ? ORDER BY timestamp DESC;",
            (pattern,),
        ).fetchall()
        return [_incident_row_to_dict(r) for r in rows]

    def summary_stats_incidents(self) -> dict[str, Any]:
        inc_count = self._conn.execute("SELECT COUNT(*) FROM incidents;").fetchone()[0]
        
        pred_rows = self._conn.execute(
            "SELECT prediction, COUNT(*) AS cnt FROM incidents GROUP BY prediction;"
        ).fetchall()
        pred_counts = {r["prediction"]: r["cnt"] for r in pred_rows}
        
        sev_rows = self._conn.execute(
            "SELECT severity, COUNT(*) AS cnt FROM incidents GROUP BY severity;"
        ).fetchall()
        sev_counts = {r["severity"]: r["cnt"] for r in sev_rows}

        earliest = self._conn.execute("SELECT MIN(timestamp) FROM incidents;").fetchone()[0]
        latest = self._conn.execute("SELECT MAX(timestamp) FROM incidents;").fetchone()[0]

        return {
            "total_incidents": inc_count,
            "prediction_counts": pred_counts,
            "severity_counts": sev_counts,
            "earliest_incident": earliest,
            "latest_incident": latest,
        }


# ---------------------------------------------------------------------------
# ThreatAssessmentQueryStore (Stage 9A)
# ---------------------------------------------------------------------------

_ASSESSMENT_SEARCHABLE_FIELDS = {
    "assessment_id", "event_id", "category", "severity",
    "network_prediction", "anomaly_prediction", "explanation", "actual_label",
}


def _assessment_row_to_dict(row: sqlite3.Row) -> dict:
    """Convert a threat assessment sqlite3.Row to a plain Python dict."""
    d = dict(row)
    # Reconstruct nested predictions and scores dictionaries for API consistency
    d["predictions"] = {
        "network": d.get("network_prediction"),
        "anomaly": d.get("anomaly_prediction"),
    }
    d["scores"] = {
        "network_confidence": d.get("network_confidence"),
        "anomaly_score": d.get("anomaly_score"),
    }
    return d


class ThreatAssessmentQueryStore(AlertQueryStore):
    """
    Read-only query interface for the soc.db threat_assessments table.
    Inherits connection logic from AlertQueryStore.
    """

    def get_recent_assessments(self, n: int = 20) -> list[dict]:
        """Return the N most recent threat assessments (by timestamp descending)."""
        rows = self._conn.execute(
            "SELECT * FROM threat_assessments ORDER BY timestamp DESC LIMIT ?;", (n,)
        ).fetchall()
        return [_assessment_row_to_dict(r) for r in rows]

    def get_assessments_by_category(self, category: str) -> list[dict]:
        """Return threat assessments matching the given category."""
        rows = self._conn.execute(
            "SELECT * FROM threat_assessments WHERE LOWER(category) = LOWER(?) ORDER BY timestamp DESC;",
            (category.strip(),),
        ).fetchall()
        return [_assessment_row_to_dict(r) for r in rows]

    def get_assessments_by_severity(self, severity: str) -> list[dict]:
        """Return threat assessments matching the given severity."""
        rows = self._conn.execute(
            "SELECT * FROM threat_assessments WHERE UPPER(severity) = UPPER(?) ORDER BY timestamp DESC;",
            (severity.strip(),),
        ).fetchall()
        return [_assessment_row_to_dict(r) for r in rows]

    def get_assessments_by_event_id(self, event_id: str) -> list[dict]:
        """Return threat assessments linked to a specific event UUID."""
        rows = self._conn.execute(
            "SELECT * FROM threat_assessments WHERE event_id = ? ORDER BY timestamp ASC;",
            (event_id.strip(),),
        ).fetchall()
        return [_assessment_row_to_dict(r) for r in rows]

    def get_assessment_by_id(self, assessment_id: str) -> dict | None:
        """Return single threat assessment by its assessment_id."""
        row = self._conn.execute(
            "SELECT * FROM threat_assessments WHERE assessment_id = ?;",
            (assessment_id.strip(),),
        ).fetchone()
        return _assessment_row_to_dict(row) if row else None

    def search_assessments(self, keyword: str, field: str = "category") -> list[dict]:
        """Search threat assessments using SQL LIKE on an allowed field."""
        if field not in _ASSESSMENT_SEARCHABLE_FIELDS:
            raise ValueError(
                f"Field '{field}' is not searchable. Allowed: {sorted(_ASSESSMENT_SEARCHABLE_FIELDS)}"
            )
        pattern = keyword if "%" in keyword else f"%{keyword}%"
        rows = self._conn.execute(
            f"SELECT * FROM threat_assessments WHERE {field} LIKE ? ORDER BY timestamp DESC;",
            (pattern,),
        ).fetchall()
        return [_assessment_row_to_dict(r) for r in rows]

    def summary_stats_assessments(self) -> dict[str, Any]:
        """Aggregate statistical overview of recorded threat assessments."""
        total_count = self._conn.execute("SELECT COUNT(*) FROM threat_assessments;").fetchone()[0]

        cat_rows = self._conn.execute(
            "SELECT category, COUNT(*) AS cnt FROM threat_assessments GROUP BY category;"
        ).fetchall()
        category_counts = {r["category"]: r["cnt"] for r in cat_rows}

        sev_rows = self._conn.execute(
            "SELECT severity, COUNT(*) AS cnt FROM threat_assessments GROUP BY severity;"
        ).fetchall()
        severity_counts = {r["severity"]: r["cnt"] for r in sev_rows}

        earliest = self._conn.execute("SELECT MIN(timestamp) FROM threat_assessments;").fetchone()[0]
        latest = self._conn.execute("SELECT MAX(timestamp) FROM threat_assessments;").fetchone()[0]

        return {
            "total_assessments": total_count,
            "category_counts": category_counts,
            "severity_counts": severity_counts,
            "earliest_assessment": earliest,
            "latest_assessment": latest,
        }


# ---------------------------------------------------------------------------
# ThreatInvestigationQueryStore (Stage 10)
# ---------------------------------------------------------------------------

_INVESTIGATION_SEARCHABLE_FIELDS = {
    "investigation_id", "event_id", "threat_category",
    "severity", "investigation_status", "summary",
}


def _investigation_row_to_dict(row: sqlite3.Row) -> dict:
    """Convert an investigation sqlite3.Row to a plain Python dict."""
    d = dict(row)
    for col in (
        "findings_by_agent_json", "supporting_evidence_json",
        "conflicting_signals_json", "reasoning_json",
        "limitations_json", "recommended_next_steps_json"
    ):
        clean_key = col.replace("_json", "")
        if col in d and d[col] is not None:
            try:
                d[clean_key] = json.loads(d[col])
            except (json.JSONDecodeError, TypeError):
                d[clean_key] = [] if "list" in clean_key or "findings" in clean_key else {}
        else:
            d[clean_key] = [] if "signals" in clean_key or "reasoning" in clean_key or "steps" in clean_key else {}
    return d


class ThreatInvestigationQueryStore(AlertQueryStore):
    """
    Read-only query interface for the soc.db threat_investigations table.
    Inherits connection lifecycle from AlertQueryStore.
    """

    def get_recent_investigations(self, n: int = 20) -> list[dict]:
        """Return the N most recent investigation reports (by timestamp descending)."""
        rows = self._conn.execute(
            "SELECT * FROM threat_investigations ORDER BY timestamp DESC LIMIT ?;", (n,)
        ).fetchall()
        return [_investigation_row_to_dict(r) for r in rows]

    def get_investigation_by_id(self, investigation_id: str) -> dict | None:
        """Return single investigation report by its UUID."""
        row = self._conn.execute(
            "SELECT * FROM threat_investigations WHERE investigation_id = ?;",
            (investigation_id.strip(),),
        ).fetchone()
        return _investigation_row_to_dict(row) if row else None

    def get_investigation_by_event_id(self, event_id: str) -> dict | None:
        """Return investigation report triggered by a specific event UUID."""
        row = self._conn.execute(
            "SELECT * FROM threat_investigations WHERE event_id = ? ORDER BY timestamp DESC LIMIT 1;",
            (event_id.strip(),),
        ).fetchone()
        return _investigation_row_to_dict(row) if row else None

    def get_investigations_by_status(self, status: str) -> list[dict]:
        """Return investigations filtered by status."""
        rows = self._conn.execute(
            "SELECT * FROM threat_investigations WHERE UPPER(investigation_status) = UPPER(?) ORDER BY timestamp DESC;",
            (status.strip(),),
        ).fetchall()
        return [_investigation_row_to_dict(r) for r in rows]

    def get_investigations_by_category(self, category: str) -> list[dict]:
        """Return investigations filtered by threat category."""
        rows = self._conn.execute(
            "SELECT * FROM threat_investigations WHERE LOWER(threat_category) = LOWER(?) ORDER BY timestamp DESC;",
            (category.strip(),),
        ).fetchall()
        return [_investigation_row_to_dict(r) for r in rows]

    def search_investigations(self, keyword: str, field: str = "summary") -> list[dict]:
        """Search investigations using SQL LIKE on an allowed column."""
        if field not in _INVESTIGATION_SEARCHABLE_FIELDS:
            raise ValueError(
                f"Field '{field}' is not searchable. Allowed: {sorted(_INVESTIGATION_SEARCHABLE_FIELDS)}"
            )
        pattern = keyword if "%" in keyword else f"%{keyword}%"
        rows = self._conn.execute(
            f"SELECT * FROM threat_investigations WHERE {field} LIKE ? ORDER BY timestamp DESC;",
            (pattern,),
        ).fetchall()
        return [_investigation_row_to_dict(r) for r in rows]

    def summary_stats_investigations(self) -> dict[str, Any]:
        """Aggregate statistical overview of completed investigations."""
        total_count = self._conn.execute("SELECT COUNT(*) FROM threat_investigations;").fetchone()[0]

        stat_rows = self._conn.execute(
            "SELECT investigation_status, COUNT(*) AS cnt FROM threat_investigations GROUP BY investigation_status;"
        ).fetchall()
        status_counts = {r["investigation_status"]: r["cnt"] for r in stat_rows}

        cat_rows = self._conn.execute(
            "SELECT threat_category, COUNT(*) AS cnt FROM threat_investigations GROUP BY threat_category;"
        ).fetchall()
        category_counts = {r["threat_category"]: r["cnt"] for r in cat_rows}

        sev_rows = self._conn.execute(
            "SELECT severity, COUNT(*) AS cnt FROM threat_investigations GROUP BY severity;"
        ).fetchall()
        severity_counts = {r["severity"]: r["cnt"] for r in sev_rows}

        earliest = self._conn.execute("SELECT MIN(timestamp) FROM threat_investigations;").fetchone()[0]
        latest = self._conn.execute("SELECT MAX(timestamp) FROM threat_investigations;").fetchone()[0]

        return {
            "total_investigations": total_count,
            "status_counts": status_counts,
            "category_counts": category_counts,
            "severity_counts": severity_counts,
            "earliest_investigation": earliest,
            "latest_investigation": latest,
        }


# ---------------------------------------------------------------------------
# ThreatIntelQueryStore (Stage 11)
# ---------------------------------------------------------------------------

def _intel_row_to_dict(row: sqlite3.Row) -> dict:
    """Convert a threat_intel_cache sqlite3.Row to a clean Python dict."""
    d = dict(row)
    if "raw_response_json" in d and d["raw_response_json"] is not None:
        try:
            d["raw_response"] = json.loads(d["raw_response_json"])
        except Exception:
            d["raw_response"] = {}
    else:
        d["raw_response"] = {}

    if "evidence_links_json" in d and d["evidence_links_json"] is not None:
        try:
            d["evidence_links"] = json.loads(d["evidence_links_json"])
        except Exception:
            d["evidence_links"] = []
    else:
        d["evidence_links"] = []

    d["is_mock"] = bool(d.get("is_mock", 0))
    expires_at = d.get("expires_at", "")
    now_iso = datetime.datetime.now().isoformat()
    d["is_expired"] = bool(expires_at and str(expires_at) < now_iso)
    return d


class ThreatIntelQueryStore(AlertQueryStore):
    """
    Read-only query interface for threat_intel_cache in soc.db.
    Inherits connection lifecycle from AlertQueryStore.
    """

    def get_cached_intel(
        self,
        indicator_type: str,
        indicator_value: str,
        provider: str | None = None,
        valid_only: bool = False,
    ) -> dict | None:
        """
        Lookup cached intelligence entry for an indicator.

        Args:
            indicator_type: 'ip', 'port', etc.
            indicator_value: The indicator value string.
            provider: Optional provider name filter.
            valid_only: If True, returns None if entry is expired.
        """
        query = "SELECT * FROM threat_intel_cache WHERE LOWER(indicator_type) = LOWER(?) AND indicator_value = ?"
        params: list[Any] = [indicator_type.strip(), str(indicator_value).strip()]
        if provider:
            query += " AND LOWER(provider) = LOWER(?)"
            params.append(provider.strip())
        query += " ORDER BY last_checked DESC LIMIT 1;"

        row = self._conn.execute(query, tuple(params)).fetchone()
        if not row:
            return None
        res = _intel_row_to_dict(row)
        if valid_only and res["is_expired"]:
            return None
        return res

    def get_recent_intel(self, n: int = 20) -> list[dict]:
        """Return the N most recently checked threat intelligence records."""
        rows = self._conn.execute(
            "SELECT * FROM threat_intel_cache ORDER BY last_checked DESC LIMIT ?;", (n,)
        ).fetchall()
        return [_intel_row_to_dict(r) for r in rows]

    def get_intel_by_verdict(self, verdict: str) -> list[dict]:
        """Return cached intel records matching a specific verdict."""
        rows = self._conn.execute(
            "SELECT * FROM threat_intel_cache WHERE UPPER(verdict) = UPPER(?) ORDER BY last_checked DESC;",
            (verdict.strip(),),
        ).fetchall()
        return [_intel_row_to_dict(r) for r in rows]

    def get_intel_by_provider(self, provider: str) -> list[dict]:
        """Return cached intel records from a specific provider."""
        rows = self._conn.execute(
            "SELECT * FROM threat_intel_cache WHERE LOWER(provider) = LOWER(?) ORDER BY last_checked DESC;",
            (provider.strip(),),
        ).fetchall()
        return [_intel_row_to_dict(r) for r in rows]

    def summary_stats_intel(self) -> dict[str, Any]:
        """Aggregate statistical summary of threat intelligence lookups."""
        total = self._conn.execute("SELECT COUNT(*) FROM threat_intel_cache;").fetchone()[0]
        verdict_rows = self._conn.execute(
            "SELECT verdict, COUNT(*) as cnt FROM threat_intel_cache GROUP BY verdict;"
        ).fetchall()
        provider_rows = self._conn.execute(
            "SELECT provider, COUNT(*) as cnt FROM threat_intel_cache GROUP BY provider;"
        ).fetchall()
        mock_count = self._conn.execute(
            "SELECT COUNT(*) FROM threat_intel_cache WHERE is_mock = 1;"
        ).fetchone()[0]
        now_iso = datetime.datetime.now().isoformat()
        expired_count = self._conn.execute(
            "SELECT COUNT(*) FROM threat_intel_cache WHERE expires_at < ?;", (now_iso,)
        ).fetchone()[0]

        return {
            "total_cached": total,
            "mock_count": mock_count,
            "real_count": total - mock_count,
            "expired_count": expired_count,
            "verdicts": {r["verdict"]: r["cnt"] for r in verdict_rows},
            "providers": {r["provider"]: r["cnt"] for r in provider_rows},
        }




