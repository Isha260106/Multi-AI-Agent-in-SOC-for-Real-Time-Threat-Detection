# Stage 5 — Central Event and Alert Storage

**Multi-Agent SOC Project — Stage 5**

---

## Overview

Stage 5 adds a persistent, queryable central store for all network-flow events and security alerts produced by the Stage 4 pipeline.

```
Event Producer  (kafka/producer.py)
        │
        ▼
Event Stream  (kafka/stream.py)
        │
        ▼
Network Detection Consumer  (kafka/consumer.py)
        │
        ├──→  Terminal output          (existing — Stage 4)
        ├──→  logs/streaming_alerts.json  (existing — Stage 4)
        │
        └──→  data/soc.db             ← NEW Stage 5
               ├── events table
               └── alerts table
                        │
                        ▼
              Search / Retrieval  (storage/query.py)
                        │
                        ▼
              Query CLI  (query_alerts.py)
```

---

## Why SQLite?

| Property | Detail |
|---|---|
| **Zero installation** | Ships with every Python interpreter — no server, no Java, no daemon |
| **Single file** | Entire database lives in `data/soc.db` — easy to copy, share, or delete |
| **Full SQL** | SELECT, WHERE, ORDER BY, LIKE, COUNT, GROUP BY, indexes |
| **Proven** | Used in production systems handling billions of rows |
| **Future extension** | The storage abstraction layer allows Elasticsearch to be swapped in later by changing one config value |

> **Elasticsearch** is noted as a future extension. It is **not** implemented in Stage 5.

---

## File Structure

```
storage/
├── __init__.py    -- Python package marker
├── config.py      -- DB path, pragmas, log paths
├── db.py          -- Schema + write API (AlertStore)
├── query.py       -- Read / search API  (AlertQueryStore)
├── ingest.py      -- Backfill existing JSON logs into soc.db
└── README.md      -- This file

query_alerts.py    -- Command-line query tool (project root)
test_storage.py    -- End-to-end validation test (project root)
```

---

## Database Schema

### `events` table

| Column | Type | Description |
|---|---|---|
| `id` | INTEGER PK | Auto-increment |
| `event_id` | TEXT UNIQUE | UUID from the producer |
| `event_type` | TEXT | `"network_flow"` |
| `timestamp` | TEXT | ISO-8601 event time |
| `source` | TEXT | `"historical_replay"` |
| `sequence` | INTEGER | Event sequence number |
| `actual_label` | TEXT NULL | Ground truth (evaluation only) |
| `features_json` | TEXT | All 78 model features as JSON |
| `ingested_at` | TEXT | When inserted into DB |

### `alerts` table

| Column | Type | Description |
|---|---|---|
| `id` | INTEGER PK | Auto-increment |
| `alert_id` | TEXT UNIQUE | Auto-generated UUID |
| `event_id` | TEXT NULL | FK → events (NULL for legacy records) |
| `agent` | TEXT | `"Network Detection Agent"` |
| `timestamp` | TEXT | ISO-8601 alert time |
| `prediction` | TEXT | `"Benign"` or `"Infilteration"` |
| `confidence` | REAL | 0.0 – 1.0 |
| `severity` | TEXT | `"LOW"` or `"HIGH"` |
| `status` | TEXT | `"NORMAL"` or `"SUSPICIOUS"` |
| `actual_label` | TEXT NULL | Ground truth (evaluation only) |
| `processing_time_s` | REAL | Consumer processing time |
| `network_context_json` | TEXT | JSON: Dst Port, Protocol, etc. |
| `class_probabilities_json` | TEXT | JSON: per-class probabilities |
| `ingested_at` | TEXT | When inserted into DB |

**Indexes:** `timestamp`, `severity`, `status`, `prediction`, `event_id`

**SQLite pragmas:** `PRAGMA foreign_keys = ON;`  `PRAGMA journal_mode = WAL;`

---

## Storage Flow (Stage 4 → Stage 5 integration)

```
Consumer receives event
        │
        ▼
agent.analyze(df)  →  alert dict
        │
        ├──→  _append_alert()    → logs/streaming_alerts.json   (Stage 4)
        │
        └──→  AlertStore.save_event(event)
              AlertStore.save_alert(alert)  → data/soc.db       (Stage 5)

If soc.db write fails:
   → Error logged clearly to streaming_runtime.log
   → Terminal warning printed
   → JSON log and terminal output are NOT affected
   → Consumer continues processing next event
```

---

## Query / Retrieval

All query methods are in `storage/query.py` → `AlertQueryStore`:

```python
from storage.query import AlertQueryStore

with AlertQueryStore() as q:
    q.get_recent_alerts(n=20)
    q.get_alerts_by_severity("HIGH")
    q.get_alerts_by_status("SUSPICIOUS")
    q.get_alerts_by_prediction("Infilteration")
    q.get_alerts_in_timerange("2026-09-16T12:00:00", "2026-09-16T13:00:00")
    q.get_alert_by_event_id("3f8a2c1d-...")
    q.count_by_prediction()
    q.count_by_severity()
    q.summary_stats()
    q.search_alerts("Infilteration", field="prediction")
```

---

## How to Run

### End-to-end demo (creates + populates soc.db automatically)

```powershell
cd E:\multi-agent-soc
python kafka/demo.py --count 20
```

### Ingest existing JSON logs into soc.db

```powershell
cd E:\multi-agent-soc

# Ingest all three log files
python storage/ingest.py

# Ingest specific files only
python storage/ingest.py --file streaming
python storage/ingest.py --file network_detection live_monitor
```

### Query the database (CLI)

```powershell
# Show last 20 alerts
python query_alerts.py --recent 20

# Show HIGH severity alerts only
python query_alerts.py --severity HIGH

# Show SUSPICIOUS status alerts only
python query_alerts.py --status SUSPICIOUS

# Show Infilteration predictions only
python query_alerts.py --prediction Infilteration

# Count breakdown by prediction + severity
python query_alerts.py --counts

# Summary statistics
python query_alerts.py --summary

# Time range query
python query_alerts.py --from "2026-09-16T12:00:00" --to "2026-09-16T13:00:00"

# Search by field
python query_alerts.py --search Infilteration --field prediction

# Alerts linked to a specific event
python query_alerts.py --event-id 3f8a2c1d-9e47-4b1a-a8c2-...

# Verbose detail mode
python query_alerts.py --recent 5 --verbose
```

### Validation test

```powershell
cd E:\multi-agent-soc
python test_storage.py
```

### Existing Stage 4 tests (must still pass)

```powershell
python test_streaming.py
python kafka/demo.py --count 20 --inject-errors
```

---

## Viewing soc.db with DB Browser for SQLite (Optional)

**DB Browser for SQLite** is a free, open-source GUI tool that lets you browse your database like a spreadsheet.

**Install:**
1. Visit https://sqlitebrowser.org/dl/
2. Download the Windows installer and install
3. Open `E:\multi-agent-soc\data\soc.db`

**Useful queries to run in the "Execute SQL" tab:**

```sql
-- All SUSPICIOUS alerts
SELECT * FROM alerts WHERE status = 'SUSPICIOUS' ORDER BY timestamp DESC;

-- Count by prediction
SELECT prediction, COUNT(*) FROM alerts GROUP BY prediction;

-- Average confidence per severity
SELECT severity, AVG(confidence) AS avg_conf FROM alerts GROUP BY severity;

-- Alerts in last 24 hours
SELECT * FROM alerts
WHERE timestamp >= datetime('now', '-1 day')
ORDER BY timestamp DESC;

-- Join events and alerts
SELECT e.event_id, e.actual_label, a.prediction, a.confidence
FROM events e
JOIN alerts a ON e.event_id = a.event_id
ORDER BY a.timestamp DESC;
```

---

## Limitations (Stage 5)

| Limitation | Notes |
|---|---|
| SQLite is single-file | Not suitable for multi-machine distributed deployment |
| No REST API | Search is Python API + CLI only |
| No Elasticsearch | Planned for a future stage |
| No dashboard | Visualisation planned for a future stage |
| No LLM reasoning | Not implemented in this stage |
| No automatic response | Not implemented in this stage |

---

## What Stage 5 Does NOT Include

The following were deliberately **not** implemented and remain for future stages:

- Elasticsearch / Kibana
- REST API / HTTP endpoint
- Dashboard or visualisation
- LLM-based alert reasoning
- Other SOC agents (Anomaly Detection, Authentication, Endpoint, Threat Intelligence, Alert Correlation, Attack Path, Investigation, Risk Assessment, Response)
- Automatic blocking or remediation
