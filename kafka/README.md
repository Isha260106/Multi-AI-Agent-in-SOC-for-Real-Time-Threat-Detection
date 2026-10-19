# Stage 4 — Real-Time Event Streaming for the Network Detection Agent

**Multi-Agent SOC Project — Stage 4**

---

## Overview

Stage 4 introduces a real-time event-streaming layer between incoming network-flow events and the existing Network Detection Agent.

```
Network Flow Dataset
        │
        ▼
  Event Producer
   (producer.py)
        │
        ▼
  Event Stream
   (stream.py)
        │
        ▼
  Network Detection Consumer
     (consumer.py)
        │
        ▼
  Network Detection Agent
 (agents/network_detection/agent.py)
        │
        ▼
  Random Forest Model
        │
        ▼
    Prediction
        │
        ▼
  Security Alert
  (logs/streaming_alerts.json)
```

---

## Important Notes

> **The dataset is used for controlled simulation / testing. It is not itself a live traffic source.**

> **Historical dataset records are replayed to simulate real-time network events.**

> **The existing model is NOT retrained or modified in any way.**

---

## File Structure

```
kafka/
├── __init__.py      -- Makes kafka/ a Python package
├── config.py        -- Central configuration (paths, topic, defaults)
├── stream.py        -- Event stream abstraction (Queue transport + optional Kafka)
├── producer.py      -- Network-flow event producer
├── consumer.py      -- Event consumer + Network Detection Agent integration
├── demo.py          -- End-to-end demonstration script
└── README.md        -- This file
```

---

## Event Format

Each network-flow event is a JSON object with the following structure:

```json
{
    "event_id":    "3f8a2c1d-...",
    "event_type":  "network_flow",
    "timestamp":   "2025-01-15T14:32:01.234567",
    "source":      "historical_replay",
    "sequence":    1,
    "actual_label": "Benign",
    "features": {
        "Dst Port":      443.0,
        "Protocol":      6.0,
        "Flow Duration": 12345.0,
        "...":           "..."
    }
}
```

### Key rules

| Field | Rule |
|---|---|
| `features` | Contains exactly the 78 model input features |
| `actual_label` | Ground-truth label from the CSV — **for validation only** |
| `Label` | **NEVER** included in `features` — the model never sees it |
| Feature names | Identical to training feature names — never changed |
| Feature order | Reordered to match training order by the agent's preprocessor |

---

## Transport Layer

The event stream is implemented with two interchangeable backends:

| Backend | Requirement | When to use |
|---|---|---|
| `queue` | None (built-in Python) | **Default** — works on any machine |
| `kafka` | Apache Kafka + Java + `kafka-python` | When a real Kafka broker is available |

The default (`queue`) uses Python's `queue.Queue` as an in-process message bus.
Both backends expose the same `send()` / `poll()` interface so that the producer
and consumer code is identical regardless of transport.

---

## What the Producer Does

`kafka/producer.py`

1. Reads network-flow records from `data/processed/cleaned_dataset.csv` in **chunks** — never loads the entire 330k-row file into memory.
2. Selects a **balanced mix** (half Benign, half Infilteration) or sequential records.
3. Serialises each row into a structured event JSON object.
4. **Strips the Label column** before building the `features` dict.
5. Sends one event at a time to the event stream.
6. Optionally waits a configurable delay between events to simulate real-time arrival rate.
7. Prints a concise one-line summary per event (not all 78 features).

---

## What the Consumer Does

`kafka/consumer.py`

1. Listens on the event stream and receives one network-flow event.
2. Extracts the 78 features from the event's `features` dict.
3. Constructs a 1-row pandas DataFrame.
4. Passes the DataFrame to the **existing** `NetworkDetectionAgent.analyze()`.
5. The agent preprocesses the input, runs the Random Forest model, and returns a structured alert.
6. The consumer enriches the alert with `event_id`, `actual_label`, and `processing_time_s`.
7. Prints a colour-coded result to the terminal.
8. Appends the alert to `logs/streaming_alerts.json`.

The consumer **does not** duplicate any model loading or prediction logic.
It calls `agents/network_detection/agent.py` as the detection component.

---

## Alert Format

Preserved from Stage 3, enriched with streaming metadata:

```json
{
    "agent":               "Network Detection Agent",
    "timestamp":           "2025-01-15T14:32:01.456789",
    "prediction":          "Infilteration",
    "confidence":          0.84,
    "severity":            "HIGH",
    "status":              "SUSPICIOUS",
    "note":                "confidence is the model's predicted probability...",
    "class_probabilities": {"Benign": 0.16, "Infilteration": 0.84},
    "network_context":     {"Dst Port": 443, "Protocol": 6, "...": "..."},
    "event_id":            "3f8a2c1d-...",
    "actual_label":        "Infilteration",
    "processing_time_s":   0.034
}
```

For benign traffic:

```json
{
    "prediction":  "Benign",
    "confidence":  0.93,
    "severity":    "LOW",
    "status":      "NORMAL",
    "...":         "..."
}
```

---

## Error Handling

The consumer handles the following conditions gracefully without crashing:

| Error condition | Response |
|---|---|
| Missing `features` key | Logs error, skips event, continues |
| Missing individual feature | Agent fills with training median, continues |
| Non-numeric feature value | Agent coerces to NaN → fills with median, continues |
| Empty features dict | Logs error, skips event, continues |
| Missing `event_id` | Uses generated fallback ID, continues |
| Model prediction error | Logs error, skips event, continues |
| JSON decode error | Logs error, skips event, continues |

---

## How to Run

### Option A: End-to-End Demo (single command, recommended)

```powershell
# From project root
python kafka/demo.py
```

```powershell
# Custom count and delay
python kafka/demo.py --count 20 --delay 0.5

# Fast demo
python kafka/demo.py --count 20 --delay 0.2

# With error handling test (injects 3 malformed events)
python kafka/demo.py --count 20 --inject-errors

# Concurrent mode (producer in background thread)
python kafka/demo.py --count 20 --delay 1 --parallel
```

### Option B: Two Terminals (simulates separate producer / consumer processes)

**Terminal 1 — Consumer (start first):**
```powershell
cd E:\multi-agent-soc
python kafka/consumer.py --count 20
```

**Terminal 2 — Producer:**
```powershell
cd E:\multi-agent-soc
python kafka/producer.py --count 20 --delay 1
```

> **Note:** In `queue` transport mode, producer and consumer must run in the same Python process because the queue is in-process. Use `demo.py` or `demo.py --parallel` for the most realistic demonstration. Use real Kafka (`--transport kafka`) for true multi-process operation.

### Option C: Validation Test

```powershell
cd E:\multi-agent-soc
python test_streaming.py
```

---

## Output Files

| File | Description |
|---|---|
| `logs/streaming_alerts.json` | Rolling JSON log of all streaming alerts |
| `logs/streaming_runtime.log` | Detailed runtime log (producer + consumer + agent) |

---

## How Historical Data is Replayed as a Real-Time Simulation

```
cleaned_dataset.csv
        │
        │  pandas read_csv (chunked, CSV_CHUNK_SIZE rows at a time)
        │
        ▼
  Balanced record selection
  (half Benign + half Infilteration)
        │
        │  strip Label column
        │  add event_id, timestamp, sequence
        │
        ▼
  Structured event JSON
        │
        │  push to event stream
        │  optionally wait --delay seconds
        │
        ▼
  Consumer receives event
        │
        │  typical latency: <50 ms per event
        │  (near-real-time event processing demonstration)
        │
        ▼
  Network Detection Agent
```

The delay between events (`--delay`) controls the simulated "arrival rate" of network flows. Setting `--delay 1.0` simulates approximately one network flow per second. Setting `--delay 0.0` processes all events as fast as possible (useful for throughput testing).

---

## Configuration

All parameters are in `kafka/config.py`:

```python
DEFAULT_TRANSPORT   = "queue"               # or "kafka"
DEFAULT_DELAY       = 1.0                   # seconds between events
DEFAULT_EVENT_COUNT = 20                    # events per demo run
CSV_CHUNK_SIZE      = 500                   # rows read per CSV chunk
KAFKA_TOPIC         = "network-flow-events"
KAFKA_BOOTSTRAP_SERVERS = "localhost:9092"
```

---

## What Stage 4 Does NOT Include

Stage 4 is purely an event-streaming integration stage. The following are **deliberately excluded** and will be added in later stages:

- Anomaly Detection Agent
- Authentication Agent
- Endpoint Security Agent
- Threat Intelligence Agent
- Alert Correlation Agent
- LLM reasoning
- Elasticsearch / Kibana
- Automatic blocking or remediation
- Any modification to the model or dataset
