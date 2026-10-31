# Sensor Integration Guide — Connecting VM Telemetry to Multi-Agent SOC

> **Document:** Sensor-to-SOC REST Integration Specification  
> **Target Audience:** VM Lab & Network Sensor Engineering Team  
> **API Version:** 1.0.0  
> **Safety Mode:** Plug-and-Play / Air-Gapped Host-Only Integration

---

## 1. Quick Start & Connection Summary

The Multi-Agent AI Security Operations Center (SOC) provides an authenticated REST ingestion endpoint ready to receive network flow records from external packet sensors (such as Python `cicflowmeter` or Java CICFlowMeter v4).

| Parameter | Specification | Notes |
| :--- | :--- | :--- |
| **Ingestion URL** | `http://<SOC_HOST_IP>:8000/api/ingest/flow` | In VirtualBox host-only labs: `http://192.168.56.1:8000/api/ingest/flow` |
| **HTTP Method** | `POST` | `Content-Type: application/json` |
| **Authentication** | `X-SOC-Sensor-Key: <SOC_SENSOR_KEY>` | Alternatively: `Authorization: Bearer <SOC_SENSOR_KEY>` |
| **Max Payload Size**| `1 MB (1,048,576 bytes)` | Recommended batch size: 10–50 flows per POST |
| **Feature Vector** | **Exactly 78 flow metrics** | Normalized numeric values (float/int) |
| **Duration Units** | **Microseconds ($\mu s$)** | Both `Flow Duration` and `IAT` fields expect $\mu s$ |

---

## 2. Sensor Pre-Flight Health Checks

Before streaming captured flows, verify network connectivity and model readiness from the sensor VM:

### 2.1 Backend Health Check
```bash
curl -s http://192.168.56.1:8000/api/health
```
**Expected Response (HTTP 200):**
```json
{
  "status": "online",
  "timestamp": "2026-10-27T12:00:00.000000",
  "database_exists": true,
  "database_path": "E:\\multi-agent-soc\\data\\soc.db"
}
```

### 2.2 Model & Preprocessing Readiness Check
```bash
curl -s http://192.168.56.1:8000/api/models/health
```
**Expected Response (HTTP 200):**
```json
{
  "status": "ok",
  "models": {
    "network_detection": {
      "loaded": true,
      "features_required": 78
    },
    "anomaly_detection": {
      "loaded": true
    }
  }
}
```

---

## 3. Sensor Payload Specification

### 3.1 Metadata Fields (Top-Level)
Keep all network identifiers outside the model feature map. Metadata fields are preserved in SQLite and dashboard forensic views:

| Field | Type | Required | Description |
| :--- | :---: | :---: | :--- |
| `event_id` | String | Optional | Unique UUID for flow. Auto-generated on host if omitted. |
| `sensor_id` | String | Recommended | Appliance identifier, e.g. `"sensor-vm-01"`. |
| `source` | String | Optional | Source identifier (default: `"live_sensor"`). |
| `timestamp`| String | Optional | ISO-8601 timestamp string (e.g. `"2026-10-27T14:30:00Z"`). |
| `sequence` | Integer| Optional | Monotonic packet/flow counter from sensor. |
| `src_ip` | String | Recommended | Observed source IPv4 address (e.g. `"10.10.10.100"`). |
| `dst_ip` | String | Recommended | Observed destination IPv4 address (e.g. `"10.10.10.20"`). |
| `src_port` | Integer| Recommended | Source transport port (1–65535). |
| `dst_port` | Integer| Recommended | Destination transport port (1–65535). |
| `protocol` | Integer/String | Recommended | `6` (TCP), `17` (UDP), `1` (ICMP). |
| `features` | Object | **Required** | Dictionary containing **all 78 canonical model features**. |

---

## 4. Canonical 78-Feature Vector

Every flow record submitted in the `features` dictionary must contain all 78 numeric metrics matching the trained model schema:

```
 1. Dst Port            2. Protocol            3. Flow Duration       4. Tot Fwd Pkts
 5. Tot Bwd Pkts        6. TotLen Fwd Pkts     7. TotLen Bwd Pkts     8. Fwd Pkt Len Max
 9. Fwd Pkt Len Min    10. Fwd Pkt Len Mean   11. Fwd Pkt Len Std    12. Bwd Pkt Len Max
13. Bwd Pkt Len Min    14. Bwd Pkt Len Mean   15. Bwd Pkt Len Std    16. Flow Byts/s
17. Flow Pkts/s        18. Flow IAT Mean      19. Flow IAT Std       20. Flow IAT Max
21. Flow IAT Min       22. Fwd IAT Tot        23. Fwd IAT Mean       24. Fwd IAT Std
25. Fwd IAT Max        26. Fwd IAT Min        27. Bwd IAT Tot        28. Bwd IAT Mean
29. Bwd IAT Std        30. Bwd IAT Max        31. Bwd IAT Min        32. Fwd PSH Flags
33. Bwd PSH Flags      34. Fwd URG Flags      35. Bwd URG Flags      36. Fwd Header Len
37. Bwd Header Len     38. Fwd Pkts/s         39. Bwd Pkts/s         40. Pkt Len Min
41. Pkt Len Max        42. Pkt Len Mean       43. Pkt Len Std        44. Pkt Len Var
45. FIN Flag Cnt       46. SYN Flag Cnt       47. RST Flag Cnt       48. PSH Flag Cnt
49. ACK Flag Cnt       50. URG Flag Cnt       51. CWE Flag Count     52. ECE Flag Cnt
53. Down/Up Ratio      54. Pkt Size Avg       55. Fwd Seg Size Avg   56. Bwd Seg Size Avg
57. Fwd Byts/b Avg     58. Fwd Pkts/b Avg     59. Fwd Blk Rate Avg   60. Bwd Byts/b Avg
61. Bwd Pkts/b Avg     62. Bwd Blk Rate Avg   63. Subflow Fwd Pkts   64. Subflow Fwd Byts
65. Subflow Bwd Pkts   66. Subflow Bwd Byts   67. Init Fwd Win Byts  68. Init Bwd Win Byts
69. Fwd Act Data Pkts  70. Fwd Seg Size Min   71. Active Mean        72. Active Std
73. Active Max         74. Active Min         75. Idle Mean          76. Idle Std
77. Idle Max           78. Idle Min
```

> [!IMPORTANT]
> - **Never fabricate missing features:** If your capture tool omits features, the API will reject the record with HTTP 422 rather than hallucinating statistics.
> - **Imputation Policy:** Up to 8 cells with `NaN` or `Inf` (e.g. from zero-duration division in instantaneous probes) are automatically imputed with training medians. More than 8 NaNs triggers an immediate HTTP 422 rejection.

---

## 5. Working Integration Examples

### 5.1 Ready-to-Use cURL Example
```bash
curl -X POST http://192.168.56.1:8000/api/ingest/flow \
  -H "Content-Type: application/json" \
  -H "X-SOC-Sensor-Key: soc-sensor-dev-key-2026" \
  -d '{
    "event_id": "sensor-flow-0001",
    "sensor_id": "soc-sensor-vm",
    "src_ip": "10.10.10.100",
    "dst_ip": "10.10.10.20",
    "src_port": 54321,
    "dst_port": 80,
    "protocol": 6,
    "features": {
      "Dst Port": 80.0, "Protocol": 6.0, "Flow Duration": 15420.0,
      "Tot Fwd Pkts": 5.0, "Tot Bwd Pkts": 4.0, "TotLen Fwd Pkts": 320.0,
      "TotLen Bwd Pkts": 512.0, "Fwd Pkt Len Max": 128.0, "Fwd Pkt Len Min": 0.0,
      "Fwd Pkt Len Mean": 64.0, "Fwd Pkt Len Std": 45.2, "Bwd Pkt Len Max": 256.0,
      "Bwd Pkt Len Min": 0.0, "Bwd Pkt Len Mean": 128.0, "Bwd Pkt Len Std": 80.5,
      "Flow Byts/s": 53955.9, "Flow Pkts/s": 583.6, "Flow IAT Mean": 1927.5,
      "Flow IAT Std": 2100.0, "Flow IAT Max": 6500.0, "Flow IAT Min": 12.0,
      "Fwd IAT Tot": 15420.0, "Fwd IAT Mean": 3855.0, "Fwd IAT Std": 2400.0,
      "Fwd IAT Max": 6500.0, "Fwd IAT Min": 50.0, "Bwd IAT Tot": 14000.0,
      "Bwd IAT Mean": 4666.7, "Bwd IAT Std": 1800.0, "Bwd IAT Max": 6000.0,
      "Bwd IAT Min": 100.0, "Fwd PSH Flags": 0.0, "Bwd PSH Flags": 0.0,
      "Fwd URG Flags": 0.0, "Bwd URG Flags": 0.0, "Fwd Header Len": 100.0,
      "Bwd Header Len": 80.0, "Fwd Pkts/s": 324.2, "Bwd Pkts/s": 259.4,
      "Pkt Len Min": 0.0, "Pkt Len Max": 256.0, "Pkt Len Mean": 83.2,
      "Pkt Len Std": 68.4, "Pkt Len Var": 4678.5, "FIN Flag Cnt": 0.0,
      "SYN Flag Cnt": 1.0, "RST Flag Cnt": 0.0, "PSH Flag Cnt": 1.0,
      "ACK Flag Cnt": 1.0, "URG Flag Cnt": 0.0, "CWE Flag Count": 0.0,
      "ECE Flag Cnt": 0.0, "Down/Up Ratio": 0.8, "Pkt Size Avg": 92.4,
      "Fwd Seg Size Avg": 64.0, "Bwd Seg Size Avg": 128.0, "Fwd Byts/b Avg": 0.0,
      "Fwd Pkts/b Avg": 0.0, "Fwd Blk Rate Avg": 0.0, "Bwd Byts/b Avg": 0.0,
      "Bwd Pkts/b Avg": 0.0, "Bwd Blk Rate Avg": 0.0, "Subflow Fwd Pkts": 5.0,
      "Subflow Fwd Byts": 320.0, "Subflow Bwd Pkts": 4.0, "Subflow Bwd Byts": 512.0,
      "Init Fwd Win Byts": 64240.0, "Init Bwd Win Byts": 65535.0,
      "Fwd Act Data Pkts": 3.0, "Fwd Seg Size Min": 20.0, "Active Mean": 0.0,
      "Active Std": 0.0, "Active Max": 0.0, "Active Min": 0.0,
      "Idle Mean": 0.0, "Idle Std": 0.0, "Idle Max": 0.0, "Idle Min": 0.0
    }
  }'
```

### 5.2 Python Client Example
```python
import requests

API_URL = "http://192.168.56.1:8000/api/ingest/flow"
SENSOR_KEY = "soc-sensor-dev-key-2026"

payload = {
    "sensor_id": "sensor-vm-01",
    "src_ip": "10.10.10.100",
    "dst_ip": "10.10.10.20",
    "src_port": 50000,
    "dst_port": 80,
    "protocol": 6,
    "features": {...}  # Exact 78 flow metrics
}

headers = {
    "Content-Type": "application/json",
    "X-SOC-Sensor-Key": SENSOR_KEY,
}

response = requests.post(API_URL, json=payload, headers=headers, timeout=5.0)

if response.status_code == 201:
    data = response.json()
    print(f"[OK] Ingested: Event={data['event_id']} Verdict={data['network_detection']['prediction']}")
elif response.status_code == 409:
    print("[WARN] Duplicate event ID submitted. Retry with fresh UUID.")
else:
    print(f"[ERROR] HTTP {response.status_code}: {response.text}")
```

---

## 6. HTTP Error Codes & Troubleshooting

| HTTP Status | Meaning | Remediation |
| :--- | :--- | :--- |
| **`201 Created`** | Success | Flow analyzed, correlated, and persisted in `soc.db`. |
| **`401 Unauthorized`** | Authentication failure | Verify `X-SOC-Sensor-Key` header matches host `.env` `SOC_SENSOR_KEY`. |
| **`409 Conflict`** | Duplicate `event_id` | Generate a fresh UUID4 for each flow record. |
| **`413 Payload Too Large`** | Request exceeds 1MB | Reduce batch size to $\le 50$ flows per POST. |
| **`422 Unprocessable`** | Missing or non-numeric features | Check response body: contains list of missing/invalid field names. |
| **`422 Unprocessable`** | Negative Flow Duration | Verify packet sniffer timestamp calculation ($\ge 0$). |
| **`500 Internal Error`** | Server / Database error | Verify host backend is running and `soc.db` is writable. |

---

## 7. Using the Built-In File Tailer (`kafka/live_adapter.py`)

If your sensor captures packets into a CSV file (e.g. `/var/log/soc/flows.csv`), you do **not** need to write a custom HTTP client. Run the project's included `LiveFlowTailer` directly on the sensor VM:

```bash
# On the Sensor VM:
python3 -m kafka.live_adapter \
    --csv-file /var/log/soc/flows.csv \
    --target-url http://192.168.56.1:8000/api/ingest/flow \
    --api-key soc-sensor-dev-key-2026 \
    --batch-size 25 \
    --poll-interval 1.0
```

The adapter automatically:
- Resolves 275+ CICFlowMeter header aliases into the canonical 78 feature names.
- Tracks file byte offsets across restarts to prevent re-submitting old flows.
- Validates microsecond units and filters partial line writes.
- Sends authenticated HTTP batches with exponential backoff retries.
