# Anomaly Detection Agent

**Multi-Agent SOC Project | Stage 6**

## 1. Purpose

The Anomaly Detection Agent identifies network flows that are statistically unusual compared to a baseline of normal traffic. It uses an unsupervised machine learning algorithm (Isolation Forest) trained exclusively on `Benign` traffic. 

## 2. Difference from Network Detection Agent

| Context | Network Detection Agent (Stage 3) | Anomaly Detection Agent (Stage 6) |
|---|---|---|
| **Question** | "Does this flow resemble a known attack class?" | "Does this flow appear unusual compared with normal behaviour?" |
| **Algorithm** | Random Forest | Isolation Forest |
| **Learning Type** | Supervised | Unsupervised |
| **Training Data** | Benign + Infilteration (labelled) | Benign only (unlabelled) |
| **Output** | Probability of specific attack class | Raw anomaly score (unusualness) |

## 3. Dataset & Feature Preparation

The agent uses the same `cleaned_dataset.csv` as the Network Detection Agent. It leverages 78 network-flow features, strictly mirroring the order and cleaning steps of the previous stage. The `Label` column is **never** provided to the model.

Preprocessing handles:
- Stripping ignored columns (`Label`, `Timestamp`, `actual_label`).
- Coercing non-numeric values to `NaN`.
- Converting infinities to `NaN`.
- Imputing `NaN` values with feature medians learned from the benign training set.

## 4. Training Approach

Run training with:
```powershell
python agents/anomaly_detection/train.py
```

The script:
1. Loads the dataset, segregating Benign and Infilteration records.
2. Selects a maximum of 60,000 Benign records for training.
3. Holds out 10,000 Benign records and 10,000 Infilteration records for evaluation.
4. Computes feature medians using the training set.
5. Trains an `IsolationForest` (default max_samples, 200 estimators) on the benign training set.
6. Automatically selects the anomaly threshold.
7. Saves `anomaly_detection_model.pkl` and `anomaly_detection_preprocessing.pkl`.

## 5. Threshold Selection

The Isolation Forest `score_samples()` function returns a negative average path length. Expected range: `[-0.5, 0.0]`, where lower scores indicate deeper anomalies.

**This score is not a probability and should not be referred to as confidence.**

To maintain a data-driven approach without data leakage:
- Threshold candidate values are drawn from the 1st to 80th percentile of scores generated on the **held-out** benign subset.
- The candidate that maximises the `F1-score` across both held-out evaluation sets (Benign + Attack) is selected.

In our current dataset, the model correctly flags attacks with a Recall ~83%, producing an F1-score of ~0.63 at the selected threshold. (Expect overlap; benign CSE-CIC-IDS2018 traffic has high variance, causing false positives in unsupervised learning).

## 6. Agent API Usage

```python
import pandas as pd
from agents.anomaly_detection.agent import AnomalyDetectionAgent

agent = AnomalyDetectionAgent()
df = pd.read_csv("traffic.csv")

# Returns a list of structured alert dictionaries
alerts = agent.analyze(df)
```

### Output Format Example
```json
{
    "agent": "Anomaly Detection Agent",
    "prediction": "Anomalous",
    "anomaly_score": -0.4217,
    "severity": "HIGH",
    "status": "SUSPICIOUS",
    "timestamp": "2026-09-17T12:00:00.000",
    "threshold_used": -0.3372,
    "note": "anomaly_score is the Isolation Forest score_samples() value...",
    "network_context": {
        "Dst Port": 443,
        "Protocol": 6,
        ...
    }
}
```

## 7. Streaming & SQLite Integration

The Anomaly Detection Agent operates alongside the Network Detection Agent in the streaming consumer (`kafka/consumer.py`).

1. **Independent execution:** Both agents process the incoming flow independently.
2. **Dedicated Logs:** Anomalies are logged to `logs/anomaly_alerts.json`.
3. **Database Insertion:** Both alerts are persisted to `data/soc.db` (`alerts` table) sharing the same parent `event_id` in the `events` table.

This leads to a true parallel multi-agent detection architecture.

## 8. Limitations

- **False Positives:** Without supervised labels, highly variable benign traffic can easily trip the unsupervised threshold. The anomaly model acts as a tripwire, not an authoritative classifier.
- **Single Threaded Agent:** The current agent wrapper performs blocking inference.

## 9. Future Work

*Not implemented in this stage:*
- **Alert Correlation Agent:** To aggregate both ND and AD alerts into a unified threat incident.
- **Investigation / Root Cause Analysis Agent.**
- **Automatic blocking mechanisms.**
