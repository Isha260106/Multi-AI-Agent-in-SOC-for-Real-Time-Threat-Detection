"""
agents/anomaly_detection/config.py
====================================
Central configuration for the Anomaly Detection Agent.

Multi-Agent SOC Project -- Stage 6: Anomaly Detection Agent
"""

import pathlib

# ---------------------------------------------------------------------------
# Project root
# ---------------------------------------------------------------------------
PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent

# ---------------------------------------------------------------------------
# Dataset
# ---------------------------------------------------------------------------
DATASET_PATH   = PROJECT_ROOT / "data" / "processed" / "cleaned_dataset.csv"
LABEL_COLUMN   = "Label"
BENIGN_LABEL   = "Benign"
ATTACK_LABEL   = "Infilteration"
CSV_CHUNK_SIZE = 10_000          # rows per chunk when reading dataset

# ---------------------------------------------------------------------------
# Model and preprocessing paths
# ---------------------------------------------------------------------------
MODEL_PATH = PROJECT_ROOT / "models" / "anomaly_detection_model.pkl"
PREP_PATH  = PROJECT_ROOT / "models" / "anomaly_detection_preprocessing.pkl"

# ---------------------------------------------------------------------------
# Training parameters
# ---------------------------------------------------------------------------
RANDOM_SEED          = 42
BENIGN_TRAIN_FRAC    = 0.80    # 80 % of benign for training; 20 % held out for eval
MAX_BENIGN_TRAIN     = 60_000  # cap training set size for speed
MAX_BENIGN_EVAL      = 10_000  # cap held-out benign eval set
MAX_ATTACK_EVAL      = 10_000  # cap attack eval set

# Isolation Forest hyper-parameters
IF_N_ESTIMATORS  = 200
IF_MAX_SAMPLES   = "auto"
IF_CONTAMINATION = "auto"      # 'auto' fits without assuming a contamination rate
IF_MAX_FEATURES  = 1.0
IF_BOOTSTRAP     = False

# ---------------------------------------------------------------------------
# Anomaly threshold
# ---------------------------------------------------------------------------
# The Isolation Forest score_samples() method returns negative anomaly scores.
# Lower (more negative) = more anomalous.
# The threshold is selected during training by evaluating on held-out data.
# See train.py for the selection procedure.
# This default is overridden by the value stored in PREP_PATH.
DEFAULT_ANOMALY_THRESHOLD = -0.10

# ---------------------------------------------------------------------------
# Alert constants
# ---------------------------------------------------------------------------
AGENT_NAME          = "Anomaly Detection Agent"
HIGH_SCORE_BOUNDARY = -0.05   # score below this → HIGH severity (updated after training)

# ---------------------------------------------------------------------------
# Log paths
# ---------------------------------------------------------------------------
LOG_DIR             = PROJECT_ROOT / "logs"
ANOMALY_LOG_FILE    = LOG_DIR / "anomaly_runtime.log"
ANOMALY_ALERT_FILE  = LOG_DIR / "anomaly_alerts.json"

# Context fields copied into alerts (same as NetworkDetectionAgent)
ALERT_CONTEXT_FIELDS = [
    "Dst Port", "Protocol", "Flow Duration",
    "Flow Pkts/s", "Flow Byts/s",
    "Fwd Pkts/s", "Bwd Pkts/s",
    "SYN Flag Cnt", "RST Flag Cnt",
    "Tot Fwd Pkts", "Tot Bwd Pkts",
]
