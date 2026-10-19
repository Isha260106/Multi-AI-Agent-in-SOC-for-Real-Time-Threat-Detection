"""
kafka/config.py
================
Central configuration for the Stage 4 event-streaming layer.

Multi-Agent SOC Project -- Stage 4: Real-Time Event Streaming

All tunable parameters live here so that producer.py and consumer.py
import from a single source of truth -- no hardcoded values scattered
across scripts.
"""

import pathlib

# ---------------------------------------------------------------------------
# Project layouts
# ---------------------------------------------------------------------------
PROJECT_ROOT = pathlib.Path(r"E:\multi-agent-soc")

MODEL_PATH  = PROJECT_ROOT / "models" / "network_detection_model.pkl"
PREP_PATH   = PROJECT_ROOT / "models" / "network_detection_preprocessing.pkl"
DATASET_PATH = PROJECT_ROOT / "data" / "processed" / "cleaned_dataset.csv"

# ---------------------------------------------------------------------------
# Log directory / files
# ---------------------------------------------------------------------------
LOG_DIR             = PROJECT_ROOT / "logs"
STREAMING_LOG_FILE  = LOG_DIR / "streaming_runtime.log"
STREAMING_ALERT_FILE = LOG_DIR / "streaming_alerts.json"

# ---------------------------------------------------------------------------
# Kafka (used when TRANSPORT = "kafka")
# ---------------------------------------------------------------------------
KAFKA_BOOTSTRAP_SERVERS = "localhost:9092"
KAFKA_TOPIC             = "network-flow-events"
KAFKA_GROUP_ID          = "soc-network-detection-consumer"

# ---------------------------------------------------------------------------
# Streaming behaviour defaults
# ---------------------------------------------------------------------------
# Transport backend: "queue" (built-in, no Kafka needed) | "kafka"
DEFAULT_TRANSPORT  = "queue"

# Seconds between events sent by the producer (can be overridden via --delay)
DEFAULT_DELAY      = 1.0

# Default number of events to send/receive per demo run
DEFAULT_EVENT_COUNT = 20

# CSV chunk size used during streaming read (rows read at a time)
CSV_CHUNK_SIZE = 500

# ---------------------------------------------------------------------------
# Event schema metadata (informational)
# ---------------------------------------------------------------------------
EVENT_TYPE = "network_flow"

# Label column in the CSV -- used by producer for test annotation only.
# It is NEVER sent as a model feature.
LABEL_COLUMN = "Label"

# ---------------------------------------------------------------------------
# Benign / attack class names (must match model training labels)
# ---------------------------------------------------------------------------
CLASS_BENIGN       = "Benign"
CLASS_INFILTERATION = "Infilteration"
