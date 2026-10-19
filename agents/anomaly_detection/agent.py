"""
agents/anomaly_detection/agent.py
===================================
Anomaly Detection Agent

Multi-Agent SOC Project -- Stage 6: Anomaly Detection Agent

PURPOSE
-------
Uses a trained Isolation Forest to detect unusual network-flow traffic
by comparing incoming flows against the normal (Benign) baseline learned
during training.

DIFFERENCE FROM NetworkDetectionAgent
--------------------------------------
NetworkDetectionAgent (Stage 3):
    "Does this flow resemble a known attack class?"
    → Supervised Random Forest classifier
    → Trained on both Benign and Infilteration labels
    → Output: "Benign" or "Infilteration"

AnomalyDetectionAgent (Stage 6):
    "Does this flow appear unusual compared with normal behaviour?"
    → Unsupervised Isolation Forest
    → Trained on Benign traffic only
    → Output: "Normal" or "Anomalous"

SCORE FORMAT
------------
The anomaly_score field is the raw Isolation Forest score_samples() value.
Range: typically [-0.5, 0.0] — lower means more anomalous.
This is NOT a probability. It is not labelled "confidence".

USAGE
-----
    from agents.anomaly_detection.agent import AnomalyDetectionAgent
    agent = AnomalyDetectionAgent()
    results = agent.analyze(dataframe)

Each result dict contains:
    {
        "agent":         "Anomaly Detection Agent",
        "prediction":    "Normal" | "Anomalous",
        "anomaly_score": float,      # Isolation Forest score (lower = more anomalous)
        "severity":      "LOW" | "HIGH",
        "status":        "NORMAL" | "SUSPICIOUS",
        "timestamp":     str,
        "network_context": dict,
        "threshold_used": float,
        "note":          str,
    }
"""

import datetime
import logging
import pathlib
import sys
from typing import Union

import numpy as np
import pandas as pd
import joblib

# ---------------------------------------------------------------------------
# Project path
# ---------------------------------------------------------------------------
PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from agents.anomaly_detection.config import (
    MODEL_PATH, PREP_PATH,
    AGENT_NAME, ALERT_CONTEXT_FIELDS,
    ANOMALY_LOG_FILE,
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger("AnomalyDetectionAgent")
if not logger.handlers:
    ANOMALY_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    _fh = logging.FileHandler(ANOMALY_LOG_FILE, encoding="utf-8")
    _fh.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    logger.addHandler(_fh)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False

# Ignored columns — same as NetworkDetectionAgent
_IGNORED_COLUMNS = {"Label", "Timestamp", "actual_label"}


# ---------------------------------------------------------------------------
# AnomalyDetectionAgent
# ---------------------------------------------------------------------------

class AnomalyDetectionAgent:
    """
    Isolation Forest-based network traffic anomaly detector.

    Identifies flows that are statistically unusual compared to the
    normal (Benign) traffic distribution seen during training.

    Does NOT identify attack categories. An anomalous flow is one that
    differs significantly from the learned normal baseline.
    """

    def __init__(
        self,
        model_path: Union[str, pathlib.Path] = MODEL_PATH,
        prep_path:  Union[str, pathlib.Path] = PREP_PATH,
    ):
        """Load model and preprocessing metadata from disk."""
        self.model_path = pathlib.Path(model_path)
        self.prep_path  = pathlib.Path(prep_path)

        logger.info("AnomalyDetectionAgent initialising...")
        self._model = self._load_model()
        self._prep  = self._load_prep()

        self._feature_names = self._prep["feature_names"]
        self._n_features    = self._prep["n_features"]
        self._medians       = self._prep["medians"]
        self._threshold     = self._prep["anomaly_threshold"]

        logger.info(
            "Agent ready. features=%d  threshold=%.6f",
            self._n_features, self._threshold,
        )

    # ------------------------------------------------------------------
    # Private: Loading
    # ------------------------------------------------------------------

    def _load_model(self):
        if not self.model_path.exists():
            raise FileNotFoundError(
                f"Anomaly model not found: {self.model_path}\n"
                f"Run: python agents/anomaly_detection/train.py"
            )
        obj = joblib.load(self.model_path)
        # Validate it is an Isolation Forest (or compatible estimator)
        if not hasattr(obj, "score_samples"):
            raise ValueError(
                f"Loaded object from {self.model_path} is not a valid "
                f"anomaly detector (no score_samples method). "
                f"Re-run train.py."
            )
        logger.info("Model loaded: %s", self.model_path)
        return obj

    def _load_prep(self) -> dict:
        if not self.prep_path.exists():
            raise FileNotFoundError(
                f"Preprocessing metadata not found: {self.prep_path}\n"
                f"Run: python agents/anomaly_detection/train.py"
            )
        meta = joblib.load(self.prep_path)
        required_keys = {"feature_names", "n_features", "medians", "anomaly_threshold"}
        missing = required_keys - set(meta.keys())
        if missing:
            raise ValueError(
                f"Preprocessing metadata is missing keys: {missing}. "
                f"Re-run train.py."
            )
        logger.info("Preprocessing metadata loaded: %s", self.prep_path)
        return meta

    # ------------------------------------------------------------------
    # Private: Input validation
    # ------------------------------------------------------------------

    def _validate_input(self, input_data) -> None:
        """
        Raise descriptive ValueError/TypeError for all invalid inputs.

        Checks:
          - Correct type (must be pd.DataFrame)
          - Non-empty
          - All 78 required features present
        """
        if not isinstance(input_data, pd.DataFrame):
            raise TypeError(
                f"AnomalyDetectionAgent.analyze() expects a pandas DataFrame. "
                f"Got: {type(input_data).__name__}."
            )
        if input_data.empty:
            raise ValueError(
                "Input DataFrame is empty. Cannot analyze zero rows."
            )
        # Drop ignored columns before checking features
        present = set(input_data.columns) - _IGNORED_COLUMNS
        missing = set(self._feature_names) - present
        if missing:
            raise ValueError(
                f"Input is missing {len(missing)} required feature(s):\n"
                f"  {sorted(missing)}\n"
                f"All 78 features must be present."
            )

    # ------------------------------------------------------------------
    # Private: Preprocessing
    # ------------------------------------------------------------------

    def preprocess(self, input_data: pd.DataFrame) -> pd.DataFrame:
        """
        Prepare raw input for Isolation Forest inference.

        Steps:
          1. Drop ignored columns (Label, Timestamp, actual_label)
          2. Select + reorder to exact training feature order
          3. Convert to numeric (coerce invalid → NaN)
          4. Replace ±inf → NaN
          5. Impute NaN with per-feature training medians
          6. Final check: no NaN, correct shape

        Returns a clean DataFrame with exactly 78 numeric columns.
        """
        # Step 1: drop ignored
        drop_cols = [c for c in _IGNORED_COLUMNS if c in input_data.columns]
        if drop_cols:
            input_data = input_data.drop(columns=drop_cols)

        # Step 2: select + reorder
        X = input_data[self._feature_names].copy()

        # Step 3: coerce to numeric
        for col in X.columns:
            X[col] = pd.to_numeric(X[col], errors="coerce")

        non_numeric = X.isna().sum()
        if non_numeric.any():
            bad = non_numeric[non_numeric > 0].index.tolist()
            logger.warning(
                "Non-numeric or missing values in %d feature(s): %s. "
                "Filling with training medians.",
                len(bad), bad[:5],
            )

        # Step 4: ±inf → NaN
        X = X.replace([np.inf, -np.inf], np.nan)

        # Step 5: impute NaN with medians
        for col in self._feature_names:
            if X[col].isna().any():
                med = self._medians.get(col, 0.0)
                X[col] = X[col].fillna(med)

        # Step 6: final check
        residual_nan = int(X.isna().sum().sum())
        if residual_nan > 0:
            raise ValueError(
                f"Preprocessing failed: {residual_nan} NaN values remain. "
                f"Check training medians."
            )
        if X.shape[1] != self._n_features:
            raise ValueError(
                f"Feature count mismatch after preprocessing: "
                f"got {X.shape[1]}, expected {self._n_features}."
            )
        return X

    # ------------------------------------------------------------------
    # Private: Score + classify
    # ------------------------------------------------------------------

    def score(self, X_clean: pd.DataFrame) -> np.ndarray:
        """
        Compute Isolation Forest anomaly scores.

        Returns an array of raw scores, one per row.
        Range: typically [-0.5, 0.0]
        Lower score = more anomalous.
        """
        return self._model.score_samples(X_clean.values)

    def _classify(self, score: float) -> tuple[str, str, str]:
        """
        Apply threshold to classify a single score.

        Returns:
            (prediction, severity, status)
        """
        if score < self._threshold:
            return "Anomalous", "HIGH", "SUSPICIOUS"
        else:
            return "Normal", "LOW", "NORMAL"

    # ------------------------------------------------------------------
    # Private: Alert generation
    # ------------------------------------------------------------------

    def _generate_alert(
        self,
        raw_row:  pd.Series,
        score:    float,
        prediction: str,
        severity:   str,
        status:     str,
    ) -> dict:
        """Build a structured anomaly alert for one flow record."""
        timestamp = datetime.datetime.now().isoformat()

        # Network context — same fields as NetworkDetectionAgent
        network_context = {}
        for field in ALERT_CONTEXT_FIELDS:
            if field in raw_row.index:
                val = raw_row[field]
                if isinstance(val, (np.integer,)):
                    val = int(val)
                elif isinstance(val, (np.floating,)):
                    val = round(float(val), 4)
                network_context[field] = val

        return {
            "agent":          AGENT_NAME,
            "timestamp":      timestamp,
            "prediction":     prediction,            # "Normal" | "Anomalous"
            "anomaly_score":  round(float(score), 6),
            "severity":       severity,
            "status":         status,
            "threshold_used": round(float(self._threshold), 6),
            "note": (
                "anomaly_score is the Isolation Forest score_samples() value. "
                "Range ~[-0.5, 0.0]. Lower = more anomalous. "
                "This is not a probability. "
                "Anomalous means the flow differs from the normal baseline, "
                "not that a specific attack type was identified."
            ),
            "network_context": network_context,
        }

    # ------------------------------------------------------------------
    # Public: Main entry point
    # ------------------------------------------------------------------

    def analyze(self, input_data: pd.DataFrame) -> list[dict]:
        """
        Full pipeline: validate → preprocess → score → classify → alert.

        Args:
            input_data: pandas DataFrame with one or more network-flow rows.
                        Must contain all 78 model features.
                        May contain Label, Timestamp, actual_label (ignored).

        Returns:
            List of alert dicts, one per input row.

        Raises:
            TypeError  : If input is not a DataFrame.
            ValueError : If input is empty, missing features, or fails preprocessing.
            FileNotFoundError : If model or metadata files are missing.
        """
        n_records = len(input_data) if isinstance(input_data, pd.DataFrame) else 0
        logger.info("Analyzing %d network-flow record(s)...", n_records)

        # Validate
        self._validate_input(input_data)

        # Preprocess
        X_clean = self.preprocess(input_data)

        # Score
        scores = self.score(X_clean)

        # Generate alerts
        alerts = []
        anomaly_count = 0
        for i in range(len(X_clean)):
            raw_row    = input_data.iloc[i]
            score      = float(scores[i])
            prediction, severity, status = self._classify(score)

            alert = self._generate_alert(raw_row, score, prediction, severity, status)
            alerts.append(alert)

            if prediction == "Anomalous":
                anomaly_count += 1
                logger.warning(
                    "[Record %d/%d] ANOMALOUS traffic detected. "
                    "score=%.6f threshold=%.6f",
                    i + 1, n_records, score, self._threshold,
                )
            else:
                logger.debug(
                    "[Record %d/%d] Normal traffic. score=%.6f",
                    i + 1, n_records, score,
                )

        logger.info(
            "Analysis complete. Anomalous: %d/%d", anomaly_count, n_records
        )
        return alerts
