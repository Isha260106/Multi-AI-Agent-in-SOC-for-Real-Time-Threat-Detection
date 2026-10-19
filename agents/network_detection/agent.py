"""
Network Monitoring & Detection Agent
======================================
Multi-Agent SOC Project -- Stage 3

This is the first functional agent in the Multi-Agent Security Operations Center.

Responsibility:
  - Accept network-flow data (as a pandas DataFrame)
  - Preprocess the input to match training conditions
  - Run the trained Random Forest model
  - Generate a structured security alert

This agent does NOT:
  - Take defensive actions (that is the Response & Remediation Agent)
  - Correlate multiple alerts (that is the Alert Correlation Agent)
  - Score risk levels (that is the Risk Assessment Agent)
  - Communicate with other agents yet (multi-agent communication is a later stage)
"""

import logging
import pathlib
import datetime
from typing import Union

import numpy as np
import pandas as pd
import joblib

# ---------------------------------------------------------------------------
# Logging Configuration
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("NetworkDetectionAgent")

# ---------------------------------------------------------------------------
# Default file paths
# ---------------------------------------------------------------------------
DEFAULT_MODEL_PATH  = pathlib.Path(r"E:\multi-agent-soc\models\network_detection_model.pkl")
DEFAULT_PREP_PATH   = pathlib.Path(r"E:\multi-agent-soc\models\network_detection_preprocessing.pkl")

# ---------------------------------------------------------------------------
# Columns to ignore if present in input (they were not used in training)
# ---------------------------------------------------------------------------
IGNORED_COLUMNS = {"Label", "Timestamp"}

# ---------------------------------------------------------------------------
# Network-context fields to include in alerts (if present in input data)
# ---------------------------------------------------------------------------
ALERT_CONTEXT_FIELDS = [
    "Dst Port",
    "Protocol",
    "Flow Duration",
    "Flow Pkts/s",
    "Flow Byts/s",
    "Fwd Pkts/s",
    "Bwd Pkts/s",
    "SYN Flag Cnt",
    "RST Flag Cnt",
    "Tot Fwd Pkts",
    "Tot Bwd Pkts",
]


class NetworkDetectionAgent:
    """
    The Network Detection Agent wraps the trained Random Forest classifier
    and exposes a clean interface for processing network-flow records.

    Usage:
        agent = NetworkDetectionAgent()
        alerts = agent.analyze(df_of_flows)
    """

    def __init__(
        self,
        model_path:  Union[str, pathlib.Path] = DEFAULT_MODEL_PATH,
        prep_path:   Union[str, pathlib.Path] = DEFAULT_PREP_PATH,
    ):
        """
        Load the trained model and the preprocessing metadata once at startup.
        Subsequent calls to analyze() reuse these loaded objects.
        """
        logger.info("Network Detection Agent starting...")

        self.model_path = pathlib.Path(model_path)
        self.prep_path  = pathlib.Path(prep_path)

        # Load model
        self._model = self._load_model()

        # Load preprocessing metadata (feature names + training medians)
        self._prep = self._load_preprocessing()

        self._feature_names   = self._prep["feature_names"]   # ordered list of 78 feature names
        self._training_medians = self._prep["medians"]         # dict: feature -> median
        self._n_features       = self._prep["n_features"]      # should be 78

        # Verify model matches preprocessing metadata
        n_model = len(self._model.feature_importances_)
        if n_model != self._n_features:
            raise ValueError(
                f"Feature count mismatch between model ({n_model}) "
                f"and preprocessing metadata ({self._n_features}). "
                f"Re-run build_preprocessing_metadata.py."
            )

        logger.info(
            f"Model loaded successfully. "
            f"Expects {self._n_features} input features."
        )

    # ------------------------------------------------------------------
    # Private: Loading helpers
    # ------------------------------------------------------------------

    def _load_model(self):
        """Load the Random Forest model from disk."""
        if not self.model_path.exists():
            raise FileNotFoundError(
                f"Model file not found: {self.model_path}\n"
                f"Please verify the path or re-run train_model.py."
            )
        logger.info(f"Loading model from: {self.model_path}")
        return joblib.load(self.model_path)

    def _load_preprocessing(self):
        """Load the preprocessing metadata (feature names + medians)."""
        if not self.prep_path.exists():
            raise FileNotFoundError(
                f"Preprocessing metadata not found: {self.prep_path}\n"
                f"Please run build_preprocessing_metadata.py first."
            )
        logger.info(f"Loading preprocessing metadata from: {self.prep_path}")
        return joblib.load(self.prep_path)

    # ------------------------------------------------------------------
    # Private: Preprocessing
    # ------------------------------------------------------------------

    def preprocess(self, input_data: pd.DataFrame) -> pd.DataFrame:
        """
        Prepare a raw input DataFrame for model inference.

        Steps:
          1. Drop ignored columns (Label, Timestamp) if present.
          2. Check all 78 expected features are present.
          3. Select and reorder to exact training feature order.
          4. Convert to numeric, coercing invalid values to NaN.
          5. Replace inf/-inf with NaN.
          6. Fill NaN with per-feature training-set medians.
          7. Final validation (no NaN, all numeric).

        Returns a clean DataFrame with exactly 78 numeric columns.
        Raises ValueError if required features are missing or unresolvable.
        """

        # Step 1: Remove ignored columns
        cols_to_drop = [c for c in IGNORED_COLUMNS if c in input_data.columns]
        if cols_to_drop:
            logger.debug(f"Dropping ignored columns: {cols_to_drop}")
            input_data = input_data.drop(columns=cols_to_drop)

        # Step 2: Check for missing required features
        present_features  = set(input_data.columns)
        expected_features = set(self._feature_names)
        missing = expected_features - present_features
        if missing:
            raise ValueError(
                f"Input is missing {len(missing)} required feature(s):\n"
                f"  {sorted(missing)}\n"
                f"Cannot predict without all 78 features."
            )

        # Step 3: Select + reorder to exact training order
        X = input_data[self._feature_names].copy()

        # Step 4: Convert to numeric (coerce non-numeric -> NaN)
        for col in X.columns:
            X[col] = pd.to_numeric(X[col], errors="coerce")

        # Check for non-numeric conversion issues
        non_numeric_nans = X.isna().sum()
        if non_numeric_nans.any():
            bad_cols = non_numeric_nans[non_numeric_nans > 0].index.tolist()
            logger.warning(
                f"Non-numeric or missing values detected in: {bad_cols}. "
                f"Will be filled with training-set medians."
            )

        # Step 5: Replace infinity with NaN
        X = X.replace([np.inf, -np.inf], np.nan)

        # Step 6: Fill NaN with training-set medians
        for col in X.columns:
            if X[col].isna().any():
                median_val = self._training_medians.get(col)
                if median_val is None or np.isnan(median_val):
                    raise ValueError(
                        f"Cannot fill NaN in feature '{col}': "
                        f"no training median is available for this feature."
                    )
                X[col] = X[col].fillna(median_val)

        # Step 7: Final validation
        remaining_nans = int(X.isna().sum().sum())
        if remaining_nans > 0:
            raise ValueError(
                f"Preprocessing failed: {remaining_nans} NaN values remain after imputation."
            )

        if X.shape[1] != self._n_features:
            raise ValueError(
                f"Feature count after preprocessing: {X.shape[1]} "
                f"(expected {self._n_features})."
            )

        return X

    # ------------------------------------------------------------------
    # Private: Prediction
    # ------------------------------------------------------------------

    def predict(self, X_clean: pd.DataFrame) -> dict:
        """
        Run model inference on a preprocessed DataFrame.

        Returns:
            {
                "predictions"  : list of predicted class labels
                "confidences"  : list of confidence scores (highest class probability)
                "probabilities": list of dicts mapping class -> probability
            }
        """
        predictions = self._model.predict(X_clean).tolist()

        classes = self._model.classes_.tolist()
        proba_matrix = self._model.predict_proba(X_clean)  # shape: (n_rows, n_classes)

        confidences  = []
        probabilities = []

        for row_proba in proba_matrix:
            # confidence = probability of the predicted class
            max_prob = float(np.max(row_proba))
            confidences.append(round(max_prob, 4))

            prob_dict = {cls: round(float(p), 4) for cls, p in zip(classes, row_proba)}
            probabilities.append(prob_dict)

        return {
            "predictions":   predictions,
            "confidences":   confidences,
            "probabilities": probabilities,
        }

    # ------------------------------------------------------------------
    # Private: Alert generation
    # ------------------------------------------------------------------

    def generate_alert(
        self,
        raw_row: pd.Series,
        prediction: str,
        confidence: float,
        probabilities: dict,
    ) -> dict:
        """
        Build a structured security alert dictionary for a single flow record.

        Severity rules (simple, first version):
          Benign         -> severity: LOW,  status: NORMAL
          Infilteration  -> severity: HIGH, status: SUSPICIOUS
        """
        timestamp = datetime.datetime.now().isoformat()

        if prediction == "Infilteration":
            severity = "HIGH"
            status   = "SUSPICIOUS"
        else:
            severity = "LOW"
            status   = "NORMAL"

        # Collect available network-context fields from the raw row
        network_context = {}
        for field in ALERT_CONTEXT_FIELDS:
            if field in raw_row.index:
                val = raw_row[field]
                # Convert numpy types to native Python for JSON compatibility
                if isinstance(val, (np.integer,)):
                    val = int(val)
                elif isinstance(val, (np.floating,)):
                    val = round(float(val), 4)
                network_context[field] = val

        alert = {
            "agent":           "Network Detection Agent",
            "timestamp":       timestamp,
            "prediction":      prediction,
            "confidence":      confidence,
            "severity":        severity,
            "status":          status,
            "note":            (
                "confidence is the model's predicted probability for this class, "
                "not proof of an attack."
            ),
            "class_probabilities": probabilities,
            "network_context": network_context,
        }

        return alert

    # ------------------------------------------------------------------
    # Public: Main entry point
    # ------------------------------------------------------------------

    def analyze(self, input_data: pd.DataFrame) -> list:
        """
        Full pipeline: preprocess -> predict -> generate alerts.

        Args:
            input_data: A pandas DataFrame with one or more network-flow records.
                        Must contain all 78 model features.
                        May optionally contain Label and/or Timestamp (they are ignored).

        Returns:
            A list of alert dictionaries -- one per input row.
        """
        n_records = len(input_data)
        logger.info(f"Processing {n_records} network-flow record(s)...")

        # Preprocess (may raise ValueError on bad input)
        X_clean = self.preprocess(input_data)

        # Predict
        result = self.predict(X_clean)
        predictions   = result["predictions"]
        confidences   = result["confidences"]
        probabilities = result["probabilities"]

        # Generate one alert per row
        alerts = []
        for i in range(n_records):
            raw_row    = input_data.iloc[i]
            prediction = predictions[i]
            confidence = confidences[i]
            proba      = probabilities[i]

            alert = self.generate_alert(raw_row, prediction, confidence, proba)
            alerts.append(alert)

            if prediction == "Infilteration":
                logger.warning(
                    f"[Record {i+1}/{n_records}] SUSPICIOUS traffic detected. "
                    f"Label=Infilteration | Confidence={confidence:.2%}"
                )
            else:
                logger.info(
                    f"[Record {i+1}/{n_records}] Normal traffic. "
                    f"Label=Benign | Confidence={confidence:.2%}"
                )

        logger.info(
            f"Analysis complete. "
            f"Suspicious: {sum(1 for p in predictions if p == 'Infilteration')}/{n_records}"
        )

        return alerts
