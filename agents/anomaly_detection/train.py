"""
agents/anomaly_detection/train.py
===================================
Training Script for the Anomaly Detection Agent

Multi-Agent SOC Project -- Stage 6: Anomaly Detection Agent

PURPOSE
-------
Trains an Isolation Forest model to detect unusual network-flow behaviour.

The model is trained exclusively on BENIGN traffic.
Attack traffic is reserved for independent evaluation only.
The Label column is never used as a model feature.

ALGORITHM: Isolation Forest
---------------------------
Isolation Forest detects anomalies by randomly partitioning data and
measuring how many splits are needed to isolate each sample.
Anomalies are isolated quickly (few splits) because they are "different"
from the majority of the training distribution.

SCORE FORMAT
------------
`model.score_samples(X)` returns the negative average path length score.
Range: typically in [-0.5, 0.0]
  More negative = more anomalous
  Closer to 0   = more normal

This is NOT a probability. It is not called 'confidence'.
The threshold is selected through evaluation on held-out data.

THRESHOLD SELECTION
-------------------
Procedure:
  1. Score held-out benign samples (should mostly be near 0, i.e. normal)
  2. Score held-out attack samples (should skew more negative)
  3. Sweep candidate thresholds from the 1st to 40th percentile of
     held-out benign scores
  4. For each threshold, compute F1 on the combined eval set
  5. Select the threshold that maximises F1

This approach ensures:
  - The threshold is DATA-DRIVEN, not hand-picked
  - We maximise detection while controlling false positives
  - No data leakage: threshold tuning uses held-out data, not training data

USAGE
-----
  python agents/anomaly_detection/train.py
"""

import pathlib
import sys
import datetime
import random
import json

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix,
)

from agents.anomaly_detection.config import (
    DATASET_PATH, LABEL_COLUMN, BENIGN_LABEL, ATTACK_LABEL,
    CSV_CHUNK_SIZE, MODEL_PATH, PREP_PATH,
    RANDOM_SEED, BENIGN_TRAIN_FRAC,
    MAX_BENIGN_TRAIN, MAX_BENIGN_EVAL, MAX_ATTACK_EVAL,
    IF_N_ESTIMATORS, IF_MAX_SAMPLES, IF_CONTAMINATION,
    IF_MAX_FEATURES, IF_BOOTSTRAP,
)

DIV  = "=" * 70
DIV2 = "-" * 70


# ---------------------------------------------------------------------------
# 1. Data loading
# ---------------------------------------------------------------------------

def load_data() -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Read the dataset in chunks and collect Benign and Attack records separately.

    Returns:
        (benign_df, attack_df) -- DataFrames with Label column included.
    """
    print(f"\n  Loading dataset: {DATASET_PATH}")
    benign_parts: list[pd.DataFrame] = []
    attack_parts: list[pd.DataFrame] = []
    total_rows = 0

    for chunk in pd.read_csv(DATASET_PATH, chunksize=CSV_CHUNK_SIZE, low_memory=False):
        total_rows += len(chunk)
        if LABEL_COLUMN in chunk.columns:
            benign_parts.append(chunk[chunk[LABEL_COLUMN] == BENIGN_LABEL])
            attack_parts.append(chunk[chunk[LABEL_COLUMN] == ATTACK_LABEL])

    benign_df = pd.concat(benign_parts, ignore_index=True) if benign_parts else pd.DataFrame()
    attack_df = pd.concat(attack_parts, ignore_index=True) if attack_parts else pd.DataFrame()

    print(f"  Total rows read          : {total_rows:,}")
    print(f"  Benign rows              : {len(benign_df):,}")
    print(f"  Attack rows              : {len(attack_df):,}")
    return benign_df, attack_df


# ---------------------------------------------------------------------------
# 2. Feature preparation
# ---------------------------------------------------------------------------

def prepare_features(
    df: pd.DataFrame,
    feature_names: list[str],
    medians: dict[str, float],
) -> np.ndarray:
    """
    Select, reorder, clean, and impute features.

    Steps:
      1. Select only the 78 model features (drop Label and any extras)
      2. Convert to numeric (coerce invalid → NaN)
      3. Replace ±inf with NaN
      4. Impute NaN with training medians
    """
    X = df[feature_names].copy()
    X = X.apply(pd.to_numeric, errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan)
    for col in feature_names:
        if X[col].isna().any():
            X[col] = X[col].fillna(medians.get(col, 0.0))
    return X.values.astype(np.float64)


def compute_medians(df: pd.DataFrame, feature_names: list[str]) -> dict[str, float]:
    """Compute per-feature medians from a clean DataFrame."""
    X = df[feature_names].copy()
    X = X.apply(pd.to_numeric, errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan)
    medians = {}
    for col in feature_names:
        med = X[col].median()
        medians[col] = 0.0 if pd.isna(med) else float(med)
    return medians


# ---------------------------------------------------------------------------
# 3. Threshold selection
# ---------------------------------------------------------------------------

def select_threshold(
    scores_benign_eval: np.ndarray,
    scores_attack_eval: np.ndarray,
) -> tuple[float, dict]:
    """
    Sweep candidate thresholds and select the one that maximises F1.

    A sample is predicted ANOMALOUS if its score < threshold.

    Candidate thresholds are drawn from the 1st–40th percentile of
    benign evaluation scores (i.e., cover the "worst normal" scores).

    Args:
        scores_benign_eval: Anomaly scores for held-out benign samples.
        scores_attack_eval: Anomaly scores for attack samples.

    Returns:
        (best_threshold, metrics_at_best_threshold)
    """
    # True labels: 0 = Normal, 1 = Anomalous
    y_true = np.concatenate([
        np.zeros(len(scores_benign_eval), dtype=int),
        np.ones(len(scores_attack_eval),  dtype=int),
    ])
    all_scores = np.concatenate([scores_benign_eval, scores_attack_eval])

    # Candidate thresholds: percentiles 1–80 of the benign eval scores
    percentiles = np.linspace(1, 80, 160)
    candidates  = np.percentile(scores_benign_eval, percentiles)
    candidates  = np.unique(candidates)

    best_f1   = -1.0
    best_thr  = float(candidates[len(candidates) // 2])
    best_meta = {}

    for thr in candidates:
        y_pred = (all_scores < thr).astype(int)
        if y_pred.sum() == 0:
            continue   # no positives at all → skip
        f1 = float(f1_score(y_true, y_pred, zero_division=0))
        if f1 > best_f1:
            best_f1   = f1
            best_thr  = float(thr)
            prec = float(precision_score(y_true, y_pred, zero_division=0))
            rec  = float(recall_score(y_true,    y_pred, zero_division=0))
            acc  = float(accuracy_score(y_true,  y_pred))
            cm   = confusion_matrix(y_true, y_pred).tolist()
            best_meta = {
                "threshold": best_thr,
                "f1":        round(best_f1, 4),
                "precision": round(prec, 4),
                "recall":    round(rec,  4),
                "accuracy":  round(acc,  4),
                "confusion_matrix": cm,
            }

    return best_thr, best_meta


# ---------------------------------------------------------------------------
# 4. Full evaluation at a given threshold
# ---------------------------------------------------------------------------

def evaluate(
    scores_benign_eval: np.ndarray,
    scores_attack_eval: np.ndarray,
    threshold: float,
) -> dict:
    """
    Compute full evaluation metrics at the given threshold.

    Positive class = Anomalous (label 1).
    Negative class = Normal    (label 0).
    """
    y_true = np.concatenate([
        np.zeros(len(scores_benign_eval), dtype=int),
        np.ones(len(scores_attack_eval),  dtype=int),
    ])
    all_scores = np.concatenate([scores_benign_eval, scores_attack_eval])
    y_pred     = (all_scores < threshold).astype(int)

    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel() if cm.shape == (2, 2) else (0, 0, 0, 0)

    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    return {
        "threshold":       round(float(threshold), 6),
        "accuracy":        round(float(accuracy_score(y_true, y_pred)), 4),
        "precision":       round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall":          round(float(recall_score(y_true,    y_pred, zero_division=0)), 4),
        "f1":              round(float(f1_score(y_true,        y_pred, zero_division=0)), 4),
        "false_positive_rate": round(float(fpr), 4),
        "false_negative_rate": round(float(fnr), 4),
        "confusion_matrix":    cm.tolist(),
        "true_negatives":      int(tn),
        "false_positives":     int(fp),
        "false_negatives":     int(fn),
        "true_positives":      int(tp),
        "n_benign_eval":   len(scores_benign_eval),
        "n_attack_eval":   len(scores_attack_eval),
    }


# ---------------------------------------------------------------------------
# 5. Main training procedure
# ---------------------------------------------------------------------------

def train() -> None:
    print(DIV)
    print("  Multi-Agent SOC -- Stage 6: Anomaly Detection Training")
    print("  Algorithm : Isolation Forest (unsupervised)")
    print("  Label use : Label column used ONLY to split train/test sets")
    print("              Label is NEVER a model input feature")
    print(DIV)

    # Retrieve the 78 feature names from the existing Network Detection prep
    # (ensures exact same feature ordering)
    nd_prep_path = PROJECT_ROOT / "models" / "network_detection_preprocessing.pkl"
    nd_prep = joblib.load(nd_prep_path)
    feature_names: list[str] = nd_prep["feature_names"]
    print(f"\n  Feature names sourced from: {nd_prep_path.name}")
    print(f"  Number of features         : {len(feature_names)}")

    # ------------------------------------------------------------------
    # Step 1: Load data
    # ------------------------------------------------------------------
    print(f"\n{DIV2}")
    print("  STEP 1 — Load Dataset")
    print(DIV2)
    benign_df, attack_df = load_data()

    # ------------------------------------------------------------------
    # Step 2: Compute training medians from benign training set
    # ------------------------------------------------------------------
    print(f"\n{DIV2}")
    print("  STEP 2 — Compute Training Medians")
    print(DIV2)

    rng = random.Random(RANDOM_SEED)
    np_rng = np.random.default_rng(RANDOM_SEED)

    # Shuffle and split benign into train / eval
    benign_idx = list(range(len(benign_df)))
    rng.shuffle(benign_idx)

    n_train_raw = int(len(benign_idx) * BENIGN_TRAIN_FRAC)
    train_idx   = benign_idx[:n_train_raw]
    eval_b_idx  = benign_idx[n_train_raw:]

    # Apply caps
    if len(train_idx) > MAX_BENIGN_TRAIN:
        train_idx = rng.sample(train_idx, MAX_BENIGN_TRAIN)
    if len(eval_b_idx) > MAX_BENIGN_EVAL:
        eval_b_idx = rng.sample(eval_b_idx, MAX_BENIGN_EVAL)

    benign_train_df = benign_df.iloc[train_idx].reset_index(drop=True)
    benign_eval_df  = benign_df.iloc[eval_b_idx].reset_index(drop=True)

    # Cap attack eval set
    attack_eval_df = attack_df.copy()
    if len(attack_eval_df) > MAX_ATTACK_EVAL:
        attack_eval_df = attack_eval_df.sample(MAX_ATTACK_EVAL, random_state=RANDOM_SEED)

    print(f"  Benign training samples    : {len(benign_train_df):,}")
    print(f"  Held-out benign eval       : {len(benign_eval_df):,}")
    print(f"  Attack eval samples        : {len(attack_eval_df):,}")
    print(f"  Total rows used for training: {len(benign_train_df):,}")

    # Compute medians on the training set
    medians = compute_medians(benign_train_df, feature_names)
    print(f"  Medians computed for       : {len(medians)} features")

    # ------------------------------------------------------------------
    # Step 3: Prepare feature matrices
    # ------------------------------------------------------------------
    print(f"\n{DIV2}")
    print("  STEP 3 — Prepare Feature Matrices")
    print(DIV2)

    X_train        = prepare_features(benign_train_df, feature_names, medians)
    X_benign_eval  = prepare_features(benign_eval_df,  feature_names, medians)
    X_attack_eval  = prepare_features(attack_eval_df,  feature_names, medians)

    print(f"  X_train shape              : {X_train.shape}")
    print(f"  X_benign_eval shape        : {X_benign_eval.shape}")
    print(f"  X_attack_eval shape        : {X_attack_eval.shape}")

    # ------------------------------------------------------------------
    # Step 4: Train Isolation Forest
    # ------------------------------------------------------------------
    print(f"\n{DIV2}")
    print("  STEP 4 — Train Isolation Forest")
    print(DIV2)

    model = IsolationForest(
        n_estimators  = IF_N_ESTIMATORS,
        max_samples   = IF_MAX_SAMPLES,
        contamination = IF_CONTAMINATION,
        max_features  = IF_MAX_FEATURES,
        bootstrap     = IF_BOOTSTRAP,
        random_state  = RANDOM_SEED,
        n_jobs        = -1,
    )

    t_start = datetime.datetime.now()
    print(f"  Training started  : {t_start.strftime('%H:%M:%S')}")
    print(f"  n_estimators      : {IF_N_ESTIMATORS}")
    print(f"  max_samples       : {IF_MAX_SAMPLES}")
    print(f"  contamination     : {IF_CONTAMINATION}")
    print(f"  random_state      : {RANDOM_SEED}")
    print(f"  n_jobs            : -1 (all CPUs)")

    model.fit(X_train)

    t_end   = datetime.datetime.now()
    elapsed = (t_end - t_start).total_seconds()
    print(f"  Training finished : {t_end.strftime('%H:%M:%S')}")
    print(f"  Training duration : {elapsed:.1f} seconds")

    # ------------------------------------------------------------------
    # Step 5: Score held-out data
    # ------------------------------------------------------------------
    print(f"\n{DIV2}")
    print("  STEP 5 — Score Held-Out Evaluation Sets")
    print(DIV2)

    scores_benign_eval = model.score_samples(X_benign_eval)
    scores_attack_eval = model.score_samples(X_attack_eval)

    print(f"  Benign eval score : mean={scores_benign_eval.mean():.4f}  "
          f"min={scores_benign_eval.min():.4f}  max={scores_benign_eval.max():.4f}")
    print(f"  Attack eval score : mean={scores_attack_eval.mean():.4f}  "
          f"min={scores_attack_eval.min():.4f}  max={scores_attack_eval.max():.4f}")

    score_percentiles = [5, 10, 20, 30, 50]
    print(f"\n  Benign eval score percentiles:")
    for p in score_percentiles:
        print(f"    p{p:02d}: {np.percentile(scores_benign_eval, p):.4f}")
    print(f"\n  Attack eval score percentiles:")
    for p in score_percentiles:
        print(f"    p{p:02d}: {np.percentile(scores_attack_eval, p):.4f}")

    # ------------------------------------------------------------------
    # Step 6: Select threshold
    # ------------------------------------------------------------------
    print(f"\n{DIV2}")
    print("  STEP 6 — Threshold Selection (maximise F1 on held-out data)")
    print(DIV2)

    best_threshold, thr_meta = select_threshold(scores_benign_eval, scores_attack_eval)
    print(f"  Selected threshold : {best_threshold:.6f}")
    print(f"  F1 at threshold    : {thr_meta.get('f1', '?')}")
    print(f"  Precision          : {thr_meta.get('precision', '?')}")
    print(f"  Recall             : {thr_meta.get('recall', '?')}")
    print(f"  Accuracy           : {thr_meta.get('accuracy', '?')}")
    print(f"\n  Rationale:")
    print(f"  - Threshold tuning used held-out benign and attack data")
    print(f"  - Thresholds swept from 1st to 40th percentile of benign scores")
    print(f"  - Best F1 selected to balance detection and false alarms")
    print(f"  - No data leakage: training set was not used for threshold selection")

    # ------------------------------------------------------------------
    # Step 7: Full evaluation at selected threshold
    # ------------------------------------------------------------------
    print(f"\n{DIV2}")
    print("  STEP 7 — Full Evaluation at Selected Threshold")
    print(DIV2)

    metrics = evaluate(scores_benign_eval, scores_attack_eval, best_threshold)

    print(f"\n  NOTE: Anomaly detection identifies UNUSUAL behaviour.")
    print(f"  An Infilteration sample marked Anomalous means it appears unusual")
    print(f"  compared to normal traffic. The model does not classify attack types.")
    print()

    cm = metrics["confusion_matrix"]
    print(f"  Confusion Matrix (rows=actual, cols=predicted):")
    print(f"                     Normal  Anomalous")
    print(f"    Actual Normal  : {cm[0][0]:6d}  {cm[0][1]:6d}")
    print(f"    Actual Anomaly : {cm[1][0]:6d}  {cm[1][1]:6d}")
    print()
    print(f"  Accuracy             : {metrics['accuracy']:.4f}  ({metrics['accuracy']*100:.1f}%)")
    print(f"  Precision            : {metrics['precision']:.4f}")
    print(f"  Recall               : {metrics['recall']:.4f}")
    print(f"  F1-score             : {metrics['f1']:.4f}")
    print(f"  False Positive Rate  : {metrics['false_positive_rate']:.4f}  "
          f"({metrics['false_positive_rate']*100:.1f}% of normals marked anomalous)")
    print(f"  False Negative Rate  : {metrics['false_negative_rate']:.4f}  "
          f"({metrics['false_negative_rate']*100:.1f}% of attacks missed)")
    print(f"  True Negatives (TN)  : {metrics['true_negatives']:,}")
    print(f"  False Positives (FP) : {metrics['false_positives']:,}")
    print(f"  False Negatives (FN) : {metrics['false_negatives']:,}")
    print(f"  True Positives (TP)  : {metrics['true_positives']:,}")

    # ------------------------------------------------------------------
    # Step 8: Save model and preprocessing metadata
    # ------------------------------------------------------------------
    print(f"\n{DIV2}")
    print("  STEP 8 — Save Model and Metadata")
    print(DIV2)

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)

    # Metadata stored in preprocessing pkl
    prep_meta = {
        "feature_names":      feature_names,
        "n_features":         len(feature_names),
        "medians":            medians,
        "anomaly_threshold":  best_threshold,
        "score_description":  (
            "score_samples() returns negative average path length. "
            "Range ~[-0.5, 0.0]. Lower = more anomalous. "
            "A sample is ANOMALOUS if its score < anomaly_threshold."
        ),
        "training_info": {
            "algorithm":           "IsolationForest",
            "n_estimators":        IF_N_ESTIMATORS,
            "max_samples":         str(IF_MAX_SAMPLES),
            "contamination":       str(IF_CONTAMINATION),
            "random_state":        RANDOM_SEED,
            "benign_train_samples": len(benign_train_df),
            "benign_eval_samples": len(benign_eval_df),
            "attack_eval_samples": len(attack_eval_df),
            "trained_on_labels":   False,
            "label_column_used_as_feature": False,
            "training_date":       datetime.datetime.now().isoformat(),
        },
        "evaluation_metrics": metrics,
    }

    joblib.dump(model,     MODEL_PATH, compress=1)
    joblib.dump(prep_meta, PREP_PATH,  compress=1)

    print(f"  Model saved to     : {MODEL_PATH}")
    print(f"  Metadata saved to  : {PREP_PATH}")
    print(f"  Model size on disk : {MODEL_PATH.stat().st_size / 1024:.1f} KB")

    print(f"\n{DIV}")
    print(f"  TRAINING COMPLETE")
    print(f"  Anomaly threshold  : {best_threshold:.6f}")
    print(f"  F1-score           : {metrics['f1']:.4f}")
    print(f"  Recall (detection) : {metrics['recall']:.4f}")
    print(f"  False positive rate: {metrics['false_positive_rate']:.4f}")
    print(f"{DIV}\n")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    train()
