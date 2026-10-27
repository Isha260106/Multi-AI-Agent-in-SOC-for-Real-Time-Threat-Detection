"""
Build Preprocessing Metadata
==============================
One-time script — run ONCE to extract:
  - Exact 78 feature names (in training order)
  - Per-feature training-set medians (for NaN imputation at inference time)

This does NOT retrain the model.
This only reads the cleaned dataset to extract median values
that were computed during training (clean_dataset.py used the full dataset median).

Output:
  <project_root>/models/network_detection_preprocessing.pkl

Fields saved:
  {
      "feature_names" : [list of 78 feature names in order],
      "medians"       : {feature_name: median_value, ...},
      "n_features"    : 78
  }
"""

import sys
import pathlib
import joblib
import pandas as pd

_PROJECT_ROOT = pathlib.Path(__file__).resolve().parent
DATASET    = _PROJECT_ROOT / "data" / "processed" / "cleaned_dataset.csv"
MODEL_FILE = _PROJECT_ROOT / "models" / "network_detection_model.pkl"
OUT_FILE   = _PROJECT_ROOT / "models" / "network_detection_preprocessing.pkl"
TARGET_COL = "Label"

print("Loading cleaned dataset...")
if not DATASET.exists():
    print(f"ERROR: Dataset not found at {DATASET}")
    sys.exit(1)

df = pd.read_csv(DATASET, low_memory=False)
print(f"Dataset shape: {df.shape}")

# Feature columns in exact training order
feature_names = [c for c in df.columns if c != TARGET_COL]
X = df[feature_names]

print(f"Number of features: {len(feature_names)}")

# Load model to verify feature count matches
print("Loading model for verification...")
if not MODEL_FILE.exists():
    print(f"ERROR: Model not found at {MODEL_FILE}")
    sys.exit(1)

model = joblib.load(MODEL_FILE)
n_model_features = len(model.feature_importances_)

if len(feature_names) != n_model_features:
    print(
        f"ERROR: Feature count mismatch!\n"
        f"  Dataset: {len(feature_names)} features\n"
        f"  Model  : {n_model_features} features"
    )
    sys.exit(1)

print(f"Feature count verified: {len(feature_names)} == {n_model_features} (OK)")

# Compute medians from the training dataset (reproduces what clean_dataset.py did)
print("Computing per-feature medians from training dataset...")
medians = {}
for col in feature_names:
    medians[col] = float(X[col].median())

# Build and save the preprocessing metadata
metadata = {
    "feature_names": feature_names,
    "medians":       medians,
    "n_features":    len(feature_names),
}

joblib.dump(metadata, OUT_FILE)
print(f"\nPreprocessing metadata saved to:\n  {OUT_FILE}")
print(f"  Features : {metadata['n_features']}")
print(f"  Sample medians:")
for feat in feature_names[:5]:
    print(f"    {feat}: {medians[feat]}")
print("  ...")
print("\nDone.")
