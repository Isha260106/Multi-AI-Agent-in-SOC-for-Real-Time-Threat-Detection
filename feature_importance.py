"""
Feature Importance Analysis
============================
Multi-Agent SOC Project — Network Monitoring & Detection Agent

Loads the trained Random Forest baseline model and the cleaned dataset,
extracts feature importances, validates results, saves a CSV and a PNG plot.

DO NOT modify, retrain, or overwrite the trained model.
This script is READ-ONLY with respect to the model.
"""

import sys
import pathlib

import numpy as np
import pandas as pd
import joblib
import matplotlib
matplotlib.use("Agg")          # non-interactive backend — no popup window
import matplotlib.pyplot as plt

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR   = pathlib.Path(__file__).resolve().parent
DATASET    = BASE_DIR / "data" / "processed" / "cleaned_dataset.csv"
MODEL_FILE = BASE_DIR / "models" / "network_detection_model.pkl"
MODELS_DIR = BASE_DIR / "models"
CSV_OUT    = MODELS_DIR / "feature_importance.csv"
PNG_OUT    = MODELS_DIR / "feature_importance_top20.png"

TARGET_COL = "Label"

# ---------------------------------------------------------------------------
# Ensure output directory exists
# ---------------------------------------------------------------------------
MODELS_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# 1. Load Dataset
# ---------------------------------------------------------------------------
print("Loading dataset...")
if not DATASET.exists():
    print(f"ERROR: Dataset not found at {DATASET}")
    sys.exit(1)

df = pd.read_csv(DATASET, low_memory=False)
print("Dataset loaded successfully.")
print(f"\nDataset shape: {df.shape}")

# ---------------------------------------------------------------------------
# 2. Validate Label column
# ---------------------------------------------------------------------------
if TARGET_COL not in df.columns:
    print(f"ERROR: Target column '{TARGET_COL}' not found in dataset.")
    sys.exit(1)

X = df.drop(columns=[TARGET_COL])
y = df[TARGET_COL]

# ---------------------------------------------------------------------------
# 3. Load Model
# ---------------------------------------------------------------------------
print("\nLoading model...")
if not MODEL_FILE.exists():
    print(f"ERROR: Model file not found at {MODEL_FILE}")
    sys.exit(1)

model = joblib.load(MODEL_FILE)
print("Model loaded successfully.")

# ---------------------------------------------------------------------------
# 4. Validation Checks
# ---------------------------------------------------------------------------
n_dataset_features   = X.shape[1]
n_model_importances  = len(model.feature_importances_)
missing_values       = int(X.isnull().sum().sum())
non_numeric_cols     = [c for c in X.columns if not pd.api.types.is_numeric_dtype(X[c])]
importance_has_nan   = bool(np.isnan(model.feature_importances_).any())
importance_negative  = bool((model.feature_importances_ < 0).any())
importance_sum       = float(model.feature_importances_.sum())

print(f"\nNumber of features: {n_dataset_features}")
print(f"Number of model importance values: {n_model_importances}")

# Critical check — feature count must match
if n_dataset_features != n_model_importances:
    print(
        f"\nERROR: Feature count mismatch!\n"
        f"  Dataset features : {n_dataset_features}\n"
        f"  Model importances: {n_model_importances}\n"
        "The column order of the CSV may not match how the model was trained."
    )
    sys.exit(1)

print("\nValidation:")
print(f"  Model loaded              : YES")
print(f"  Dataset loaded            : YES")
print(f"  Label column found        : YES")
print(f"  Feature count             : {n_dataset_features}")
print(f"  Missing values in X       : {missing_values}")

if non_numeric_cols:
    print(f"  WARNING - Non-numeric cols: {non_numeric_cols}")
else:
    print(f"  All X columns numeric     : YES")

importance_valid = (not importance_has_nan) and (not importance_negative)
print(f"  Importance values valid   : {'YES' if importance_valid else 'NO (check warnings)'}")
print(f"  Importance sum            : {importance_sum:.4f}")

if not importance_valid:
    print("ERROR: Feature importance values contain NaN or negative values. Stopping.")
    sys.exit(1)

if not (0.9999 <= importance_sum <= 1.0001):
    print(
        f"WARNING: Importance values sum to {importance_sum:.6f} (expected ~1.0). "
        "Proceeding, but please investigate."
    )

# ---------------------------------------------------------------------------
# 5. Build Feature Importance DataFrame
# ---------------------------------------------------------------------------
fi_df = pd.DataFrame({
    "Feature"   : X.columns,
    "Importance": model.feature_importances_
}).sort_values("Importance", ascending=False).reset_index(drop=True)

# ---------------------------------------------------------------------------
# 6. Print Top 20
# ---------------------------------------------------------------------------
top20 = fi_df.head(20)

print("\nTop 20 Important Features:")
print(f"\n{'Feature':<45} {'Importance':>12}")
print("-" * 58)
for _, row in top20.iterrows():
    print(f"{row['Feature']:<45} {row['Importance']:>12.5f}")

# ---------------------------------------------------------------------------
# 7. Save CSV — all 78 features
# ---------------------------------------------------------------------------
fi_df.to_csv(CSV_OUT, index=False)
print(f"\nFeature importance CSV saved to:\n  {CSV_OUT}")
print(f"  ({len(fi_df)} features, columns: Feature, Importance)")

# ---------------------------------------------------------------------------
# 8. Visualization — horizontal bar chart, top 20
# ---------------------------------------------------------------------------
plot_df = top20.sort_values("Importance", ascending=True)   # ascending for horizontal bar

fig, ax = plt.subplots(figsize=(12, 8))

bars = ax.barh(
    plot_df["Feature"],
    plot_df["Importance"],
    color=plt.cm.viridis(np.linspace(0.25, 0.85, len(plot_df))),
    edgecolor="white",
    linewidth=0.5
)

# Value labels on bars
for bar, val in zip(bars, plot_df["Importance"]):
    ax.text(
        bar.get_width() + 0.0003,
        bar.get_y() + bar.get_height() / 2,
        f"{val:.4f}",
        va="center",
        ha="left",
        fontsize=8,
        color="#333333"
    )

ax.set_xlabel("Feature Importance (Mean Decrease in Impurity)", fontsize=11)
ax.set_ylabel("Feature", fontsize=11)
ax.set_title("Top 20 Random Forest Feature Importances", fontsize=14, fontweight="bold", pad=14)
ax.tick_params(axis="y", labelsize=9)
ax.tick_params(axis="x", labelsize=9)

# Light grid on x-axis only
ax.xaxis.grid(True, linestyle="--", alpha=0.6)
ax.set_axisbelow(True)
ax.spines["top"].set_visible(False)
ax.spines["right"].set_visible(False)

# Subtitle annotation
ax.annotate(
    "Baseline Random Forest — Network Monitoring & Detection Agent | CIC-IDS 2018",
    xy=(0.5, -0.10),
    xycoords="axes fraction",
    ha="center",
    fontsize=8,
    color="gray"
)

plt.tight_layout()
fig.savefig(PNG_OUT, dpi=150, bbox_inches="tight")
plt.close(fig)

print(f"\nFeature importance plot saved to:\n  {PNG_OUT}")

# ---------------------------------------------------------------------------
# 9. Done
# ---------------------------------------------------------------------------
print("\nFeature importance analysis completed successfully.")
print("\nFiles created:")
print(f"  {CSV_OUT}")
print(f"  {PNG_OUT}")
