import argparse
import pathlib
import pandas as pd

_PROJECT_ROOT = pathlib.Path(__file__).resolve().parent

parser = argparse.ArgumentParser(description="Clean raw CICFlowMeter CSV for model training")
parser.add_argument(
    "--input",
    default=str(_PROJECT_ROOT / "data" / "processed" / "Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv"),
    help="Path to raw input CSV (default: data/processed/<CIC-filename>.csv)",
)
parser.add_argument(
    "--output",
    default=str(_PROJECT_ROOT / "data" / "processed" / "cleaned_dataset.csv"),
    help="Path to write cleaned CSV (default: data/processed/cleaned_dataset.csv)",
)
args = parser.parse_args()

input_file = pathlib.Path(args.input)
output_file = pathlib.Path(args.output)

print("Loading dataset...")

df = pd.read_csv(input_file, low_memory=False)

print("Original shape:", df.shape)

# Remove repeated header rows
df = df[df["Label"] != "Label"].copy()

# Timestamp is not used for the first ML model
df = df.drop(columns=["Timestamp"])

# Separate features and label
feature_columns = [col for col in df.columns if col != "Label"]

# Convert feature columns to numeric
for col in feature_columns:
    df[col] = pd.to_numeric(df[col], errors="coerce")

# Replace infinite values with NaN
df = df.replace([float("inf"), float("-inf")], pd.NA)

# Fill missing numerical values with median
for col in feature_columns:
    if df[col].isna().any():
        median_value = df[col].median()

        if pd.notna(median_value):
            df[col] = df[col].fillna(median_value)
        else:
            # If the entire column is empty, remove it
            df = df.drop(columns=[col])

print("Cleaned shape:", df.shape)

print("\nLabel distribution:")
print(df["Label"].value_counts())

print("\nTotal missing values:", df.isnull().sum().sum())

# Save cleaned dataset
df.to_csv(output_file, index=False)

print("\nCleaned dataset saved at:")
print(output_file)
