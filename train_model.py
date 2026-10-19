import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib

# Dataset
input_file = r"E:\multi-agent-soc\data\processed\cleaned_dataset.csv"

# Model output
model_file = r"E:\multi-agent-soc\models\network_detection_model.pkl"

print("Loading dataset...")

df = pd.read_csv(input_file, low_memory=False)

print("Dataset shape:", df.shape)

# Separate features and target
X = df.drop(columns=["Label"])
y = df["Label"]

print("\nFeatures:", X.shape[1])
print("Samples:", X.shape[0])

print("\nLabels:")
print(y.value_counts())

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("\nTraining samples:", X_train.shape[0])
print("Testing samples:", X_test.shape[0])

# Create Random Forest
print("\nTraining Random Forest...")

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)

model.fit(X_train, y_train)

print("Training completed!")

# Predictions
y_pred = model.predict(X_test)

# Evaluation
accuracy = accuracy_score(y_test, y_pred)

print("\nAccuracy:", accuracy)

print("\nClassification Report:")
print(classification_report(y_test, y_pred))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# Save model
joblib.dump(model, model_file)

print("\nModel saved to:")
print(model_file)
