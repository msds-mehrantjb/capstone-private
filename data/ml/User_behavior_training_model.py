import os
import joblib
import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import LabelEncoder
from sklearn.impute import SimpleImputer
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.ensemble import RandomForestClassifier

# =========================
# 1. Load Dataset
# =========================
DATA_PATH = "./user_behavior_training_dataset.parquet"
TARGET_COLUMN = "risk_level"

df = pd.read_parquet(DATA_PATH)

# =========================
# 2. Use ONLY required features
# =========================
feature_columns = [
    "failedLoginAttempts",
    "accessFrequency",
    "loginConsistency",
    "passwordResets",
    "sessionDuration"
]

required_columns = feature_columns + [TARGET_COLUMN]

df = df[required_columns].copy()

# =========================
# 3. Convert numeric
# =========================
for col in feature_columns:
    df[col] = pd.to_numeric(df[col], errors="coerce")

# =========================
# 4. Define X and y
# =========================
X = df[feature_columns].copy()
y = df[TARGET_COLUMN].copy()

# =========================
# 5. Encode target
# =========================
label_encoder = LabelEncoder()
y_encoded = label_encoder.fit_transform(y)

print("Target classes:", list(label_encoder.classes_))

# =========================
# 6. Train/Test Split
# =========================
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y_encoded,
    test_size=0.2,
    random_state=42,
    stratify=y_encoded
)

# =========================
# 7. Preprocessing
# =========================
preprocessor = ColumnTransformer([
    ("num", SimpleImputer(strategy="median"), feature_columns)
])

# =========================
# 8. Model (FINAL)
# =========================
model = RandomForestClassifier(
    n_estimators=400,
    max_depth=10,
    random_state=42,
    n_jobs=-1
)

# =========================
# 9. Pipeline
# =========================
pipeline = Pipeline([
    ("preprocessor", preprocessor),
    ("model", model)
])

# =========================
# 10. Train
# =========================
pipeline.fit(X_train, y_train)

# =========================
# 11. Evaluate
# =========================
y_pred = pipeline.predict(X_test)
y_proba = pipeline.predict_proba(X_test)

print("\nClassification Report:\n")
print(classification_report(y_test, y_pred, target_names=label_encoder.classes_))

print("Confusion Matrix:")
print(confusion_matrix(y_test, y_pred))

print(f"\nAccuracy: {accuracy_score(y_test, y_pred):.4f}")

# =========================
# 12. Probabilities
# =========================
predicted_labels = label_encoder.inverse_transform(y_pred)
ml_probability = y_proba.max(axis=1)

prob_df = pd.DataFrame(
    y_proba,
    columns=[f"prob_{cls}" for cls in label_encoder.classes_]
)

prob_df["predicted_risk_level"] = predicted_labels
prob_df["ml_probability"] = ml_probability

print("\nSample Predictions:")
print(prob_df.head())

# =========================
# 13. Feature Importance
# =========================
importances = pipeline.named_steps["model"].feature_importances_

importance_df = pd.DataFrame({
    "feature": feature_columns,
    "importance": importances
}).sort_values(by="importance", ascending=False)

print("\nFeature Importance:")
print(importance_df)

# =========================
# 14. Save Model
# =========================
MODEL_DIR = "./models"
os.makedirs(MODEL_DIR, exist_ok=True)

joblib.dump(pipeline, f"{MODEL_DIR}/rf_behavior_model.joblib")
joblib.dump(label_encoder, f"{MODEL_DIR}/label_encoder.joblib")

print("\nModel saved successfully.")

# =========================
# 15. Inference Function
# =========================
def predict_user_risk(sample_dict):
    sample_df = pd.DataFrame([sample_dict])

    defaults = {
        "failedLoginAttempts": 0,
        "accessFrequency": 0,
        "loginConsistency": 0,
        "passwordResets": 0,
        "sessionDuration": 0
    }

    for col in feature_columns:
        if col not in sample_df.columns:
            sample_df[col] = defaults[col]
        sample_df[col] = pd.to_numeric(sample_df[col], errors="coerce")

    pred_encoded = pipeline.predict(sample_df)[0]
    pred_label = label_encoder.inverse_transform([pred_encoded])[0]

    probs = pipeline.predict_proba(sample_df)[0]
    ml_prob = float(np.max(probs))

    class_probs = {
        cls: float(prob)
        for cls, prob in zip(label_encoder.classes_, probs)
    }

    return {
        "predicted_risk_level": pred_label,
        "ml_probability": ml_prob,
        "class_probabilities": class_probs
    }

# =========================
# 16. Example Prediction
# =========================
example_user = {
    "failedLoginAttempts": 2,
    "accessFrequency": 5,
    "loginConsistency": 3,
    "passwordResets": 1,
    "sessionDuration": 3600
}

print("\nExample prediction:")
print(predict_user_risk(example_user))