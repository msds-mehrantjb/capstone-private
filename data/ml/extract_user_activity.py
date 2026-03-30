import json
import pandas as pd
from pathlib import Path

# -----------------------------
# Paths
# -----------------------------
BASE_PATH = Path(".")
INPUT_FILE = BASE_PATH / "user_activity_data_orig.json"
OUTPUT_FILE = BASE_PATH / "user_behavior_training_dataset.parquet"

# -----------------------------
# Config
# -----------------------------
TARGET_COLUMN = "risk_level"

required_columns = [
    "failedLoginAttempts",
    "accessFrequency",
    "loginConsistency",
    "passwordResets",
    "sessionDuration",
    TARGET_COLUMN,
]

# -----------------------------
# Load JSON data
# -----------------------------
with open(INPUT_FILE, "r") as f:
    data = json.load(f)

# -----------------------------
# Helper: Convert HH:MM:SS -> seconds
# -----------------------------
def convert_to_seconds(time_str):
    try:
        h, m, s = map(int, str(time_str).split(":"))
        return h * 3600 + m * 60 + s
    except Exception:
        return 0

# -----------------------------
# Risk labeling function
# -----------------------------
def compute_risk_level(incident_reports):
    if incident_reports == 0:
        return "Low"
    elif incident_reports <= 2:
        return "Medium"
    else:
        return "High"

# -----------------------------
# Extract only required fields
# -----------------------------
records = []

for entry in data:
    incident_reports = entry.get("incidentReports", 0)

    record = {
        "failedLoginAttempts": entry.get("failedLoginAttempts", 0),
        "accessFrequency": entry.get("accessFrequency", 0),
        "loginConsistency": entry.get("loginConsistency", 0),
        "passwordResets": entry.get("passwordResets", 0),
        "sessionDuration": convert_to_seconds(entry.get("sessionDuration", "0:0:0")),
        TARGET_COLUMN: compute_risk_level(incident_reports),
    }

    records.append(record)

# -----------------------------
# Create DataFrame
# -----------------------------
df = pd.DataFrame(records)

# -----------------------------
# Keep only required columns
# -----------------------------
df = df[required_columns].copy()

# -----------------------------
# Convert numeric columns
# -----------------------------
numeric_columns = [
    "failedLoginAttempts",
    "accessFrequency",
    "loginConsistency",
    "passwordResets",
    "sessionDuration",
]

for col in numeric_columns:
    df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

# -----------------------------
# Save as Parquet
# -----------------------------
df.to_parquet(OUTPUT_FILE, index=False)

print(f"✅ Dataset saved to: {OUTPUT_FILE}")
print("Columns:", df.columns.tolist())
print(df.head())