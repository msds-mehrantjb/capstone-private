import pandas as pd
from pathlib import Path

# ---------------------------------------------------
# Paths
# ---------------------------------------------------

DATA_DIR = Path("data/ml")

SERVER_CSV = "server_role_training_dataset.csv"
WORKSTATION_CSV = "workstation_role_training_dataset.csv"

SERVER_PARQUET = "server_role_training_dataset.parquet"
WORKSTATION_PARQUET = "workstation_role_training_dataset.parquet"


# ---------------------------------------------------
# Convert CSV → Parquet
# ---------------------------------------------------

def convert_csv_to_parquet(csv_path, parquet_path):
    print(f"Loading {csv_path} ...")

    df = pd.read_csv(csv_path)

    print(f"Rows: {len(df)}  |  Columns: {len(df.columns)}")

    df.to_parquet(
        parquet_path,
        engine="pyarrow",
        compression="snappy",
        index=False
    )

    print(f"Saved parquet → {parquet_path}\n")


# ---------------------------------------------------
# Main
# ---------------------------------------------------

def main():

    convert_csv_to_parquet(
        SERVER_CSV,
        SERVER_PARQUET
    )

    convert_csv_to_parquet(
        WORKSTATION_CSV,
        WORKSTATION_PARQUET
    )

    print("Conversion complete.")


if __name__ == "__main__":
    main()