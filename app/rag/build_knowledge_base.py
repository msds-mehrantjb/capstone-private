from pathlib import Path
import json
import hashlib
import pandas as pd
import chromadb
from sentence_transformers import SentenceTransformer

BASE_DIR = Path(__file__).resolve().parents[2]
DOCS_DIR = BASE_DIR / "data" / "knowledge_base"
CHROMA_DIR = BASE_DIR / "app" / "chroma_db"
HASH_FILE = BASE_DIR / "app" / "rag" / "dataset_hashes.json"

EMBED_MODEL = "all-MiniLM-L6-v2"
COLLECTION_NAME = "iso27001_knowledge"

DATASET_FILES = [
    "windows_software-categorized.csv",
    "workstation_role_detection_indicators.csv",
    "nist_cia_server_roles_dataset.csv",
    "workstation_cia_dataset.csv",
]


def clean_value(val):
    if pd.isna(val):
        return ""
    return str(val).strip()


def file_hash(path: Path) -> str:
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(8192):
            sha.update(chunk)
    return sha.hexdigest()


def ensure_hash_file_exists() -> None:
    HASH_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not HASH_FILE.exists():
        initial = {name: "" for name in DATASET_FILES}
        HASH_FILE.write_text(json.dumps(initial, indent=2), encoding="utf-8")


def load_saved_hashes() -> dict:
    ensure_hash_file_exists()
    try:
        data = json.loads(HASH_FILE.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {name: "" for name in DATASET_FILES}
        return {name: str(data.get(name, "")) for name in DATASET_FILES}
    except Exception:
        return {name: "" for name in DATASET_FILES}


def compute_current_hashes() -> dict:
    hashes = {}
    for name in DATASET_FILES:
        csv_path = DOCS_DIR / name
        if not csv_path.exists():
            raise FileNotFoundError(f"Missing dataset file: {csv_path}")
        hashes[name] = file_hash(csv_path)
    return hashes


def save_hashes(hashes: dict) -> None:
    HASH_FILE.write_text(json.dumps(hashes, indent=2), encoding="utf-8")


def row_to_doc(source_name: str, row: pd.Series, idx: int):
    row_dict = {k: clean_value(v) for k, v in row.to_dict().items()}

    if source_name == "windows_software-categorized":
        software = row_dict.get("software_name", "") or row_dict.get("software", "")
        category = row_dict.get("category", "")
        vendor = row_dict.get("vendor", "")
        document = (
            f"Software '{software}' is categorized as '{category}'. "
            f"Vendor: '{vendor}'. "
            f"This software may help identify host function, user activity, or operational role."
        )
        metadata = {
            "source": source_name,
            "type": "software_category",
            "software_name": software,
            "category": category,
            "vendor": vendor,
        }

    elif source_name == "workstation_role_detection_indicators":
        workstation_role = row_dict.get("workstation_role", "") or row_dict.get("role", "")
        indicator_type = row_dict.get("indicator_type", "")
        indicator_value = row_dict.get("indicator_value", "") or row_dict.get("indicator", "")
        document = (
            f"Indicator '{indicator_value}' of type '{indicator_type}' suggests the workstation role "
            f"'{workstation_role}'."
        )
        metadata = {
            "source": source_name,
            "type": "workstation_indicator",
            "workstation_role": workstation_role,
            "indicator_type": indicator_type,
            "indicator_value": indicator_value,
        }

    elif source_name == "nist_cia_server_roles_dataset":
        role = row_dict.get("role", "") or row_dict.get("server_role", "")
        c = row_dict.get("confidentiality", "")
        i = row_dict.get("integrity", "")
        a = row_dict.get("availability", "")
        document = (
            f"Server role '{role}' has CIA ratings: "
            f"Confidentiality='{c}', Integrity='{i}', Availability='{a}'."
        )
        metadata = {
            "source": source_name,
            "type": "server_cia",
            "role": role,
            "confidentiality": c,
            "integrity": i,
            "availability": a,
        }

    elif source_name == "workstation_cia_dataset":
        role = row_dict.get("workstation_role", "") or row_dict.get("role", "")
        c = row_dict.get("confidentiality", "")
        i = row_dict.get("integrity", "")
        a = row_dict.get("availability", "")
        document = (
            f"Workstation role '{role}' has CIA ratings: "
            f"Confidentiality='{c}', Integrity='{i}', Availability='{a}'."
        )
        metadata = {
            "source": source_name,
            "type": "workstation_cia",
            "workstation_role": role,
            "confidentiality": c,
            "integrity": i,
            "availability": a,
        }

    else:
        document = " | ".join([f"{k}: {v}" for k, v in row_dict.items() if v])
        metadata = {"source": source_name, "type": "generic"}

    doc_id = f"{source_name}_{idx}"
    return doc_id, document, metadata


def ingest_csv(collection, embedder, csv_path: Path, batch_size: int = 5000) -> int:
    source_name = csv_path.stem
    df = pd.read_csv(csv_path)

    if df.empty:
        return 0

    total_rows = len(df)

    for start in range(0, total_rows, batch_size):
        end = min(start + batch_size, total_rows)

        batch_ids = []
        batch_docs = []
        batch_metas = []

        for idx in range(start, end):
            row = df.iloc[idx]
            doc_id, document, metadata = row_to_doc(source_name, row, idx)
            batch_ids.append(doc_id)
            batch_docs.append(document)
            batch_metas.append(metadata)

        batch_embeddings = embedder.encode(
            batch_docs,
            show_progress_bar=False
        ).tolist()

        collection.upsert(
            ids=batch_ids,
            documents=batch_docs,
            metadatas=batch_metas,
            embeddings=batch_embeddings,
        )

    return total_rows


def build_knowledge_base():
    client = chromadb.PersistentClient(path=str(CHROMA_DIR))
    embedder = SentenceTransformer(EMBED_MODEL)

    try:
        client.delete_collection(COLLECTION_NAME)
    except Exception:
        pass

    collection = client.create_collection(name=COLLECTION_NAME)

    total_rows = 0
    for name in DATASET_FILES:
        csv_file = DOCS_DIR / name
        total_rows += ingest_csv(collection, embedder, csv_file)

    return total_rows


def rebuild_if_needed():
    saved_hashes = load_saved_hashes()
    current_hashes = compute_current_hashes()

    first_build = any(not saved_hashes.get(name) for name in DATASET_FILES)
    changed = saved_hashes != current_hashes

    if first_build:
        total_rows = build_knowledge_base()
        save_hashes(current_hashes)
        return {
            "success": True,
            "kb_status": "created",
            "rows_embedded": total_rows,
            "message": "Knowledge base was not initialized. ChromaDB knowledge base has been created and dataset_hashes.json has been updated.",
        }

    if changed:
        total_rows = build_knowledge_base()
        save_hashes(current_hashes)
        return {
            "success": True,
            "kb_status": "updated",
            "rows_embedded": total_rows,
            "message": "Dataset changes detected. ChromaDB knowledge base has been rebuilt and dataset_hashes.json has been updated.",
        }

    return {
        "success": True,
        "kb_status": "up_to_date",
        "rows_embedded": 0,
        "message": "Knowledge base is already up to date. No rebuild was needed.",
    }


def main():
    rebuild_if_needed()


if __name__ == "__main__":
    main()