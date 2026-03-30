import os
import re
import math
import json
import pickle
import requests
import pandas as pd
from typing import List, Dict, Set

# =========================================================
# VULNERABILITY_NAME -> CONTROL MAPPING
# =========================================================

# =========================
# PATH FIX (same as first file)
# =========================
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../"))

DATA_DIR = os.path.join(BASE_DIR, "data", "work", "2026")

CSV_FILE = os.path.join(DATA_DIR, "iso27002_controls_2022.csv")
RISK_JSON_FILE = os.path.join(DATA_DIR, "RiskEvaluationTreatment.json")
EMBED_CACHE_FILE = os.path.join(DATA_DIR, "iso27002_local_embeddings2.pkl")
OUTPUT_FILE = os.path.join(DATA_DIR, "vulnerability_name_to_controls.json")
# =========================

OLLAMA_EMBED_URL = "http://localhost:11434/api/embed"
EMBED_MODEL = "nomic-embed-text"
TOP_K = 5

SESSION = requests.Session()

CONTROL_HINTS = {
    "5.15": ["access control", "authorization", "unauthorized access"],
    "5.17": ["authentication", "credentials", "password", "identity"],
    "5.18": ["access rights", "least privilege", "authorized access"],
    "8.2": ["privileged access", "privilege escalation", "admin rights"],
    "8.5": ["secure authentication", "authentication bypass", "logon"],
    "8.8": ["technical vulnerability", "patch", "unpatched", "vulnerability management"],
    "8.9": ["configuration", "hardening", "secure configuration", "misconfiguration"],
    "8.16": ["monitoring", "detection", "anomalous activity", "logging"],
    "8.20": ["network security", "remote attack", "network exposure", "remote code execution"],
    "8.21": ["network services", "service exposure", "network-facing service"],
}


def normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", str(text).lower()).strip()


def tokenize(text: str) -> Set[str]:
    return set(re.findall(r"[a-z0-9\.\-]+", normalize_text(text)))


def cosine_similarity(v1, v2) -> float:
    dot = sum(a * b for a, b in zip(v1, v2))
    norm1 = math.sqrt(sum(a * a for a in v1))
    norm2 = math.sqrt(sum(b * b for b in v2))
    if norm1 == 0 or norm2 == 0:
        return 0.0
    return dot / (norm1 * norm2)


def dedupe_keep_order(items):
    seen = set()
    out = []
    for x in items:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


def get_embedding(text: str):
    response = SESSION.post(
        OLLAMA_EMBED_URL,
        json={
            "model": EMBED_MODEL,
            "input": text,
            "keep_alive": "10m"
        },
        timeout=180
    )
    response.raise_for_status()
    data = response.json()
    return data["embeddings"][0]


def get_embeddings_batch(texts: List[str]):
    if not texts:
        return []

    response = SESSION.post(
        OLLAMA_EMBED_URL,
        json={
            "model": EMBED_MODEL,
            "input": texts,
            "keep_alive": "10m"
        },
        timeout=300
    )
    response.raise_for_status()
    data = response.json()
    return data["embeddings"]


def load_controls(csv_file: str):
    df = pd.read_csv(csv_file)
    records = []

    for _, row in df.iterrows():
        control_id = str(row.get("Control", "")).strip()

        text = (
            f"Section: {row.get('Section', '')}\n"
            f"Control ID: {control_id}\n"
            f"Control Name: {row.get('Title', '')}\n"
            f"Status: {row.get('Status', '')}\n"
            f"Purpose: {row.get('Purpose', '')}\n"
            f"Keywords: {'; '.join(CONTROL_HINTS.get(control_id, []))}"
        )

        records.append({
            "control_id": control_id,
            "title": str(row.get("Title", "")).strip(),
            "section": str(row.get("Section", "")).strip(),
            "status": str(row.get("Status", "")).strip(),
            "purpose": str(row.get("Purpose", "")).strip(),
            "text": text
        })

    return records


def build_or_load_control_embeddings(force_rebuild=False):
    if os.path.exists(EMBED_CACHE_FILE) and not force_rebuild:
        print(f"[INFO] Loading embeddings from {EMBED_CACHE_FILE}...")

        with open(EMBED_CACHE_FILE, "rb") as f:
            cached = pickle.load(f)

        if cached and isinstance(cached, list):
            sample = cached[0]
            if "control_id" in sample and "embedding" in sample:
                return cached

        print("[INFO] Existing embedding cache invalid. Rebuilding...")

    print("[INFO] Building control embeddings...")

    records = load_controls(CSV_FILE)
    texts = [r["text"] for r in records]

    embeddings = get_embeddings_batch(texts)

    embedded_records = []
    for record, emb in zip(records, embeddings):
        item = dict(record)
        item["embedding"] = emb
        embedded_records.append(item)

    os.makedirs(DATA_DIR, exist_ok=True)

    with open(EMBED_CACHE_FILE, "wb") as f:
        pickle.dump(embedded_records, f)

    print(f"[INFO] Saved embeddings to {EMBED_CACHE_FILE}")

    return embedded_records


def load_target_vulnerability_names(json_file: str):
    if not os.path.exists(json_file):
        raise FileNotFoundError(f"Risk file not found: {json_file}")

    with open(json_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, dict):
        records = data.get("hosts", [])
    elif isinstance(data, list):
        records = data
    else:
        raise ValueError("Unsupported JSON structure")

    results = []
    seen = set()

    for record in records:
        evaluation = str(record.get("evaluation", "")).strip().lower()
        treatment = str(record.get("treatment", "")).strip().lower()
        vulnerability_name = str(record.get("vulnerability_name", "")).strip()
        cve = str(record.get("cve", "")).strip()

        if evaluation == "treat" and treatment == "mitigate" and vulnerability_name:
            key = (vulnerability_name.lower(), cve.upper())
            if key not in seen:
                seen.add(key)
                results.append({
                    "vulnerability_name": vulnerability_name,
                    "cve": cve
                })

    return results


def extract_traits(vulnerability_name: str):
    text = normalize_text(vulnerability_name)
    traits = set()

    if "privilege escalation" in text or "elevation of privilege" in text:
        traits.add("privilege escalation")

    if "authentication" in text or "logon" in text or "ntlm" in text:
        traits.add("authentication weakness")

    if "dns" in text or "http" in text or "outlook" in text:
        traits.add("network-facing service")

    if "remote code execution" in text:
        traits.add("network-based exploitation")

    if "windows" in text or "microsoft" in text:
        traits.add("windows")

    if "active directory" in text or "domain" in text:
        traits.add("active directory")

    return sorted(traits)


def compute_boost(vulnerability_name: str, traits: List[str], control_record: Dict) -> float:
    control_id = control_record["control_id"]
    boost = 0.0

    if "privilege escalation" in traits and control_id == "8.2":
        boost += 0.20

    if "authentication weakness" in traits and control_id == "8.5":
        boost += 0.20

    if "network-based exploitation" in traits and control_id in {"8.20", "8.21"}:
        boost += 0.15

    if "windows" in traits and control_id == "8.8":
        boost += 0.05

    if "active directory" in traits and control_id in {"5.17", "8.2", "8.5"}:
        boost += 0.10

    return boost


def merge_results(results):
    merged = {}

    for item in results:
        cid = item["control_id"]
        cname = item["control_name"]
        cves = item["related_cves"]

        if cid not in merged:
            merged[cid] = {
                "control_id": cid,
                "control_name": cname,
                "related_cves": set()
            }

        merged[cid]["related_cves"].update(cves)

    final = []
    for cid, item in merged.items():
        final.append({
            "control_id": item["control_id"],
            "control_name": item["control_name"],
            "related_cves": sorted(list(item["related_cves"]))
        })

    return final


def rank_controls_for_vulnerability(vulnerability_name: str, embedded_controls: List[Dict], top_k=TOP_K):
    query_embedding = get_embedding(vulnerability_name)
    query_tokens = tokenize(vulnerability_name)
    traits = extract_traits(vulnerability_name)

    scored = []

    for record in embedded_controls:
        semantic = cosine_similarity(query_embedding, record["embedding"])
        record_tokens = tokenize(record["text"])
        keyword = len(query_tokens & record_tokens) / max(1, len(query_tokens))
        boost = compute_boost(vulnerability_name, traits, record)

        final_score = (semantic * 0.65) + (keyword * 0.25) + boost

        scored.append({
            "control_id": record["control_id"],
            "control_name": record["title"],
            "section": record["section"],
            "purpose": record["purpose"],
            "semantic": round(semantic, 6),
            "keyword": round(keyword, 6),
            "boost": round(boost, 6),
            "final_score": round(final_score, 6),
        })

    scored.sort(key=lambda x: x["final_score"], reverse=True)
    return scored[:top_k]


def main():
    embedded_controls = build_or_load_control_embeddings()
    targets = load_target_vulnerability_names(RISK_JSON_FILE)

    print(f"[INFO] Loaded {len(embedded_controls)} controls")
    print(f"[INFO] Loaded {len(targets)} Treat+Mitigate vulnerability names")

    all_results = []

    for idx, item in enumerate(targets, start=1):
        vulnerability_name = item["vulnerability_name"]
        cve = item["cve"]

        print(f"\n[{idx}/{len(targets)}] {vulnerability_name} ({cve})")

        ranked_controls = rank_controls_for_vulnerability(
            vulnerability_name=vulnerability_name,
            embedded_controls=embedded_controls,
            top_k=TOP_K
        )

        for r in ranked_controls:
            all_results.append({
                "control_id": r["control_id"],
                "control_name": r["control_name"],
                "related_cves": [cve]
            })

        for r in ranked_controls:
            print(f"  {r['control_id']} - {r['control_name']} | score={r['final_score']}")

    final_results = sorted(
        merge_results(all_results),
        key=lambda x: float(x["control_id"])
    )

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(final_results, f, indent=2)

    print("\n========= FINAL RESULT =========\n")

    for item in final_results:
        print(f"{item['control_id']} -> {item['control_name']} -> {item['related_cves']}")

    print(f"\n[INFO] Results saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()