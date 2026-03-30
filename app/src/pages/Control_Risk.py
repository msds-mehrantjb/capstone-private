import os
import re
import math
import json
import pickle
import requests
import pandas as pd

# =========================
# PATH FIX (CRITICAL)
# =========================
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../"))

DATA_DIR = os.path.join(BASE_DIR, "data", "work", "2026")

CSV_FILE = os.path.join(DATA_DIR, "iso27002_controls_2022.csv")
EMBED_CACHE_FILE = os.path.join(DATA_DIR, "iso27002_local_embeddings.pkl")

# =========================

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OLLAMA_GEN_URL = "http://localhost:11434/api/generate"
OLLAMA_EMBED_URL = "http://localhost:11434/api/embed"

EMBED_MODEL = "nomic-embed-text"
LLM_MODEL = "llama3"
TOP_K = 6
EMBED_BATCH_SIZE = 32  # try 16, 32, or 64 depending on VRAM

CONTROL_HINTS = {
    "5.15": ["access control", "unauthorized access", "authorization"],
    "5.17": ["authentication", "credentials", "authentication information"],
    "5.18": ["access rights", "least privilege", "authorized access"],
    "8.2": ["privileged access", "privilege escalation", "admin rights"],
    "8.5": ["secure authentication", "authentication bypass", "logon"],
    "8.8": ["technical vulnerability", "cve", "patch", "unpatched"],
    "8.9": ["configuration", "hardening", "secure configuration"],
    "8.16": ["monitoring", "detection", "anomalous activity"],
    "8.20": ["network security", "network attack", "remote attack"],
    "8.21": ["network services", "service exposure", "network-facing service"],
}

# Reuse a single HTTP session for better performance
SESSION = requests.Session()


def normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", str(text).lower()).strip()


def tokenize(text: str):
    return set(re.findall(r"[a-z0-9\.\-]+", normalize_text(text)))


def cosine_similarity(v1, v2):
    dot = sum(a * b for a, b in zip(v1, v2))
    norm1 = math.sqrt(sum(a * a for a in v1))
    norm2 = math.sqrt(sum(b * b for b in v2))
    if norm1 == 0 or norm2 == 0:
        return 0.0
    return dot / (norm1 * norm2)


def get_embedding(text: str):
    """
    Single-text embedding helper.
    Uses Ollama's /api/embed endpoint.
    """
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


def get_embeddings_batch(texts):
    """
    Batch embedding helper.
    Much more GPU-friendly than one-request-per-text.
    """
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


def load_controls(csv_file):
    df = pd.read_csv(csv_file)
    records = []

    for _, row in df.iterrows():
        control_id = str(row.get("Control", ""))

        text = (
            f"Section: {row.get('Section', '')}\n"
            f"Control ID: {control_id}\n"
            f"Control Name: {row.get('Title', '')}\n"
            f"Status: {row.get('Status', '')}\n"
            f"Purpose: {row.get('Purpose', '')}\n"
            f"Keywords: {'; '.join(CONTROL_HINTS.get(control_id, []))}"
        )

        records.append({
            "Control": control_id,
            "Title": str(row.get("Title", "")),
            "Section": str(row.get("Section", "")),
            "Status": str(row.get("Status", "")),
            "Purpose": str(row.get("Purpose", "")),
            "text": text
        })

    return records


def build_or_load_embeddings(force_rebuild=False):
    if os.path.exists(EMBED_CACHE_FILE) and not force_rebuild:
        with open(EMBED_CACHE_FILE, "rb") as f:
            return pickle.load(f)

    print("Building local embeddings for controls...")

    records = load_controls(CSV_FILE)
    embedded = []

    total = len(records)
    for start in range(0, total, EMBED_BATCH_SIZE):
        end = min(start + EMBED_BATCH_SIZE, total)
        batch = records[start:end]
        texts = [record["text"] for record in batch]

        print(f"Embedding batch {start + 1}-{end} of {total} ...")
        embeddings = get_embeddings_batch(texts)

        for record, embedding in zip(batch, embeddings):
            item = dict(record)
            item["embedding"] = embedding
            embedded.append(item)

    os.makedirs(os.path.dirname(EMBED_CACHE_FILE), exist_ok=True)

    with open(EMBED_CACHE_FILE, "wb") as f:
        pickle.dump(embedded, f)

    return embedded


def fetch_cve_from_nvd(cve_id: str):
    response = SESSION.get(
        NVD_API_URL,
        params={"cveId": cve_id},
        timeout=120
    )
    response.raise_for_status()
    data = response.json()

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        raise ValueError(f"No CVE found in NVD for {cve_id}")

    cve = vulns[0]["cve"]

    description = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            description = d.get("value", "")
            break

    cwe_values = []
    for w in cve.get("weaknesses", []):
        for desc in w.get("description", []):
            if desc.get("value"):
                cwe_values.append(desc["value"])

    metrics = cve.get("metrics", {})
    severity = None
    vector = None

    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if key in metrics and metrics[key]:
            metric = metrics[key][0]
            cvss = metric.get("cvssData", {})
            severity = metric.get("baseSeverity") or cvss.get("baseSeverity")
            vector = cvss.get("vectorString")
            break

    return {
        "cve_id": cve_id,
        "description": description,
        "cwe": cwe_values,
        "severity": severity,
        "vector": vector,
    }


def extract_traits(cve_info):
    text = normalize_text(
        " ".join([
            cve_info.get("description", ""),
            " ".join(cve_info.get("cwe", [])),
            cve_info.get("vector", "") or "",
        ])
    )

    traits = set()

    if "privilege escalation" in text:
        traits.add("privilege escalation")

    if "authentication" in text or "bypass" in text:
        traits.add("authentication weakness")

    if "access control" in text:
        traits.add("access control failure")

    if "remote code execution" in text:
        traits.add("network-based exploitation")

    if "cwe-" in text:
        traits.add("technical vulnerability")

    if cve_info.get("severity"):
        traits.add(str(cve_info["severity"]).lower())

    return sorted(traits)


def retrieve_controls(query_text, traits, embedded_records, top_k=TOP_K):
    query_embedding = get_embedding(query_text)

    scored = []

    query_tokens = tokenize(query_text)

    for record in embedded_records:
        semantic = cosine_similarity(query_embedding, record["embedding"])
        record_tokens = tokenize(record["text"])
        keyword = len(query_tokens & record_tokens) / max(1, len(query_tokens))

        boost = 0.0
        if "privilege escalation" in traits and record["Control"] == "8.2":
            boost += 0.2

        final_score = (semantic * 0.65) + (keyword * 0.25) + boost

        scored.append({
            "final_score": final_score,
            "record": record
        })

    scored.sort(key=lambda x: x["final_score"], reverse=True)
    return scored[:top_k]


def ask_llama3(cve_info, traits, retrieved_controls):
    allowed_controls = [
        {
            "control_id": item["record"]["Control"],
            "control_name": item["record"]["Title"],
            "section": item["record"]["Section"],
            "purpose": item["record"]["Purpose"]
        }
        for item in retrieved_controls
    ]

    prompt = f"""
You are an ISO 27001 expert.

CVE: {cve_info['cve_id']}
Description: {cve_info['description']}
Traits: {traits}

You must choose controls ONLY from this allowed list.
Do not invent control IDs.
Do not rename controls.
Do not duplicate controls.

Allowed controls:
{json.dumps(allowed_controls, indent=2)}

Return valid JSON only in this format:
{{
  "risk": "{cve_info['cve_id']}",
  "controls": [
    {{
      "control_id": "...",
      "control_name": "...",
      "reason": "..."
    }}
  ]
}}
"""

    response = SESSION.post(
        OLLAMA_GEN_URL,
        json={
            "model": LLM_MODEL,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "keep_alive": "10m"
        },
        timeout=180
    )
    response.raise_for_status()

    return response.json()["response"]


def map_cve_to_controls(cve_id: str):
    embedded_records = build_or_load_embeddings()

    cve_info = fetch_cve_from_nvd(cve_id)
    traits = extract_traits(cve_info)

    query_text = cve_info["description"]
    retrieved = retrieve_controls(query_text, traits, embedded_records)

    answer = ask_llama3(cve_info, traits, retrieved)
    return answer


if __name__ == "__main__":
    print(map_cve_to_controls("CVE-2020-1472"))