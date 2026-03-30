import os
import re
import math
import json
import requests
import pandas as pd
import chromadb
from chromadb.config import Settings

# =========================================================
# CONTROL -> CVE MAPPING PIPELINE
# =========================================================
# Flow:
# 1) Load ISO controls from CSV
# 2) Resolve a target control by ID
# 3) Extract control keywords + mapped CWE IDs + optional CPE/platform hints
# 4) Query NVD for candidate CVEs using:
#       - cweId
#       - keywordSearch
#       - optional cpeName / virtualMatchString
# 5) Build / store CVE embeddings in ChromaDB
# 6) Rank candidates using:
#       final_score = (semantic * 0.65) + (keyword * 0.25) + boost
# 7) Return structured JSON
# =========================================================

# -------------------------
# PATHS
# -------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

DATA_DIR = os.path.join(BASE_DIR, "data")
CSV_FILE = os.path.join("iso27002_controls_2022.csv")
CHROMA_DIR = os.path.join("chroma_control_to_cve")

# -------------------------
# ENDPOINTS / MODELS
# -------------------------
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OLLAMA_EMBED_URL = "http://localhost:11434/api/embed"

EMBED_MODEL = "nomic-embed-text"
TOP_K = 10
NVD_PAGE_SIZE = 200  # NVD allows much higher, but 200 is reasonable
SESSION = requests.Session()

# Optional:
# If you have an NVD API key, uncomment and set it here:
# SESSION.headers.update({"apiKey": "YOUR_NVD_API_KEY"})

# ---------------------------------------------------------
# CONTROL HINTS
# ---------------------------------------------------------
# This is the curated control-to-CWE/keyword/platform layer.
# Expand it over time for better accuracy.
#
# Notes:
# - Prefer more concrete CWE IDs instead of very abstract ones.
# - platform_keywords and cpe_filters are optional contextual boosters.
# ---------------------------------------------------------
CONTROL_MAPPINGS = {
    "5.15": {
        "keywords": ["access control", "authorization", "unauthorized access"],
        "cwes": ["CWE-285", "CWE-862", "CWE-639"],
        "platform_keywords": [],
        "cpe_filters": []
    },
    "5.17": {
        "keywords": ["authentication", "credentials", "password", "identity"],
        "cwes": ["CWE-287", "CWE-288"],
        "platform_keywords": [],
        "cpe_filters": []
    },
    "5.18": {
        "keywords": ["access rights", "least privilege", "authorized access"],
        "cwes": ["CWE-285", "CWE-862", "CWE-250"],
        "platform_keywords": [],
        "cpe_filters": []
    },
    "8.2": {
        "keywords": ["privileged access", "privilege escalation", "admin rights"],
        "cwes": ["CWE-269", "CWE-250", "CWE-285"],
        "platform_keywords": ["windows", "linux", "active directory"],
        "cpe_filters": []
    },
    "8.5": {
        "keywords": ["secure authentication", "authentication bypass", "logon"],
        "cwes": ["CWE-287", "CWE-288", "CWE-425"],
        "platform_keywords": ["windows", "active directory", "sso"],
        "cpe_filters": []
    },
    "8.8": {
        "keywords": ["technical vulnerability", "patch", "unpatched", "vulnerability management"],
        "cwes": [],
        "platform_keywords": [],
        "cpe_filters": []
    },
    "8.9": {
        "keywords": ["configuration", "hardening", "secure configuration", "misconfiguration"],
        "cwes": [],
        "platform_keywords": ["windows", "linux", "apache", "nginx", "microsoft"],
        "cpe_filters": []
    },
    "8.16": {
        "keywords": ["monitoring", "detection", "anomalous activity", "logging"],
        "cwes": [],
        "platform_keywords": [],
        "cpe_filters": []
    },
    "8.20": {
        "keywords": ["network security", "remote attack", "network exposure", "remote code execution"],
        "cwes": [],
        "platform_keywords": ["windows", "vpn", "firewall", "router", "switch"],
        "cpe_filters": []
    },
    "8.21": {
        "keywords": ["network services", "service exposure", "network-facing service"],
        "cwes": [],
        "platform_keywords": ["http", "https", "ssh", "rdp", "smb", "dns"],
        "cpe_filters": []
    },
}

# ---------------------------------------------------------
# UTILITIES
# ---------------------------------------------------------
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

def dedupe_keep_order(items):
    seen = set()
    out = []
    for x in items:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out

# ---------------------------------------------------------
# OLLAMA EMBEDDINGS
# ---------------------------------------------------------
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

    # Ollama /api/embed returns {"embeddings": [[...]]}
    return data["embeddings"][0]

# ---------------------------------------------------------
# LOAD ISO CONTROLS
# ---------------------------------------------------------
def load_controls(csv_file: str):
    df = pd.read_csv(csv_file)
    records = []

    for _, row in df.iterrows():
        control_id = str(row.get("Control", "")).strip()

        records.append({
            "control_id": control_id,
            "section": str(row.get("Section", "")).strip(),
            "title": str(row.get("Title", "")).strip(),
            "status": str(row.get("Status", "")).strip(),
            "purpose": str(row.get("Purpose", "")).strip(),
        })

    return records

def get_control_record(control_id: str, controls):
    for record in controls:
        if record["control_id"] == control_id:
            return record
    raise ValueError(f"Control ID not found: {control_id}")

# ---------------------------------------------------------
# CONTROL QUERY BUILDING
# ---------------------------------------------------------
def build_control_profile(control_record):
    control_id = control_record["control_id"]
    hints = CONTROL_MAPPINGS.get(control_id, {})

    keywords = dedupe_keep_order(
        hints.get("keywords", []) +
        tokenize(control_record["title"]) -
        {"and", "or", "the", "of", "for", "to", "in", "a"}
        if control_record["title"] else hints.get("keywords", [])
    )

    # Fix mixed type if tokenize() result got concatenated
    normalized_keywords = []
    for item in keywords:
        if isinstance(item, str):
            normalized_keywords.append(item)

    profile = {
        "control_id": control_id,
        "control_name": control_record["title"],
        "section": control_record["section"],
        "purpose": control_record["purpose"],
        "keywords": dedupe_keep_order(
            hints.get("keywords", []) + normalized_keywords[:6]
        ),
        "cwes": dedupe_keep_order(hints.get("cwes", [])),
        "platform_keywords": dedupe_keep_order(hints.get("platform_keywords", [])),
        "cpe_filters": dedupe_keep_order(hints.get("cpe_filters", [])),
    }

    return profile

# ---------------------------------------------------------
# NVD FETCH HELPERS
# ---------------------------------------------------------
def nvd_get(params):
    response = SESSION.get(NVD_API_URL, params=params, timeout=120)
    response.raise_for_status()
    return response.json()

def parse_cve_item(item):
    cve = item.get("cve", {})

    cve_id = cve.get("id", "")
    description = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            description = d.get("value", "")
            break

    cwe_values = []
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            value = desc.get("value")
            if value:
                cwe_values.append(value)

    severity = None
    vector = None
    metrics = cve.get("metrics", {})

    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if key in metrics and metrics[key]:
            metric = metrics[key][0]
            cvss = metric.get("cvssData", {})
            severity = metric.get("baseSeverity") or cvss.get("baseSeverity")
            vector = cvss.get("vectorString")
            break

    cpe_uris = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                crit = cpe_match.get("criteria")
                if crit:
                    cpe_uris.append(crit)

    return {
        "cve_id": cve_id,
        "description": description,
        "cwes": dedupe_keep_order(cwe_values),
        "severity": severity,
        "vector": vector,
        "cpes": dedupe_keep_order(cpe_uris),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
    }

def fetch_cves_by_cwe(cwe_id, max_results=200):
    results = []
    start_index = 0

    while len(results) < max_results:
        data = nvd_get({
            "cweId": cwe_id,
            "resultsPerPage": min(NVD_PAGE_SIZE, max_results - len(results)),
            "startIndex": start_index,
            "noRejected": None
        })

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            break

        results.extend(parse_cve_item(v) for v in vulns)

        total = data.get("totalResults", 0)
        start_index += data.get("resultsPerPage", len(vulns))
        if start_index >= total:
            break

    return results[:max_results]

def fetch_cves_by_keywords(keywords, max_results=200):
    if not keywords:
        return []

    query = " ".join(keywords[:6])

    results = []
    start_index = 0

    while len(results) < max_results:
        data = nvd_get({
            "keywordSearch": query,
            "resultsPerPage": min(NVD_PAGE_SIZE, max_results - len(results)),
            "startIndex": start_index,
            "noRejected": None
        })

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            break

        results.extend(parse_cve_item(v) for v in vulns)

        total = data.get("totalResults", 0)
        start_index += data.get("resultsPerPage", len(vulns))
        if start_index >= total:
            break

    return results[:max_results]

def fetch_cves_by_cpe(cpe_name, max_results=200):
    results = []
    start_index = 0

    while len(results) < max_results:
        data = nvd_get({
            "cpeName": cpe_name,
            "resultsPerPage": min(NVD_PAGE_SIZE, max_results - len(results)),
            "startIndex": start_index,
            "noRejected": None
        })

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            break

        results.extend(parse_cve_item(v) for v in vulns)

        total = data.get("totalResults", 0)
        start_index += data.get("resultsPerPage", len(vulns))
        if start_index >= total:
            break

    return results[:max_results]

def collect_candidate_cves(profile, per_source_limit=150):
    all_candidates = []

    # 1) CWE-driven retrieval
    for cwe_id in profile["cwes"]:
        try:
            all_candidates.extend(fetch_cves_by_cwe(cwe_id, max_results=per_source_limit))
        except Exception as e:
            print(f"[WARN] CWE fetch failed for {cwe_id}: {e}")

    # 2) Keyword-driven retrieval
    try:
        all_candidates.extend(fetch_cves_by_keywords(profile["keywords"], max_results=per_source_limit))
    except Exception as e:
        print(f"[WARN] Keyword fetch failed: {e}")

    # 3) Optional CPE-driven retrieval
    for cpe_name in profile["cpe_filters"]:
        try:
            all_candidates.extend(fetch_cves_by_cpe(cpe_name, max_results=per_source_limit))
        except Exception as e:
            print(f"[WARN] CPE fetch failed for {cpe_name}: {e}")

    # Dedupe by CVE ID
    deduped = {}
    for item in all_candidates:
        deduped[item["cve_id"]] = item

    return list(deduped.values())

# ---------------------------------------------------------
# CHROMADB
# ---------------------------------------------------------
def get_chroma_collection():
    client = chromadb.PersistentClient(path=CHROMA_DIR, settings=Settings(anonymized_telemetry=False))
    collection = client.get_or_create_collection(name="control_to_cve_candidates")
    return collection

def cve_document_text(cve):
    return (
        f"CVE ID: {cve['cve_id']}\n"
        f"Description: {cve.get('description', '')}\n"
        f"CWE: {'; '.join(cve.get('cwes', []))}\n"
        f"Severity: {cve.get('severity', '')}\n"
        f"Vector: {cve.get('vector', '') or ''}\n"
        f"CPEs: {'; '.join(cve.get('cpes', [])[:10])}"
    )

def upsert_cves_to_chroma(collection, cves):
    ids = []
    documents = []
    metadatas = []
    embeddings = []

    for cve in cves:
        text = cve_document_text(cve)
        emb = get_embedding(text)

        ids.append(cve["cve_id"])
        documents.append(text)
        metadatas.append({
            "cve_id": cve["cve_id"],
            "severity": cve.get("severity") or "",
            "published": cve.get("published") or "",
        })
        embeddings.append(emb)

    if ids:
        collection.upsert(
            ids=ids,
            documents=documents,
            metadatas=metadatas,
            embeddings=embeddings
        )

# ---------------------------------------------------------
# SCORING
# ---------------------------------------------------------
def compute_boost(control_profile, cve):
    text = normalize_text(
        " ".join([
            cve.get("description", ""),
            " ".join(cve.get("cwes", [])),
            " ".join(cve.get("cpes", []))
        ])
    )

    boost = 0.0

    # Platform / technology boost
    for platform_word in control_profile["platform_keywords"]:
        if normalize_text(platform_word) in text:
            boost += 0.05

    # Severity boost
    severity = (cve.get("severity") or "").lower()
    if severity == "critical":
        boost += 0.10
    elif severity == "high":
        boost += 0.06

    # Specific control logic
    if control_profile["control_id"] == "8.2" and "privilege" in text:
        boost += 0.15

    if control_profile["control_id"] == "8.5" and ("authentication" in text or "bypass" in text):
        boost += 0.15

    if control_profile["control_id"] == "8.8":
        boost += 0.05  # technical vulnerability management is intentionally broad

    return boost

def rank_cves_for_control(control_profile, candidate_cves, top_k=TOP_K):
    query_text = (
        f"Control ID: {control_profile['control_id']}\n"
        f"Control Name: {control_profile['control_name']}\n"
        f"Purpose: {control_profile['purpose']}\n"
        f"Keywords: {'; '.join(control_profile['keywords'])}\n"
        f"CWEs: {'; '.join(control_profile['cwes'])}"
    )

    query_embedding = get_embedding(query_text)
    query_tokens = tokenize(" ".join(control_profile["keywords"] + control_profile["cwes"]))

    scored = []
    for cve in candidate_cves:
        cve_text = cve_document_text(cve)
        cve_embedding = get_embedding(cve_text)

        semantic = cosine_similarity(query_embedding, cve_embedding)

        cve_tokens = tokenize(cve_text)
        keyword = len(query_tokens & cve_tokens) / max(1, len(query_tokens))

        boost = compute_boost(control_profile, cve)

        final_score = (semantic * 0.65) + (keyword * 0.25) + boost

        scored.append({
            "cve_id": cve["cve_id"],
            "description": cve["description"],
            "cwes": cve["cwes"],
            "severity": cve["severity"],
            "published": cve["published"],
            "last_modified": cve["last_modified"],
            "semantic": round(semantic, 6),
            "keyword": round(keyword, 6),
            "boost": round(boost, 6),
            "final_score": round(final_score, 6),
        })

    scored.sort(key=lambda x: x["final_score"], reverse=True)
    return scored[:top_k]

# ---------------------------------------------------------
# MAIN PIPELINE
# ---------------------------------------------------------
def map_control_to_cves(control_id: str, csv_file: str = CSV_FILE, top_k: int = TOP_K):
    controls = load_controls(csv_file)
    control_record = get_control_record(control_id, controls)
    control_profile = build_control_profile(control_record)

    print(f"[INFO] Control selected: {control_profile['control_id']} - {control_profile['control_name']}")
    print(f"[INFO] Keywords: {control_profile['keywords']}")
    print(f"[INFO] CWEs: {control_profile['cwes']}")

    candidate_cves = collect_candidate_cves(control_profile)

    if not candidate_cves:
        return {
            "control_id": control_profile["control_id"],
            "control_name": control_profile["control_name"],
            "message": "No candidate CVEs found from NVD using current CWE/keyword/CPE profile.",
            "candidates": []
        }

    print(f"[INFO] Candidate CVEs collected: {len(candidate_cves)}")

    # Store candidates in ChromaDB
    collection = get_chroma_collection()
    upsert_cves_to_chroma(collection, candidate_cves)

    ranked = rank_cves_for_control(control_profile, candidate_cves, top_k=top_k)

    return {
        "control_id": control_profile["control_id"],
        "control_name": control_profile["control_name"],
        "section": control_profile["section"],
        "purpose": control_profile["purpose"],
        "keywords": control_profile["keywords"],
        "mapped_cwes": control_profile["cwes"],
        "top_cves": ranked
    }

# ---------------------------------------------------------
# EXAMPLE USAGE
# ---------------------------------------------------------
if __name__ == "__main__":
    # Example:
    # 8.5 -> Secure authentication
    # 8.2 -> Privileged access rights
    # 8.8 -> Management of technical vulnerabilities

    result = map_control_to_cves("8.5", csv_file=CSV_FILE, top_k=10)
    print(json.dumps(result, indent=2))