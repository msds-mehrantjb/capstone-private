from fastapi import APIRouter, Query, HTTPException
import json
import os
import re
import math
import pickle
from pathlib import Path
from typing import Any

import pandas as pd
import requests
from pydantic import BaseModel


router = APIRouter(prefix="/api/annex-a-soa", tags=["annex-a-soa"])


VALID_STEP_STATUSES = {"Blocked", "Not Started", "In Progress", "Completed"}
VALID_IMPLEMENTATION_STATUSES = {
    "",
    "Not Implemented",
    "Planned",
    "In Progress",
    "Implemented",
    "Not Applicable",
}

class AddRequest(BaseModel):
    year: int | None = 2026
    control_id: str

class DeleteRequest(BaseModel):
    year: int | None = 2026
    control_id: str

class CreateRequest(BaseModel):
    year: int | None = 2026
    force: bool = False


class ResetRequest(BaseModel):
    year: int | None = 2026
    confirm: bool = False


class UpdateStatusRequest(BaseModel):
    year: int | None = 2026
    control_id: str
    implementation_status: str


class SubmitRequest(BaseModel):
    year: int | None = 2026
    confirm: bool = False

class RecommendRequest(BaseModel):
    year: int | None = 2026
    
# =========================================================
# PATHS
# =========================================================
def find_project_root() -> Path:
    current = Path(__file__).resolve()
    for parent in [current] + list(current.parents):
        if (parent / "data" / "work").exists():
            return parent
    raise RuntimeError("Could not find project root containing data/work")


BASE_DIR = find_project_root()


def _work_dir(year: int) -> Path:
    return BASE_DIR / "data" / "work" / str(year)


def _annex_a_soa_file(year: int) -> Path:
    return _work_dir(year) / "AnnexA_SoA.json"


def _risk_eval_treatment_file(year: int) -> Path:
    return _work_dir(year) / "RiskEvaluationTreatment.json"


def _system_status_file(year: int) -> Path:
    return _work_dir(year) / "SystemStatus.json"


def _controls_csv_file(year: int) -> Path:
    return _work_dir(year) / "iso27002_controls_2022.csv"


def _embed_cache_file(year: int) -> Path:
    return _work_dir(year) / "iso27002_local_embeddings.pkl"


# =========================================================
# OLLAMA / RAG CONFIG
# =========================================================
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OLLAMA_GEN_URL = "http://localhost:11434/api/generate"
OLLAMA_EMBED_URL = "http://localhost:11434/api/embed"

EMBED_MODEL = "nomic-embed-text"
LLM_MODEL = "llama3"
TOP_K = 6
EMBED_BATCH_SIZE = 32

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

SESSION = requests.Session()


# =========================================================
# BASIC HELPERS
# =========================================================
def _load_json(path: Path) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def _normalize_text(value: Any) -> str:
    return str(value or "").strip()


def _normalize_key(value: Any) -> str:
    return _normalize_text(value).lower()


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


# =========================================================
# SYSTEM STATUS
# =========================================================
def _load_system_status_or_default(year: int) -> dict:
    path = _system_status_file(year)

    if not path.exists():
        return {
            "meta": {"name": "System Status", "version": "1.0"},
            "sections": {
                "scope_context": {"status": "Not Started"},
                "assets_cia": {"status": "Not Started"},
                "risk_analysis": {"status": "Not Started"},
                "risk_evaluation_treatment": {"status": "Not Started"},
                "annex_a_soa": {"status": "Blocked"},
                "action_plan_implementation": {"status": "Blocked"},
            },
        }

    try:
        data = _load_json(path)
        if not isinstance(data, dict):
            data = {}
    except Exception:
        data = {}

    if not isinstance(data.get("meta"), dict):
        data["meta"] = {"name": "System Status", "version": "1.0"}

    if not isinstance(data.get("sections"), dict):
        data["sections"] = {}

    defaults = {
        "scope_context": {"status": "Not Started"},
        "assets_cia": {"status": "Not Started"},
        "risk_analysis": {"status": "Not Started"},
        "risk_evaluation_treatment": {"status": "Not Started"},
        "annex_a_soa": {"status": "Blocked"},
        "action_plan_implementation": {"status": "Blocked"},
    }

    for section_name, default_value in defaults.items():
        if not isinstance(data["sections"].get(section_name), dict):
            data["sections"][section_name] = default_value

    return data


def _set_section_status(year: int, section_name: str, new_status: str) -> None:
    if new_status not in VALID_STEP_STATUSES:
        raise ValueError(f"Invalid status: {new_status}")

    doc = _load_system_status_or_default(year)

    if section_name not in doc["sections"] or not isinstance(doc["sections"][section_name], dict):
        doc["sections"][section_name] = {}

    doc["sections"][section_name]["status"] = new_status
    _save_json(_system_status_file(year), doc)


def _annex_section_is_read_only(year: int) -> bool:
    doc = _load_system_status_or_default(year)
    status = doc.get("sections", {}).get("annex_a_soa", {}).get("status")
    return status == "Completed"


# =========================================================
# ANNEX DOCUMENT HELPERS
# =========================================================
def _blank_annex_doc() -> dict:
    return {"controls": []}


def _load_annex_doc_or_blank(year: int) -> dict:
    path = _annex_a_soa_file(year)

    if not path.exists():
        return _blank_annex_doc()

    try:
        data = _load_json(path)
        if not isinstance(data, dict):
            return _blank_annex_doc()

        controls = data.get("controls")
        if not isinstance(controls, list):
            data["controls"] = []

        return data
    except Exception:
        return _blank_annex_doc()


def _all_controls(doc: dict) -> list[dict]:
    controls = doc.get("controls", [])
    if not isinstance(controls, list):
        return []
    return [c for c in controls if isinstance(c, dict)]


def _derive_annex_status_from_doc(doc: dict) -> str:
    controls = _all_controls(doc)
    if len(controls) == 0:
        return "Not Started"
    return "In Progress"


def _sync_annex_status(year: int, doc: dict | None = None) -> str:
    if _annex_section_is_read_only(year):
        _set_section_status(year, "annex_a_soa", "Completed")
        return "Completed"

    if doc is None:
        doc = _load_annex_doc_or_blank(year)

    new_status = _derive_annex_status_from_doc(doc)
    _set_section_status(year, "annex_a_soa", new_status)
    return new_status


def _find_control(doc: dict, control_id: str) -> tuple[int | None, dict | None]:
    target = _normalize_key(control_id)
    controls = _all_controls(doc)

    for idx, control in enumerate(controls):
        if _normalize_key(control.get("control_id")) == target:
            return idx, control

    return None, None


# =========================================================
# RISK EVALUATION LOADING
# =========================================================
def _load_risk_eval_doc(year: int) -> dict:
    path = _risk_eval_treatment_file(year)
    if not path.exists():
        raise FileNotFoundError(
            "RiskEvaluationTreatment.json was not found. Finalize the risk evaluation/treatment step first."
        )

    data = _load_json(path)
    if not isinstance(data, dict):
        raise ValueError("RiskEvaluationTreatment.json is invalid.")

    hosts = data.get("hosts")
    if not isinstance(hosts, list):
        data["hosts"] = []

    return data


def _is_record_applicable(record: dict) -> bool:
    return (
        _normalize_key(record.get("evaluation")) == "treat"
        and _normalize_key(record.get("treatment")) == "mitigate"
    )


# =========================================================
# RAG HELPERS
# =========================================================
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


def get_embeddings_batch(texts):
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


def load_controls(csv_file: Path):
    if not csv_file.exists():
        raise FileNotFoundError(f"Control catalog file not found: {csv_file}")

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
            "Control": control_id,
            "Title": str(row.get("Title", "")),
            "Section": str(row.get("Section", "")),
            "Status": str(row.get("Status", "")),
            "Purpose": str(row.get("Purpose", "")),
            "text": text
        })

    return records


def build_or_load_embeddings(year: int, force_rebuild: bool = False):
    cache_file = _embed_cache_file(year)
    csv_file = _controls_csv_file(year)

    if cache_file.exists() and not force_rebuild:
        with open(cache_file, "rb") as f:
            return pickle.load(f)

    records = load_controls(csv_file)
    embedded = []

    total = len(records)
    for start in range(0, total, EMBED_BATCH_SIZE):
        end = min(start + EMBED_BATCH_SIZE, total)
        batch = records[start:end]
        texts = [record["text"] for record in batch]

        embeddings = get_embeddings_batch(texts)

        for record, embedding in zip(batch, embeddings):
            item = dict(record)
            item["embedding"] = embedding
            embedded.append(item)

    cache_file.parent.mkdir(parents=True, exist_ok=True)
    with open(cache_file, "wb") as f:
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


def extract_traits_from_text(text: str, severity: str | None = None):
    text = normalize_text(text)
    traits = set()

    if "privilege escalation" in text:
        traits.add("privilege escalation")

    if "authentication" in text or "bypass" in text:
        traits.add("authentication weakness")

    if "access control" in text:
        traits.add("access control failure")

    if "remote code execution" in text:
        traits.add("network-based exploitation")

    if "misconfiguration" in text or "configuration" in text:
        traits.add("configuration weakness")

    if "vulnerability" in text or "cve-" in text:
        traits.add("technical vulnerability")

    if severity:
        traits.add(str(severity).lower())

    return sorted(traits)


def build_query_from_record(record: dict) -> str:
    parts = [
        record.get("risk", ""),
        record.get("vulnerability_name", ""),
        record.get("cve", ""),
        record.get("decision_reason", ""),
        record.get("control_reference", ""),
        record.get("role", ""),
        record.get("hostname", ""),
        record.get("CIA rating", ""),
    ]
    return " ".join(str(x or "") for x in parts).strip()


def retrieve_controls(query_text, traits, embedded_records, top_k=TOP_K):
    query_embedding = get_embedding(query_text)
    query_tokens = tokenize(query_text)

    scored = []

    for record in embedded_records:
        semantic = cosine_similarity(query_embedding, record["embedding"])
        record_tokens = tokenize(record["text"])
        keyword = len(query_tokens & record_tokens) / max(1, len(query_tokens))

        boost = 0.0
        if "privilege escalation" in traits and record["Control"] == "8.2":
            boost += 0.2
        if "authentication weakness" in traits and record["Control"] == "8.5":
            boost += 0.2
        if "technical vulnerability" in traits and record["Control"] == "8.8":
            boost += 0.2
        if "configuration weakness" in traits and record["Control"] == "8.9":
            boost += 0.2
        if "network-based exploitation" in traits and record["Control"] in {"8.20", "8.21"}:
            boost += 0.2

        final_score = (semantic * 0.65) + (keyword * 0.25) + boost

        scored.append({
            "final_score": final_score,
            "record": record
        })

    scored.sort(key=lambda x: x["final_score"], reverse=True)
    return scored[:top_k]


def ask_llama3_for_controls(risk_id: str, query_text: str, traits, retrieved_controls):
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
You are an ISO 27001:2022 expert.

Risk ID: {risk_id}
Query: {query_text}
Traits: {traits}

You must choose the best fitting controls ONLY from the allowed list below.
Do not invent control IDs.
Do not rename controls.
Do not duplicate controls.
Prefer the most relevant controls for mitigating the vulnerability.

Allowed controls:
{json.dumps(allowed_controls, indent=2)}

Return valid JSON only in this format:
{{
  "risk": "{risk_id}",
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

    raw = response.json()["response"]
    return json.loads(raw)


def _safe_fetch_cve_description(cve_id: str) -> tuple[str, str | None]:
    try:
        cve_info = fetch_cve_from_nvd(cve_id)
        return cve_info.get("description", ""), cve_info.get("severity")
    except Exception:
        return "", None


def map_record_to_controls(record: dict, embedded_records: list[dict]) -> dict:
    cve_id = _normalize_text(record.get("cve"))
    risk_id = _normalize_text(record.get("riskid")) or cve_id or _normalize_text(record.get("risk"))

    local_query = build_query_from_record(record)

    nvd_desc = ""
    severity = None
    if cve_id.upper().startswith("CVE-"):
        nvd_desc, severity = _safe_fetch_cve_description(cve_id)

    query_text = " ".join([local_query, nvd_desc]).strip()
    if not query_text:
        query_text = _normalize_text(record.get("risk")) or _normalize_text(record.get("vulnerability_name"))

    traits = extract_traits_from_text(query_text, severity)
    retrieved = retrieve_controls(query_text, traits, embedded_records, top_k=TOP_K)
    llm_answer = ask_llama3_for_controls(risk_id=risk_id, query_text=query_text, traits=traits, retrieved_controls=retrieved)

    return {
        "risk_id": risk_id,
        "cve": cve_id,
        "query_text": query_text,
        "traits": traits,
        "retrieved": retrieved,
        "llm_answer": llm_answer,
    }


# =========================================================
# BUILD ANNEX A & SOA FROM FILTERED RISK RECORDS USING RAG
# =========================================================
def _build_annex_from_risk_eval(year: int) -> dict:
    risk_eval_doc = _load_risk_eval_doc(year)
    hosts = risk_eval_doc.get("hosts", [])

    applicable_records = [
        r for r in hosts
        if isinstance(r, dict) and _is_record_applicable(r)
    ]

    embedded_records = build_or_load_embeddings(year)

    matched_controls: dict[str, dict] = {}

    for record in applicable_records:
        try:
            result = map_record_to_controls(record, embedded_records)
            risk_id = result["risk_id"]
            cve_id = result["cve"]

            controls = result.get("llm_answer", {}).get("controls", [])
            if not isinstance(controls, list):
                controls = []

            for control in controls:
                control_id = _normalize_text(control.get("control_id"))
                control_name = _normalize_text(control.get("control_name"))
                reason = _normalize_text(control.get("reason"))

                if not control_id:
                    continue

                if control_id not in matched_controls:
                    matched_controls[control_id] = {
                        "control_id": control_id,
                        "control_name": control_name,
                        "domain": "ISO 27001:2022 Control",
                        "applicable": True,
                        "implementation_status": "",
                        "justification": reason,
                        "related_risks": [],
                        "risk_ids": [],
                        "source_records": [],
                    }

                if cve_id and cve_id not in matched_controls[control_id]["related_risks"]:
                    matched_controls[control_id]["related_risks"].append(cve_id)

                if risk_id and risk_id not in matched_controls[control_id]["risk_ids"]:
                    matched_controls[control_id]["risk_ids"].append(risk_id)

                matched_controls[control_id]["source_records"].append({
                    "hostname": _normalize_text(record.get("hostname")),
                    "role": _normalize_text(record.get("role")),
                    "riskid": _normalize_text(record.get("riskid")),
                    "risk": _normalize_text(record.get("risk")),
                    "vulnerability_name": _normalize_text(record.get("vulnerability_name")),
                    "cve": cve_id,
                    "reason": reason,
                })

        except Exception as e:
            # keep processing other records
            fallback_key = f"ERROR-{_normalize_text(record.get('riskid')) or _normalize_text(record.get('cve')) or 'UNKNOWN'}"
            matched_controls[fallback_key] = {
                "control_id": fallback_key,
                "control_name": "RAG Mapping Error",
                "domain": "System",
                "applicable": False,
                "implementation_status": "",
                "justification": f"Failed to map controls automatically: {str(e)}",
                "related_risks": [_normalize_text(record.get("cve"))],
                "risk_ids": [_normalize_text(record.get("riskid"))],
                "source_records": [{
                    "hostname": _normalize_text(record.get("hostname")),
                    "role": _normalize_text(record.get("role")),
                    "riskid": _normalize_text(record.get("riskid")),
                    "risk": _normalize_text(record.get("risk")),
                    "vulnerability_name": _normalize_text(record.get("vulnerability_name")),
                    "cve": _normalize_text(record.get("cve")),
                }],
            }

    controls = sorted(
        matched_controls.values(),
        key=lambda x: x.get("control_id", "")
    )

    return {"controls": controls}

def _recommend_controls_from_risk_eval(year: int) -> list[dict]:
    risk_eval_doc = _load_risk_eval_doc(year)
    hosts = risk_eval_doc.get("hosts", [])

    applicable_records = [
        r for r in hosts
        if isinstance(r, dict) and _is_record_applicable(r)
    ]

    embedded_records = build_or_load_embeddings(year)

    recommended_controls = {}

    for record in applicable_records:
        try:
            result = map_record_to_controls(record, embedded_records)

            controls = result.get("llm_answer", {}).get("controls", [])
            if not isinstance(controls, list):
                continue

            for c in controls:
                cid = _normalize_text(c.get("control_id"))
                cname = _normalize_text(c.get("control_name"))

                if not cid:
                    continue

                if cid not in recommended_controls:
                    recommended_controls[cid] = {
                        "control_id": cid,
                        "control_name": cname
                    }

        except Exception:
            continue

    return sorted(
        recommended_controls.values(),
        key=lambda x: x["control_id"]
    )

def _build_single_control_from_rag(year: int, target_control_id: str) -> dict | None:
    risk_eval_doc = _load_risk_eval_doc(year)
    hosts = risk_eval_doc.get("hosts", [])

    applicable_records = [
        r for r in hosts
        if isinstance(r, dict) and _is_record_applicable(r)
    ]

    embedded_records = build_or_load_embeddings(year)

    aggregated = None

    for record in applicable_records:
        try:
            result = map_record_to_controls(record, embedded_records)

            controls = result.get("llm_answer", {}).get("controls", [])
            if not isinstance(controls, list):
                continue

            for c in controls:
                cid = _normalize_text(c.get("control_id"))
                cname = _normalize_text(c.get("control_name"))
                reason = _normalize_text(c.get("reason"))

                if cid != target_control_id:
                    continue

                if aggregated is None:
                    aggregated = {
                        "control_id": cid,
                        "control_name": cname,
                        "domain": "ISO 27001:2022 Control",
                        "applicable": True,
                        "implementation_status": "",
                        "justification": reason,
                        "related_risks": [],
                        "risk_ids": [],
                        "source_records": [],
                    }

                cve_id = _normalize_text(record.get("cve"))
                risk_id = _normalize_text(record.get("riskid"))

                if cve_id and cve_id not in aggregated["related_risks"]:
                    aggregated["related_risks"].append(cve_id)

                if risk_id and risk_id not in aggregated["risk_ids"]:
                    aggregated["risk_ids"].append(risk_id)

                aggregated["source_records"].append({
                    "hostname": _normalize_text(record.get("hostname")),
                    "role": _normalize_text(record.get("role")),
                    "riskid": risk_id,
                    "risk": _normalize_text(record.get("risk")),
                    "vulnerability_name": _normalize_text(record.get("vulnerability_name")),
                    "cve": cve_id,
                    "reason": reason,
                })

        except Exception:
            continue

    return aggregated
    
# =========================================================
# ROUTES
# =========================================================
@router.get("/inventory")
def get_annex_inventory(year: int = Query(2026)):
    doc = _load_annex_doc_or_blank(int(year))
    _sync_annex_status(int(year), doc)
    return doc


@router.post("/create")
def create_annex_a_soa(payload: CreateRequest):
    year = int(payload.year or 2026)
    current = _load_annex_doc_or_blank(year)

    if _annex_section_is_read_only(year):
        return {
            "success": False,
            "message": "Annex A & SoA has already been submitted and is now read-only.",
            "inventory": current,
        }

    if len(_all_controls(current)) > 0 and not payload.force:
        return {
            "success": False,
            "message": "AnnexA_SoA.json already exists and contains data. Pass force=true to replace it.",
            "inventory": current,
        }

    try:
        new_doc = _build_annex_from_risk_eval(year)
    except FileNotFoundError as e:
        return {
            "success": False,
            "message": str(e),
            "inventory": current,
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Annex A & SoA creation failed: {e}",
            "inventory": current,
        }

    _save_json(_annex_a_soa_file(year), new_doc)
    _set_section_status(year, "annex_a_soa", "In Progress")

    return {
        "success": True,
        "message": "Annex A & SoA table initialized successfully using Llama3 + RAG.",
        "inventory": new_doc,
    }


@router.get("/details")
def get_control_details(
    control_id: str = Query(...),
    year: int = Query(2026),
):
    doc = _load_annex_doc_or_blank(int(year))
    idx, control = _find_control(doc, control_id)

    if control is None or idx is None:
        return {
            "success": False,
            "message": f"Control '{control_id}' was not found.",
            "control": None,
        }

    return {
        "success": True,
        "control": control,
    }


@router.post("/update-status")
def update_control_status(payload: UpdateStatusRequest):
    year = int(payload.year or 2026)
    doc = _load_annex_doc_or_blank(year)

    if _annex_section_is_read_only(year):
        return {
            "success": False,
            "message": "Annex A & SoA has already been submitted and is now read-only.",
            "inventory": doc,
        }

    status_value = _normalize_text(payload.implementation_status)
    if status_value not in VALID_IMPLEMENTATION_STATUSES:
        return {
            "success": False,
            "message": (
                "Invalid implementation_status. Allowed values are: "
                "Not Implemented, Planned, In Progress, Implemented, Not Applicable."
            ),
            "inventory": doc,
        }

    idx, control = _find_control(doc, payload.control_id)
    if control is None or idx is None:
        return {
            "success": False,
            "message": f"Control '{payload.control_id}' was not found.",
            "inventory": doc,
        }

    old_value = _normalize_text(control.get("implementation_status"))
    control["implementation_status"] = status_value

    controls = doc.get("controls", [])
    if isinstance(controls, list):
        controls[idx] = control
        doc["controls"] = controls

    _save_json(_annex_a_soa_file(year), doc)
    _sync_annex_status(year, doc)

    return {
        "success": True,
        "message": (
            f"Implementation status updated for {payload.control_id}. "
            f"Old Value: {old_value or 'NA'} | New Value: {status_value or 'NA'}"
        ),
        "control_id": payload.control_id,
        "implementation_status": status_value,
        "inventory": doc,
    }


@router.post("/reset")
def reset_annex_a_soa(payload: ResetRequest):
    year = int(payload.year or 2026)
    doc = _load_annex_doc_or_blank(year)

    if _annex_section_is_read_only(year):
        return {
            "success": False,
            "message": "Annex A & SoA has already been submitted and is now read-only.",
            "inventory": doc,
        }

    if not payload.confirm:
        return {
            "success": True,
            "requires_confirmation": True,
            "message": "All implementation status values will be reset, are you sure?",
            "inventory": doc,
        }

    controls = _all_controls(doc)
    for control in controls:
        control["implementation_status"] = ""

    doc["controls"] = controls

    _save_json(_annex_a_soa_file(year), doc)
    _set_section_status(year, "annex_a_soa", "In Progress")

    return {
        "success": True,
        "message": "Annex A & SoA implementation status values have been reset.",
        "inventory": doc,
    }


@router.post("/submit")
def submit_annex_a_soa(payload: SubmitRequest):
    year = int(payload.year or 2026)
    doc = _load_annex_doc_or_blank(year)

    if not payload.confirm:
        return {
            "success": True,
            "requires_confirmation": True,
            "message": "The Annex A & SoA results will be finalized and locked, are you sure?",
            "inventory": doc,
        }

    controls = _all_controls(doc)
    if len(controls) == 0:
        return {
            "success": False,
            "message": "AnnexA_SoA.json is empty. Run /create first.",
            "inventory": doc,
        }

    incomplete = [
        c["control_id"]
        for c in controls
        if _normalize_text(c.get("applicable")).lower() != "false"
        and _normalize_text(c.get("implementation_status")) == ""
    ]

    if len(incomplete) > 0:
        return {
            "success": False,
            "message": (
                "You cannot submit the Annex A & SoA table while applicable controls have no "
                f"implementation status. Missing: {', '.join(incomplete)}"
            ),
            "inventory": doc,
        }

    status_doc = _load_system_status_or_default(year)
    status_doc["sections"]["annex_a_soa"]["status"] = "Completed"

    if status_doc["sections"].get("action_plan_implementation", {}).get("status") == "Blocked":
        status_doc["sections"]["action_plan_implementation"]["status"] = "In Progress"

    _save_json(_system_status_file(year), status_doc)

    return {
        "success": True,
        "message": "Annex A & SoA finalized.",
        "records_finalized": len(controls),
        "inventory": doc,
    }

@router.post("/delete")
def delete_annex_control(payload: DeleteRequest):
    year = int(payload.year or 2026)
    doc = _load_annex_doc_or_blank(year)

    if _annex_section_is_read_only(year):
        return {
            "success": False,
            "message": "Annex A & SoA has already been submitted and is now read-only.",
            "inventory": doc,
        }

    controls = _all_controls(doc)
    new_controls = [
        c for c in controls
        if _normalize_key(c.get("control_id")) != _normalize_key(payload.control_id)
    ]

    if len(new_controls) == len(controls):
        return {
            "success": False,
            "message": f"Control '{payload.control_id}' was not found.",
            "inventory": doc,
        }

    doc["controls"] = new_controls

    _save_json(_annex_a_soa_file(year), doc)
    _sync_annex_status(year, doc)

    return {
        "success": True,
        "message": f"Control {payload.control_id} deleted successfully.",
        "inventory": doc,
    }

@router.post("/recommend")
def recommend_controls(payload: RecommendRequest):
    year = int(payload.year or 2026)

    try:
        recommendations = _recommend_controls_from_risk_eval(year)

        return {
            "success": True,
            "message": "Recommended controls generated successfully.",
            "recommendations": recommendations
        }

    except FileNotFoundError as e:
        return {
            "success": False,
            "message": str(e),
            "recommendations": []
        }

    except Exception as e:
        return {
            "success": False,
            "message": f"Recommendation failed: {str(e)}",
            "recommendations": []
        }

@router.post("/add")
def add_control_to_annex(payload: AddRequest):
    year = int(payload.year or 2026)
    control_id = _normalize_text(payload.control_id)

    doc = _load_annex_doc_or_blank(year)

    if _annex_section_is_read_only(year):
        return {
            "success": False,
            "message": "Annex A & SoA has already been submitted and is now read-only.",
            "inventory": doc,
        }

    # Prevent duplicates
    existing_ids = {
        _normalize_key(c.get("control_id"))
        for c in _all_controls(doc)
    }

    if _normalize_key(control_id) in existing_ids:
        return {
            "success": False,
            "message": f"Control {control_id} already exists in the table.",
            "inventory": doc,
        }

    # Validate against recommend list
    try:
        recommendations = _recommend_controls_from_risk_eval(year)
        allowed_ids = {_normalize_key(r["control_id"]) for r in recommendations}

        if _normalize_key(control_id) not in allowed_ids:
            return {
                "success": False,
                "message": "Control must be selected from the recommendation list.",
                "inventory": doc,
            }

    except Exception as e:
        return {
            "success": False,
            "message": f"Failed to validate recommendation list: {str(e)}",
            "inventory": doc,
        }

    # Build control using RAG + LLM
    try:
        new_control = _build_single_control_from_rag(year, control_id)

        if not new_control:
            return {
                "success": False,
                "message": f"Failed to generate control {control_id} using RAG pipeline.",
                "inventory": doc,
            }

    except Exception as e:
        return {
            "success": False,
            "message": f"Control generation failed: {str(e)}",
            "inventory": doc,
        }

    # Add to table
    controls = _all_controls(doc)
    controls.append(new_control)
    doc["controls"] = sorted(controls, key=lambda x: x.get("control_id", ""))

    _save_json(_annex_a_soa_file(year), doc)
    _sync_annex_status(year, doc)

    return {
        "success": True,
        "message": f"Control {control_id} added successfully using Llama3 reasoning.",
        "inventory": doc,
    }