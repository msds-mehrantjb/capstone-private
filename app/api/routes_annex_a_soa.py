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

from app.api.aiml_kpi_telemetry import (
    ollama_total_tokens,
    safe_increment_llm_counter,
    safe_increment_rag_counter,
)


router = APIRouter(prefix="/api/annex-a-soa", tags=["annex-a-soa"])


VALID_STEP_STATUSES = {"Blocked", "Not Started", "In Progress", "Completed"}
ANNEX_PREREQUISITE_SECTIONS = (
    "scope_context",
    "assets_cia",
    "threats_vulns",
    "existing_controls_postures",
    "risk_analysis",
    "risk_evaluation_treatment",
)
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

class InfoRequest(BaseModel):
    year: int | None = 2026
    control_id: str
    
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


def _models_dir() -> Path:
    return BASE_DIR / "data" / "models"


def _knowledge_base_dir() -> Path:
    return BASE_DIR / "data" / "knowledge_base"


def _annex_a_soa_file(year: int) -> Path:
    return _work_dir(year) / "AnnexA_SoA.json"


def _risk_eval_treatment_file(year: int) -> Path:
    return _work_dir(year) / "RiskEvaluationTreatment.json"


def _action_plan_implementation_file(year: int) -> Path:
    return _work_dir(year) / "ActionPlanImplementation.json"


def _action_implementation_guides_file(year: int) -> Path:
    return _work_dir(year) / "ActionImplementationGuides.json"


def _legacy_action_plan_implementation_file(year: int) -> Path:
    return _work_dir(year) / "ActionPlanImplementaion.json"


def _system_status_file(year: int) -> Path:
    return _work_dir(year) / "SystemStatus.json"


def _controls_csv_file(year: int) -> Path:
    return _knowledge_base_dir() / "iso27002_controls_2022.csv"


def _embed_cache_file(year: int) -> Path:
    return _models_dir() / "iso27002_local_embeddings.pkl"


# =========================================================
# OLLAMA / RAG CONFIG
# =========================================================
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OLLAMA_GEN_URL = "http://localhost:11434/api/generate"
OLLAMA_EMBED_URL = "http://localhost:11434/api/embed"

EMBED_MODEL = "nomic-embed-text"
LLM_MODEL = "qwen3:14b"
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

CONTROL_TO_CVE_MAPPINGS = {
    "5.15": {
        "keywords": ["access control", "authorization", "unauthorized access"],
        "cwes": ["CWE-285", "CWE-862", "CWE-639"],
        "platform_keywords": [],
    },
    "5.17": {
        "keywords": ["authentication", "credentials", "password", "identity"],
        "cwes": ["CWE-287", "CWE-288"],
        "platform_keywords": [],
    },
    "5.18": {
        "keywords": ["access rights", "least privilege", "authorized access"],
        "cwes": ["CWE-285", "CWE-862", "CWE-250"],
        "platform_keywords": [],
    },
    "8.2": {
        "keywords": ["privileged access", "privilege escalation", "admin rights"],
        "cwes": ["CWE-269", "CWE-250", "CWE-285"],
        "platform_keywords": ["windows", "linux", "active directory"],
    },
    "8.5": {
        "keywords": ["secure authentication", "authentication bypass", "logon"],
        "cwes": ["CWE-287", "CWE-288", "CWE-425"],
        "platform_keywords": ["windows", "active directory", "sso"],
    },
    "8.8": {
        "keywords": ["technical vulnerability", "patch", "unpatched", "vulnerability management"],
        "cwes": [],
        "platform_keywords": [],
    },
    "8.9": {
        "keywords": ["configuration", "hardening", "secure configuration", "misconfiguration"],
        "cwes": [],
        "platform_keywords": ["windows", "linux", "apache", "nginx", "microsoft"],
    },
    "8.16": {
        "keywords": ["monitoring", "detection", "anomalous activity", "logging"],
        "cwes": [],
        "platform_keywords": [],
    },
    "8.20": {
        "keywords": ["network security", "remote attack", "network exposure", "remote code execution"],
        "cwes": [],
        "platform_keywords": ["windows", "vpn", "firewall", "router", "switch"],
    },
    "8.21": {
        "keywords": ["network services", "service exposure", "network-facing service"],
        "cwes": [],
        "platform_keywords": ["http", "https", "ssh", "rdp", "smb", "dns"],
    },
}

CONTROL_RECOMMEND_TOP_K_CVES = 5
CONTROL_RECOMMEND_TOP_K_CONTROLS = 5
NVD_PAGE_SIZE = 100

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


GENERIC_RETRIEVAL_FALLBACK_REASON = "Fallback from retrieval because LLM returned no valid controls."


def _is_generic_retrieval_fallback_reason(value: Any) -> bool:
    return _normalize_text(value).lower() == GENERIC_RETRIEVAL_FALLBACK_REASON.lower()


def _unique_nonempty(values: list[Any], limit: int = 3) -> list[str]:
    unique = []
    seen = set()

    for value in values:
        text = _normalize_text(value)
        key = text.lower()
        if text == "" or key in seen:
            continue
        seen.add(key)
        unique.append(text)
        if len(unique) >= limit:
            break

    return unique


def _source_record_context(source_records: Any) -> str:
    if not isinstance(source_records, list):
        return ""

    records = [item for item in source_records if isinstance(item, dict)]
    vulnerabilities = _unique_nonempty([item.get("vulnerability_name") for item in records])
    risks = _unique_nonempty([item.get("risk") for item in records])
    roles = _unique_nonempty([item.get("role") for item in records])

    context_parts = []
    if vulnerabilities:
        context_parts.append(f"vulnerabilities such as {', '.join(vulnerabilities)}")
    elif risks:
        context_parts.append(f"risks such as {', '.join(risks)}")

    if roles:
        context_parts.append(f"affected {', '.join(roles)} assets")

    return " across ".join(context_parts)


def _build_contextual_control_justification(
    control_id: str,
    control_name: str,
    source_records: Any = None,
    purpose: str = "",
    traits: Any = None,
) -> str:
    control_label = _normalize_text(control_id)
    name = _normalize_text(control_name)
    if name:
        control_label = f"{control_label} ({name})" if control_label else name

    source_context = _source_record_context(source_records)
    trait_values = _unique_nonempty(traits if isinstance(traits, list) else [])
    trait_context = ", ".join(trait_values)
    purpose_text = _normalize_text(purpose).rstrip(".")

    if source_context:
        return (
            f"Control {control_label} is recommended to address {source_context} "
            "and support the selected mitigation treatment."
        )

    if trait_context and purpose_text:
        return (
            f"Control {control_label} is recommended because the risk context includes "
            f"{trait_context}; its ISO 27002 purpose is {purpose_text}."
        )

    if trait_context:
        return (
            f"Control {control_label} is recommended because the risk context includes "
            f"{trait_context}."
        )

    if purpose_text:
        return (
            f"Control {control_label} is recommended because its ISO 27002 purpose is "
            f"{purpose_text}."
        )

    return (
        f"Control {control_label} is recommended based on the retrieved ISO 27002 "
        "match and the current risk evaluation context."
    )


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


def _safe_json_loads(value: str) -> Any:
    try:
        return json.loads(value)
    except Exception:
        return None


def _normalize_llm_controls_payload(
    raw_payload: Any,
    allowed_controls: list[dict],
    fallback_traits: Any = None,
) -> dict:
    """
    Normalize LLM output into:
    {
      "risk": "...",
      "controls": [
        {
          "control_id": "...",
          "control_name": "...",
          "reason": "..."
        }
      ]
    }

    Accepts these malformed variants too:
    - {"controls": "8.8"}
    - {"controls": ["8.8", "8.9"]}
    - {"controls": {"control_id": "8.8", ...}}
    - ["8.8", {"control_id": "8.9", ...}]
    - "8.8"
    """
    allowed_map = {}
    for item in allowed_controls:
        if not isinstance(item, dict):
            continue

        cid = _normalize_text(item.get("control_id"))
        if cid == "":
            continue

        allowed_map[_normalize_key(cid)] = {
            "control_id": cid,
            "control_name": _normalize_text(item.get("control_name")),
            "section": _normalize_text(item.get("section")),
            "purpose": _normalize_text(item.get("purpose")),
        }

    normalized = {
        "risk": "",
        "controls": [],
    }

    # allow raw payload itself to be list/string and not only dict
    if isinstance(raw_payload, dict):
        normalized["risk"] = _normalize_text(raw_payload.get("risk"))
        raw_controls = raw_payload.get("controls", [])
    elif isinstance(raw_payload, list):
        raw_controls = raw_payload
    elif isinstance(raw_payload, str):
        raw_controls = [raw_payload]
    else:
        raw_controls = []

    # normalize controls into a list
    if isinstance(raw_controls, dict):
        raw_controls = [raw_controls]
    elif isinstance(raw_controls, str):
        raw_controls = [raw_controls]
    elif not isinstance(raw_controls, list):
        raw_controls = []

    seen = set()

    for item in raw_controls:
        control_id = ""
        control_name = ""
        reason = ""

        # valid object case
        if isinstance(item, dict):
            control_id = _normalize_text(
                item.get("control_id")
                or item.get("id")
                or item.get("control")
            )
            control_name = _normalize_text(
                item.get("control_name")
                or item.get("name")
                or item.get("title")
            )
            reason = _normalize_text(
                item.get("reason")
                or item.get("justification")
                or item.get("why")
            )

        # plain string case: "8.8" or "8.8 - Management of technical vulnerabilities"
        elif isinstance(item, str):
            text = _normalize_text(item)

            # first try to extract an ISO control pattern like 8.8 / A.8.8
            match = re.search(r"\b(?:A\.)?(\d+\.\d+)\b", text, flags=re.IGNORECASE)
            if match:
                control_id = _normalize_text(match.group(1))
            else:
                # fallback: use full string
                control_id = text

            reason = "Selected by LLM from allowed controls."

        else:
            continue

        if control_id == "":
            continue

        key = _normalize_key(control_id)
        if key.startswith("a."):
            key = key[2:]  # normalize A.8.8 -> 8.8

        matched_key = None

        if key in allowed_map:
            matched_key = key
        else:
            # tolerant matching: "8.8" vs "A.8.8" or prefix variants
            for ak in allowed_map:
                if ak == key or ak.endswith(key) or key.endswith(ak):
                    matched_key = ak
                    break

        if not matched_key:
            continue

        resolved_control_id = allowed_map[matched_key]["control_id"]
        resolved_control_name = allowed_map[matched_key]["control_name"]

        if control_name == "":
            control_name = resolved_control_name

        if reason == "":
            reason = "Selected by LLM from allowed controls."

        if matched_key in seen:
            continue
        seen.add(matched_key)

        normalized["controls"].append({
            "control_id": resolved_control_id,
            "control_name": control_name,
            "reason": reason,
        })

    # fallback only from retrieved/allowed controls, never from malformed arbitrary data
    if len(normalized["controls"]) == 0:
        for item in allowed_controls[:3]:
            if not isinstance(item, dict):
                continue

            fallback_id = _normalize_text(item.get("control_id"))
            fallback_name = _normalize_text(item.get("control_name"))

            if fallback_id == "":
                continue

            fallback_key = _normalize_key(fallback_id)
            if fallback_key in seen:
                continue
            seen.add(fallback_key)

            normalized["controls"].append({
                "control_id": fallback_id,
                "control_name": fallback_name,
                "reason": _build_contextual_control_justification(
                    control_id=fallback_id,
                    control_name=fallback_name,
                    purpose=_normalize_text(item.get("purpose")),
                    traits=fallback_traits,
                ),
            })

    return normalized


def _extract_valid_controls_from_llm_answer(llm_answer: Any) -> list[dict]:
    """
    Extract only safe dict controls.
    Also accepts string controls and converts them to dicts so the caller
    never does item['control_id'] on a plain string.
    """
    if not isinstance(llm_answer, dict):
        return []

    raw_controls = llm_answer.get("controls", [])

    if isinstance(raw_controls, dict):
        raw_controls = [raw_controls]
    elif isinstance(raw_controls, str):
        raw_controls = [raw_controls]
    elif not isinstance(raw_controls, list):
        return []

    valid_controls = []

    for item in raw_controls:
        if isinstance(item, dict):
            control_id = _normalize_text(item.get("control_id"))
            control_name = _normalize_text(item.get("control_name"))
            reason = _normalize_text(item.get("reason"))
        elif isinstance(item, str):
            control_id = _normalize_text(item)
            control_name = ""
            reason = "Selected by LLM."
        else:
            continue

        if control_id == "":
            continue

        valid_controls.append({
            "control_id": control_id,
            "control_name": control_name,
            "reason": reason,
        })

    return valid_controls

def _tokenize_for_match(text: str) -> list[str]:
    return [t for t in re.findall(r"[a-zA-Z0-9\.\-]+", (text or "").lower()) if len(t) > 2]


def _keyword_score(text: str, query_terms: list[str]) -> float:
    text_l = (text or "").lower()
    if not query_terms:
        return 0.0

    hits = sum(1 for term in query_terms if term and term.lower() in text_l)
    return hits / max(len(query_terms), 1)


def _cosine_similarity_simple(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0

    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))

    if norm_a == 0 or norm_b == 0:
        return 0.0

    return dot / (norm_a * norm_b)


def _nvd_get(params: dict) -> dict:
    res = SESSION.get(NVD_API_URL, params=params, timeout=120)
    res.raise_for_status()
    return res.json()


def _parse_cve_item(item: dict) -> dict:
    cve = item.get("cve", {})

    cve_id = _normalize_text(cve.get("id"))
    description = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            description = _normalize_text(d.get("value"))
            break

    cwe_values = []
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            value = _normalize_text(desc.get("value"))
            if value:
                cwe_values.append(value)

    severity = ""
    metrics = cve.get("metrics", {})
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if key in metrics and metrics[key]:
            metric = metrics[key][0]
            cvss = metric.get("cvssData", {})
            severity = _normalize_text(metric.get("baseSeverity") or cvss.get("baseSeverity"))
            break

    cpes = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                crit = _normalize_text(cpe_match.get("criteria"))
                if crit:
                    cpes.append(crit)

    return {
        "cve_id": cve_id,
        "description": description,
        "cwes": sorted(set(cwe_values)),
        "severity": severity,
        "cpes": sorted(set(cpes)),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
    }


def _fetch_cves_by_cwe(cwe_id: str, max_results: int = 100) -> list[dict]:
    results = []
    start_index = 0

    while len(results) < max_results:
        data = _nvd_get({
            "cweId": cwe_id,
            "resultsPerPage": min(NVD_PAGE_SIZE, max_results - len(results)),
            "startIndex": start_index,
        })

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            break

        results.extend(_parse_cve_item(v) for v in vulns)

        total = int(data.get("totalResults", 0))
        start_index += int(data.get("resultsPerPage", len(vulns)))
        if start_index >= total:
            break

    return results[:max_results]


def _fetch_cves_by_keywords(keywords: list[str], max_results: int = 100) -> list[dict]:
    if not keywords:
        return []

    query = " ".join(keywords[:6])
    results = []
    start_index = 0

    while len(results) < max_results:
        data = _nvd_get({
            "keywordSearch": query,
            "resultsPerPage": min(NVD_PAGE_SIZE, max_results - len(results)),
            "startIndex": start_index,
        })

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            break

        results.extend(_parse_cve_item(v) for v in vulns)

        total = int(data.get("totalResults", 0))
        start_index += int(data.get("resultsPerPage", len(vulns)))
        if start_index >= total:
            break

    return results[:max_results]


def _build_control_profile_for_cves(control: dict) -> dict:
    control_id = _normalize_text(control.get("control_id") or control.get("control"))
    control_name = _normalize_text(control.get("control_name"))
    justification = _normalize_text(control.get("justification"))

    hints = CONTROL_TO_CVE_MAPPINGS.get(control_id, {})

    title_tokens = _tokenize_for_match(control_name)
    justification_tokens = _tokenize_for_match(justification)

    keywords = []
    seen = set()

    for item in hints.get("keywords", []) + title_tokens[:6] + justification_tokens[:6]:
        key = _normalize_text(item)
        if key and key not in seen:
            seen.add(key)
            keywords.append(item)

    return {
        "control_id": control_id,
        "control_name": control_name,
        "justification": justification,
        "keywords": keywords,
        "cwes": hints.get("cwes", []),
        "platform_keywords": hints.get("platform_keywords", []),
    }


def _collect_candidate_cves_for_control(control_profile: dict, max_results_per_source: int = 60) -> list[dict]:
    all_candidates = []

    for cwe_id in control_profile.get("cwes", []):
        try:
            all_candidates.extend(_fetch_cves_by_cwe(cwe_id, max_results=max_results_per_source))
        except Exception:
            pass

    try:
        all_candidates.extend(
            _fetch_cves_by_keywords(control_profile.get("keywords", []), max_results=max_results_per_source)
        )
    except Exception:
        pass

    deduped = {}
    for item in all_candidates:
        cve_id = _normalize_text(item.get("cve_id"))
        if cve_id:
            deduped[cve_id] = item

    return list(deduped.values())


def _cve_document_text(cve: dict) -> str:
    return (
        f"CVE ID: {_normalize_text(cve.get('cve_id'))}\n"
        f"Description: {_normalize_text(cve.get('description'))}\n"
        f"CWE: {'; '.join(cve.get('cwes', []))}\n"
        f"Severity: {_normalize_text(cve.get('severity'))}\n"
        f"CPEs: {'; '.join(cve.get('cpes', [])[:10])}"
    )


def _compute_cve_boost(control_profile: dict, cve: dict) -> float:
    text = _normalize_text(
        " ".join([
            _normalize_text(cve.get("description")),
            " ".join(cve.get("cwes", [])),
            " ".join(cve.get("cpes", [])),
        ])
    )

    boost = 0.0

    for platform_word in control_profile.get("platform_keywords", []):
        if _normalize_text(platform_word) and _normalize_text(platform_word) in text:
            boost += 0.05

    severity = _normalize_text(cve.get("severity")).lower()
    if severity == "critical":
        boost += 0.10
    elif severity == "high":
        boost += 0.06

    control_id = _normalize_text(control_profile.get("control_id"))
    if control_id == "8.2" and "privilege" in text:
        boost += 0.15
    if control_id == "8.5" and ("authentication" in text or "bypass" in text or "logon" in text):
        boost += 0.15
    if control_id == "8.8":
        boost += 0.05

    return boost


def _rank_cves_for_control(control_profile: dict, candidate_cves: list[dict], top_k: int = 5) -> list[dict]:
    if not candidate_cves:
        return []

    query_text = (
        f"Control ID: {_normalize_text(control_profile.get('control_id'))}\n"
        f"Control Name: {_normalize_text(control_profile.get('control_name'))}\n"
        f"Justification: {_normalize_text(control_profile.get('justification'))}\n"
        f"Keywords: {'; '.join(control_profile.get('keywords', []))}\n"
        f"CWEs: {'; '.join(control_profile.get('cwes', []))}"
    )

    try:
        query_embedding = get_embedding(query_text)
    except Exception:
        query_embedding = []

    query_terms = _tokenize_for_match(
        " ".join(control_profile.get("keywords", []) + control_profile.get("cwes", []))
    )

    scored = []
    for cve in candidate_cves:
        cve_text = _cve_document_text(cve)

        try:
            cve_embedding = get_embedding(cve_text)
        except Exception:
            cve_embedding = []

        semantic = _cosine_similarity_simple(query_embedding, cve_embedding) if query_embedding and cve_embedding else 0.0
        keyword = _keyword_score(cve_text, query_terms)
        boost = _compute_cve_boost(control_profile, cve)

        final_score = (semantic * 0.65) + (keyword * 0.25) + boost

        scored.append({
            "cve_id": _normalize_text(cve.get("cve_id")),
            "description": _normalize_text(cve.get("description")),
            "cwes": cve.get("cwes", []),
            "severity": _normalize_text(cve.get("severity")),
            "published": cve.get("published"),
            "last_modified": cve.get("last_modified"),
            "final_score": final_score,
        })

    scored.sort(key=lambda x: x["final_score"], reverse=True)
    return scored[:top_k]


def _load_iso_records_for_recommend(year: int) -> list[dict]:
    csv_file = _controls_csv_file(year)
    if not csv_file.exists():
        raise FileNotFoundError(f"Control catalog file not found: {csv_file}")

    df = pd.read_csv(csv_file)
    records = []

    for _, row in df.iterrows():
        control_id = _normalize_text(row.get("Control"))
        title = _normalize_text(row.get("Title"))
        section = _normalize_text(row.get("Section"))
        status = _normalize_text(row.get("Status"))
        purpose = _normalize_text(row.get("Purpose"))

        records.append({
            "_control_id": control_id,
            "Title": title,
            "Section": section,
            "Status": status,
            "Purpose": purpose,
            "_text": (
                f"Section: {section}\n"
                f"Control ID: {control_id}\n"
                f"Control Name: {title}\n"
                f"Status: {status}\n"
                f"Purpose: {purpose}\n"
                f"Keywords: {'; '.join(CONTROL_HINTS.get(control_id, []))}"
            ),
        })

    return records

def _get_iso_record_by_control_id(year: int, control_id: str) -> dict | None:
    target = _normalize_text(control_id)
    if target == "":
        return None

    for rec in _load_iso_records_for_recommend(year):
        if _normalize_text(rec.get("_control_id")) == target:
            return rec

    return None

def _infer_controls_from_cves(year: int, ranked_cves: list[dict], exclude_control_ids: set[str]) -> list[dict]:
    iso_records = _load_iso_records_for_recommend(year)
    embedded_records = build_or_load_embeddings(year, force_rebuild=True)

    embedding_by_control = {}
    for item in embedded_records:
        if not isinstance(item, dict):
            continue
        cid = _normalize_text(item.get("Control"))
        if cid:
            embedding_by_control[cid] = item

    recommendations = []
    added = set()

    for cve in ranked_cves:
        cve_id = _normalize_text(cve.get("cve_id"))
        cve_desc = _normalize_text(cve.get("description"))
        if not cve_desc:
            continue

        query_terms = _tokenize_for_match(cve_desc)

        try:
            query_embedding = get_embedding(cve_desc)
            use_semantic = True
        except Exception:
            query_embedding = []
            use_semantic = False

        scored: list[tuple[float, dict]] = []

        for rec in iso_records:
            rec_control_id = _normalize_text(rec.get("_control_id"))
            if rec_control_id in exclude_control_ids:
                continue

            rec_text = rec.get("_text", "")
            semantic = 0.0

            if use_semantic and rec_control_id in embedding_by_control:
                try:
                    semantic = cosine_similarity(
                        query_embedding,
                        embedding_by_control[rec_control_id]["embedding"]
                    )
                except Exception:
                    semantic = 0.0

            keyword = _keyword_score(rec_text, query_terms)

            boost = 0.0
            if "CWE-" in cve_desc and "technical vulnerability" in rec_text.lower():
                boost += 0.10
            if any(x in cve_desc.lower() for x in ["authentication", "credentials", "password", "logon", "mfa"]):
                if rec_control_id in {"5.17", "8.5"}:
                    boost += 0.15
            if any(x in cve_desc.lower() for x in ["privilege", "elevation of privilege", "administrator"]):
                if rec_control_id in {"5.18", "8.2"}:
                    boost += 0.15
            if any(x in cve_desc.lower() for x in ["configuration", "misconfiguration", "hardening"]):
                if rec_control_id == "8.9":
                    boost += 0.15
            if any(x in cve_desc.lower() for x in ["remote code execution", "network", "service exposure"]):
                if rec_control_id in {"8.20", "8.21"}:
                    boost += 0.15
            if any(x in cve_desc.lower() for x in ["logging", "audit", "event"]):
                if rec_control_id == "8.16":
                    boost += 0.10
            if any(x in cve_desc.lower() for x in ["monitoring", "detection", "alert"]):
                if rec_control_id == "8.16":
                    boost += 0.10

            final_score = (semantic * 0.50) + (keyword * 0.35) + boost
            scored.append((final_score, rec))

        scored.sort(key=lambda x: x[0], reverse=True)

        for score, rec in scored[:CONTROL_RECOMMEND_TOP_K_CONTROLS]:
            rec_control_id = _normalize_text(rec.get("_control_id"))
            if not rec_control_id or rec_control_id in exclude_control_ids or rec_control_id in added:
                continue

            added.add(rec_control_id)
            recommendations.append({
                "control_id": rec_control_id,
                "control_name": _normalize_text(rec.get("Title")),
                "justification": (
                    f"Recommended based on CVE {cve_id or 'N/A'} and related vulnerability context."
                ),
            })

    return recommendations


def _sort_recommendations_by_control_id(recommendations: list[dict]) -> list[dict]:
    return sorted(recommendations, key=lambda x: _normalize_text(x.get("control_id")))

def _infer_domain_from_control_id(control_id: str) -> str:
    cid = _normalize_text(control_id)

    if cid.startswith("5."):
        return "Organizational Controls"
    if cid.startswith("6."):
        return "People Controls"
    if cid.startswith("7."):
        return "Physical Controls"
    if cid.startswith("8."):
        return "Technological Controls"

    return "ISO 27001:2022 Control"
    
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
                "threats_vulns": {"status": "Not Started"},
                "existing_controls_postures": {"status": "Not Started"},
                "risk_analysis": {"status": "Not Started"},
                "risk_evaluation_treatment": {"status": "Not Started"},
                "annex_a_soa": {"status": "Not Started"},
                "action_plan_implementation": {"status": "Not Started"},
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
        "threats_vulns": {"status": "Not Started"},
        "existing_controls_postures": {"status": "Not Started"},
        "risk_analysis": {"status": "Not Started"},
        "risk_evaluation_treatment": {"status": "Not Started"},
        "annex_a_soa": {"status": "Not Started"},
        "action_plan_implementation": {"status": "Not Started"},
    }

    for section_name, default_value in defaults.items():
        if not isinstance(data["sections"].get(section_name), dict):
            data["sections"][section_name] = default_value

    return data


def _mark_annex_prerequisites_completed(status_doc: dict) -> dict:
    if not isinstance(status_doc, dict):
        status_doc = {}

    sections = status_doc.get("sections")
    if not isinstance(sections, dict):
        sections = {}
        status_doc["sections"] = sections

    for section_name in ANNEX_PREREQUISITE_SECTIONS:
        section = sections.get(section_name)
        if not isinstance(section, dict):
            section = {}
            sections[section_name] = section
        section["status"] = "Completed"

    annex_section = sections.get("annex_a_soa")
    if not isinstance(annex_section, dict):
        annex_section = {}
        sections["annex_a_soa"] = annex_section
    annex_section["status"] = "Completed"

    return status_doc


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
        status_doc = _mark_annex_prerequisites_completed(_load_system_status_or_default(year))
        _save_json(_system_status_file(year), status_doc)
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


def _action_plan_field_order(year: int) -> list[str]:
    template_path = _action_plan_template_file(year)
    if template_path is None:
        return list(ACTION_PLAN_DEFAULT_FIELDS)

    try:
        template_doc = _load_json(template_path)
        hosts = template_doc.get("hosts")
        if not isinstance(hosts, list) or len(hosts) == 0 or not isinstance(hosts[0], dict):
            return list(ACTION_PLAN_DEFAULT_FIELDS)

        ordered_fields = list(hosts[0].keys())
        for field_name in ACTION_PLAN_DEFAULT_FIELDS:
            if field_name not in ordered_fields:
                ordered_fields.append(field_name)

        return ordered_fields
    except Exception:
        return list(ACTION_PLAN_DEFAULT_FIELDS)


def _append_unique(mapping: dict[str, list[str]], key: Any, value: Any) -> None:
    normalized_key = _normalize_key(key)
    normalized_value = _normalize_text(value)

    if normalized_key == "" or normalized_value == "":
        return

    bucket = mapping.setdefault(normalized_key, [])
    if normalized_value not in bucket:
        bucket.append(normalized_value)


def _build_action_plan_control_lookup(doc: dict) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    controls_by_risk_id: dict[str, list[str]] = {}
    controls_by_cve: dict[str, list[str]] = {}

    for control in _all_controls(doc):
        control_id = _normalize_text(control.get("control_id"))
        if control_id == "":
            continue

        risk_ids = control.get("risk_ids")
        if isinstance(risk_ids, list):
            for risk_id in risk_ids:
                _append_unique(controls_by_risk_id, risk_id, control_id)

        source_records = control.get("source_records")
        if not isinstance(source_records, list):
            continue

        for source_record in source_records:
            if not isinstance(source_record, dict):
                continue

            _append_unique(controls_by_risk_id, source_record.get("riskid"), control_id)
            _append_unique(controls_by_cve, source_record.get("cve"), control_id)

    return controls_by_risk_id, controls_by_cve


def _blank_evidence() -> dict:
    return {
        "responsible": "",
        "resources": "",
        "date": "",
        "url": "",
        "desc": ""
    }


def _blank_host_from_record(record: dict) -> dict:
    return {
        "hostname": _normalize_text(record.get("hostname")),
        "ip_address": _normalize_text(record.get("ip_address")),
        "role": _normalize_text(record.get("role")),
        "CIA rating": _normalize_text(record.get("CIA rating")),
        "vulnerability_name": _normalize_text(record.get("vulnerability_name")),
        "cve": _normalize_text(record.get("cve")),
        "riskid": _normalize_text(record.get("riskid")),
        "evidence": [_blank_evidence()]
    }


def _build_action_plan_doc(year: int, annex_doc: dict) -> dict:
    controls = _all_controls(annex_doc)
    action_plan_controls = []

    for control in controls:
        control_id = _normalize_text(control.get("control_id") or control.get("control"))
        control_name = _normalize_text(control.get("control_name"))
        implementation_status = _normalize_text(control.get("implementation_status")) or "In Progress"
        justification = _normalize_text(control.get("justification"))
        treatment_action = _normalize_text(control.get("treatment_action"))

        source_records = control.get("source_records", [])
        if not isinstance(source_records, list):
            source_records = []

        if _is_generic_retrieval_fallback_reason(justification):
            justification = _build_contextual_control_justification(
                control_id=control_id,
                control_name=control_name,
                source_records=source_records,
            )

        hosts = []
        for record in source_records:
            if isinstance(record, dict):
                hosts.append(_blank_host_from_record(record))

        action_plan_controls.append({
            "control": control_id,
            "control_name": control_name,
            "implementation_status": implementation_status,
            "justification": justification,
            "treatment_action": treatment_action,
            "hosts": hosts
        })

    return {
        "controls": action_plan_controls
    }

def _restore_action_plan_doc_if_missing(year: int, annex_doc: dict, force: bool = False) -> tuple[Path, dict, str]:
    output_path = _action_plan_implementation_file(year)

    if output_path.exists() and not force:
        try:
            existing_doc = _load_json(output_path)
            if isinstance(existing_doc, dict):
                return output_path, existing_doc, "existing"
        except Exception:
            pass

    legacy_output_path = _legacy_action_plan_implementation_file(year)
    if legacy_output_path.exists() and not force:
        try:
            legacy_doc = _load_json(legacy_output_path)
            if isinstance(legacy_doc, dict):
                _save_json(output_path, legacy_doc)
                return output_path, legacy_doc, "migrated"
        except Exception:
            pass

    action_plan_doc = _build_action_plan_doc(year, annex_doc)
    _save_json(output_path, action_plan_doc)
    return output_path, action_plan_doc, "generated"
    

def _format_control_label(control: dict) -> str:
    control_id = _normalize_text(control.get("control_id")) or "Unknown Control"
    control_name = _normalize_text(control.get("control_name"))

    if control_name == "":
        return control_id

    return f"{control_id} ({control_name})"


# =========================================================
# RISK EVALUATION LOADING
# =========================================================
def _load_risk_eval_doc(year: int) -> dict:
    path = _risk_eval_treatment_file(year)
    if not path.exists():
        raise FileNotFoundError(
            "Finalize the risk evaluation/treatment step first."
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


def retrieve_controls(query_text, traits, embedded_records, top_k=TOP_K, year: int = 2026):
    query_embedding = get_embedding(query_text)
    query_tokens = tokenize(query_text)

    scored = []

    for record in embedded_records:
        # 🔥 FIX: skip invalid records
        if not isinstance(record, dict):
            print("SKIPPED invalid embedded record:", repr(record))
            continue

        if "embedding" not in record:
            print("SKIPPED missing embedding:", record)
            continue

        if "text" not in record:
            print("SKIPPED missing text:", record)
            continue

        try:
            semantic = cosine_similarity(query_embedding, record["embedding"])
        except Exception as e:
            print("SKIPPED bad embedding:", str(e))
            continue

        record_tokens = tokenize(record["text"])
        keyword = len(query_tokens & record_tokens) / max(1, len(query_tokens))

        boost = 0.0
        if "privilege escalation" in traits and record.get("Control") == "8.2":
            boost += 0.2
        if "authentication weakness" in traits and record.get("Control") == "8.5":
            boost += 0.2
        if "technical vulnerability" in traits and record.get("Control") == "8.8":
            boost += 0.2
        if "configuration weakness" in traits and record.get("Control") == "8.9":
            boost += 0.2
        if "network-based exploitation" in traits and record.get("Control") in {"8.20", "8.21"}:
            boost += 0.2

        final_score = (semantic * 0.65) + (keyword * 0.25) + boost

        scored.append({
            "final_score": final_score,
            "record": record
        })

    scored.sort(key=lambda x: x["final_score"], reverse=True)
    retrieved = scored[:top_k]
    safe_increment_rag_counter(year, success=bool(retrieved))
    return retrieved

def _generate_control_info_with_llama3(info_context: dict, year: int = 2026) -> dict:
    control_id = _normalize_text(info_context.get("control_id"))
    control_name = _normalize_text(info_context.get("control_name"))
    domain = _normalize_text(info_context.get("domain"))
    section = _normalize_text(info_context.get("section"))
    status = _normalize_text(info_context.get("status"))
    purpose = _normalize_text(info_context.get("purpose"))
    recommendation_justification = _normalize_text(info_context.get("recommendation_justification"))
    annex_justification = _normalize_text(info_context.get("annex_justification"))
    related_risks = info_context.get("related_risks", [])
    risk_ids = info_context.get("risk_ids", [])
    host_lines = info_context.get("host_lines", [])

    prompt = f"""
You are an ISO 27001:2022 and ISO 27002:2022 expert.

Generate control information for one recommended control.

STRICT RULES:
1. Return ONLY valid JSON.
2. Do NOT return markdown.
3. Do NOT add extra keys.
4. Use this exact schema:
{{
  "domain": "string",
  "concern": "string",
  "justification": "string"
}}

Control Context:
Control ID: {control_id}
Control Name: {control_name}
Domain: {domain}
Section: {section}
Status: {status}
Purpose: {purpose}

Recommendation Justification:
{recommendation_justification or "NA"}

Existing Annex Justification:
{annex_justification or "NA"}

Related Risks:
{json.dumps(related_risks, ensure_ascii=False)}

Risk IDs:
{json.dumps(risk_ids, ensure_ascii=False)}

Source Records:
{json.dumps(host_lines, ensure_ascii=False, indent=2)}

Output Requirements:
- "domain" must reflect the ISO control family for this control.
- "concern" must briefly state what security concern or problem this control addresses.

- "justification" MUST:
  • Explain why this control is needed based on identified vulnerabilities
  • Focus on weaknesses, misconfigurations, missing controls, or exposure
  • MUST NOT mention CVE IDs
  • MUST NOT include CVE numbers or CVE references
  • MUST describe vulnerability types instead (e.g., "unpatched systems", "weak authentication", "exposed services")
""".strip()

    response = SESSION.post(
        OLLAMA_GEN_URL,
        json={
            "model": LLM_MODEL,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "keep_alive": "10m",
            "options": {
                "temperature": 0.2,
                "top_p": 0.9,
                "num_predict": 400
            }
        },
        timeout=180
    )
    response.raise_for_status()

    response_data = response.json()
    safe_increment_llm_counter(year, ollama_total_tokens(response_data))
    raw = response_data.get("response", "")
    parsed = _safe_json_loads(raw)

    if not isinstance(parsed, dict):
        return {
            "domain": domain or "ISO 27001:2022 Control",
            "concern": purpose or f"Security concern addressed by control {control_id}.",
            "justification": recommendation_justification or annex_justification or f"Control {control_id} is relevant to the current risk context.",
        }
        
    justification_raw = _normalize_text(parsed.get("justification"))
    
    justification_clean = _remove_cve_references(
        justification_raw or recommendation_justification or annex_justification
    )
    
    return {
        "domain": _normalize_text(parsed.get("domain")) or domain or "ISO 27001:2022 Control",
        "concern": _normalize_text(parsed.get("concern")) or purpose or f"Security concern addressed by control {control_id}.",
        "justification": justification_clean,
    }

def _apply_create_like_context_to_control(year: int, control: dict) -> dict:
    """
    Enrich a control with the same contextual generation behavior used by
    the create/info pipeline so /add produces domain + justification
    from the same source context.
    """
    if not isinstance(control, dict):
        return control

    control_id = _normalize_text(control.get("control_id"))
    if control_id == "":
        return control

    try:
        info_context = _build_recommended_control_info_context(year, control_id)
    except Exception:
        info_context = None

    if info_context is None:
        # Safe fallback: preserve existing values, but ensure domain exists
        control["domain"] = _normalize_text(control.get("domain")) or _infer_domain_from_control_id(control_id)
        control["justification"] = _normalize_text(control.get("justification"))
        return control

    try:
        llm_info = _generate_control_info_with_llama3(info_context, year=year)
    except Exception:
        llm_info = None

    control["domain"] = (
        _normalize_text((llm_info or {}).get("domain"))
        or _normalize_text(control.get("domain"))
        or _infer_domain_from_control_id(control_id)
    )

    control["justification"] = (
        _normalize_text((llm_info or {}).get("justification"))
        or _normalize_text(control.get("justification"))
        or _normalize_text(info_context.get("annex_justification"))
        or _normalize_text(info_context.get("recommendation_justification"))
    )

    # Optional but useful: keep control name aligned with the richer context
    control["control_name"] = (
        _normalize_text(control.get("control_name"))
        or _normalize_text(info_context.get("control_name"))
    )

    return control

def _remove_cve_references(text: str) -> str:
    if not text:
        return ""
    return re.sub(r"CVE-\d{4}-\d{4,7}", "", text, flags=re.IGNORECASE)

    
def ask_llama3_for_controls(risk_id: str, query_text: str, traits, retrieved_controls, year: int = 2026):
    allowed_controls = []

    for item in retrieved_controls:
        if not isinstance(item, dict):
            continue

        record_obj = item.get("record")
        if not isinstance(record_obj, dict):
            continue

        allowed_controls.append({
            "control_id": _normalize_text(record_obj.get("Control")),
            "control_name": _normalize_text(record_obj.get("Title")),
            "section": _normalize_text(record_obj.get("Section")),
            "purpose": _normalize_text(record_obj.get("Purpose")),
        })

    prompt = f"""
You are an ISO 27001:2022 expert.

Risk ID: {risk_id}
Query: {query_text}
Traits: {traits}

You must choose the best fitting controls ONLY from the allowed list below.

Rules:
1. Return ONLY valid JSON.
2. Do NOT return markdown.
3. "controls" must be a JSON array.
4. Each element inside "controls" must be an object with:
   - "control_id": string
   - "control_name": string
   - "reason": string

Allowed controls:
{json.dumps(allowed_controls, indent=2)}

Return valid JSON only.
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

    response_data = response.json()
    safe_increment_llm_counter(year, ollama_total_tokens(response_data))
    raw = response_data.get("response", "")
    parsed = _safe_json_loads(raw)

    normalized = _normalize_llm_controls_payload(
        parsed,
        allowed_controls,
        fallback_traits=traits,
    )
    if normalized["risk"] == "":
        normalized["risk"] = risk_id

    return normalized

def _safe_fetch_cve_description(cve_id: str) -> tuple[str, str | None]:
    try:
        cve_info = fetch_cve_from_nvd(cve_id)
        return cve_info.get("description", ""), cve_info.get("severity")
    except Exception:
        return "", None


def map_record_to_controls(record: dict, embedded_records: list[dict], year: int = 2026) -> dict:
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

    retrieved = retrieve_controls(query_text, traits, embedded_records, top_k=TOP_K, year=year)

    llm_answer = ask_llama3_for_controls(
        risk_id=risk_id,
        query_text=query_text,
        traits=traits,
        retrieved_controls=retrieved,
        year=year,
    )

    controls = _extract_valid_controls_from_llm_answer(llm_answer)

    if not controls:
        raise ValueError(f"No valid controls returned for risk {risk_id}")

    for control in controls:
        if not isinstance(control, dict):
            raise ValueError(f"Invalid control object for risk {risk_id}")
        if _normalize_text(control.get('control_id')) == "":
            raise ValueError(f"Missing control_id for risk {risk_id}")

    return {
        "risk_id": risk_id,
        "cve": cve_id,
        "query_text": query_text,
        "traits": traits,
        "retrieved": retrieved,
        "llm_answer": {
            "risk": risk_id,
            "controls": controls,
        },
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

    embedded_records = build_or_load_embeddings(year, force_rebuild=True)

    matched_controls: dict[str, dict] = {}

    for record in applicable_records:
        try:
            result = map_record_to_controls(record, embedded_records, year=year)
            risk_id = result["risk_id"]
            cve_id = result["cve"]

            controls = result.get("llm_answer", {}).get("controls", [])
            if not isinstance(controls, list):
                raise ValueError(f"Invalid controls format for risk {risk_id}")

            for control in controls:
                if not isinstance(control, dict):
                    raise ValueError(f"Invalid control object for risk {risk_id}: {control}")

                control_id = _normalize_text(control.get("control_id"))
                control_name = _normalize_text(control.get("control_name"))
                reason = _normalize_text(control.get("reason"))

                if _is_generic_retrieval_fallback_reason(reason):
                    reason = _build_contextual_control_justification(
                        control_id=control_id,
                        control_name=control_name,
                        source_records=[record],
                        traits=result.get("traits"),
                    )

                if not control_id:
                    continue

                if control_id not in matched_controls:
                    matched_controls[control_id] = {
                        "control_id": control_id,
                        "control_name": control_name,
                        "domain": _infer_domain_from_control_id(control_id),
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
            print("FAILED RECORD:", json.dumps(record, indent=2))
            print(f"[ERROR] Control mapping failed for record {record.get('riskid')}: {str(e)}")
            continue

    controls = sorted(
        matched_controls.values(),
        key=lambda x: x.get("control_id", "")
    )

    return {"controls": controls}

def _recommend_controls_from_annex(year: int) -> list[dict]:
    doc = _load_annex_doc_or_blank(year)
    controls = _all_controls(doc)

    if not controls:
        return [{
            "control_id": "8.8",
            "control_name": "Management of technical vulnerabilities",
            "justification": "Default fallback recommendation because no Annex A & SoA controls currently exist.",
        }]

    existing_ids = {
        _normalize_key(c.get("control_id") or c.get("control"))
        for c in controls
        if isinstance(c, dict)
    }

    all_ranked_cves = []

    for control in controls:
        control_profile = _build_control_profile_for_cves(control)

        candidate_cves = _collect_candidate_cves_for_control(
            control_profile,
            max_results_per_source=40,
        )

        ranked_cves = _rank_cves_for_control(
            control_profile,
            candidate_cves,
            top_k=CONTROL_RECOMMEND_TOP_K_CVES,
        )

        all_ranked_cves.extend(ranked_cves)

        source_records = control.get("source_records", [])
        if isinstance(source_records, list):
            for host in source_records:
                if not isinstance(host, dict):
                    continue

                host_desc = " ".join([
                    _normalize_text(host.get("vulnerability_name")),
                    _normalize_text(host.get("cve")),
                    _normalize_text(host.get("risk")),
                    _normalize_text(host.get("role")),
                ]).strip()

                if not host_desc:
                    continue

                all_ranked_cves.append({
                    "cve_id": _normalize_text(host.get("cve")),
                    "description": host_desc,
                    "cwes": [],
                    "severity": "",
                    "published": None,
                    "last_modified": None,
                    "final_score": 0.30,
                })

    deduped_cves = {}
    for item in all_ranked_cves:
        cve_key = _normalize_text(item.get("cve_id")) or _normalize_text(item.get("description"))
        if not cve_key:
            continue

        if cve_key not in deduped_cves or item.get("final_score", 0.0) > deduped_cves[cve_key].get("final_score", 0.0):
            deduped_cves[cve_key] = item

    ranked_unique_cves = sorted(
        deduped_cves.values(),
        key=lambda x: x.get("final_score", 0.0),
        reverse=True,
    )[:10]

    recommendations = _infer_controls_from_cves(
        year=year,
        ranked_cves=ranked_unique_cves,
        exclude_control_ids=existing_ids,
    )

    deduped_recommendations = []
    seen = set()

    for item in recommendations:
        cid = _normalize_key(item.get("control_id"))
        if cid and cid not in seen and cid not in existing_ids:
            seen.add(cid)
            deduped_recommendations.append(item)

    deduped_recommendations = _sort_recommendations_by_control_id(deduped_recommendations)

    if len(deduped_recommendations) == 0:
        if "8.8" not in existing_ids:
            return [{
                "control_id": "8.8",
                "control_name": "Management of technical vulnerabilities",
                "justification": "Default fallback recommendation because no additional controls were inferred.",
            }]
        return []

    return deduped_recommendations

def _build_single_control_from_annex_recommendation(
    year: int,
    target_control_id: str,
    recommendation_justification: str = ""
) -> dict | None:
    target_control_id = _normalize_text(target_control_id)
    if target_control_id == "":
        return None

    annex_doc = _load_annex_doc_or_blank(year)
    existing_controls = _all_controls(annex_doc)

    iso_records = _load_iso_records_for_recommend(year)
    iso_match = None

    for rec in iso_records:
        if _normalize_text(rec.get("_control_id")) == target_control_id:
            iso_match = rec
            break

    if iso_match is None:
        return None

    aggregated_source_records = []
    related_risks = []
    risk_ids = []
    seen_source_keys = set()

    for control in existing_controls:
        source_records = control.get("source_records", [])
        if not isinstance(source_records, list):
            continue

        for record in source_records:
            if not isinstance(record, dict):
                continue

            record_key = (
                _normalize_text(record.get("hostname")),
                _normalize_text(record.get("riskid")),
                _normalize_text(record.get("cve")),
                _normalize_text(record.get("vulnerability_name")),
            )

            if record_key in seen_source_keys:
                continue

            seen_source_keys.add(record_key)
            aggregated_source_records.append({
                "hostname": _normalize_text(record.get("hostname")),
                "ip_address": _normalize_text(record.get("ip_address")),
                "role": _normalize_text(record.get("role")),
                "CIA rating": _normalize_text(record.get("CIA rating")),
                "riskid": _normalize_text(record.get("riskid")),
                "risk": _normalize_text(record.get("risk")),
                "vulnerability_name": _normalize_text(record.get("vulnerability_name")),
                "cve": _normalize_text(record.get("cve")),
                "evaluation": _normalize_text(record.get("evaluation")),
                "treatment": _normalize_text(record.get("treatment")),
                "reason": f"Recommended from Annex A & SoA analysis for control {target_control_id}.",
            })

            cve_id = _normalize_text(record.get("cve"))
            risk_id = _normalize_text(record.get("riskid"))

            if cve_id and cve_id not in related_risks:
                related_risks.append(cve_id)

            if risk_id and risk_id not in risk_ids:
                risk_ids.append(risk_id)

    if not aggregated_source_records:
        try:
            risk_eval_doc = _load_risk_eval_doc(year)
            hosts = risk_eval_doc.get("hosts", [])
            for record in hosts:
                if not isinstance(record, dict):
                    continue
                if not _is_record_applicable(record):
                    continue

                aggregated_source_records.append({
                    "hostname": _normalize_text(record.get("hostname")),
                    "ip_address": _normalize_text(record.get("ip_address")),
                    "role": _normalize_text(record.get("role")),
                    "CIA rating": _normalize_text(record.get("CIA rating")),
                    "riskid": _normalize_text(record.get("riskid")),
                    "risk": _normalize_text(record.get("risk")),
                    "vulnerability_name": _normalize_text(record.get("vulnerability_name")),
                    "cve": _normalize_text(record.get("cve")),
                    "evaluation": _normalize_text(record.get("evaluation")),
                    "treatment": _normalize_text(record.get("treatment")),
                    "reason": f"Recommended from Annex A & SoA analysis for control {target_control_id}.",
                })

                cve_id = _normalize_text(record.get("cve"))
                risk_id = _normalize_text(record.get("riskid"))

                if cve_id and cve_id not in related_risks:
                    related_risks.append(cve_id)

                if risk_id and risk_id not in risk_ids:
                    risk_ids.append(risk_id)
        except Exception:
            pass

    return {
        "control_id": target_control_id,
        "control_name": _normalize_text(iso_match.get("Title")),
        "domain": "ISO 27001:2022 Control",
        "applicable": True,
        "implementation_status": "",
        "justification": (
            recommendation_justification
            if _normalize_text(recommendation_justification)
            else f"Recommended control {target_control_id} based on Annex A & SoA analysis."
        ),
        "related_risks": related_risks,
        "risk_ids": risk_ids,
        "source_records": aggregated_source_records,
    }

def _build_single_control_from_rag(year: int, target_control_id: str) -> dict | None:
    risk_eval_doc = _load_risk_eval_doc(year)
    hosts = risk_eval_doc.get("hosts", [])

    applicable_records = [
        r for r in hosts
        if isinstance(r, dict) and _is_record_applicable(r)
    ]

    embedded_records = build_or_load_embeddings(year, force_rebuild=True)

    aggregated = None

    for record in applicable_records:
        try:
            result = map_record_to_controls(record, embedded_records, year=year)
            controls = result.get("llm_answer", {}).get("controls", [])
            
            if not isinstance(controls, list):
                raise ValueError(f"Invalid controls format for risk {risk_id}")
                
            for c in controls:
                cid = c["control_id"]
                cname = c["control_name"]
                reason = c["reason"]

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

def _build_recommended_control_info_context(year: int, control_id: str) -> dict | None:
    target_control_id = _normalize_text(control_id)
    if target_control_id == "":
        return None

    recommendation_justification = ""
    try:
        recommendations = _recommend_controls_from_annex(year)
    except Exception:
        recommendations = []

    for item in recommendations:
        if _normalize_text(item.get("control_id")) == target_control_id:
            recommendation_justification = _normalize_text(item.get("justification"))
            break

    control = _build_single_control_from_annex_recommendation(
        year=year,
        target_control_id=target_control_id,
        recommendation_justification=recommendation_justification,
    )

    if control is None:
        control = _build_single_control_from_rag(year, target_control_id)

    if control is None:
        return None

    iso_record = _get_iso_record_by_control_id(year, target_control_id)

    host_lines = []
    for item in control.get("source_records", []):
        if not isinstance(item, dict):
            continue

        host_lines.append(
            " | ".join([
                f"hostname={_normalize_text(item.get('hostname'))}",
                f"role={_normalize_text(item.get('role'))}",
                f"riskid={_normalize_text(item.get('riskid'))}",
                f"risk={_normalize_text(item.get('risk'))}",
                f"vulnerability={_normalize_text(item.get('vulnerability_name'))}",
                f"cve={_normalize_text(item.get('cve'))}",
                f"reason={_normalize_text(item.get('reason'))}",
            ])
        )

    return {
        "control_id": target_control_id,
        "control_name": _normalize_text(
            control.get("control_name") or (iso_record or {}).get("Title")
        ),
        "domain": _infer_domain_from_control_id(target_control_id),
        "section": _normalize_text((iso_record or {}).get("Section")),
        "status": _normalize_text((iso_record or {}).get("Status")),
        "purpose": _normalize_text((iso_record or {}).get("Purpose")),
        "recommendation_justification": recommendation_justification,
        "annex_justification": _normalize_text(control.get("justification")),
        "related_risks": control.get("related_risks", []),
        "risk_ids": control.get("risk_ids", []),
        "source_records": control.get("source_records", []),
        "host_lines": host_lines,
    }
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
            "message": "The Annex A & SoA results will be finalized and locked, are you sure?",
            "inventory": doc,
        }

    controls = _all_controls(doc)
    if not controls:
        return {
            "success": False,
            "message": "The Annex A & SoA table is empty. Run /create first.",
            "inventory": doc,
        }

    missing_status: list[str] = []
    invalid_status: list[str] = []

    for control in controls:
        status_value = _normalize_text(control.get("implementation_status"))

        if status_value in {"", "-- Select --", "-- select --"}:
            missing_status.append(_format_control_label(control))
        elif status_value not in VALID_IMPLEMENTATION_STATUSES:
            invalid_status.append(f"{_format_control_label(control)} -> {status_value}")

    if missing_status:
        return {
            "success": False,
            "message": (
                "Please select an implementation status for every control before submitting "
                f"the Annex A & SoA table. Missing selections: {', '.join(missing_status)}"
            ),
            "inventory": doc,
        }

    if invalid_status:
        return {
            "success": False,
            "message": (
                "One or more controls have an invalid implementation status value. "
                f"Please update these rows and try again: {', '.join(invalid_status)}"
            ),
            "inventory": doc,
        }

    try:
        action_plan_path, action_plan_doc, _ = _restore_action_plan_doc_if_missing(
            year=year,
            annex_doc=doc,
            force=True,
        )
        _save_json(_action_implementation_guides_file(year), {"guides": []})
    except FileNotFoundError as e:
        return {
            "success": False,
            "message": str(e),
            "inventory": doc,
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Failed to create ActionPlanImplementation.json: {str(e)}",
            "inventory": doc,
        }

    status_doc = _load_system_status_or_default(year)
    status_doc = _mark_annex_prerequisites_completed(status_doc)

    if status_doc["sections"].get("action_plan_implementation", {}).get("status") != "Completed":
        status_doc["sections"]["action_plan_implementation"]["status"] = "In Progress"

    _save_json(_system_status_file(year), status_doc)

    return {
        "success": True,
        "message": "Annex A & SoA finalized.",
        "records_finalized": len(controls),
        "action_plan_records_created": len(action_plan_doc.get("controls", [])),
        "action_plan_file": action_plan_path.name,
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
        doc = _load_annex_doc_or_blank(year)
        existing_ids = {
            _normalize_key(c.get("control_id"))
            for c in _all_controls(doc)
        }
        recommendations = [
            rec for rec in _recommend_controls_from_annex(year)
            if _normalize_key(rec.get("control_id")) not in existing_ids
        ]

        return {
            "success": True,
            "message": "Recommended controls generated successfully.",
            "recommendations": recommendations,
        }

    except FileNotFoundError as e:
        return {
            "success": False,
            "message": str(e),
            "recommendations": [],
        }

    except Exception as e:
        return {
            "success": False,
            "message": f"Recommendation failed: {str(e)}",
            "recommendations": [],
        }
    
@router.post("/add")
def add_control_to_annex(payload: AddRequest):
    year = int(payload.year or 2026)
    control_id = _normalize_text(payload.control_id)
    recommendations = _recommend_controls_from_annex(year)
    
    recommendation_map = {
        _normalize_key(r["control_id"]): r
        for r in recommendations
    }
    
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
        recommendations = _recommend_controls_from_annex(year)
        recommendations = [
            r for r in recommendations
            if _normalize_key(r.get("control_id")) not in existing_ids
        ]
        allowed_ids = {_normalize_key(r["control_id"]) for r in recommendations}

        recommendation_map = {
            _normalize_key(r["control_id"]): r
            for r in recommendations
        }        
        
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

    # Build control using Annex recommendation pipeline first, then fallback to RAG
    try:
        rec_key = _normalize_key(control_id)
        rec_item = recommendation_map.get(rec_key)
    
        rec_justification = ""
        if rec_item:
            rec_justification = _normalize_text(rec_item.get("justification"))
    
        new_control = _build_single_control_from_annex_recommendation(
            year=year,
            target_control_id=control_id,
            recommendation_justification=rec_justification,
        )
    
        if not new_control:
            new_control = _build_single_control_from_rag(year, control_id)
    
        if not new_control:
            return {
                "success": False,
                "message": (
                    f"Failed to generate control {control_id}. "
                    f"It was recommended successfully, but no buildable source context was found."
                ),
                "inventory": doc,
            }
    
        # apply the same contextual behavior used by create/info
        new_control = _apply_create_like_context_to_control(year, new_control)
    
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

@router.post("/info")
def get_recommended_control_info(payload: InfoRequest):
    year = int(payload.year or 2026)
    control_id = _normalize_text(payload.control_id)

    if control_id == "":
        return {
            "success": False,
            "message": "control_id is required.",
            "control": None,
        }

    try:
        info_context = _build_recommended_control_info_context(year, control_id)
    except FileNotFoundError as e:
        return {
            "success": False,
            "message": str(e),
            "control": None,
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Failed to prepare control information context: {str(e)}",
            "control": None,
        }

    if info_context is None:
        return {
            "success": False,
            "message": f"Control '{control_id}' was not found in the recommendation/control catalog context.",
            "control": None,
        }

    try:
        llm_info = _generate_control_info_with_llama3(info_context, year=year)
    except Exception as e:
        return {
            "success": False,
            "message": f"Failed to generate control information via RAG + Llama3: {str(e)}",
            "control": None,
        }

    return {
        "success": True,
        "message": f"Control information generated for {control_id}.",
        "control": {
            "control_id": info_context["control_id"],
            "control_name": info_context["control_name"],
            "domain": llm_info["domain"],
            "concern": llm_info["concern"],
            "justification": llm_info["justification"],
        },
    }
