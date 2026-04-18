from fastapi import APIRouter, Query
from pydantic import BaseModel
from fastapi import UploadFile, File
import csv
import json
import os
import pickle
import re
from pathlib import Path
from typing import Any
import math

import requests

print("LOADED routes_action_plan_implementation.py")

router = APIRouter(
    prefix="/api/action-plan-implementation",
    tags=["action-plan-implementation"],
)


# =========================================================
# CONSTANTS
# =========================================================
VALID_STEP_STATUSES = {"Blocked", "Not Started", "In Progress", "Completed"}

VALID_IMPLEMENTATION_STATUSES = {
    "",
    "Not Implemented",
    "Planned",
    "In Progress",
    "Implemented",
    "Not Applicable",
}

EVIDENCE_TOP_K = 10

EVIDENCE_CONTROL_HINTS = {
    "5.15": ["access control", "authorization", "access restriction", "unauthorized access"],
    "5.17": ["authentication", "credentials", "password", "mfa", "logon"],
    "5.18": ["access rights", "least privilege", "role-based access", "privileged accounts"],
    "8.2": ["privileged access", "administrator access", "elevation of privilege"],
    "8.5": ["secure authentication", "authentication bypass", "mfa", "logon protection"],
    "8.7": ["malware protection", "antimalware", "endpoint protection"],
    "8.8": ["technical vulnerability", "patching", "cve", "vulnerability remediation"],
    "8.9": ["configuration", "hardening", "secure baseline", "misconfiguration"],
    "8.13": ["backup", "restore", "recovery", "resilience"],
    "8.15": ["logging", "audit trail", "event logs", "security logs"],
    "8.16": ["monitoring", "detection", "alerting", "anomalous activity"],
    "8.20": ["network security", "segmentation", "firewall", "remote attack"],
    "8.21": ["network services", "service exposure", "internet-facing service"],
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

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_PAGE_SIZE = 100

# =========================================================
# REQUEST MODELS
# =========================================================
class RecommendTreatmentRequest(BaseModel):
    year: int | None = 2026
    control_id: str


class ResetRequest(BaseModel):
    year: int | None = 2026
    confirm: bool = False


class SubmitRequest(BaseModel):
    year: int | None = 2026
    confirm: bool = False


class UpdateStatusRequest(BaseModel):
    year: int | None = 2026
    control_id: str
    implementation_status: str


class DeleteRequest(BaseModel):
    year: int | None = 2026
    control_id: str

class AddEvidenceItem(BaseModel):
    responsible: str = ""
    resources: str = ""
    date: str = ""
    url: str = ""
    desc: str = ""


class AddEvidenceRequest(BaseModel):
    year: int | None = 2026
    control_id: str
    hostname: str
    vulnerability_name: str
    evidence: AddEvidenceItem
    
class DeleteEvidenceRequest(BaseModel):
    year: int | None = 2026
    control_id: str
    hostname: str
    vulnerability_name: str
    evidence_index: int

class EditEvidenceRequest(BaseModel):
    year: int | None = 2026
    control_id: str
    hostname: str
    vulnerability_name: str
    evidence_index: int
    evidence: AddEvidenceItem

class RecommendAllTreatmentRequest(BaseModel):
    year: int | None = 2026
    
# =========================================================
# PROJECT PATHS
# =========================================================
def find_project_root() -> Path:
    current = Path(__file__).resolve()
    for parent in [current] + list(current.parents):
        if (parent / "data" / "work").exists():
            return parent
    raise RuntimeError("Could not find project root containing data/work")


BASE_DIR = find_project_root()

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen3:14b")
OLLAMA_EMBED_URL = os.getenv("OLLAMA_EMBED_URL", "http://localhost:11434/api/embeddings")
OLLAMA_EMBED_MODEL = os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text")


def _work_dir(year: int) -> Path:
    return BASE_DIR / "data" / "work" / str(year)


def _iso_csv_path(year: int) -> Path:
    return _work_dir(year) / "iso27002_controls_2022.csv"


def _iso_embedding_cache_path(year: int) -> Path:
    return _work_dir(year) / "iso27002_local_embeddings.pkl"


def _annex_a_soa_file(year: int) -> Path:
    return _work_dir(year) / "AnnexA_SoA.json"


def _action_plan_implementation_file(year: int) -> Path:
    return _work_dir(year) / "ActionPlanImplementation.json"


def _legacy_action_plan_implementation_file(year: int) -> Path:
    return _work_dir(year) / "ActionPlanImplementaion.json"


def _system_status_file(year: int) -> Path:
    return _work_dir(year) / "SystemStatus.json"


def _action_implementation_guides_file(year: int) -> Path:
    return _work_dir(year) / "ActionImplementationGuides.json"


def _asset_inventory_file(year: int) -> Path:
    return _work_dir(year) / "AssetInventory.json"


def _existing_controls_postures_file(year: int) -> Path:
    return _work_dir(year) / "ExistingControlsPostures.json"


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


def _safe_join_lines(items: list[str]) -> str:
    return "\n".join(x for x in items if _normalize_text(x) != "")

def _ensure_action_implementation_guides_file_exists(year: int):
    path = _action_implementation_guides_file(year)
    print("GUIDES PATH =", path)
    print("GUIDES EXISTS BEFORE =", path.exists())    
    if not path.exists():
        doc = _blank_action_implementation_guides_doc(year)
        _save_action_implementation_guides_doc(year, doc)
        
# =========================================================
# SYSTEM STATUS HELPERS
# =========================================================
def _load_system_status_or_default(year: int) -> dict:
    path = _system_status_file(year)

    default_doc = {
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

    if not path.exists():
        return default_doc

    try:
        data = _load_json(path)
        if not isinstance(data, dict):
            return default_doc
    except Exception:
        return default_doc

    if not isinstance(data.get("meta"), dict):
        data["meta"] = default_doc["meta"]

    if not isinstance(data.get("sections"), dict):
        data["sections"] = {}

    for section_name, default_value in default_doc["sections"].items():
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


def _action_plan_section_is_read_only(year: int) -> bool:
    doc = _load_system_status_or_default(year)
    return doc.get("sections", {}).get("action_plan_implementation", {}).get("status") == "Completed"


# =========================================================
# ACTION PLAN DOCUMENT HELPERS
# =========================================================
def _blank_action_plan_doc() -> dict:
    return {"controls": []}


def _all_controls(doc: dict) -> list[dict]:
    controls = doc.get("controls", [])
    if not isinstance(controls, list):
        return []
    return [c for c in controls if isinstance(c, dict)]


def _load_annex_doc_or_blank(year: int) -> dict:
    path = _annex_a_soa_file(year)

    if not path.exists():
        return {"controls": []}

    try:
        data = _load_json(path)
        if not isinstance(data, dict):
            return {"controls": []}
        if not isinstance(data.get("controls"), list):
            data["controls"] = []
        return data
    except Exception:
        return {"controls": []}


def _build_action_plan_doc(year: int, annex_doc: dict) -> dict:
    controls = _all_controls(annex_doc)
    action_plan_controls = []

    for control in controls:
        control_id = _normalize_text(control.get("control_id"))
        control_name = _normalize_text(control.get("control_name"))
        justification = _normalize_text(control.get("justification"))
        implementation_status = _normalize_text(control.get("implementation_status"))

        source_records = control.get("source_records", [])
        if not isinstance(source_records, list):
            source_records = []

        hosts = []
        for record in source_records:
            if not isinstance(record, dict):
                continue

            hosts.append(
                {
                    "hostname": _normalize_text(record.get("hostname")),
                    "ip_address": _normalize_text(record.get("ip_address")),
                    "role": _normalize_text(record.get("role")),
                    "CIA rating": _normalize_text(record.get("CIA rating")),
                    "vulnerability_name": _normalize_text(record.get("vulnerability_name")),
                    "cve": _normalize_text(record.get("cve")),
                    "riskid": _normalize_text(record.get("riskid")),
                    "risk": _normalize_text(record.get("risk")),
                    "evaluation": _normalize_text(record.get("evaluation")),
                    "treatment": _normalize_text(record.get("treatment")),
                    "treatment_action": "",
                    "control": control_id,
                    "responsible": "",
                    "resources": "",
                    "date": "",
                    "implementation_status": implementation_status,
                    "evidence": [                  ],
                }
            )

        action_plan_controls.append(
            {
                "control_id": control_id,
                "control": control_id,
                "control_name": control_name,
                "justification": justification,
                "implementation_status": implementation_status,
                "treatment_action": "",
                "hosts": hosts,
            }
        )

    return {"controls": action_plan_controls}


def _restore_action_plan_doc_if_missing(year: int) -> tuple[Path, dict, str]:
    output_path = _action_plan_implementation_file(year)

    if output_path.exists():
        try:
            existing_doc = _load_json(output_path)
            if isinstance(existing_doc, dict):
                return output_path, existing_doc, "existing"
        except Exception:
            pass

    legacy_path = _legacy_action_plan_implementation_file(year)
    if legacy_path.exists():
        try:
            legacy_doc = _load_json(legacy_path)
            if isinstance(legacy_doc, dict):
                _save_json(output_path, legacy_doc)
                return output_path, legacy_doc, "migrated"
        except Exception:
            pass

    annex_doc = _load_annex_doc_or_blank(year)
    new_doc = _build_action_plan_doc(year, annex_doc)
    _save_json(output_path, new_doc)
    return output_path, new_doc, "generated"


def _load_action_plan_doc_or_blank(year: int) -> dict:
    output_path, doc, _ = _restore_action_plan_doc_if_missing(year)

    if not output_path.exists():
        return _blank_action_plan_doc()

    if not isinstance(doc, dict):
        return _blank_action_plan_doc()

    if not isinstance(doc.get("controls"), list):
        doc["controls"] = []

    return doc


def _derive_action_plan_status_from_doc(doc: dict) -> str:
    return "Not Started" if len(_all_controls(doc)) == 0 else "In Progress"


def _sync_action_plan_status(year: int, doc: dict | None = None) -> str:
    if _action_plan_section_is_read_only(year):
        _set_section_status(year, "action_plan_implementation", "Completed")
        return "Completed"

    if doc is None:
        doc = _load_action_plan_doc_or_blank(year)

    new_status = _derive_action_plan_status_from_doc(doc)
    _set_section_status(year, "action_plan_implementation", new_status)
    return new_status


def _find_control(doc: dict, control_id: str) -> tuple[int | None, dict | None]:
    target = _normalize_key(control_id)
    controls = _all_controls(doc)

    for idx, control in enumerate(controls):
        if (
            _normalize_key(control.get("control_id")) == target
            or _normalize_key(control.get("control")) == target
        ):
            return idx, control

    return None, None


def _format_control_label(control: dict) -> str:
    control_id = _normalize_text(control.get("control_id") or control.get("control")) or "Unknown Control"
    control_name = _normalize_text(control.get("control_name"))
    return control_id if control_name == "" else f"{control_id} ({control_name})"


# =========================================================
# RAG / LLM HELPERS
# =========================================================
def _tokenize_for_match(text: str) -> list[str]:
    return [t for t in re.findall(r"[a-zA-Z0-9\.\-]+", (text or "").lower()) if len(t) > 2]


def _keyword_score(text: str, query_terms: list[str]) -> float:
    text_l = (text or "").lower()
    if not query_terms:
        return 0.0

    hits = sum(1 for term in query_terms if term and term.lower() in text_l)
    return hits / max(len(query_terms), 1)


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0

    dot = sum(x * y for x, y in zip(a, b))
    norm_a = sum(x * x for x in a) ** 0.5
    norm_b = sum(y * y for y in b) ** 0.5

    if norm_a == 0 or norm_b == 0:
        return 0.0

    return dot / (norm_a * norm_b)

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
    res = requests.get(NVD_API_URL, params=params, timeout=120)
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


def _get_embedding(text: str) -> list[float]:
    payload = {
        "model": OLLAMA_EMBED_MODEL,
        "prompt": text,
    }

    res = requests.post(OLLAMA_EMBED_URL, json=payload, timeout=120)
    res.raise_for_status()
    data = res.json()

    embedding = data.get("embedding")
    if not isinstance(embedding, list):
        raise ValueError("Embedding response did not contain a valid embedding vector.")

    return embedding


def _load_embedding_cache(year: int) -> dict:
    path = _iso_embedding_cache_path(year)

    if not path.exists():
        return {}

    try:
        with open(path, "rb") as f:
            data = pickle.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_embedding_cache(year: int, cache: dict) -> None:
    path = _iso_embedding_cache_path(year)
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "wb") as f:
        pickle.dump(cache, f)


def _load_iso_controls_csv(year: int) -> list[dict]:
    path = _iso_csv_path(year)

    if not path.exists():
        raise FileNotFoundError(f"ISO controls CSV not found: {path}")

    rows: list[dict] = []

    with open(path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            row = dict(row)

            section = _normalize_text(row.get("Section"))
            control = _normalize_text(row.get("Control"))
            title = _normalize_text(row.get("Title"))
            purpose = _normalize_text(row.get("Purpose"))
            status = _normalize_text(row.get("Status"))

            row["_control_id"] = control or section
            row["_text"] = (
                f"Section: {section}\n"
                f"Control: {control}\n"
                f"Title: {title}\n"
                f"Status: {status}\n"
                f"Purpose: {purpose}\n"
                f"Keywords: {'; '.join(EVIDENCE_CONTROL_HINTS.get(control, []))}"
            )
            rows.append(row)

    return rows


def _retrieve_relevant_iso_controls(
    year: int,
    control_id: str,
    control_name: str,
    justification: str,
    host_lines: list[str],
    top_k: int = 5,
) -> list[dict]:
    records = _load_iso_controls_csv(year)
    cache = _load_embedding_cache(year)

    query = "\n".join(
        [
            f"Control ID: {control_id}",
            f"Control Name: {control_name}",
            f"Justification: {justification}",
            "Affected Hosts:",
            *host_lines,
        ]
    ).strip()

    query_terms = _tokenize_for_match(
        f"{control_id} {control_name} {justification} {' '.join(host_lines)}"
    )

    try:
        query_embedding = _get_embedding(query)
        use_semantic = True
    except Exception:
        query_embedding = []
        use_semantic = False

    scored: list[tuple[float, dict]] = []
    cache_changed = False

    for rec in records:
        rec_text = rec.get("_text", "")
        rec_key = f"{_normalize_text(rec.get('_control_id'))}::{rec_text}"

        semantic = 0.0
        if use_semantic:
            try:
                if rec_key not in cache:
                    cache[rec_key] = _get_embedding(rec_text)
                    cache_changed = True
                semantic = _cosine_similarity(query_embedding, cache[rec_key])
            except Exception:
                semantic = 0.0

        keyword = _keyword_score(rec_text, query_terms)

        boost = 0.0
        rec_control = _normalize_text(rec.get("_control_id"))
        if rec_control.lower() == control_id.lower():
            boost += 0.20
        if control_name and control_name.lower() in rec_text.lower():
            boost += 0.10

        final_score = (semantic * 0.50) + (keyword * 0.35) + boost
        scored.append((final_score, rec))

    if cache_changed:
        _save_embedding_cache(year, cache)

    scored.sort(key=lambda x: x[0], reverse=True)
    return [item[1] for item in scored[:top_k]]


def _build_evidence_query_context(
    control_id: str,
    control_name: str,
    justification: str,
    hostname: str,
    role: str,
    vulnerability_name: str,
    cve: str,
    risk: str,
    treatment_action: str,
    existing_evidence: list[dict] | None = None,
) -> str:
    evidence_lines = []
    if isinstance(existing_evidence, list):
        for item in existing_evidence:
            if isinstance(item, dict):
                evidence_lines.append(
                    " | ".join(
                        [
                            f"responsible={_normalize_text(item.get('responsible'))}",
                            f"resources={_normalize_text(item.get('resources'))}",
                            f"date={_normalize_text(item.get('date'))}",
                            f"url={_normalize_text(item.get('url'))}",
                            f"desc={_normalize_text(item.get('desc'))}",
                        ]
                    )
                )

    parts = [
        f"Control ID: {control_id}",
        f"Control Name: {control_name}",
        f"Justification: {justification}",
        f"Hostname: {hostname}",
        f"Role: {role}",
        f"Vulnerability: {vulnerability_name}",
        f"CVE: {cve}",
        f"Risk: {risk}",
        f"Treatment Action: {treatment_action}",
        "Existing Evidence:",
        *evidence_lines,
    ]

    return "\n".join(x for x in parts if _normalize_text(x) != "")


def _extract_evidence_traits_from_text(text: str) -> list[str]:
    text_l = _normalize_text(text).lower()
    traits = set()

    if any(x in text_l for x in ["authentication", "password", "credential", "mfa", "logon"]):
        traits.add("authentication weakness")

    if any(x in text_l for x in ["privilege", "administrator", "admin", "least privilege"]):
        traits.add("privileged access")

    if any(x in text_l for x in ["cve-", "patch", "unpatched", "vulnerability", "remediation"]):
        traits.add("technical vulnerability")

    if any(x in text_l for x in ["configuration", "misconfiguration", "hardening", "baseline"]):
        traits.add("configuration weakness")

    if any(x in text_l for x in ["logging", "audit", "event log"]):
        traits.add("logging evidence")

    if any(x in text_l for x in ["monitoring", "alert", "detection", "anomalous"]):
        traits.add("monitoring evidence")

    if any(x in text_l for x in ["firewall", "network", "segmentation", "internet-facing", "exposed service"]):
        traits.add("network security")

    if any(x in text_l for x in ["backup", "restore", "recovery"]):
        traits.add("recovery evidence")

    if any(x in text_l for x in ["malware", "antivirus", "endpoint protection", "defender"]):
        traits.add("malware protection")

    return sorted(traits)


def _fallback_evidence_recommendations(
    control_id: str,
    control_name: str,
    hostname: str,
    vulnerability_name: str,
    cve: str,
    treatment_action: str,
) -> list[str]:
    items = [
        f"Patch status report showing remediation for {cve or vulnerability_name} on host {hostname}",
        f"Vulnerability scan result confirming {cve or vulnerability_name} is no longer detected on {hostname}",
        f"Change ticket or remediation work order linked to host {hostname}",
        f"Screenshot or export of installed update / hotfix proving the vulnerability remediation was applied",
        f"Administrator validation or sign-off confirming vulnerability treatment completion for {hostname}",
        f"Before-and-after security test result proving the technical vulnerability was mitigated",
        f"System or endpoint protection log confirming the remediation for {cve or vulnerability_name}",
        f"Evidence note mapping treatment action to ISO 27001 control 8.8 completion: {treatment_action or 'technical vulnerability remediation'}",
    ]

    unique_items = []
    seen = set()
    for item in items:
        key = item.lower()
        if key not in seen:
            seen.add(key)
            unique_items.append(item)

    return unique_items[:6]

    
def _generate_treatment_action_with_llama3(
    control_id: str,
    control_name: str,
    justification: str,
    host_lines: list[str],
    retrieved_controls: list[dict],
) -> str:

    retrieved_text = "\n\n".join(
        [
            (
                f"Control Reference {i + 1}\n"
                f"Section: {_normalize_text(rec.get('Section'))}\n"
                f"Control: {_normalize_text(rec.get('Control'))}\n"
                f"Title: {_normalize_text(rec.get('Title'))}\n"
                f"Purpose: {_normalize_text(rec.get('Purpose'))}"
            )
            for i, rec in enumerate(retrieved_controls)
        ]
    )

    prompt = f"""
You are an ISO 27001:2022 and ISO 27002:2022 expert.

Generate treatment actions for the given control.

FORMAT REQUIREMENTS (STRICT):
- First line MUST be exactly:
  Recommended treatment actions:
- Then provide bullet points using "-" (dash)
- Each action must be practical and implementation-oriented
- No explanations
- No paragraphs
- No numbering
- No markdown symbols like *

Target control:
Control ID: {control_id}
Control Name: {control_name}
Justification: {justification or "NA"}

Affected hosts:
{_safe_join_lines(host_lines) or "NA"}

ISO guidance:
{retrieved_text or "NA"}
""".strip()

    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
    }

    res = requests.post(OLLAMA_URL, json=payload, timeout=180)
    res.raise_for_status()
    data = res.json()

    response_text = _normalize_text(data.get("response"))

    if not response_text.startswith("Recommended treatment actions:"):
        lines = response_text.splitlines()
        
        clean_bullets = []
        
        for line in lines:
            line = line.strip()
        
            if not line:
                continue
        
            line = re.sub(r"^[\-\*\d\.\)\(]+\s*", "", line)
        
            parts = re.split(r";|\.\s+", line)
        
            for part in parts:
                part = part.strip()
                if not part:
                    continue
            
                clean_bullets.append(f"- {part}")
        
        seen = set()
        final_bullets = []
        for b in clean_bullets:
            if b not in seen:
                seen.add(b)
                final_bullets.append(b)
        
        response_text = "Recommended treatment actions:\n" + "\n".join(final_bullets)

    return response_text

def _control_id_sort_key(control_id: str):
    parts = _normalize_text(control_id).split(".")
    key = []
    for part in parts:
        if part.isdigit():
            key.append((0, int(part)))
        else:
            key.append((1, part))
    return tuple(key)


def _sort_recommendations_by_control_id(items: list[dict]) -> list[dict]:
    return sorted(
        items,
        key=lambda x: _control_id_sort_key(_normalize_text(x.get("control_id")))
    )

def _generate_evidence_recommendations_with_llama3(
    year: int,
    control_id: str,
    control_name: str,
    justification: str,
    hostname: str,
    role: str,
    vulnerability_name: str,
    cve: str,
    risk: str,
    treatment_action: str,
    existing_evidence: list[dict] | None = None,
) -> list[str]:
    query_context = _build_evidence_query_context(
        control_id=control_id,
        control_name=control_name,
        justification=justification,
        hostname=hostname,
        role=role,
        vulnerability_name=vulnerability_name,
        cve=cve,
        risk=risk,
        treatment_action=treatment_action,
        existing_evidence=existing_evidence,
    )

    traits = _extract_evidence_traits_from_text(query_context)

    host_lines = [
        f"Host={hostname}",
        f"Role={role}",
        f"Vulnerability={vulnerability_name}",
        f"CVE={cve}",
        f"Risk={risk}",
        f"Treatment Action={treatment_action}",
    ]

    retrieved_controls = _retrieve_relevant_iso_controls(
        year=year,
        control_id=control_id,
        control_name=control_name,
        justification=justification,
        host_lines=host_lines,
        top_k=EVIDENCE_TOP_K,
    )

    retrieved_text = "\n\n".join(
        [
            (
                f"Reference {i + 1}\n"
                f"Section: {_normalize_text(rec.get('Section'))}\n"
                f"Control: {_normalize_text(rec.get('Control'))}\n"
                f"Title: {_normalize_text(rec.get('Title'))}\n"
                f"Purpose: {_normalize_text(rec.get('Purpose'))}"
            )
            for i, rec in enumerate(retrieved_controls)
        ]
    )

    existing_evidence_text = []
    if isinstance(existing_evidence, list):
        for item in existing_evidence:
            if isinstance(item, dict):
                existing_evidence_text.append(
                    f"- responsible={_normalize_text(item.get('responsible'))}, "
                    f"resources={_normalize_text(item.get('resources'))}, "
                    f"date={_normalize_text(item.get('date'))}, "
                    f"url={_normalize_text(item.get('url'))}, "
                    f"desc={_normalize_text(item.get('desc'))}"
                )

    prompt = f"""
You are an ISO 27001:2022 implementation expert.

Generate recommended implementation evidence items for the selected host.

STRICT RULES:
- Return 5 to 8 short practical evidence examples
- Focus on evidence that can prove the treatment or implementation work
- Use only concrete evidence items such as screenshots, configuration exports, logs, tickets, approvals, test results, reports, or change records
- Prefer evidence that matches the target control, host, vulnerability, and treatment action
- Avoid duplicates
- Do not repeat any existing evidence
- No explanations
- No numbering
- No markdown
- Each line must be one evidence item only

Context:
Control ID: {control_id}
Control Name: {control_name}
Justification: {justification or "NA"}
Hostname: {hostname or "NA"}
Role: {role or "NA"}
Vulnerability: {vulnerability_name or "NA"}
CVE: {cve or "NA"}
Risk: {risk or "NA"}
Treatment Action: {treatment_action or "NA"}
Traits: {traits}

Existing Evidence:
{chr(10).join(existing_evidence_text) or "NA"}

Relevant ISO Guidance:
{retrieved_text or "NA"}
""".strip()

    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
    }

    res = requests.post(OLLAMA_URL, json=payload, timeout=180)
    res.raise_for_status()
    data = res.json()

    raw_text = _normalize_text(data.get("response"))
    if raw_text == "":
        return _fallback_evidence_recommendations(
            control_id=control_id,
            control_name=control_name,
            hostname=hostname,
            vulnerability_name=vulnerability_name,
            cve=cve,
            treatment_action=treatment_action,
        )

    items = []
    for line in raw_text.splitlines():
        cleaned = re.sub(r"^[\-\*\d\.\)\(]+\s*", "", line.strip())
        if cleaned:
            items.append(cleaned)

    existing_keys = set()
    if isinstance(existing_evidence, list):
        for item in existing_evidence:
            if isinstance(item, dict):
                combined = " ".join(
                    [
                        _normalize_text(item.get("responsible")),
                        _normalize_text(item.get("resources")),
                        _normalize_text(item.get("date")),
                        _normalize_text(item.get("url")),
                        _normalize_text(item.get("desc")),
                    ]
                ).strip().lower()
                if combined:
                    existing_keys.add(combined)

    unique_items = []
    seen = set()
    for item in items:
        key = item.lower().strip()
        if not key or key in seen:
            continue

        duplicate_existing = False
        for existing_key in existing_keys:
            if key == existing_key or key in existing_key or existing_key in key:
                duplicate_existing = True
                break

        if duplicate_existing:
            continue

        seen.add(key)
        unique_items.append(item)

    if not unique_items:
        return _fallback_evidence_recommendations(
            control_id=control_id,
            control_name=control_name,
            hostname=hostname,
            vulnerability_name=vulnerability_name,
            cve=cve,
            treatment_action=treatment_action,
        )

    return unique_items[:8]

def _generate_meaningful_evidence_desc_with_llama3(
    year: int,
    control_id: str,
    control_name: str,
    justification: str,
    hostname: str,
    role: str,
    vulnerability_name: str,
    cve: str,
    risk: str,
    treatment_action: str,
) -> str:
    host_lines = [
        f"Host={hostname}",
        f"Role={role}",
        f"Vulnerability={vulnerability_name}",
        f"CVE={cve}",
        f"Risk={risk}",
        f"Treatment Action={treatment_action}",
    ]

    retrieved_controls = _retrieve_relevant_iso_controls(
        year=year,
        control_id=control_id,
        control_name=control_name,
        justification=justification,
        host_lines=host_lines,
        top_k=5,
    )

    retrieved_text = "\n\n".join(
        [
            (
                f"Reference {i + 1}\n"
                f"Section: {_normalize_text(rec.get('Section'))}\n"
                f"Control: {_normalize_text(rec.get('Control'))}\n"
                f"Title: {_normalize_text(rec.get('Title'))}\n"
                f"Purpose: {_normalize_text(rec.get('Purpose'))}"
            )
            for i, rec in enumerate(retrieved_controls)
        ]
    )

    prompt = f"""
You are an ISO 27001:2022 implementation expert.

Write ONE short but meaningful evidence description for a host under a selected control.

STRICT RULES:
- Output exactly one sentence only
- Keep it concise but meaningful
- Base it on the treatment action
- Mention the host
- Mention the control
- Describe what the evidence proves
- Do not use bullets
- Do not use numbering
- Do not use markdown
- Do not mention ISO guidance text directly
- Do not be generic like "evidence for host under control"

Context:
Control ID: {control_id or "NA"}
Control Name: {control_name or "NA"}
Justification: {justification or "NA"}
Hostname: {hostname or "NA"}
Role: {role or "NA"}
Vulnerability: {vulnerability_name or "NA"}
CVE: {cve or "NA"}
Risk: {risk or "NA"}
Treatment Action: {treatment_action or "NA"}

Relevant ISO Guidance:
{retrieved_text or "NA"}
""".strip()

    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
    }

    res = requests.post(OLLAMA_URL, json=payload, timeout=180)
    res.raise_for_status()
    data = res.json()

    desc = _normalize_text(data.get("response"))

    if not desc:
        desc = (
            f"Evidence shows treatment action for host {hostname} under control "
            f"{control_id} ({control_name}) was implemented."
        )

    return desc.replace("\n", " ").strip()
    
# =========================================================
# ACTION IMPLEMENTATION GUIDES HELPERS
# =========================================================
def _blank_action_implementation_guides_doc(year: int) -> dict:
    return {
        "guides": []
    }

def _load_json_or_default(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        data = _load_json(path)
        return data if isinstance(data, type(default)) else default
    except Exception:
        return default


def _load_action_implementation_guides_doc_or_blank(year: int) -> dict:
    path = _action_implementation_guides_file(year)
    default_doc = _blank_action_implementation_guides_doc(year)
    doc = _load_json_or_default(path, default_doc)

    if not isinstance(doc, dict):
        return default_doc

    if not isinstance(doc.get("guides"), list):
        doc["guides"] = []

    return doc


def _save_action_implementation_guides_doc(year: int, doc: dict) -> None:
    _save_json(_action_implementation_guides_file(year), doc)


def _all_guides(doc: dict) -> list[dict]:
    guides = doc.get("guides", [])
    if not isinstance(guides, list):
        return []
    return [g for g in guides if isinstance(g, dict)]


def _next_guide_id(year: int, guides_doc: dict) -> str:
    max_n = 0

    for guide in _all_guides(guides_doc):
        value = _normalize_text(guide.get("guide_id"))
        m = re.match(rf"^AIG-{int(year)}-(\d+)$", value)
        if m:
            max_n = max(max_n, int(m.group(1)))

    return f"AIG-{int(year)}-{max_n + 1:04d}"


def _next_evidence_id(year: int, action_doc: dict) -> str:
    max_n = 0
    for control in _all_controls(action_doc):
        hosts = control.get("hosts", [])
        if not isinstance(hosts, list):
            continue
        for host in hosts:
            if not isinstance(host, dict):
                continue
            evidence_list = host.get("evidence", [])
            if not isinstance(evidence_list, list):
                continue
            for evidence in evidence_list:
                if not isinstance(evidence, dict):
                    continue
                value = _normalize_text(evidence.get("evidence_id"))
                m = re.match(rf"^EVID-{int(year)}-(\d+)$", value)
                if m:
                    max_n = max(max_n, int(m.group(1)))
    return f"EVID-{int(year)}-{max_n + 1:04d}"


def _remove_guide_by_key(year: int, evidence_id: str) -> bool:
    doc = _load_action_implementation_guides_doc_or_blank(year)
    original = len(_all_guides(doc))

    doc["guides"] = [
        g for g in _all_guides(doc)
        if _normalize_key(g.get("evidence_id")) != _normalize_key(evidence_id)
    ]

    changed = len(doc["guides"]) != original
    if changed:
        _save_action_implementation_guides_doc(year, doc)

    return changed


def _append_guide(year: int, guide: dict) -> None:
    doc = _load_action_implementation_guides_doc_or_blank(year)
    guides = _all_guides(doc)
    guides.append(guide)
    doc["guides"] = guides
    _save_action_implementation_guides_doc(year, doc)


def _load_asset_inventory_or_blank(year: int) -> dict:
    return _load_json_or_default(_asset_inventory_file(year), {})


def _load_existing_controls_postures_or_blank(year: int) -> dict:
    return _load_json_or_default(_existing_controls_postures_file(year), {})


def _find_asset_inventory_host(year: int, hostname: str) -> dict:
    doc = _load_asset_inventory_or_blank(year)
    for subnet in doc.get("subnets", []):
        if not isinstance(subnet, dict):
            continue
        for asset in subnet.get("assets", []):
            if isinstance(asset, dict) and _normalize_key(asset.get("hostname")) == _normalize_key(hostname):
                return asset

    for network in doc.get("networks", []):
        if not isinstance(network, dict):
            continue
        for subnet in network.get("subnets", []):
            if not isinstance(subnet, dict):
                continue
            for host in subnet.get("hosts", []):
                if isinstance(host, dict) and _normalize_key(host.get("hostname")) == _normalize_key(hostname):
                    return host

    return {}


def _find_existing_controls_posture(year: int, hostname: str) -> dict:
    doc = _load_existing_controls_postures_or_blank(year)
    hosts = doc.get("hosts", [])
    if not isinstance(hosts, list):
        return {}
    for item in hosts:
        if isinstance(item, dict) and _normalize_key(item.get("hostname")) == _normalize_key(hostname):
            return item
    return {}


def _flatten_existing_controls(existing_controls: Any) -> list[str]:
    results: list[str] = []
    if not isinstance(existing_controls, dict):
        return results
    for category, values in existing_controls.items():
        if isinstance(values, list):
            for value in values:
                v = _normalize_text(value)
                if v:
                    results.append(v)
        else:
            v = _normalize_text(values)
            if v:
                results.append(v)
    return results


def _derive_evidence_name_from_item(evidence: dict) -> str:
    desc = _normalize_text(evidence.get("desc"))
    resources = _normalize_text(evidence.get("resources"))
    url = _normalize_text(evidence.get("url"))

    text = desc or resources or url
    if not text:
        return "Implementation evidence"

    short = text.split("\n", 1)[0].strip()
    if len(short) > 80:
        short = short[:77].rstrip() + "..."
    return short


def _derive_evidence_type_from_item(evidence: dict) -> str:
    url = _normalize_text(evidence.get("url")).lower()
    desc = _normalize_text(evidence.get("desc")).lower()

    if any(url.endswith(ext) for ext in [".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp"]):
        return "Screenshot"
    if url.endswith(".pdf"):
        return "PDF"
    if any(term in desc for term in ["scan", "scanner", "report"]):
        return "Scan Report"
    if any(term in desc for term in ["log", "event", "audit"]):
        return "Log Export"
    return "Document"


def _safe_department_from_asset(asset: dict) -> str:
    detail = asset.get("detail", {}) if isinstance(asset, dict) else {}
    business_context = detail.get("business_context", {}) if isinstance(detail, dict) else {}
    return _normalize_text(business_context.get("department"))


def _safe_os_version_from_asset(asset: dict) -> str:
    if not isinstance(asset, dict):
        return ""
    value = _normalize_text(asset.get("operating_system"))
    if value:
        return value
    detail = asset.get("detail", {})
    if isinstance(detail, dict):
        profile = detail.get("device_profile", {})
        if isinstance(profile, dict):
            return _normalize_text(profile.get("os_version"))
    return ""


def _safe_device_type_from_asset(asset: dict) -> str:
    return _normalize_text(asset.get("device_type") or ("Server" if "server" in _normalize_text(asset.get("role")).lower() else "Workstation"))


def _safe_ip_from_asset(asset: dict) -> str:
    if not isinstance(asset, dict):
        return ""
    value = _normalize_text(asset.get("ip_address"))
    if value:
        return value
    location = asset.get("location", {})
    if isinstance(location, dict):
        return _normalize_text(location.get("ip_address"))
    return ""


def _safe_cia_from_asset(asset: dict, fallback: str = "") -> str:
    if not isinstance(asset, dict):
        return fallback
    cia_rating = asset.get("cia_rating")
    if isinstance(cia_rating, dict):
        criticality = _normalize_text(cia_rating.get("criticality"))
        if criticality:
            return criticality
    cia_impact = asset.get("cia_impact")
    if isinstance(cia_impact, dict):
        values = [
            _normalize_text(cia_impact.get("confidentiality")),
            _normalize_text(cia_impact.get("integrity")),
            _normalize_text(cia_impact.get("availability")),
        ]
        values = [v for v in values if v]
        if values:
            return "/".join(values)
    return fallback


def _ensure_evidence_ids_for_host(year: int, action_doc: dict, host: dict) -> bool:
    changed = False
    evidence_list = host.get("evidence", [])
    if not isinstance(evidence_list, list):
        evidence_list = []

    new_list = []
    for evidence in evidence_list:
        if not isinstance(evidence, dict):
            continue
        item = dict(evidence)
        if _normalize_text(item.get("evidence_id")) == "":
            item["evidence_id"] = _next_evidence_id(year, action_doc)
            changed = True
        new_list.append(item)

    if changed:
        host["evidence"] = new_list
    return changed

def _build_minimal_guide_references(cve_id: str) -> list[dict]:
    cve_id = _normalize_text(cve_id)

    refs = [
        {
            "ref_id": "MS-01",
            "source": f"Microsoft Security Update {cve_id}" if cve_id else "Microsoft Security Update"
        },
        {
            "ref_id": "CISA-01",
            "source": "CISA Known Exploited Vulnerabilities Catalog"
        },
        {
            "ref_id": "NVD-01",
            "source": f"NVD {cve_id} Technical Details" if cve_id else "NVD Technical Details"
        },
        {
            "ref_id": "MS-Baseline",
            "source": "Microsoft Security Compliance Toolkit"
        }
    ]

    return refs

def _build_vulnerability_generation_hints(cve_id: str, vulnerability_name: str, role: str) -> str:
    cve_id_l = _normalize_text(cve_id).lower()
    vuln_l = _normalize_text(vulnerability_name).lower()
    role_l = _normalize_text(role).lower()

    hints = []

    # DNS
    if "dns" in vuln_l or "cve-2020-1350" in cve_id_l:
        hints.extend([
            "Affected service is likely Windows DNS Server.",
            "Relevant commands may include Get-Service DNS, Restart-Service DNS, Resolve-DnsName.",
            "Relevant hardening may include TCP/UDP 53 firewall restrictions.",
            "Relevant evidence may include DNS service status, firewall rules, hotfix output, and DNS logs."
        ])

    # SMB / file sharing
    if "smb" in vuln_l or "445" in vuln_l:
        hints.extend([
            "Relevant commands may include Get-SmbServerConfiguration and firewall rules for TCP 445.",
            "Relevant evidence may include SMB configuration output and firewall rule listings."
        ])

    # WinRM / remote management
    if "winrm" in vuln_l or "wsman" in vuln_l or "5985" in vuln_l or "5986" in vuln_l:
        hints.extend([
            "Relevant commands may include Get-ChildItem WSMan:\\localhost\\Service and Set-Item WSMan:\\localhost\\Service\\AllowUnencrypted -Value false.",
            "Relevant evidence may include WSMan configuration output and firewall rules."
        ])

    # RDP
    if "rdp" in vuln_l or "3389" in vuln_l:
        hints.extend([
            "Relevant commands may include firewall restrictions for TCP 3389 and registry or policy validation for RDP hardening.",
            "Relevant evidence may include firewall rules, service status, and policy screenshots."
        ])

    # IIS / web app
    if "iis" in vuln_l or "http" in vuln_l or "https" in vuln_l or "web" in vuln_l or "apache" in vuln_l or "nginx" in vuln_l:
        hints.extend([
            "Relevant actions may include service validation, TLS hardening, application firewall rules, and web configuration review.",
            "Relevant evidence may include service status, config export, WAF configuration, and log review."
        ])

    # Patch / update
    if "patch" in vuln_l or "update" in vuln_l or cve_id_l.startswith("cve-"):
        hints.extend([
            "If patching is relevant, use Get-WindowsUpdate, Install-WindowsUpdate, and Get-HotFix where applicable.",
            "Relevant evidence may include installed hotfix output and screenshots."
        ])

    # Firewall / network exposure
    if "firewall" in vuln_l or "port" in vuln_l or "network" in vuln_l or "exposure" in vuln_l:
        hints.extend([
            "If network restriction is relevant, use New-NetFirewallRule and validation with Get-NetFirewallRule or exported firewall configuration.",
            "Relevant evidence may include rule listings and firewall export."
        ])

    # Logging / monitoring
    if "monitor" in vuln_l or "logging" in vuln_l or "detect" in vuln_l or "audit" in vuln_l:
        hints.extend([
            "Relevant commands may include event log export, Defender detection review, and service-specific diagnostic logging.",
            "Relevant evidence may include EVTX export, log screenshots, and detection output."
        ])

    # Malware / Defender
    if "malware" in vuln_l or "defender" in vuln_l or "antivirus" in vuln_l:
        hints.extend([
            "Relevant commands may include Get-MpComputerStatus and Get-MpThreatDetection.",
            "Relevant evidence may include Defender status and threat detection output."
        ])

    # Baseline / hardening
    if "hardening" in vuln_l or "baseline" in vuln_l or "misconfiguration" in vuln_l or "configuration" in vuln_l:
        hints.extend([
            "Relevant actions may include Microsoft Security Compliance Toolkit baseline application or policy validation.",
            "Relevant evidence may include GPO report, local policy export, or screenshots."
        ])

    # Domain controller safety
    if "domain controller" in role_l or "active directory" in role_l:
        hints.extend([
            "Preserve domain services availability during remediation.",
            "Prefer validation commands safe for a domain controller."
        ])

    if not hints:
        hints.extend([
            "Generate concrete Windows remediation steps based on the treatment action, host role, and vulnerability context.",
            "Prefer technical commands, validation commands, and concrete evidence collection instructions."
        ])

    return "\\n".join(hints)


def _generate_real_implementation_steps_with_llm(context: dict) -> list[dict]:
    import json
    import re

    prompt = f"""
You are a senior Windows security engineer and enterprise remediation specialist.

Generate a REAL technical remediation guide for a Windows enterprise host.

STRICT RULES:
- Output ONLY valid JSON
- No markdown
- No explanations
- Use the EXACT JSON schema provided below
- Do NOT change the schema
- Every step must be technical and implementation-oriented
- Do NOT use generic steps like:
  - Review scope
  - Apply treatment action
  - Validate remediation
- Break work into specific technical actions
- Prefer 4 to 8 steps
- Each step must contain:
  - title
  - description
  - commands
  - expected_result
  - output_type
  - evidence_capture
- commands must be a JSON array of strings
- Use real Windows / PowerShell / CMD commands where applicable
- If a task is manual, keep commands as an empty array and explain the action in description
- expected_result must be concrete and technical
- evidence_capture must say exactly what proof to capture
- Do not merge all work into one or two steps
- Do not repeat the treatment text verbatim
- Make the guide specific to the vulnerability, host role, control, and treatment action
- If the issue is patch-related, include install and validation commands
- If the issue is service-related, include service validation commands
- If the issue is firewall/network-related, include actual firewall commands
- If the issue is hardening-related, include configuration commands or concrete admin actions
- If the issue is monitoring-related, include logging/monitoring commands or exact tool usage
- If the issue is evidence-oriented, include concrete evidence collection commands

Context:
Host: {context.get("hostname", "")}
Role: {context.get("role", "")}
OS: {context.get("os_version", "")}
Control: {context.get("control_id", "")} - {context.get("control_name", "")}
Vulnerability: {context.get("vulnerability_name", "")}
CVE: {context.get("cve_id", "")}
Severity: {context.get("severity", "")}
Treatment Action: {context.get("treatment_action", "")}

Technical Hints:
{context.get("generation_hints", "")}

Return JSON in this exact format:
[
  {{
    "step_no": 1,
    "title": "Short technical step title",
    "description": "Concrete technical instruction for this step.",
    "commands": [
      "command 1",
      "command 2"
    ],
    "expected_result": "Concrete technical expected result.",
    "output_type": "Command output / screenshot / log export / firewall rule list / service status / patch list / PDF / report",
    "evidence_capture": "Exactly what evidence to capture for this step."
  }}
]

Generate only the JSON array.
""".strip()

    cleaned = ""

    try:
        payload = {
            "model": OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False,
        }
        
        res = requests.post(OLLAMA_URL, json=payload, timeout=180)
        res.raise_for_status()
        data = res.json()
        
        response = _normalize_text(data.get("response"))

        if not isinstance(response, str):
            raise ValueError("LLM response is not a string.")

        cleaned = response.strip()
        cleaned = cleaned.replace("\\u2013", "-").replace("\\u2014", "-")

        if cleaned.startswith("```"):
            cleaned = re.sub(r"^```(?:json)?", "", cleaned).strip()
            cleaned = re.sub(r"```$", "", cleaned).strip()

        match = re.search(r"\[\s*{.*}\s*\]", cleaned, re.DOTALL)
        if match:
            cleaned = match.group(0)

        steps = json.loads(cleaned)

        if not isinstance(steps, list):
            raise ValueError("LLM response is not a JSON list.")

        normalized_steps = []
        for i, step in enumerate(steps, start=1):
            if not isinstance(step, dict):
                continue

            commands = step.get("commands", [])
            if not isinstance(commands, list):
                commands = []

            normalized_steps.append({
                "step_no": int(step.get("step_no", i)),
                "title": str(step.get("title", "")).strip() or f"Step {i}",
                "description": str(step.get("description", "")).strip(),
                "commands": [str(cmd).strip() for cmd in commands if str(cmd).strip()],
                "expected_result": str(step.get("expected_result", "")).strip(),
                "output_type": str(step.get("output_type", "")).strip(),
                "evidence_capture": str(step.get("evidence_capture", "")).strip(),
            })

        if not normalized_steps:
            raise ValueError("No usable steps returned by LLM.")

        return normalized_steps

    except Exception as e:
        print("LLM PARSE / GENERATION ERROR:")
        print(e)
        print("RAW RESPONSE:")
        print(cleaned)
        raise

def _generate_flat_action_implementation_guide(year: int, control: dict, host: dict, evidence: dict) -> dict:
    guides_doc = _load_action_implementation_guides_doc_or_blank(year)

    evidence_id = _normalize_text(evidence.get("evidence_id"))
    if evidence_id == "":
        raise ValueError("Evidence item is missing evidence_id.")

    asset_host = _find_asset_inventory_host(year, _normalize_text(host.get("hostname")))

    hostname = _normalize_text(host.get("hostname"))
    role = _normalize_text(host.get("role")) or _normalize_text(asset_host.get("role"))
    department = _safe_department_from_asset(asset_host)
    os_version = _safe_os_version_from_asset(asset_host)

    control_id = _normalize_text(control.get("control_id") or control.get("control"))
    control_name = _normalize_text(control.get("control_name"))

    cve_id = _normalize_text(host.get("cve"))
    vulnerability_name = _normalize_text(host.get("vulnerability_name"))
    severity = _normalize_text(host.get("risk")) or _normalize_text(host.get("severity"))

    treatment_action = _normalize_text(host.get("treatment_action") or control.get("treatment_action"))

    evidence_name = _derive_evidence_name_from_item(evidence)
    evidence_description = _normalize_text(evidence.get("desc")) or evidence_name
    evidence_format = "PDF + Logs + Firewall Export"

    references = _build_minimal_guide_references(cve_id)
    generation_hints = _build_vulnerability_generation_hints(
        cve_id,
        vulnerability_name,
        role
    )
    
    implementation_steps = _generate_real_implementation_steps_with_llm({
        "hostname": hostname,
        "role": role,
        "os_version": os_version,
        "control_id": control_id,
        "control_name": control_name,
        "vulnerability_name": vulnerability_name,
        "cve_id": cve_id,
        "severity": severity,
        "treatment_action": treatment_action,
        "generation_hints": generation_hints,   # 🔥 ADD THIS
    })
    return {
        "guide_id": _next_guide_id(year, guides_doc),
        "evidence_id": evidence_id,
        "hostname": hostname,
        "role": role,
        "department": department,
        "os_version": os_version,
        "control_id": control_id,
        "control_name": control_name,
        "cve_id": cve_id,
        "vulnerability_name": vulnerability_name,
        "severity": severity,
        "treatment_action": treatment_action,
        "evidence_name": evidence_name,
        "evidence_description": evidence_description,
        "evidence_format": evidence_format,
        "references": references,
        "implementation_steps": implementation_steps,
    }

def _replace_guide_for_evidence(year: int, control: dict, host: dict, evidence: dict) -> dict:
    evidence_id = _normalize_text(evidence.get("evidence_id"))
    if evidence_id == "":
        raise ValueError("Evidence item is missing evidence_id.")

    _ensure_action_implementation_guides_file_exists(year)
    doc = _load_action_implementation_guides_doc_or_blank(year)
    print("REPLACING GUIDE FOR EVIDENCE:", evidence_id)

    doc["guides"] = [
        g for g in doc.get("guides", [])
        if _normalize_key(g.get("evidence_id")) != _normalize_key(evidence_id)
    ]

    guide = _generate_flat_action_implementation_guide(year, control, host, evidence)
    steps = guide.get("implementation_steps")
    if not isinstance(steps, list) or len(steps) == 0:
        raise ValueError("Guide generation failed: no implementation steps returned.")
    
    doc["guides"].append(guide)

    _save_action_implementation_guides_doc(year, doc)
    return guide

    
# =========================================================
# ROUTES
# =========================================================
@router.get("/inventory")
def get_action_plan_inventory(year: int = Query(2026)):
    doc = _load_action_plan_doc_or_blank(int(year))
    _sync_action_plan_status(int(year), doc)
    return doc


@router.post("/create")
def create_action_plan_implementation(year: int = 2026):
    annex_doc = _load_annex_doc_or_blank(int(year))
    controls = _all_controls(annex_doc)

    if len(controls) == 0:
        return {
            "success": False,
            "message": "Annex A & SoA is empty. Submit Annex A & SoA first.",
            "inventory": _blank_action_plan_doc(),
        }

    new_doc = _build_action_plan_doc(int(year), annex_doc)
    _save_json(_action_plan_implementation_file(int(year)), new_doc)
    _set_section_status(int(year), "action_plan_implementation", "In Progress")

    return {
        "success": True,
        "message": "Action Plan / Implementation table initialized successfully.",
        "inventory": new_doc,
    }


@router.get("/details")
def get_action_plan_details(control_id: str = Query(...), year: int = Query(2026)):
    doc = _load_action_plan_doc_or_blank(int(year))
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
def update_action_plan_status(payload: UpdateStatusRequest):
    year = int(payload.year or 2026)
    doc = _load_action_plan_doc_or_blank(year)

    if _action_plan_section_is_read_only(year):
        return {
            "success": False,
            "message": "Action Plan / Implementation has already been submitted and is now read-only.",
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

    hosts = control.get("hosts", [])
    if isinstance(hosts, list):
        for host in hosts:
            if isinstance(host, dict):
                host["implementation_status"] = status_value
        control["hosts"] = hosts

    controls = doc.get("controls", [])
    if isinstance(controls, list):
        controls[idx] = control
        doc["controls"] = controls

    _save_json(_action_plan_implementation_file(year), doc)
    _sync_action_plan_status(year, doc)

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
def reset_action_plan(payload: ResetRequest):
    year = int(payload.year or 2026)
    doc = _load_action_plan_doc_or_blank(year)

    if _action_plan_section_is_read_only(year):
        return {
            "success": False,
            "message": "Action Plan / Implementation has already been submitted and is now read-only.",
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

        hosts = control.get("hosts", [])
        if isinstance(hosts, list):
            for host in hosts:
                if isinstance(host, dict):
                    host["implementation_status"] = ""
            control["hosts"] = hosts

    doc["controls"] = controls
    _save_json(_action_plan_implementation_file(year), doc)
    
    status_doc = _load_system_status_or_default(year)
    
    current_status = status_doc["sections"]["action_plan_implementation"].get("status")
    
    if current_status == "In Progress":
        status_doc["sections"]["action_plan_implementation"]["status"] = "In Progress"
    else:
        status_doc["sections"]["action_plan_implementation"]["status"] = "In Progress"
    
    _save_json(_system_status_file(year), status_doc)

    return {
        "success": True,
        "message": "The Action Plan / Implementation table data submitted succcesfully.",
        "records_finalized": len(controls),
        "inventory": doc,
    }

@router.post("/delete")
def delete_action_plan_control(payload: DeleteRequest):
    year = int(payload.year or 2026)
    doc = _load_action_plan_doc_or_blank(year)

    if _action_plan_section_is_read_only(year):
        return {
            "success": False,
            "message": "Action Plan / Implementation has already been submitted and is now read-only.",
            "inventory": doc,
        }

    controls = _all_controls(doc)
    new_controls = [
        c for c in controls
        if (
            _normalize_key(c.get("control_id")) != _normalize_key(payload.control_id)
            and _normalize_key(c.get("control")) != _normalize_key(payload.control_id)
        )
    ]

    if len(new_controls) == len(controls):
        return {
            "success": False,
            "message": f"Control '{payload.control_id}' was not found.",
            "inventory": doc,
        }

    doc["controls"] = new_controls
    _save_json(_action_plan_implementation_file(year), doc)
    _sync_action_plan_status(year, doc)

    return {
        "success": True,
        "message": f"Control {payload.control_id} deleted successfully.",
        "inventory": doc,
    }


@router.post("/submit")
def submit_action_plan(payload: SubmitRequest):
    year = int(payload.year or 2026)
    doc = _load_action_plan_doc_or_blank(year)

    if _action_plan_section_is_read_only(year):
        return {
            "success": False,
            "message": "Action Plan / Implementation has already been submitted and is now read-only.",
            "inventory": doc,
        }

    if not payload.confirm:
        return {
            "success": True,
            "requires_confirmation": True,
            "message": "The Action Plan / Implementation results will be finalized and locked, are you sure?",
            "inventory": doc,
        }

    controls = _all_controls(doc)
    if len(controls) == 0:
        return {
            "success": False,
            "message": "The Action Plan / Implementation table is empty.",
            "inventory": doc,
        }

    missing_status = []
    invalid_status = []

    for control in controls:
        status_value = _normalize_text(control.get("implementation_status"))

        if status_value in {"", "-- Select --", "-- select --"}:
            missing_status.append(_format_control_label(control))
            continue

        if status_value not in VALID_IMPLEMENTATION_STATUSES:
            invalid_status.append(f"{_format_control_label(control)} -> {status_value}")

    if missing_status:
        return {
            "success": False,
            "message": (
                "Please select an implementation status for every control before submitting the "
                f"Action Plan / Implementation table. Missing selections: {', '.join(missing_status)}"
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

    _save_json(_action_plan_implementation_file(year), doc)
    
    status_doc = _load_system_status_or_default(year)
    
    current_status = status_doc["sections"]["action_plan_implementation"].get("status")
    
    if current_status != "In Progress":
        status_doc["sections"]["action_plan_implementation"]["status"] = "In Progress"
    
    _save_json(_system_status_file(year), status_doc)
    
    return {
        "success": True,
        "message": "The Action Plan / Implementation table data submitted succcesfully.",
        "records_finalized": len(controls),
        "inventory": doc,
    }

@router.post("/recommend-treatment")
def recommend_treatment_action(payload: RecommendTreatmentRequest):
    year = int(payload.year or 2026)
    doc = _load_action_plan_doc_or_blank(year)

    if _action_plan_section_is_read_only(year):
        return {
            "success": False,
            "message": "Action Plan / Implementation has already been submitted and is now read-only.",
            "inventory": doc,
        }

    idx, control = _find_control(doc, payload.control_id)
    if control is None or idx is None:
        return {
            "success": False,
            "message": f"Control '{payload.control_id}' was not found.",
            "inventory": doc,
        }

    control_id = _normalize_text(control.get("control_id") or control.get("control"))
    control_name = _normalize_text(control.get("control_name"))
    justification = _normalize_text(control.get("justification"))

    hosts = control.get("hosts", [])
    host_lines = []
    if isinstance(hosts, list):
        for host in hosts:
            if isinstance(host, dict):
                host_lines.append(
                    f"Host={_normalize_text(host.get('hostname'))}, "
                    f"Role={_normalize_text(host.get('role'))}, "
                    f"Vulnerability={_normalize_text(host.get('vulnerability_name'))}, "
                    f"CVE={_normalize_text(host.get('cve'))}, "
                    f"Risk={_normalize_text(host.get('risk'))}"
                )

    try:
        retrieved_controls = _retrieve_relevant_iso_controls(
            year=year,
            control_id=control_id,
            control_name=control_name,
            justification=justification,
            host_lines=host_lines,
            top_k=5,
        )

        generated_treatment_action = _generate_treatment_action_with_llama3(
            control_id=control_id,
            control_name=control_name,
            justification=justification,
            host_lines=host_lines,
            retrieved_controls=retrieved_controls,
        )
    except Exception as e:
        return {
            "success": False,
            "message": f"Failed to generate treatment action via RAG + Llama3: {str(e)}",
            "inventory": doc,
        }

    control["treatment_action"] = generated_treatment_action

    controls = doc.get("controls", [])
    if isinstance(controls, list):
        controls[idx] = control
        doc["controls"] = controls

    _save_json(_action_plan_implementation_file(year), doc)
    _sync_action_plan_status(year, doc)

    return {
        "success": True,
        "message": f"Treatment action generated for control {control_id}.",
        "control": control,
        "inventory": doc,
    }

@router.post("/add-evidence")
def add_evidence_to_host(payload: AddEvidenceRequest):
    year = int(payload.year or 2026)
    doc = _load_action_plan_doc_or_blank(year)

    if _action_plan_section_is_read_only(year):
        return {
            "success": False,
            "message": "Action Plan / Implementation has already been submitted and is now read-only.",
            "inventory": doc,
        }

    idx, control = _find_control(doc, payload.control_id)
    if control is None or idx is None:
        return {
            "success": False,
            "message": f"Control '{payload.control_id}' was not found.",
            "inventory": doc,
        }

    hosts = control.get("hosts", [])
    if not isinstance(hosts, list):
        hosts = []

    target_host_index = None
    for host_idx, host in enumerate(hosts):
        if not isinstance(host, dict):
            continue
        if (
            _normalize_key(host.get("hostname")) == _normalize_key(payload.hostname)
            and _normalize_key(host.get("vulnerability_name")) == _normalize_key(payload.vulnerability_name)
        ):
            target_host_index = host_idx
            break

    if target_host_index is None:
        return {
            "success": False,
            "message": f"Host '{payload.hostname}' was not found under control '{payload.control_id}'.",
            "inventory": doc,
        }

    host = hosts[target_host_index]
    _ensure_evidence_ids_for_host(year, doc, host)

    existing_evidence = host.get("evidence", [])
    if not isinstance(existing_evidence, list):
        existing_evidence = []

    cleaned_evidence = []
    for item in existing_evidence:
        if not isinstance(item, dict):
            continue

        normalized_item = {
            "evidence_id": _normalize_text(item.get("evidence_id")) or _next_evidence_id(year, doc),
            "responsible": _normalize_text(item.get("responsible")),
            "resources": _normalize_text(item.get("resources")),
            "date": _normalize_text(item.get("date")),
            "url": _normalize_text(item.get("url")),
            "desc": _normalize_text(item.get("desc")),
        }

        if any(v for k, v in normalized_item.items() if k != "evidence_id"):
            cleaned_evidence.append(normalized_item)

    existing_evidence = cleaned_evidence

    control_id = _normalize_text(control.get("control_id") or control.get("control"))
    control_name = _normalize_text(control.get("control_name"))
    justification = _normalize_text(control.get("justification"))

    hostname = _normalize_text(host.get("hostname"))
    role = _normalize_text(host.get("role"))
    vulnerability_name = _normalize_text(host.get("vulnerability_name"))
    cve = _normalize_text(host.get("cve"))
    risk = _normalize_text(host.get("risk"))
    treatment_action = _normalize_text(host.get("treatment_action") or control.get("treatment_action"))

    desc_value = _normalize_text(payload.evidence.desc)

    if desc_value == "":
        try:
            desc_value = _generate_meaningful_evidence_desc_with_llama3(
                year=year,
                control_id=control_id,
                control_name=control_name,
                justification=justification,
                hostname=hostname,
                role=role,
                vulnerability_name=vulnerability_name,
                cve=cve,
                risk=risk,
                treatment_action=treatment_action,
            )
        except Exception:
            desc_value = (
                f"Evidence confirms the treatment action for host {hostname} "
                f"under control {control_id} ({control_name}) was implemented."
            )

    new_evidence = {
        "evidence_id": _next_evidence_id(year, doc),
        "responsible": _normalize_text(payload.evidence.responsible),
        "resources": _normalize_text(payload.evidence.resources),
        "date": _normalize_text(payload.evidence.date),
        "url": _normalize_text(payload.evidence.url),
        "desc": desc_value,
    }

    if not any(v for k, v in new_evidence.items() if k != "evidence_id"):
        return {
            "success": False,
            "message": "At least one evidence field must be provided.",
            "inventory": doc,
        }

    existing_evidence.append(new_evidence)
    host["evidence"] = existing_evidence
    hosts[target_host_index] = host
    control["hosts"] = hosts

    controls = doc.get("controls", [])
    if isinstance(controls, list):
        controls[idx] = control
        doc["controls"] = controls

    _save_json(_action_plan_implementation_file(year), doc)

    guide = None
    try:
        _ensure_action_implementation_guides_file_exists(year)
    
        guide = _replace_guide_for_evidence(
            year=year,
            control=control,
            host=host,
            evidence=new_evidence,
        )
    
    except Exception as e:
        import traceback
        print("GUIDE GENERATION FAILED")
        print(traceback.format_exc())
    
        return {
            "success": False,
            "message": f"Evidence was added but guide generation failed: {str(e)}",
            "inventory": doc,
        }

    _sync_action_plan_status(year, doc)
    print("GUIDE FILE PATH:", _action_implementation_guides_file(year))
    return {
        "success": True,
        "message": f"Evidence added for host {payload.hostname} under control {payload.control_id}. Guide generated successfully.",
        "guide_id": guide.get("guide_id") if isinstance(guide, dict) else "",
        "guide_key": guide.get("guide_key") if isinstance(guide, dict) else "",
        "inventory": doc,
    }

@router.post("/upload-evidence")
async def upload_evidence(file: UploadFile = File(...), year: int = 2026):
    save_dir = _work_dir(year) / "evidence"
    save_dir.mkdir(parents=True, exist_ok=True)

    file_path = save_dir / file.filename

    with open(file_path, "wb") as f:
        f.write(await file.read())

    return {
        "success": True,
        "path": str(file_path),
    }

@router.post("/delete-evidence")
def delete_evidence(payload: DeleteEvidenceRequest):
    year = int(payload.year or 2026)
    doc = _load_action_plan_doc_or_blank(year)

    if _action_plan_section_is_read_only(year):
        return {
            "success": False,
            "message": "Action Plan / Implementation has already been submitted and is now read-only.",
            "inventory": doc,
        }

    idx, control = _find_control(doc, payload.control_id)
    if control is None or idx is None:
        return {
            "success": False,
            "message": f"Control '{payload.control_id}' was not found.",
            "inventory": doc,
        }

    hosts = control.get("hosts", [])
    if not isinstance(hosts, list):
        hosts = []

    target_host_index = None
    for host_idx, host in enumerate(hosts):
        if (
            isinstance(host, dict)
            and _normalize_key(host.get("hostname")) == _normalize_key(payload.hostname)
            and _normalize_key(host.get("vulnerability_name")) == _normalize_key(payload.vulnerability_name)
        ):
            target_host_index = host_idx
            break

    if target_host_index is None:
        return {
            "success": False,
            "message": f"Host '{payload.hostname}' was not found under control '{payload.control_id}'.",
            "inventory": doc,
        }

    host = hosts[target_host_index]
    _ensure_evidence_ids_for_host(year, doc, host)
    evidence = host.get("evidence", [])
    if not isinstance(evidence, list):
        evidence = []

    if payload.evidence_index < 0 or payload.evidence_index >= len(evidence):
        return {
            "success": False,
            "message": "Selected evidence index is invalid.",
            "inventory": doc,
        }

    removed_item = evidence.pop(payload.evidence_index) if isinstance(evidence[payload.evidence_index], dict) else {}
    removed_evidence_id = _normalize_text(removed_item.get("evidence_id"))

    host["evidence"] = evidence
    hosts[target_host_index] = host
    control["hosts"] = hosts

    controls = doc.get("controls", [])
    if isinstance(controls, list):
        controls[idx] = control
        doc["controls"] = controls

    _save_json(_action_plan_implementation_file(year), doc)
    guide_deleted = _remove_guide_by_key(year, removed_evidence_id) if removed_evidence_id else False
    _sync_action_plan_status(year, doc)

    return {
        "success": True,
        "message": "Selected evidence was deleted successfully.",
        "guide_deleted": guide_deleted,
        "inventory": doc,
    }

@router.post("/edit-evidence")
def edit_evidence(payload: EditEvidenceRequest):
    year = int(payload.year or 2026)
    doc = _load_action_plan_doc_or_blank(year)

    if _action_plan_section_is_read_only(year):
        return {
            "success": False,
            "message": "Action Plan / Implementation has already been submitted and is now read-only.",
            "inventory": doc,
        }

    idx, control = _find_control(doc, payload.control_id)
    if control is None or idx is None:
        return {
            "success": False,
            "message": f"Control '{payload.control_id}' was not found.",
            "inventory": doc,
        }

    hosts = control.get("hosts", [])
    if not isinstance(hosts, list):
        hosts = []

    target_host_index = None
    for host_idx, host in enumerate(hosts):
        if (
            isinstance(host, dict)
            and _normalize_key(host.get("hostname")) == _normalize_key(payload.hostname)
            and _normalize_key(host.get("vulnerability_name")) == _normalize_key(payload.vulnerability_name)
        ):
            target_host_index = host_idx
            break

    if target_host_index is None:
        return {
            "success": False,
            "message": (
                f"Host '{payload.hostname}' with vulnerability "
                f"'{payload.vulnerability_name}' was not found under control '{payload.control_id}'."
            ),
            "inventory": doc,
        }

    host = hosts[target_host_index]
    _ensure_evidence_ids_for_host(year, doc, host)
    evidence_list = host.get("evidence", [])
    if not isinstance(evidence_list, list):
        evidence_list = []

    evidence_index = int(payload.evidence_index)
    if evidence_index < 0 or evidence_index >= len(evidence_list):
        return {
            "success": False,
            "message": "Selected evidence index is invalid.",
            "inventory": doc,
        }

    old_item = evidence_list[evidence_index] if isinstance(evidence_list[evidence_index], dict) else {}
    evidence_id = _normalize_text(old_item.get("evidence_id")) or _next_evidence_id(year, doc)

    updated_evidence = {
        "evidence_id": evidence_id,
        "responsible": _normalize_text(payload.evidence.responsible),
        "resources": _normalize_text(payload.evidence.resources),
        "date": _normalize_text(payload.evidence.date),
        "url": _normalize_text(payload.evidence.url),
        "desc": _normalize_text(payload.evidence.desc),
    }

    if not any(v for k, v in updated_evidence.items() if k != "evidence_id"):
        return {
            "success": False,
            "message": "Please fill at least one evidence field.",
            "inventory": doc,
        }

    evidence_list[evidence_index] = updated_evidence
    host["evidence"] = evidence_list
    hosts[target_host_index] = host
    control["hosts"] = hosts

    controls = doc.get("controls", [])
    if isinstance(controls, list):
        controls[idx] = control
        doc["controls"] = controls

    _save_json(_action_plan_implementation_file(year), doc)

    guide = None
    try:
        guide = _replace_guide_for_evidence(year, control, host, updated_evidence)
    except Exception as e:
        return {
            "success": False,
            "message": f"Evidence was updated but guide regeneration failed: {str(e)}",
            "inventory": doc,
        }

    _sync_action_plan_status(year, doc)

    return {
        "success": True,
        "message": f"Evidence updated for host '{payload.hostname}'. Guide regenerated successfully.",
        "guide_id": guide.get("guide_id") if isinstance(guide, dict) else "",
        "guide_key": guide.get("guide_key") if isinstance(guide, dict) else "",
        "inventory": doc,
    }

@router.post("/recommend-treatment-all")
def recommend_treatment_action_all(payload: RecommendAllTreatmentRequest):
    year = int(payload.year or 2026)
    doc = _load_action_plan_doc_or_blank(year)

    if _action_plan_section_is_read_only(year):
        return {
            "success": False,
            "message": "Action Plan / Implementation is read-only.",
            "inventory": doc,
        }

    controls = _all_controls(doc)
    if not controls:
        return {
            "success": False,
            "message": "No controls found in the Action Plan / Implementation table.",
            "inventory": doc,
        }

    MAX_HOSTS_FOR_PROMPT = 5
    MAX_JUSTIFICATION_CHARS = 500

    for idx, control in enumerate(controls):
        control_id = _normalize_text(control.get("control_id") or control.get("control"))
        control_name = _normalize_text(control.get("control_name"))
        justification = _normalize_text(control.get("justification"))
        justification_for_prompt = (
            (justification[:MAX_JUSTIFICATION_CHARS] + '...') 
            if len(justification) > MAX_JUSTIFICATION_CHARS 
            else justification
        )

        hosts = control.get("hosts", [])

        # Build host lines including RiskID to make duplicates unique
        host_lines = [
            f"Host={_normalize_text(h.get('hostname'))} | Role={_normalize_text(h.get('role'))} | "
            f"Vulnerability={_normalize_text(h.get('vulnerability_name'))} | CVE={_normalize_text(h.get('cve'))} | "
            f"Risk={_normalize_text(h.get('risk'))} | RiskID={_normalize_text(h.get('riskid'))}"
            for h in hosts if isinstance(h, dict)
        ] or ["NA"]


        # Limit host lines for LLM prompt
        host_lines_for_prompt = host_lines[:MAX_HOSTS_FOR_PROMPT]
        if len(host_lines) > MAX_HOSTS_FOR_PROMPT:
            host_lines_for_prompt.append(f"...and {len(host_lines) - MAX_HOSTS_FOR_PROMPT} more hosts")

        retrieved_controls = _retrieve_relevant_iso_controls(
            year=year,
            control_id=control_id,
            control_name=control_name,
            justification=justification_for_prompt,
            host_lines=host_lines_for_prompt,
            top_k=5,
        )


        # LLM wrapped in try/except
        try:
            generated_treatment_action = _generate_treatment_action_with_llama3(
                control_id=control_id,
                control_name=control_name,
                justification=justification_for_prompt,
                host_lines=host_lines_for_prompt,
                retrieved_controls=retrieved_controls,
            )
        except Exception as e:
            print(f"[ERROR] LLM failed for control {control_id}: {e}")
            generated_treatment_action = f"Recommended treatment actions:\n- Apply controls for {control_id} on all hosts."

        # Fallback if empty
        if not generated_treatment_action:
            print(f"[WARN] Empty treatment returned for control {control_id}, applying fallback")
            generated_treatment_action = f"Recommended treatment actions:\n- Apply controls for {control_id} on all hosts."

        # Apply to control
        control["treatment_action"] = generated_treatment_action

        # Apply to all hosts individually
        for host in hosts:
            if isinstance(host, dict):
                host["treatment_action"] = generated_treatment_action

        controls[idx] = control

    doc["controls"] = controls
    _save_json(_action_plan_implementation_file(year), doc)
    _sync_action_plan_status(year, doc)

    return {
        "success": True,
        "message": "Treatment actions generated for all controls and hosts.",
        "inventory": doc,
    }