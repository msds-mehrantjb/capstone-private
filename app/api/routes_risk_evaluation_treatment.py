from fastapi import APIRouter, Query, HTTPException
import json
from pathlib import Path
from typing import Any
import requests
from pydantic import BaseModel

from app.api.aiml_kpi_telemetry import ollama_total_tokens, safe_increment_llm_counter

router = APIRouter(
    prefix="/api/risk-evaluation-treatment",
    tags=["risk-evaluation-treatment"],
)

VALID_STEP_STATUSES = {"Blocked", "Not Started", "In Progress", "Completed"}
VALID_RISK_VALUES = {"Critical", "High", "Medium", "Low", "Unscanned"}
VALID_TREATMENT_VALUES = {"Mitigate", "Accept", "Transfer", "Avoid"}

VALID_EVALUATION_VALUES = {"Accept", "Monitor", "Treat"}


class SetEvaluationRequest(BaseModel):
    year: int | None = 2026
    hostname: str
    cve: str
    evaluation: str


class SetTreatmentRequest(BaseModel):
    year: int | None = 2026
    hostname: str
    cve: str
    treatment: str


class SubmitRequest(BaseModel):
    year: int | None = 2026
    confirm: bool = False


class ReinitializeRequest(BaseModel):
    year: int | None = 2026
    confirm: bool = False


def find_project_root() -> Path:
    current = Path(__file__).resolve()
    for parent in [current] + list(current.parents):
        if (parent / "data" / "work").exists():
            return parent
    raise RuntimeError("Could not find project root containing data/work")


BASE_DIR = find_project_root()

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OLLAMA_GEN_URL = "http://localhost:11434/api/generate"
LLM_MODEL = "qwen3:14b"

SESSION = requests.Session()


def _work_dir(year: int) -> Path:
    return BASE_DIR / "data" / "work" / str(year)


def _risk_evaluation_treatment_file(year: int) -> Path:
    return _work_dir(year) / "RiskEvaluationTreatment.json"


def _annex_a_soa_file(year: int) -> Path:
    return _work_dir(year) / "AnnexA_SoA.json"


def _system_status_file(year: int) -> Path:
    return _work_dir(year) / "SystemStatus.json"


def _action_plan_implementation_file(year: int) -> Path:
    return _work_dir(year) / "ActionPlanImplementation.json"


def _action_implementation_guides_file(year: int) -> Path:
    return _work_dir(year) / "ActionImplementationGuides.json"


def _monitoring_improvement_file(year: int) -> Path:
    return _work_dir(year) / "MonitoringImprovement.json"


def _monitoring_implementation_guides_file(year: int) -> Path:
    return _work_dir(year) / "MonitoringImplementationGuides.json"

def _load_json(path: Path) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def _normalize_hostname(value: str) -> str:
    return (value or "").strip().lower()


def _normalize_risk(value: str) -> str:
    raw = (value or "").strip().lower()
    if raw == "critical":
        return "Critical"
    if raw == "high":
        return "High"
    if raw == "medium":
        return "Medium"
    if raw == "low":
        return "Low"
    if raw == "unscanned":
        return "Unscanned"
    return ""


VALID_TREATMENT_VALUES = {"Mitigate", "Accept", "Transfer", "Avoid"}


def _normalize_treatment(value: str) -> str:
    raw = (value or "").strip().lower()
    if raw == "mitigate":
        return "Mitigate"
    if raw == "accept":
        return "Accept"
    if raw == "transfer":
        return "Transfer"
    if raw == "avoid":
        return "Avoid"
    if raw == "-":
        return "-"
    return ""


def _normalize_record_treatment_for_evaluation(evaluation: str, treatment: str) -> str:
    normalized_evaluation = _normalize_evaluation(evaluation)
    normalized_treatment = _normalize_treatment(treatment)

    if normalized_evaluation != "Treat":
        return "-"

    if normalized_treatment in VALID_TREATMENT_VALUES:
        return normalized_treatment

    return ""

def _normalize_evaluation(value: str) -> str:
    raw = (value or "").strip().lower()
    if raw == "accept":
        return "Accept"
    if raw == "monitor":
        return "Monitor"
    if raw == "treat":
        return "Treat"
    return ""


def _derive_risk_evaluation_from_risk(risk: str) -> str:
    normalized = _normalize_risk(risk)

    if normalized == "Low":
        return "Accept"
    if normalized == "Medium":
        return "Monitor"
    if normalized in {"High", "Critical"}:
        return "Treat"
    return ""


def _blank_risk_evaluation_treatment_inventory() -> dict:
    return {"hosts": []}


def _all_hosts(inventory: dict) -> list[dict]:
    hosts = inventory.get("hosts", [])
    if not isinstance(hosts, list):
        return []
    return [h for h in hosts if isinstance(h, dict)]


def _normalize_existing_record(record: dict) -> dict:
    risk_value = _normalize_risk(str(record.get("risk") or "Unscanned")) or "Unscanned"
    cve_value = str(record.get("cve") or "").strip()

    evaluation_value = _normalize_evaluation(
        str(
            record.get("evaluation")
            or record.get("Evaluation")
            or ""
        ).strip()
    )

    if not evaluation_value:
        evaluation_value = _derive_default_evaluation({
            "cve": cve_value,
            "risk": risk_value,
        })

    raw_treatment = str(
        record.get("treatment")
        or record.get("Treatment")
        or ""
    ).strip()

    normalized_treatment = _normalize_record_treatment_for_evaluation(
        evaluation_value,
        raw_treatment,
    )

    # Migrate legacy User Activity Behavior rows that were previously auto-set
    # to Monitor when Low risk. Low risk should now default to Accept.
    if (
        cve_value.upper().startswith("UB-WS-")
        and risk_value == "Low"
        and evaluation_value == "Monitor"
        and normalized_treatment == "-"
    ):
        evaluation_value = "Accept"
        normalized_treatment = "-"

    return {
        "hostname": str(record.get("hostname") or "").strip(),
        "ip_address": str(record.get("ip_address") or "").strip(),
        "role": str(record.get("role") or "").strip(),
        "CIA rating": str(
            record.get("CIA rating")
            or record.get("cia_rating")
            or record.get("impact")
            or ""
        ).strip(),
        "vulnerability_name": str(record.get("vulnerability_name") or "").strip(),
        "cve": cve_value,
        "riskid": str(record.get("riskid") or "").strip(),
        "risk": risk_value,
        "evaluation": evaluation_value,
        "treatment": normalized_treatment,
    }
    
def _load_risk_evaluation_treatment_inventory_or_blank(year: int) -> dict:
    path = _risk_evaluation_treatment_file(year)

    if not path.exists():
        return _blank_risk_evaluation_treatment_inventory()

    try:
        data = _load_json(path)
        if isinstance(data, dict):
            if not isinstance(data.get("hosts"), list):
                data["hosts"] = []
            original_hosts = _all_hosts(data)
            normalized_hosts = [_normalize_existing_record(h) for h in original_hosts]
            data["hosts"] = normalized_hosts
            if normalized_hosts != original_hosts:
                _save_json(path, data)
            return data
    except Exception:
        pass

    return _blank_risk_evaluation_treatment_inventory()


def _load_system_status_or_default(year: int) -> dict:
    path = _system_status_file(year)

    if not path.exists():
        return {
            "meta": {"name": "System Status", "version": "1.0"},
            "sections": {
                "scope_context": {"status": "Not Started"},
                "assets_cia": {"status": "Not Started"},
                "risk_analysis": {"status": "Not Started"},
                "risk_evaluation_treatment": {"status": "Blocked"},
                "annex_a_soa": {"status": "Blocked"},
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
        "risk_evaluation_treatment": {"status": "Blocked"},
        "annex_a_soa": {"status": "Blocked"},
    }

    for key, value in defaults.items():
        if not isinstance(data["sections"].get(key), dict):
            data["sections"][key] = value.copy()

    return data


def _set_section_status(year: int, section_name: str, new_status: str) -> None:
    if new_status not in VALID_STEP_STATUSES:
        raise ValueError(f"Invalid status: {new_status}")

    doc = _load_system_status_or_default(year)

    if section_name not in doc["sections"] or not isinstance(doc["sections"][section_name], dict):
        doc["sections"][section_name] = {}

    doc["sections"][section_name]["status"] = new_status
    _save_json(_system_status_file(year), doc)


def _set_risk_evaluation_treatment_status(year: int, new_status: str) -> None:
    _set_section_status(year, "risk_evaluation_treatment", new_status)


def _set_annex_a_soa_status(year: int, new_status: str) -> None:
    _set_section_status(year, "annex_a_soa", new_status)


def _set_action_plan_implementation_status(year: int, new_status: str) -> None:
    _set_section_status(year, "action_plan_implementation", new_status)


def _set_monitoring_improvement_status(year: int, new_status: str) -> None:
    _set_section_status(year, "monitoring_improvement", new_status)


def _risk_evaluation_treatment_is_read_only(year: int) -> bool:
    doc = _load_system_status_or_default(year)
    status = doc.get("sections", {}).get("risk_evaluation_treatment", {}).get("status")
    return status == "Completed"


def _ensure_risk_evaluation_treatment_editable(year: int, inventory: dict | None = None) -> None:
    doc = inventory if isinstance(inventory, dict) else _load_risk_evaluation_treatment_inventory_or_blank(year)
    if len(_all_hosts(doc)) == 0:
        return
    if _risk_evaluation_treatment_is_read_only(year):
        _set_risk_evaluation_treatment_status(year, "In Progress")


def _find_record_by_hostname_and_cve(
    inventory: dict,
    hostname: str,
    cve: str,
) -> tuple[int | None, dict | None]:
    target_host = _normalize_hostname(hostname)
    target_cve = (cve or "").strip().lower()

    hosts = _all_hosts(inventory)
    for idx, host in enumerate(hosts):
        current_host = _normalize_hostname(str(host.get("hostname", "")))
        current_cve = str(host.get("cve", "")).strip().lower()
        if current_host == target_host and current_cve == target_cve:
            return idx, host

    return None, None

def _build_action_plan_record(record: dict) -> dict:
    r = _normalize_existing_record(record)
    return {
        "hostname": str(r.get("hostname") or "").strip(),
        "ip_address": str(r.get("ip_address") or "").strip(),
        "role": str(r.get("role") or "").strip(),
        "CIA rating": str(r.get("CIA rating") or "").strip(),
        "vulnerability_name": str(r.get("vulnerability_name") or "").strip(),
        "cve": str(r.get("cve") or "").strip(),
        "riskid": str(r.get("riskid") or "").strip(),
        "risk": str(r.get("risk") or "").strip(),
        "evaluation": str(r.get("evaluation") or "").strip(),
        "treatment": str(r.get("treatment") or "").strip(),
        "treatment_action": "",
        "control": "",
        "responsible": "",
        "resources": "",
        "date": "",
    }

def _fetch_cve_from_nvd(cve_id: str) -> dict:
    response = SESSION.get(
        NVD_API_URL,
        params={"cveId": cve_id},
        timeout=120,
    )
    response.raise_for_status()
    data = response.json()

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return {
            "cve_id": cve_id,
            "description": "",
            "severity": "",
            "cwe": [],
            "vector": "",
        }

    cve = vulns[0].get("cve", {})

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

    severity = ""
    vector = ""
    metrics = cve.get("metrics", {})

    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if key in metrics and metrics[key]:
            metric = metrics[key][0]
            cvss = metric.get("cvssData", {})
            severity = metric.get("baseSeverity") or cvss.get("baseSeverity") or ""
            vector = cvss.get("vectorString") or ""
            break

    return {
        "cve_id": cve_id,
        "description": description,
        "severity": severity,
        "cwe": cwe_values,
        "vector": vector,
    }


def _derive_default_evaluation(record: dict) -> str:
    risk = _normalize_risk(str(record.get("risk") or ""))

    return _derive_risk_evaluation_from_risk(risk)

def _ask_llama3_for_monitoring_fields(record: dict, cve_info: dict, year: int = 2026) -> tuple[str, str]:
    hostname = str(record.get("hostname") or "").strip()
    role = str(record.get("role") or "").strip()
    cia_rating = str(record.get("CIA rating") or "").strip()
    vulnerability_name = str(record.get("vulnerability_name") or "").strip()
    cve_id = str(record.get("cve") or "").strip()
    risk = str(record.get("risk") or "").strip()
    evaluation = str(record.get("evaluation") or "").strip()

    prompt = f"""
You are an ISO 27001 cybersecurity expert.

Generate two short fields for a MonitoringImprovement.json record:
1. justification
2. recommended_action

Use the host context and the CVE details from NVD.
Be specific, practical, and concise.
The justification field is required. It must be one short paragraph explaining why this risk needs monitoring.
The recommended_action field is required. It must start with "Recommended monitoring actions:" and then use dash bullets.
Do not use markdown.
Return valid JSON only in this format:
{{
  "justification": "...",
  "recommended_action": "..."
}}

Host context:
hostname: {hostname}
role: {role}
CIA rating: {cia_rating}
vulnerability_name: {vulnerability_name}
cve: {cve_id}
risk: {risk}
evaluation: {evaluation}

NVD data:
description: {cve_info.get("description", "")}
severity: {cve_info.get("severity", "")}
cwe: {", ".join(cve_info.get("cwe", []))}
vector: {cve_info.get("vector", "")}
"""

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
                "num_predict": 300
            }
        },
        timeout=180,
    )
    response.raise_for_status()

    response_data = response.json()
    safe_increment_llm_counter(year, ollama_total_tokens(response_data))
    raw = response_data.get("response", "{}")
    try:
        parsed = json.loads(raw)
    except Exception:
        parsed = {}

    justification = str(parsed.get("justification") or "").strip()
    recommended_action = str(parsed.get("recommended_action") or "").strip()

    return justification, recommended_action


def _ask_llama3_for_monitoring_justification(record: dict, cve_info: dict, year: int = 2026) -> str:
    hostname = str(record.get("hostname") or "").strip()
    role = str(record.get("role") or "").strip()
    cia_rating = str(record.get("CIA rating") or "").strip()
    vulnerability_name = str(record.get("vulnerability_name") or "").strip()
    cve_id = str(record.get("cve") or "").strip()
    risk = str(record.get("risk") or "").strip()
    evaluation = str(record.get("evaluation") or "").strip()

    prompt = f"""
Return JSON only with one key named justification.
The justification value must be non-empty and must be one short ISO 27001 monitoring paragraph.

Write why ongoing monitoring is needed for this exact risk:
Host: {hostname or "affected asset"}
Role: {role or "unknown role"}
CIA rating: {cia_rating or "unknown"}
Vulnerability: {vulnerability_name or cve_id or "identified vulnerability"}
CVE: {cve_id or "NA"}
Risk level: {risk or "Monitor"}
Evaluation decision: {evaluation or "Monitor"}
NVD description: {cve_info.get("description", "") or "No NVD description available."}
NVD severity: {cve_info.get("severity", "") or "NA"}
NVD CWE: {", ".join(cve_info.get("cwe", [])) or "NA"}
NVD vector: {cve_info.get("vector", "") or "NA"}

The paragraph must explain detection, exposure review, remediation tracking, evidence collection, and ISO 27001 continual improvement.
Do not return an empty string.
"""

    response = SESSION.post(
        OLLAMA_GEN_URL,
        json={
            "model": LLM_MODEL,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "keep_alive": "10m",
            "options": {
                "temperature": 0.15,
                "top_p": 0.85,
                "num_predict": 220,
            },
        },
        timeout=180,
    )
    response.raise_for_status()

    response_data = response.json()
    safe_increment_llm_counter(year, ollama_total_tokens(response_data))
    raw = response_data.get("response", "{}")
    try:
        parsed = json.loads(raw)
    except Exception:
        parsed = {}

    return str(parsed.get("justification") or "").strip()


def _is_meaningful_monitoring_text(value: str) -> bool:
    return len((value or "").strip()) >= 30


def _safe_generate_monitoring_fields(record: dict, year: int = 2026) -> tuple[str, str]:
    cve_id = str(record.get("cve") or "").strip()

    cve_info = {
        "cve_id": cve_id,
        "description": "",
        "severity": "",
        "cwe": [],
        "vector": "",
    }

    if cve_id.upper().startswith("CVE-"):
        try:
            cve_info = _fetch_cve_from_nvd(cve_id)
        except Exception:
            pass

    fallback_justification, fallback_action = _fallback_monitoring_fields(record)

    try:
        justification, recommended_action = _ask_llama3_for_monitoring_fields(record, cve_info, year=year)
    except Exception:
        justification, recommended_action = "", ""

    if not _is_meaningful_monitoring_text(justification):
        try:
            justification = _ask_llama3_for_monitoring_justification(record, cve_info, year=year)
        except Exception:
            justification = ""

    return (
        justification if _is_meaningful_monitoring_text(justification) else fallback_justification,
        recommended_action if _is_meaningful_monitoring_text(recommended_action) else fallback_action,
    )


def _fallback_monitoring_fields(record: dict) -> tuple[str, str]:
    hostname = str(record.get("hostname") or "").strip()
    vulnerability_name = str(record.get("vulnerability_name") or "").strip()
    cve_id = str(record.get("cve") or "").strip()
    risk = str(record.get("risk") or "").strip()

    vulnerability_label = vulnerability_name or cve_id or "the identified vulnerability"
    host_label = hostname or "the affected asset"
    risk_label = risk or "the monitored risk"

    justification = (
        f"Monitoring is required for {vulnerability_label} on {host_label} because the risk is currently "
        f"evaluated as {risk_label} and was selected for ongoing monitoring instead of immediate treatment. "
        "Tracking security events, exposure, patch status, and remediation evidence helps confirm the risk "
        "stays controlled and supports ISO 27001 continual improvement."
    )
    recommended_action = (
        "Recommended monitoring actions:\n"
        f"- Review security logs and alerts related to {vulnerability_label} on affected hosts.\n"
        "- Track patch, configuration, and exposure status until the risk is formally reassessed.\n"
        "- Collect monitoring evidence such as scan results, SIEM alerts, tickets, or screenshots.\n"
        "- Escalate repeated suspicious activity or failed remediation for corrective action."
    )

    return justification, recommended_action
    

def _build_monitoring_improvement_record(record: dict, year: int = 2026) -> dict:
    r = _normalize_existing_record(record)
    justification, recommended_action = _safe_generate_monitoring_fields(r, year=year)

    return {
        "hostname": str(r.get("hostname") or "").strip(),
        "ip_address": str(r.get("ip_address") or "").strip(),
        "role": str(r.get("role") or "").strip(),
        "CIA rating": str(r.get("CIA rating") or "").strip(),
        "vulnerability_name": str(r.get("vulnerability_name") or "").strip(),
        "justification": justification,
        "recommended_action": recommended_action,
        "cve": str(r.get("cve") or "").strip(),
        "riskid": str(r.get("riskid") or "").strip(),
        "risk": str(r.get("risk") or "").strip(),
        "evaluation": str(r.get("evaluation") or "").strip(),
        "evidence": [
            {
                "responsible": "",
                "resources": "",
                "date": "",
                "url": "",
                "desc": "",
            }
        ],
    }


def _blank_controls_doc() -> dict:
    return {"controls": []}


def _blank_monitoring_evidence() -> dict:
    return {
        "responsible": "",
        "resources": "",
        "date": "",
        "url": "",
        "desc": "",
    }


def _build_monitoring_improvement_doc(records: list[dict], year: int = 2026) -> dict:
    cve_map: dict[str, dict] = {}

    for record in records:
        r = _normalize_existing_record(record)

        if str(r.get("evaluation") or "").strip() != "Monitor":
            continue

        cve_value = str(r.get("cve") or "").strip()
        if not cve_value:
            continue

        vulnerability_value = str(r.get("vulnerability_name") or "").strip()

        if cve_value not in cve_map:
            justification, recommended_action = _safe_generate_monitoring_fields(r, year=year)
            cve_map[cve_value] = {
                "CVE": cve_value,
                "vulnerability": vulnerability_value,
                "implementation_status": "In Progress",
                "justification": justification,
                "recommended_action": recommended_action,
                "hosts": [],
            }

        host_obj = {
            "hostname": str(r.get("hostname") or "").strip(),
            "ip_address": str(r.get("ip_address") or "").strip(),
            "role": str(r.get("role") or "").strip(),
            "CIA rating": str(r.get("CIA rating") or "").strip(),
            "vulnerability_name": vulnerability_value,
            "risk": str(r.get("risk") or "").strip(),
            "riskid": str(r.get("riskid") or "").strip(),
            "evaluation": str(r.get("evaluation") or "").strip(),
            "treatment": str(r.get("treatment") or "").strip(),
            "evidence": [_blank_monitoring_evidence()],
        }

        existing_hosts = cve_map[cve_value]["hosts"]
        duplicate = any(
            _normalize_hostname(str(h.get("hostname") or "")) == _normalize_hostname(host_obj["hostname"])
            and str(h.get("ip_address") or "").strip() == host_obj["ip_address"]
            for h in existing_hosts
            if isinstance(h, dict)
        )

        if not duplicate:
            existing_hosts.append(host_obj)

    return {"cves": list(cve_map.values())}


@router.get("/inventory")
def get_risk_evaluation_treatment_inventory(year: int = Query(2026)):
    year = int(year)
    path = _risk_evaluation_treatment_file(year)

    if not path.exists():
        raise HTTPException(status_code=404, detail="You didn't finalize the risk analysis.")

    inventory = _load_risk_evaluation_treatment_inventory_or_blank(year)

    _ensure_risk_evaluation_treatment_editable(year, inventory)

    return inventory


@router.get("/exists")
def risk_evaluation_treatment_exists(year: int = Query(2026)):
    path = _risk_evaluation_treatment_file(int(year))
    return {"exists": path.exists()}


@router.post("/set-treatment")
def set_treatment(payload: SetTreatmentRequest):
    year = int(payload.year or 2026)
    inventory = _load_risk_evaluation_treatment_inventory_or_blank(year)
    _ensure_risk_evaluation_treatment_editable(year, inventory)

    if _risk_evaluation_treatment_is_read_only(year):
        return {
            "success": False,
            "message": "Risk evaluation and treatment has already been submitted and is now read-only.",
            "inventory": inventory,
        }

    idx, record = _find_record_by_hostname_and_cve(inventory, payload.hostname, payload.cve)
    if record is None or idx is None:
        return {
            "success": False,
            "message": f"Record not found for host '{payload.hostname}' and CVE '{payload.cve}'.",
            "inventory": inventory,
        }

    current_evaluation = _normalize_evaluation(str(record.get("evaluation") or ""))

    if current_evaluation != "Treat":
        record["treatment"] = "-"
        hosts = inventory.get("hosts", [])
        if isinstance(hosts, list):
            hosts[idx] = _normalize_existing_record(record)
            inventory["hosts"] = hosts

        _save_json(_risk_evaluation_treatment_file(year), inventory)
        _set_risk_evaluation_treatment_status(year, "In Progress")

        return {
            "success": True,
            "message": (
                f"Treatment is not applicable for {payload.hostname} / {payload.cve} "
                f"because evaluation is not Treat."
            ),
            "inventory": inventory,
        }

    raw_treatment = str(payload.treatment or "").strip()

    if raw_treatment == "":
        normalized_treatment = ""
    else:
        normalized_treatment = _normalize_treatment(raw_treatment)
        if normalized_treatment not in VALID_TREATMENT_VALUES:
            return {
                "success": False,
                "message": "Invalid treatment value. Allowed values are Mitigate, Accept, Transfer, Avoid, or empty.",
                "inventory": inventory,
            }

    old_treatment = str(record.get("treatment") or "")
    record["treatment"] = normalized_treatment

    hosts = inventory.get("hosts", [])
    if isinstance(hosts, list):
        hosts[idx] = _normalize_existing_record(record)
        inventory["hosts"] = hosts

    _save_json(_risk_evaluation_treatment_file(year), inventory)
    _set_risk_evaluation_treatment_status(year, "In Progress")

    return {
        "success": True,
        "message": (
            f"Treatment updated for {payload.hostname} / {payload.cve}. "
            f"Old Treatment: {old_treatment} | New Treatment: {normalized_treatment}"
        ),
        "inventory": inventory,
    }


@router.post("/submit")
def submit_risk_evaluation_treatment(payload: SubmitRequest):
    year = int(payload.year or 2026)
    inventory = _load_risk_evaluation_treatment_inventory_or_blank(year)
    _ensure_risk_evaluation_treatment_editable(year, inventory)
    hosts = _all_hosts(inventory)

    if _risk_evaluation_treatment_is_read_only(year):
        return {
            "success": False,
            "message": "Risk evaluation and treatment has already been submitted and is now read-only.",
            "inventory": inventory,
        }

    if len(hosts) == 0:
        return {
            "success": False,
            "message": "The table is empty. There is nothing to submit.",
            "inventory": inventory,
        }

    if not payload.confirm:
        return {
            "success": False,
            "requires_confirmation": True,
            "message": "Are you sure you want to submit RiskEvaluationTreatment? After submission, the table becomes read-only.",
            "inventory": inventory,
        }

    blank_treatments = [
        h for h in hosts
        if str(h.get("evaluation") or "").strip() == "Treat"
        and str(h.get("treatment") or "").strip() not in VALID_TREATMENT_VALUES
    ]

    if blank_treatments:
        return {
            "success": False,
            "message": "You cannot submit the table while you still have record(s) with empty treatment.",
            "inventory": inventory,
        }

    normalized_hosts = [_normalize_existing_record(h) for h in hosts]

    monitoring_doc = _build_monitoring_improvement_doc(normalized_hosts, year=year)
    monitoring_count = len(monitoring_doc.get("cves", []))

    _save_json(_risk_evaluation_treatment_file(year), inventory)
    _save_json(_annex_a_soa_file(year), _blank_controls_doc())
    _save_json(_action_plan_implementation_file(year), _blank_controls_doc())
    _save_json(_action_implementation_guides_file(year), {"guides": []})
    _save_json(_monitoring_improvement_file(year), monitoring_doc)
    _save_json(_monitoring_implementation_guides_file(year), {"guides": []})

    _set_risk_evaluation_treatment_status(year, "In Progress")
    _set_annex_a_soa_status(year, "Not Started")
    _set_action_plan_implementation_status(year, "Not Started")
    _set_monitoring_improvement_status(year, "In Progress" if monitoring_count > 0 else "Not Started")

    return {
        "success": True,
        "message": (
            "Risk Evaluation/Treatment submitted successfully. "
            "Annex A & SoA and Action Plan / Implementation were reset, "
            f"and Monitoring / Improvement was rebuilt with {monitoring_count} CVE record(s)."
        ),
        "inventory": inventory,
        "monitoring_records_created": monitoring_count,
    }

@router.post("/reinitialize")
def reinitialize_risk_evaluation_treatment(payload: ReinitializeRequest):
    year = int(payload.year or 2026)
    inventory = _load_risk_evaluation_treatment_inventory_or_blank(year)
    _ensure_risk_evaluation_treatment_editable(year, inventory)

    if _risk_evaluation_treatment_is_read_only(year):
        return {
            "success": False,
            "message": "Risk evaluation and treatment has already been submitted and is now read-only.",
            "inventory": inventory,
        }

    hosts = _all_hosts(inventory)
    if len(hosts) == 0:
        return {
            "success": False,
            "message": "You need to finalize the risk analysis first.",
            "inventory": inventory,
        }

    if not payload.confirm:
        return {
            "success": True,
            "requires_confirmation": True,
            "message": "Risk Evaluation and Treatment will be re-initialized with the original default states. Are you sure?",
            "inventory": inventory,
        }

    new_hosts = []

    for record in hosts:
        r = _normalize_existing_record(record)
        risk_value = _normalize_risk(str(r.get("risk") or "Unscanned")) or "Unscanned"

        r["risk"] = risk_value
        default_evaluation = _derive_default_evaluation(r)
        
        r["evaluation"] = default_evaluation
        r["treatment"] = "" if default_evaluation == "Treat" else "-"
        new_hosts.append(r)

    inventory["hosts"] = new_hosts

    _save_json(_risk_evaluation_treatment_file(year), inventory)
    _set_risk_evaluation_treatment_status(year, "In Progress")

    return {
        "success": True,
        "message": f"Risk Evaluation and Treatment has been re-initialized successfully for {len(new_hosts)} records.",
        "records_reinitialized": len(new_hosts),
        "inventory": inventory,
    }

@router.post("/set-evaluation")
def set_evaluation(payload: SetEvaluationRequest):
    year = int(payload.year or 2026)
    inventory = _load_risk_evaluation_treatment_inventory_or_blank(year)
    _ensure_risk_evaluation_treatment_editable(year, inventory)

    if _risk_evaluation_treatment_is_read_only(year):
        return {
            "success": False,
            "message": "Risk evaluation and treatment has already been submitted and is now read-only.",
            "inventory": inventory,
        }

    normalized_evaluation = _normalize_evaluation(payload.evaluation)
    if normalized_evaluation not in VALID_EVALUATION_VALUES:
        return {
            "success": False,
            "message": "Invalid evaluation value. Allowed values are Accept, Monitor, or Treat.",
            "inventory": inventory,
        }

    idx, record = _find_record_by_hostname_and_cve(inventory, payload.hostname, payload.cve)
    if record is None or idx is None:
        return {
            "success": False,
            "message": f"Record not found for host '{payload.hostname}' and CVE '{payload.cve}'.",
            "inventory": inventory,
        }

    record["evaluation"] = normalized_evaluation

    if normalized_evaluation != "Treat":
        record["treatment"] = "-"

    hosts = inventory.get("hosts", [])
    if isinstance(hosts, list):
        hosts[idx] = _normalize_existing_record(record)
        inventory["hosts"] = hosts

    _save_json(_risk_evaluation_treatment_file(year), inventory)
    _set_risk_evaluation_treatment_status(year, "In Progress")

    return {
        "success": True,
        "message": f"Evaluation updated for {payload.hostname} / {payload.cve}.",
        "inventory": inventory,
    }
