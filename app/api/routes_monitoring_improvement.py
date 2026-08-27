from fastapi import APIRouter, Query, UploadFile, File
from pydantic import BaseModel
import csv
import json
import math
import os
import pickle
import re
from pathlib import Path
from typing import Any
from datetime import datetime
from datetime import date
import requests

from app.api.aiml_kpi_telemetry import (
    ollama_total_tokens,
    safe_increment_llm_counter,
    safe_increment_rag_counter,
)
from app.api.performance_telemetry import (
    performance_span,
    resolve_telemetry_year,
    safe_embedding_configuration,
    safe_llm_configuration,
)
from app.api.workflow_gate import ensure_previous_steps_completed


router = APIRouter(
    prefix="/api/monitoring-improvement",
    tags=["monitoring-improvement"],
)


# =========================================================
# CONSTANTS
# =========================================================
VALID_STEP_STATUSES = {"Blocked", "Not Started", "In Progress", "Completed"}

VALID_MONITORING_STATUSES = {
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

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_PAGE_SIZE = 100


# =========================================================
# REQUEST MODELS
# =========================================================
class RecommendTreatmentRequest(BaseModel):
    year: int | None = 2026
    control_id: str  # carries CVE value


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

class EvidenceDefaultsRequest(BaseModel):
    year: int | None = 2026
    control_id: str
    hostname: str
    vulnerability_name: str = ""


class EvidenceDefaultsResponse(BaseModel):
    success: bool = True
    message: str = ""
    evidence: AddEvidenceItem
    inventory: dict | None = None


class EvidenceAllRequest(BaseModel):
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

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434/api/generate")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen3.8:27b")
OLLAMA_EMBED_URL = os.getenv("OLLAMA_EMBED_URL", "http://127.0.0.1:11434/api/embeddings")
OLLAMA_EMBED_MODEL = os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text")


def _work_dir(year: int) -> Path:
    return BASE_DIR / "data" / "work" / str(year)


def _knowledge_base_dir() -> Path:
    return BASE_DIR / "data" / "knowledge_base"


def _ml_dir() -> Path:
    return BASE_DIR / "data" / "ml"


def _risk_evaluation_treatment_file(year: int) -> Path:
    return _work_dir(year) / "RiskEvaluationTreatment.json"


def _iso_csv_path(year: int) -> Path:
    return _knowledge_base_dir() / "iso27002_controls_2022.csv"


def _iso_embedding_cache_path(year: int) -> Path:
    return _ml_dir() / "iso27002_local_embeddings.pkl"


def _action_plan_implementation_file(year: int) -> Path:
    return _work_dir(year) / "ActionPlanImplementation.json"


def _monitoring_improvement_file(year: int) -> Path:
    return _work_dir(year) / "MonitoringImprovement.json"


def _monitoring_implementation_guides_file(year: int) -> Path:
    return _work_dir(year) / "MonitoringImplementationGuides.json"


def _legacy_monitoring_improvement_file(year: int) -> Path:
    return _work_dir(year) / "MonitoringAndImprovement.json"


def _system_status_file(year: int) -> Path:
    return _work_dir(year) / "SystemStatus.json"


def _asset_inventory_file(year: int) -> Path:
    return _work_dir(year) / "AssetInventory.json"


# =========================================================
# BASIC HELPERS
# =========================================================
def _load_json(path: Path) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _blank_monitoring_improvement_doc() -> dict:
    return {
        "status": "Not Started",
        "meta": {
            "submitted": False,
            "read_only": False,
        },
        "cves": [],
    }


def _set_monitoring_improvement_doc_state(
    doc: dict,
    *,
    status: str,
    submitted: bool,
    read_only: bool,
) -> dict:
    if not isinstance(doc, dict):
        doc = {}
    if not isinstance(doc.get("meta"), dict):
        doc["meta"] = {}

    doc["status"] = status
    doc["meta"]["submitted"] = submitted
    doc["meta"]["read_only"] = read_only
    return doc


def _blank_monitoring_implementation_guides_doc(year: int) -> dict:
    return {"guides": []}


def _save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def _load_json_or_default(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        data = _load_json(path)
        return data if isinstance(data, type(default)) else default
    except Exception:
        return default


def _normalize_text(value: Any) -> str:
    return str(value or "").strip()


def _normalize_key(value: Any) -> str:
    return _normalize_text(value).lower()


def _default_date_when_url_present(date_value: Any, url_value: Any) -> str:
    normalized_date = _normalize_text(date_value)
    if normalized_date:
        return normalized_date
    if _normalize_text(url_value):
        return date.today().isoformat()
    return ""


def _safe_join_lines(items: list[str]) -> str:
    return "\n".join(x for x in items if _normalize_text(x) != "")


def _load_monitoring_implementation_guides_doc_or_blank(year: int) -> dict:
    path = _monitoring_implementation_guides_file(year)
    default_doc = _blank_monitoring_implementation_guides_doc(year)
    doc = _load_json_or_default(path, default_doc)
    if not isinstance(doc, dict):
        return default_doc
    if not isinstance(doc.get("guides"), list):
        doc["guides"] = []
    return doc


def _save_monitoring_implementation_guides_doc(year: int, doc: dict) -> None:
    _save_json(_monitoring_implementation_guides_file(year), doc)


def _all_guides(doc: dict) -> list[dict]:
    guides = doc.get("guides", [])
    if not isinstance(guides, list):
        return []
    return [g for g in guides if isinstance(g, dict)]


def _next_monitoring_guide_id(year: int, guides_doc: dict) -> str:
    max_n = 0
    for guide in _all_guides(guides_doc):
        value = _normalize_text(guide.get("guide_id"))
        match = re.match(rf"^MIG-{int(year)}-(\d+)$", value)
        if match:
            max_n = max(max_n, int(match.group(1)))
    return f"MIG-{int(year)}-{max_n + 1:04d}"


def _next_monitoring_evidence_id(year: int, monitoring_doc: dict) -> str:
    max_n = 0
    for control in monitoring_doc.get("cves", []):
        if not isinstance(control, dict):
            continue
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
                match = re.match(rf"^MEVID-{int(year)}-(\d+)$", value)
                if match:
                    max_n = max(max_n, int(match.group(1)))
    return f"MEVID-{int(year)}-{max_n + 1:04d}"


def _remove_monitoring_guide_by_key(year: int, evidence_id: str) -> bool:
    doc = _load_monitoring_implementation_guides_doc_or_blank(year)
    original = len(_all_guides(doc))
    doc["guides"] = [
        guide
        for guide in _all_guides(doc)
        if _normalize_key(guide.get("evidence_id")) != _normalize_key(evidence_id)
    ]
    changed = len(doc["guides"]) != original
    if changed:
        _save_monitoring_implementation_guides_doc(year, doc)
    return changed


def _reset_monitoring_implementation_guides(year: int) -> None:
    _save_monitoring_implementation_guides_doc(year, _blank_monitoring_implementation_guides_doc(year))


def _load_asset_inventory_or_blank(year: int) -> dict:
    return _load_json_or_default(_asset_inventory_file(year), {})


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
            "annex_a_soa": {"status": "Not Started"},
            "action_plan_implementation": {"status": "Completed"},
            "monitoring_improvement": {"status": "Not Started"},
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


def _monitoring_improvement_section_is_read_only(year: int) -> bool:
    doc = _load_monitoring_improvement_doc_or_blank(year)
    explicit_status = _normalize_text(doc.get("status"))
    if explicit_status == "Completed":
        return True

    meta = doc.get("meta", {})
    if isinstance(meta, dict):
        return bool(meta.get("submitted") or meta.get("read_only"))

    return False


# =========================================================
# USER BEHAVIOR JUSTIFICATION HELPERS
# =========================================================
def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None or str(value).strip() == "":
            return default
        return float(value)
    except Exception:
        return default


def _score_level(score: float) -> str:
    if score >= 8:
        return "Critical"
    if score >= 6:
        return "High"
    if score >= 4:
        return "Medium"
    return "Low"


def _extract_behavior_scores_from_host(host: dict) -> dict:
    user_behavior = host.get("user_behavior") or {}

    return {
        "failedLoginAttempts": _to_float(user_behavior.get("failedLoginAttempts")),
        "accessFrequency": _to_float(user_behavior.get("accessFrequency")),
        "loginConsistency": _to_float(user_behavior.get("loginConsistency")),
        "passwordResets": _to_float(user_behavior.get("passwordResets")),
        "sessionDuration": _to_float(user_behavior.get("sessionDuration")),
    }


def _feature_sentence(feature_name: str, score: float) -> str:
    level = _score_level(score)

    if feature_name == "failedLoginAttempts":
        if level == "Critical":
            return f"Failed Login Attempts is {level} ({score:g}), showing a very elevated number of failed logon attempts that may indicate repeated unauthorized access attempts or abnormal credential use"
        if level == "High":
            return f"Failed Login Attempts is {level} ({score:g}), indicating a significant number of failed logon attempts that should be investigated"
        if level == "Medium":
            return f"Failed Login Attempts is {level} ({score:g}), showing noticeable failed logon activity that should continue to be monitored"
        return f"Failed Login Attempts is {level} ({score:g}), indicating limited failed logon activity at this time"

    if feature_name == "accessFrequency":
        if level == "Critical":
            return f"Access Frequency is {level} ({score:g}), indicating very frequent system access activity that may reflect abnormal workstation usage"
        if level == "High":
            return f"Access Frequency is {level} ({score:g}), showing frequent access activity that is above normal expectation and requires review"
        if level == "Medium":
            return f"Access Frequency is {level} ({score:g}), indicating moderately increased access activity that should remain under observation"
        return f"Access Frequency is {level} ({score:g}), suggesting access volume remains within a lower-risk range"

    if feature_name == "loginConsistency":
        if level == "Critical":
            return f"Login Consistency is {level} ({score:g}), indicating a strongly abnormal or unstable login pattern compared with expected user behavior"
        if level == "High":
            return f"Login Consistency is {level} ({score:g}), showing a notable deviation in login regularity that may reflect suspicious usage behavior"
        if level == "Medium":
            return f"Login Consistency is {level} ({score:g}), indicating some irregularity in login behavior that should be monitored"
        return f"Login Consistency is {level} ({score:g}), suggesting the user's login pattern remains relatively stable"

    if feature_name == "passwordResets":
        if level == "Critical":
            return f"Password Resets is {level} ({score:g}), reflecting unusually high password reset activity that may indicate account misuse or credential-related issues"
        if level == "High":
            return f"Password Resets is {level} ({score:g}), showing elevated password reset activity that should be validated"
        if level == "Medium":
            return f"Password Resets is {level} ({score:g}), indicating moderate password reset activity that warrants continued review"
        return f"Password Resets is {level} ({score:g}), showing limited password reset activity"

    if feature_name == "sessionDuration":
        if level == "Critical":
            return f"Session Duration is {level} ({score:g}), indicating unusually long or abnormal user sessions that may reflect persistent or inappropriate access"
        if level == "High":
            return f"Session Duration is {level} ({score:g}), showing extended session behavior that should be reviewed"
        if level == "Medium":
            return f"Session Duration is {level} ({score:g}), indicating moderately unusual session length patterns that should continue to be monitored"
        return f"Session Duration is {level} ({score:g}), suggesting session length remains in a lower-risk range"

    return f"{feature_name} is {level} ({score:g})"


def _build_ub_ws_xx_host_justification(host: dict) -> str:
    hostname = _normalize_text(host.get("hostname")) or "Unknown Host"
    scores = _extract_behavior_scores_from_host(host)

    failed_login_score = scores["failedLoginAttempts"]
    access_frequency_score = scores["accessFrequency"]
    login_consistency_score = scores["loginConsistency"]
    password_resets_score = scores["passwordResets"]
    session_duration_score = scores["sessionDuration"]

    # build bullet lines
    feature_lines = [
        f"- {_feature_sentence('failedLoginAttempts', failed_login_score)}",
        f"- {_feature_sentence('accessFrequency', access_frequency_score)}",
        f"- {_feature_sentence('loginConsistency', login_consistency_score)}",
        f"- {_feature_sentence('passwordResets', password_resets_score)}",
        f"- {_feature_sentence('sessionDuration', session_duration_score)}",
    ]

    highest_feature_name, highest_feature_score = max(scores.items(), key=lambda x: x[1])

    highest_label_map = {
        "failedLoginAttempts": "Failed Login Attempts",
        "accessFrequency": "Access Frequency",
        "loginConsistency": "Login Consistency",
        "passwordResets": "Password Resets",
        "sessionDuration": "Session Duration",
    }

    highest_label = highest_label_map.get(highest_feature_name, highest_feature_name)
    highest_level = _score_level(highest_feature_score)

    return (
        f"For workstation {hostname}, monitoring is justified based on user activity behavior features:\n\n"
        + "\n".join(feature_lines)
        + f"\n\nThe strongest contributing feature is {highest_label} assessed at {highest_level} ({highest_feature_score:g})."
    )

def _generate_ub_ws_xx_justification(hosts: list[dict]) -> str:
    valid_hosts = [h for h in hosts if isinstance(h, dict)]

    if not valid_hosts:
        return (
            "Monitoring is justified based on user activity behavior features:\n\n"
            "- Failed Login Attempts is Low (0), indicating limited failed logon activity at this time\n"
            "- Access Frequency is Low (0), suggesting access volume remains within a lower-risk range\n"
            "- Login Consistency is Low (0), suggesting the user's login pattern remains relatively stable\n"
            "- Password Resets is Low (0), showing limited password reset activity\n"
            "- Session Duration is Low (0), suggesting session length remains in a lower-risk range"
        )

    return "\n\n".join(_build_ub_ws_xx_host_justification(host) for host in valid_hosts)

def _risk_analysis_file(year: int) -> Path:
    return _work_dir(year) / "RiskAnalysis.json"


def _load_risk_analysis_doc_or_blank(year: int) -> dict:
    path = _risk_analysis_file(year)

    if not path.exists():
        return {"hosts": []}

    try:
        data = _load_json(path)
        if not isinstance(data, dict):
            return {"hosts": []}
        return data
    except Exception:
        return {"hosts": []}


def _find_user_behavior_from_risk_analysis(
    year: int,
    hostname: str,
    cve_value: str,
) -> dict:
    risk_doc = _load_risk_analysis_doc_or_blank(year)
    records = risk_doc.get("hosts", [])
    if not isinstance(records, list):
        return {}

    target_host = _normalize_key(hostname)
    target_cve = _normalize_key(cve_value)

    for rec in records:
        if not isinstance(rec, dict):
            continue

        rec_host = _normalize_key(rec.get("hostname"))
        rec_cve = _normalize_key(rec.get("cve") or rec.get("CVE"))

        if rec_host == target_host and rec_cve == target_cve:
            ub = rec.get("user_behavior")
            return ub if isinstance(ub, dict) else {}

    return {}

def _generate_user_behavior_monitoring_actions(hosts: list[dict]) -> str:
    if not hosts:
        return "Recommended monitoring actions:\n- Monitor user activity logs regularly"

    lines = ["Recommended monitoring actions:"]

    for host in hosts:
        hostname = _normalize_text(host.get("hostname")) or "Unknown"

        scores = _extract_behavior_scores_from_host(host)

        for feature, score in scores.items():
            level = _score_level(score)

            # ================================
            # FAILED LOGIN ATTEMPTS
            # ================================
            if feature == "failedLoginAttempts":
                if level in ["High", "Critical"]:
                    lines.append(f"- Monitor failed login attempts on {hostname} in real-time and trigger alerts for repeated authentication failures (ISO 27001:2022 - 8.5, 8.16)")
                elif level == "Medium":
                    lines.append(f"- Review failed login attempts on {hostname} daily and correlate with authentication logs to detect abnormal patterns (ISO 27001:2022 - 8.15)")
                else:
                    lines.append(f"- Periodically review failed login attempts on {hostname} through audit logs to ensure no emerging brute-force patterns (ISO 27001:2022 - 8.15)")

            # ================================
            # ACCESS FREQUENCY
            # ================================
            elif feature == "accessFrequency":
                if level in ["High", "Critical"]:
                    lines.append(f"- Monitor access frequency on {hostname} and generate alerts for abnormal spikes in user activity (ISO 27001:2022 - 8.16)")
                elif level == "Medium":
                    lines.append(f"- Track access frequency trends on {hostname} and compare against baseline user behavior (ISO 27001:2022 - 8.15)")
                else:
                    lines.append(f"- Maintain periodic monitoring of access activity on {hostname} to validate normal usage patterns (ISO 27001:2022 - 8.15)")

            # ================================
            # LOGIN CONSISTENCY
            # ================================
            elif feature == "loginConsistency":
                if level in ["High", "Critical"]:
                    lines.append(f"- Detect anomalous login patterns on {hostname} using behavior analytics and trigger alerts for irregular login timing or locations (ISO 27001:2022 - 8.16)")
                elif level == "Medium":
                    lines.append(f"- Monitor login consistency deviations on {hostname} and investigate irregular login behavior (ISO 27001:2022 - 8.15)")
                else:
                    lines.append(f"- Periodically review login consistency on {hostname} to ensure stable user behavior patterns (ISO 27001:2022 - 8.15)")

            # ================================
            # PASSWORD RESETS
            # ================================
            elif feature == "passwordResets":
                if level in ["High", "Critical"]:
                    lines.append(f"- Monitor password reset activity on {hostname} and alert on excessive or unauthorized reset attempts (ISO 27001:2022 - 5.17, 8.5)")
                elif level == "Medium":
                    lines.append(f"- Track password reset frequency on {hostname} and validate against user support requests (ISO 27001:2022 - 5.18)")
                else:
                    lines.append(f"- Periodically review password reset logs on {hostname} to ensure normal account management activity (ISO 27001:2022 - 5.18)")

            # ================================
            # SESSION DURATION
            # ================================
            elif feature == "sessionDuration":
                if level in ["High", "Critical"]:
                    lines.append(f"- Monitor session duration on {hostname} and trigger alerts for unusually long or persistent sessions (ISO 27001:2022 - 8.16)")
                elif level == "Medium":
                    lines.append(f"- Analyze session duration trends on {hostname} to detect abnormal user behavior (ISO 27001:2022 - 8.15)")
                else:
                    lines.append(f"- Maintain periodic review of session duration logs on {hostname} to confirm normal session patterns (ISO 27001:2022 - 8.15)")

    # remove duplicates
    unique = []
    seen = set()
    for l in lines:
        if l not in seen:
            seen.add(l)
            unique.append(l)

    return "\n".join(unique)

def _generate_user_behavior_monitoring_action_with_llama3(
    year: int,
    control_id: str,
    control_name: str,
    justification: str,
    hosts: list[dict],
    retrieved_controls: list[dict],
) -> str:
    host_context_blocks = []

    for host in hosts:
        if not isinstance(host, dict):
            continue

        hostname = _normalize_text(host.get("hostname")) or "Unknown Host"
        role = _normalize_text(host.get("role")) or "Unknown Role"
        cia = _normalize_text(host.get("CIA rating")) or "NA"

        scores = _extract_behavior_scores_from_host(host)

        feature_lines = [
            f"- Failed Login Attempts: {_score_level(scores['failedLoginAttempts'])} ({scores['failedLoginAttempts']:g})",
            f"- Access Frequency: {_score_level(scores['accessFrequency'])} ({scores['accessFrequency']:g})",
            f"- Login Consistency: {_score_level(scores['loginConsistency'])} ({scores['loginConsistency']:g})",
            f"- Password Resets: {_score_level(scores['passwordResets'])} ({scores['passwordResets']:g})",
            f"- Session Duration: {_score_level(scores['sessionDuration'])} ({scores['sessionDuration']:g})",
        ]

        host_context_blocks.append(
            f"Host: {hostname}\n"
            f"Role: {role}\n"
            f"CIA: {cia}\n"
            f"Feature Levels:\n" + "\n".join(feature_lines)
        )

    retrieved_text = "\n\n".join(
        [
            (
                f"ISO Reference {i + 1}\n"
                f"Section: {_normalize_text(rec.get('Section'))}\n"
                f"Control: {_normalize_text(rec.get('Control'))}\n"
                f"Title: {_normalize_text(rec.get('Title'))}\n"
                f"Purpose: {_normalize_text(rec.get('Purpose'))}"
            )
            for i, rec in enumerate(retrieved_controls)
        ]
    )

    prompt = f"""
You are an ISO 27001:2022 monitoring and improvement expert.

Generate recommended monitoring actions for a User Activity Behavior vulnerability.

STRICT REQUIREMENTS:
- First line must be exactly: Recommended monitoring actions:
- Then provide bullet lines starting with "-"
- Each bullet must be on its own separate line
- Create monitoring actions specifically based on the level of EACH of these five features:
  Failed Login Attempts
  Access Frequency
  Login Consistency
  Password Resets
  Session Duration
- Mention all five features
- Tailor the action to the feature level
- Use LLM reasoning together with the ISO 27001:2022 references provided
- Actions must be monitoring-oriented, practical, and auditor-friendly
- Focus on logging, alerting, anomaly detection, review frequency, threshold checks, escalation, and follow-up
- No numbering
- No paragraphs after the bullets
- No markdown other than the "-" bullet lines

Target Record:
CVE: {control_id}
Vulnerability: {control_name}
Justification:
{justification or "NA"}

Host Feature Context:
{chr(10).join(host_context_blocks) or "NA"}

Relevant ISO 27001 / ISO 27002 References:
{retrieved_text or "NA"}
""".strip()

    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "think": False,
        "options": {
            "temperature": 0.1,
            "top_p": 0.9,
            "num_predict": 90,
        },
    }

    with performance_span(
        year=resolve_telemetry_year(),
        operation_id="monitoring.user_behavior_action",
        llm_configuration=safe_llm_configuration(model=OLLAMA_MODEL, payload=payload),
    ) as span:
        res = requests.post(OLLAMA_URL, json=payload, timeout=180)
        res.raise_for_status()
        data = res.json()
        span.set_ollama_metrics(data)
    safe_increment_llm_counter(year, ollama_total_tokens(data))

    response_text = _normalize_text(data.get("response"))

    if not response_text.startswith("Recommended monitoring actions:"):
        lines = [x.strip() for x in response_text.splitlines() if x.strip()]
        bullets = []

        for line in lines:
            cleaned = re.sub(r"^[\-\*\d\.\)\(]+\s*", "", line)
            if cleaned:
                bullets.append(f"- {cleaned}")

        response_text = "Recommended monitoring actions:\n" + "\n".join(bullets)

    return response_text


def _map_responsible_from_role(role: str) -> str:
    role_l = _normalize_text(role).lower()

    if any(x in role_l for x in ["domain controller", "active directory", "identity", "authentication"]):
        return "Identity & Access Management Team / ISMS Auditor Team"

    if any(x in role_l for x in ["dns", "dhcp", "network", "firewall", "router", "gateway", "proxy"]):
        return "Network & Infrastructure Security Team / ISMS Auditor Team"

    if any(x in role_l for x in ["web", "application", "app", "database", "sql", "api"]):
        return "Application & Platform Security Team / ISMS Auditor Team"

    if any(x in role_l for x in ["mail", "exchange", "messaging"]):
        return "Messaging & Collaboration Security Team / ISMS Auditor Team"

    if any(x in role_l for x in ["endpoint", "workstation", "desktop", "laptop", "client"]):
        return "Endpoint Security Team / ISMS Auditor Team"

    if any(x in role_l for x in ["backup", "storage", "file server", "nas"]):
        return "Infrastructure Operations Team / ISMS Auditor Team"

    if any(x in role_l for x in ["soc", "siem", "monitoring", "security"]):
        return "Security Operations Center / ISMS Auditor Team"

    return "System Security Team / ISMS Auditor Team"


def _build_resources_value(hostname: str, role: str) -> str:
    host_value = _normalize_text(hostname) or "Unknown Host"
    role_value = _normalize_text(role) or "Unknown Role"
    return f"{host_value} / {role_value}"


def _evidence_has_meaningful_content(evidence: Any) -> bool:
    if not isinstance(evidence, dict):
        return False
    return any(
        _normalize_text(evidence.get(field)) != ""
        for field in ["responsible", "resources", "date", "url", "desc"]
    )


def _ensure_monitoring_evidence_ids_for_host(year: int, monitoring_doc: dict, host: dict) -> bool:
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
            item["evidence_id"] = _next_monitoring_evidence_id(year, monitoring_doc)
            changed = True
        new_list.append(item)

    if changed:
        host["evidence"] = new_list
    return changed


def _clean_evidence_list(year: int, monitoring_doc: dict, evidence_list: Any) -> list[dict]:
    if not isinstance(evidence_list, list):
        return []

    cleaned: list[dict] = []
    for item in evidence_list:
        if not isinstance(item, dict):
            continue

        normalized_item = {
            "evidence_id": _normalize_text(item.get("evidence_id")) or _next_monitoring_evidence_id(year, monitoring_doc),
            "responsible": _normalize_text(item.get("responsible")),
            "resources": _normalize_text(item.get("resources")),
            "date": _normalize_text(item.get("date")),
            "url": _normalize_text(item.get("url")),
            "desc": _normalize_text(item.get("desc")),
        }

        if _evidence_has_meaningful_content(normalized_item):
            cleaned.append(normalized_item)

    return cleaned


def _derive_evidence_name_from_item(evidence: dict) -> str:
    desc = _normalize_text(evidence.get("desc"))
    resources = _normalize_text(evidence.get("resources"))
    url = _normalize_text(evidence.get("url"))

    text = desc or resources or url
    if not text:
        return "Monitoring evidence"

    short = text.split("\n", 1)[0].strip()
    if len(short) > 80:
        short = short[:77].rstrip() + "..."
    return short


def _build_minimal_guide_references(cve_id: str) -> list[dict]:
    cve_id = _normalize_text(cve_id)
    vuln_source = (
        f"Vulnerability intelligence: NVD {cve_id} Technical Details"
        f" | https://nvd.nist.gov/vuln/detail/{cve_id}"
        f" | Microsoft Security Update {cve_id}"
        f" | CISA Known Exploited Vulnerabilities Catalog"
        if cve_id.upper().startswith("CVE-")
        else (
            f"Vulnerability source: no public CVE reference was available for {vulnerability_name or control_id or 'this record'} | "
            f"guide context was derived from {_monitoring_improvement_file(year)} and {_asset_inventory_file(year)}"
        )
    )

    return [
        {
            "ref_id": "MS-01",
            "source": f"Microsoft Security Update {cve_id}" if cve_id else "Microsoft Security Update",
        },
        {
            "ref_id": "CISA-01",
            "source": "CISA Known Exploited Vulnerabilities Catalog",
        },
        {
            "ref_id": "NVD-01",
            "source": f"NVD {cve_id} Technical Details" if cve_id else "NVD Technical Details",
        },
        {
            "ref_id": "MS-Baseline",
            "source": "Microsoft Security Compliance Toolkit",
        },
    ]


def _reference_detail_text(value: Any) -> str:
    return _normalize_text(value).replace("\r", " ").replace("\n", " | ")


def _build_monitoring_guide_references(
    year: int,
    control: dict,
    host: dict,
    evidence: dict,
    asset_host: dict,
    generation_hints: str,
    method_label: str = "LLM-generated monitoring guide",
) -> list[dict]:
    control_id = _normalize_text(control.get("CVE"))
    control_name = _normalize_text(control.get("vulnerability"))
    cve_id = _normalize_text(host.get("cve") or control.get("CVE"))
    vulnerability_name = _normalize_text(host.get("vulnerability_name") or control_name)
    refs = [
        {
            "ref_id": "ISO-27002",
            "source": f"ISO/IEC 27002:2022 monitoring and logging guidance for {control_id or 'the mapped control context'}",
        },
        {
            "ref_id": "MS-Baseline",
            "source": "Microsoft Security Compliance Toolkit / Microsoft security monitoring documentation",
        },
        {
            "ref_id": "CISA-01",
            "source": "CISA Known Exploited Vulnerabilities Catalog",
        },
    ]

    if cve_id.upper().startswith("CVE-"):
        refs.insert(
            1,
            {
                "ref_id": "NVD-01",
                "source": f"NVD {cve_id} Technical Details | https://nvd.nist.gov/vuln/detail/{cve_id}",
            },
        )
        refs.insert(
            2,
            {
                "ref_id": "MSRC-01",
                "source": f"Microsoft Security Response Center guidance for {cve_id}",
            },
        )
    else:
        refs.insert(
            1,
            {
                "ref_id": "MS-Docs",
                "source": (
                    "Microsoft Learn security monitoring, Defender, and Windows event logging documentation "
                    f"relevant to {vulnerability_name or control_id or 'the monitored behavior'}"
                ),
            },
        )
        refs.insert(
            2,
            {
                "ref_id": "NIST-Guide",
                "source": "NIST continuous monitoring, incident detection, and audit logging guidance",
            },
        )

    return refs


def _build_vulnerability_generation_hints(cve_id: str, vulnerability_name: str, role: str) -> str:
    cve_id_l = _normalize_text(cve_id).lower()
    vuln_l = _normalize_text(vulnerability_name).lower()
    role_l = _normalize_text(role).lower()

    hints = []

    if "dns" in vuln_l or "cve-2020-1350" in cve_id_l:
        hints.extend([
            "Affected service is likely Windows DNS Server.",
            "Relevant commands may include Get-Service DNS, Restart-Service DNS, Resolve-DnsName.",
            "Monitoring evidence may include DNS logs, firewall rules, and patch validation output.",
        ])

    if "smb" in vuln_l or "445" in vuln_l:
        hints.extend([
            "Relevant commands may include Get-SmbServerConfiguration and firewall rules for TCP 445.",
            "Monitoring evidence may include SMB configuration output and exposure validation.",
        ])

    if "winrm" in vuln_l or "wsman" in vuln_l or "5985" in vuln_l or "5986" in vuln_l:
        hints.extend([
            "Relevant commands may include Get-ChildItem WSMan:\\localhost\\Service and firewall checks for WinRM.",
            "Monitoring evidence may include WSMan configuration output, firewall rules, and PowerShell operational logs.",
        ])

    if "rdp" in vuln_l or "3389" in vuln_l:
        hints.extend([
            "Relevant commands may include firewall restrictions for TCP 3389 and validation for RDP hardening.",
            "Monitoring evidence may include firewall rules, event logs, and session monitoring screenshots.",
        ])

    if "web" in vuln_l or "http" in vuln_l or "https" in vuln_l or "apache" in vuln_l or "nginx" in vuln_l:
        hints.extend([
            "Relevant actions may include service validation, TLS hardening, application firewall rules, and log review.",
            "Monitoring evidence may include web server logs, WAF alerts, and configuration exports.",
        ])

    if "patch" in vuln_l or "update" in vuln_l or cve_id_l.startswith("cve-"):
        hints.extend([
            "If patching is relevant, use Get-HotFix or installed update validation where applicable.",
            "Monitoring evidence may include installed hotfix output, vulnerability scan results, and change tickets.",
        ])

    if "monitor" in vuln_l or "logging" in vuln_l or "detect" in vuln_l or "audit" in vuln_l:
        hints.extend([
            "Relevant commands may include event log export, Defender detection review, and service-specific diagnostic logging.",
            "Monitoring evidence may include EVTX export, SIEM screenshots, and detection output.",
        ])

    if "malware" in vuln_l or "defender" in vuln_l or "antivirus" in vuln_l:
        hints.extend([
            "Relevant commands may include Get-MpComputerStatus and Get-MpThreatDetection.",
            "Monitoring evidence may include Defender alerts, detection history, and quarantine output.",
        ])

    if "domain controller" in role_l or "active directory" in role_l:
        hints.extend([
            "Preserve domain services availability during monitoring actions.",
            "Prefer validation commands that are safe for a domain controller.",
        ])

    if not hints:
        hints.extend([
            "Generate concrete Windows monitoring and validation steps based on the recommended monitoring action, host role, and vulnerability context.",
            "Prefer technical commands, validation commands, and concrete evidence collection instructions.",
        ])

    return "\n".join(hints)


def _generate_real_monitoring_steps_with_llm(year: int, context: dict) -> list[dict]:
    prompt = f"""
You are a senior Windows security engineer and enterprise monitoring specialist.

Generate a REAL technical monitoring guide for a Windows enterprise host.

STRICT RULES:
- Output ONLY valid JSON
- No markdown
- No explanations
- Use the EXACT JSON schema provided below
- Do NOT change the schema
- Every step must be technical and monitoring-oriented
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
- Make the guide specific to the vulnerability, host role, CVE, and recommended monitoring action
- Include technical verification, logging, detection, exposure validation, and evidence collection

Context:
Host: {context.get("hostname", "")}
Role: {context.get("role", "")}
OS: {context.get("os_version", "")}
Control: {context.get("control_id", "")} - {context.get("control_name", "")}
Vulnerability: {context.get("vulnerability_name", "")}
CVE: {context.get("cve_id", "")}
Severity: {context.get("severity", "")}
Recommended Monitoring Action: {context.get("recommended_action", "")}

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
            "think": False,
            "options": {
                "temperature": 0.1,
                "top_p": 0.9,
                "num_predict": 900,
            },
        }

        with performance_span(
            year=year,
            operation_id="monitoring.real_steps",
            llm_configuration=safe_llm_configuration(model=OLLAMA_MODEL, payload=payload),
        ) as span:
            res = requests.post(OLLAMA_URL, json=payload, timeout=180)
            res.raise_for_status()
            data = res.json()
            span.set_ollama_metrics(data)
        safe_increment_llm_counter(year, ollama_total_tokens(data))

        response = _normalize_text(data.get("response"))
        if not isinstance(response, str):
            raise ValueError("LLM response is not a string.")

        cleaned = response.strip().replace("\\u2013", "-").replace("\\u2014", "-")
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
    except Exception:
        print("MONITORING GUIDE GENERATION FAILED")
        print(cleaned)
        raise


def _generate_flat_monitoring_implementation_guide(year: int, control: dict, host: dict, evidence: dict) -> dict:
    guides_doc = _load_monitoring_implementation_guides_doc_or_blank(year)

    evidence_id = _normalize_text(evidence.get("evidence_id"))
    if evidence_id == "":
        raise ValueError("Evidence item is missing evidence_id.")

    asset_host = _find_asset_inventory_host(year, _normalize_text(host.get("hostname")))

    hostname = _normalize_text(host.get("hostname"))
    role = _normalize_text(host.get("role")) or _normalize_text(asset_host.get("role"))
    department = _safe_department_from_asset(asset_host)
    os_version = _safe_os_version_from_asset(asset_host)

    control_id = _normalize_text(control.get("CVE"))
    control_name = _normalize_text(control.get("vulnerability"))
    cve_id = _normalize_text(host.get("cve") or control.get("CVE"))
    vulnerability_name = _normalize_text(host.get("vulnerability_name") or control_name)
    severity = _normalize_text(host.get("risk"))
    recommended_action = _normalize_text(control.get("recommended_action"))

    evidence_name = _derive_evidence_name_from_item(evidence)
    evidence_description = _normalize_text(evidence.get("desc")) or evidence_name
    evidence_format = "PDF + Logs + Monitoring Export"
    generation_hints = _build_vulnerability_generation_hints(cve_id, vulnerability_name, role)
    references = _build_monitoring_guide_references(
        year=year,
        control=control,
        host=host,
        evidence=evidence,
        asset_host=asset_host,
        generation_hints=generation_hints,
        method_label="LLM-generated monitoring guide",
    )

    implementation_steps = _generate_real_monitoring_steps_with_llm(year, {
        "hostname": hostname,
        "role": role,
        "os_version": os_version,
        "control_id": control_id,
        "control_name": control_name,
        "vulnerability_name": vulnerability_name,
        "cve_id": cve_id,
        "severity": severity,
        "recommended_action": recommended_action,
        "generation_hints": generation_hints,
    })

    return {
        "guide_id": _next_monitoring_guide_id(year, guides_doc),
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
        "recommended_action": recommended_action,
        "evidence_name": evidence_name,
        "evidence_description": evidence_description,
        "evidence_format": evidence_format,
        "references": references,
        "implementation_steps": implementation_steps,
    }


def _fallback_monitoring_implementation_steps(context: dict) -> list[dict]:
    hostname = _normalize_text(context.get("hostname")) or "the target host"
    role = _normalize_text(context.get("role")) or "target system"
    control_id = _normalize_text(context.get("control_id")) or "the selected control"
    control_name = _normalize_text(context.get("control_name")) or "selected monitoring record"
    vulnerability_name = _normalize_text(context.get("vulnerability_name")) or "the identified vulnerability"
    cve_id = _normalize_text(context.get("cve_id"))
    recommended_action = _normalize_text(context.get("recommended_action")) or (
        f"Perform the approved monitoring activity for {control_id} ({control_name})."
    )
    cve_suffix = f" ({cve_id})" if cve_id else ""
    vuln_l = vulnerability_name.lower()
    cve_l = cve_id.lower()
    role_l = role.lower()

    if "remote desktop" in vuln_l or "rdp" in vuln_l or cve_l == "cve-2019-0708":
        return [
            {
                "step_no": 1,
                "title": "Validate RDP Exposure And Listener State",
                "description": (
                    f"Confirm whether {hostname} exposes Remote Desktop Services before reviewing monitoring evidence for "
                    f"{vulnerability_name}{cve_suffix} on the {role} role."
                ),
                "commands": [
                    "Get-Service TermService",
                    "Get-NetTCPConnection -LocalPort 3389 -ErrorAction SilentlyContinue",
                    'Get-NetFirewallRule -DisplayGroup "Remote Desktop" | Select-Object DisplayName,Enabled,Direction,Action',
                ],
                "expected_result": f"RDP service, TCP 3389 listener state, and Remote Desktop firewall rules are captured for {hostname}.",
                "output_type": "RDP service status / listener output / firewall rule export",
                "evidence_capture": f"Attach the RDP service, listener, and firewall outputs for {hostname}.",
            },
            {
                "step_no": 2,
                "title": "Review RDP Authentication Events",
                "description": (
                    f"Review logon activity that may indicate exploitation attempts or brute-force activity related to "
                    f"{vulnerability_name}{cve_suffix}."
                ),
                "commands": [
                    "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625,4778,4779} -MaxEvents 80",
                    "Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' -MaxEvents 80",
                ],
                "expected_result": f"Successful, failed, and session-based RDP logon events are available for review on {hostname}.",
                "output_type": "Security log excerpt / Terminal Services operational log",
                "evidence_capture": f"Export RDP authentication and session event records for {hostname}.",
            },
            {
                "step_no": 3,
                "title": "Confirm RDP Patch And Hardening State",
                "description": (
                    f"Validate that patch and hardening controls for {vulnerability_name}{cve_suffix} are tracked while monitoring continues."
                ),
                "commands": [
                    "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 30",
                    r'reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication',
                    'Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" -Name fDenyTSConnections',
                ],
                "expected_result": f"Patch status, Network Level Authentication state, and RDP enablement state are documented for {hostname}.",
                "output_type": "Patch inventory / registry output / configuration state",
                "evidence_capture": f"Capture patch and RDP hardening output plus any related vulnerability scan result for {hostname}.",
            },
            {
                "step_no": 4,
                "title": "Correlate RDP Alerts And Escalations",
                "description": f"Correlate RDP activity with the approved monitoring action: {recommended_action}",
                "commands": [
                    "Get-MpThreatDetection",
                    "Get-WinEvent -LogName System -MaxEvents 50",
                ],
                "expected_result": f"RDP-related alerts or abnormal access patterns are either documented as clean or escalated for {hostname}.",
                "output_type": "Defender alert output / system log excerpt / ticket reference",
                "evidence_capture": f"Attach SIEM or Defender alert screenshots and any escalation ticket for {hostname}.",
            },
        ]

    if "docker" in vuln_l or "container escape" in vuln_l or cve_l == "cve-2019-5736":
        return [
            {
                "step_no": 1,
                "title": "Confirm Docker Runtime Presence",
                "description": (
                    f"Verify whether {hostname} runs Docker or container tooling before collecting monitoring evidence for "
                    f"{vulnerability_name}{cve_suffix}."
                ),
                "commands": [
                    "docker version",
                    "docker info",
                    "docker ps --all",
                ],
                "expected_result": f"Docker runtime version, daemon configuration, and container inventory are captured for {hostname}.",
                "output_type": "Docker version / daemon info / container inventory",
                "evidence_capture": f"Save Docker runtime and container inventory output for {hostname}.",
            },
            {
                "step_no": 2,
                "title": "Review Container Privilege And Mount Risk",
                "description": (
                    f"Identify risky container settings that could increase exposure to {vulnerability_name}{cve_suffix}, "
                    "including privileged mode and sensitive host mounts."
                ),
                "commands": [
                    "docker ps --format \"table {{.ID}}\\t{{.Image}}\\t{{.Names}}\"",
                    "docker inspect $(docker ps -q) --format '{{.Name}} Privileged={{.HostConfig.Privileged}} Binds={{.HostConfig.Binds}}'",
                    "docker images --digests",
                ],
                "expected_result": f"Privileged containers, host bind mounts, and image inventory are documented for {hostname}.",
                "output_type": "Docker inspect output / image inventory",
                "evidence_capture": f"Attach Docker inspect output showing privilege and mount review for {hostname}.",
            },
            {
                "step_no": 3,
                "title": "Validate Docker Patch And Package State",
                "description": f"Track Docker package and runtime patch state while monitoring {vulnerability_name}{cve_suffix}.",
                "commands": [
                    "docker version --format '{{json .}}'",
                    "Get-Package | Where-Object {$_.Name -match 'Docker|container'}",
                    "winget list | findstr /i docker",
                ],
                "expected_result": f"Docker package/runtime version evidence is available for remediation tracking on {hostname}.",
                "output_type": "Package inventory / Docker version JSON",
                "evidence_capture": f"Capture package inventory, Docker version, and vulnerability scan/ticket evidence for {hostname}.",
            },
            {
                "step_no": 4,
                "title": "Review Container Security Logs",
                "description": f"Review Docker and endpoint logs for suspicious container activity on {hostname}.",
                "commands": [
                    "docker events --since 24h",
                    "Get-WinEvent -LogName System -MaxEvents 80",
                    "Get-MpThreatDetection",
                ],
                "expected_result": f"Container lifecycle events and endpoint alerts are reviewed and exceptions are escalated for {hostname}.",
                "output_type": "Docker event output / endpoint alert output / system log excerpt",
                "evidence_capture": f"Attach Docker event logs, alert review output, and any escalation record for {hostname}.",
            },
        ]

    if "jupyter" in vuln_l or cve_l == "cve-2021-32797":
        return [
            {
                "step_no": 1,
                "title": "Identify Jupyter Service Exposure",
                "description": f"Confirm whether {hostname} exposes Jupyter notebooks or lab services for {vulnerability_name}{cve_suffix}.",
                "commands": [
                    "jupyter server list",
                    "jupyter notebook list",
                    "Get-NetTCPConnection | Where-Object {$_.LocalPort -in 8888,8889,8890}",
                ],
                "expected_result": f"Jupyter service URLs, tokens, and exposed ports are identified for {hostname}.",
                "output_type": "Jupyter server list / port listener output",
                "evidence_capture": f"Capture Jupyter server list and listening port evidence for {hostname}.",
            },
            {
                "step_no": 2,
                "title": "Review Jupyter Authentication Configuration",
                "description": f"Validate authentication, token, password, and remote access settings for Jupyter on {hostname}.",
                "commands": [
                    "jupyter --paths",
                    "Get-ChildItem $env:USERPROFILE\\.jupyter -Force -ErrorAction SilentlyContinue",
                    "Select-String -Path $env:USERPROFILE\\.jupyter\\*.py -Pattern 'token|password|ip|allow_origin' -ErrorAction SilentlyContinue",
                ],
                "expected_result": f"Jupyter authentication and binding configuration is available for review on {hostname}.",
                "output_type": "Jupyter config file excerpt / path list",
                "evidence_capture": f"Attach redacted Jupyter configuration evidence for {hostname}.",
            },
            {
                "step_no": 3,
                "title": "Review Notebook Access Logs",
                "description": f"Collect Jupyter access and application logs to detect unauthorized use or exposure for {vulnerability_name}{cve_suffix}.",
                "commands": [
                    "Get-ChildItem $env:USERPROFILE\\.jupyter -Recurse -Include *.log -ErrorAction SilentlyContinue",
                    "Get-WinEvent -LogName Application -MaxEvents 80",
                ],
                "expected_result": f"Jupyter and application logs are collected or their absence is documented for {hostname}.",
                "output_type": "Jupyter log file list / application log excerpt",
                "evidence_capture": f"Attach Jupyter log excerpts, SIEM events, or a screenshot of monitored access for {hostname}.",
            },
        ]

    if "tensorboard" in vuln_l or "containerd" in vuln_l or cve_l == "cve-2020-15257":
        return [
            {
                "step_no": 1,
                "title": "Confirm TensorBoard And Container Runtime Exposure",
                "description": (
                    f"Identify TensorBoard, Python, and container runtime exposure on {hostname} before monitoring "
                    f"{vulnerability_name}{cve_suffix}."
                ),
                "commands": [
                    "Get-Process | Where-Object {$_.ProcessName -match 'tensorboard|python|containerd|docker'}",
                    "Get-NetTCPConnection | Where-Object {$_.LocalPort -in 6006,8080,8888}",
                    "docker ps --all",
                ],
                "expected_result": f"TensorBoard processes, listening ports, and related containers are documented for {hostname}.",
                "output_type": "Process list / listener output / container inventory",
                "evidence_capture": f"Capture process, port, and container evidence for {hostname}.",
            },
            {
                "step_no": 2,
                "title": "Validate TensorBoard Binding And Access Controls",
                "description": f"Check whether TensorBoard is bound to localhost or protected by approved access controls on {hostname}.",
                "commands": [
                    "Get-NetTCPConnection | Where-Object {$_.LocalPort -eq 6006}",
                    "Get-ChildItem -Recurse -Filter '*tensorboard*' -ErrorAction SilentlyContinue",
                    "docker inspect $(docker ps -q) --format '{{.Name}} NetworkMode={{.HostConfig.NetworkMode}} Ports={{.NetworkSettings.Ports}}'",
                ],
                "expected_result": f"TensorBoard binding, exposed ports, and container network mode are reviewed for {hostname}.",
                "output_type": "Listener output / file inventory / Docker network config",
                "evidence_capture": f"Attach binding and access-control evidence for TensorBoard on {hostname}.",
            },
            {
                "step_no": 3,
                "title": "Monitor Unauthorized Access Indicators",
                "description": f"Review endpoint and application logs for unauthorized access attempts against TensorBoard on {hostname}.",
                "commands": [
                    "Get-WinEvent -LogName Application -MaxEvents 80",
                    "Get-WinEvent -LogName Security -MaxEvents 80",
                    "Get-MpThreatDetection",
                ],
                "expected_result": f"Unauthorized TensorBoard access indicators are documented as absent or escalated for {hostname}.",
                "output_type": "Application log / security log / Defender alert output",
                "evidence_capture": f"Attach log excerpts, alert output, or SIEM screenshots for {hostname}.",
            },
        ]

    if "dns" in vuln_l or cve_l == "cve-2020-1350":
        return [
            {
                "step_no": 1,
                "title": "Confirm DNS Monitoring Scope",
                "description": f"Validate DNS service and listener exposure on {hostname} for monitoring {vulnerability_name}{cve_suffix}.",
                "commands": ["Get-Service DNS", "Get-NetTCPConnection -LocalPort 53 -ErrorAction SilentlyContinue", "Get-DnsServerDiagnostics"],
                "expected_result": f"DNS service state and listener exposure are captured for {hostname}.",
                "output_type": "DNS service status / listener output / diagnostic settings",
                "evidence_capture": f"Attach DNS service and listener evidence for {hostname}.",
            },
            {
                "step_no": 2,
                "title": "Review DNS Server Events",
                "description": f"Review DNS logs for errors, suspicious queries, or exploitation indicators related to {vulnerability_name}{cve_suffix}.",
                "commands": ["Get-WinEvent -LogName 'DNS Server' -MaxEvents 100", "Get-WinEvent -LogName System -MaxEvents 80"],
                "expected_result": f"DNS operational and system events are reviewed for {hostname}.",
                "output_type": "DNS event log excerpt / system log excerpt",
                "evidence_capture": f"Export DNS event evidence and any SIEM alerts for {hostname}.",
            },
            {
                "step_no": 3,
                "title": "Track DNS Patch And Restriction State",
                "description": f"Confirm patch status and firewall restrictions for DNS exposure while monitoring continues.",
                "commands": ["Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 30", 'Get-NetFirewallRule | Where-Object {$_.DisplayName -match "DNS"}'],
                "expected_result": f"DNS patch and firewall state are documented for {hostname}.",
                "output_type": "Patch inventory / firewall rule output",
                "evidence_capture": f"Capture patch, firewall, and scan result evidence for {hostname}.",
            },
        ]

    return [
        {
            "step_no": 1,
            "title": "Capture Current Host Monitoring Baseline",
            "description": (
                f"Collect a current technical baseline for {hostname} to confirm the host state, "
                f"active services, and network exposure relevant to {vulnerability_name}{cve_suffix} "
                f"on the {role} role."
            ),
            "commands": [
                "hostname",
                'Get-Service | Where-Object {$_.Status -eq "Running"}',
                "Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,State,OwningProcess",
            ],
            "expected_result": (
                f"A current baseline is captured for {hostname}, including running services and network "
                f"connections that are relevant to {vulnerability_name}."
            ),
            "output_type": "Command output / service status / network connection list",
            "evidence_capture": (
                f"Capture the service and network output for {hostname} as the baseline monitoring evidence."
            ),
        },
        {
            "step_no": 2,
            "title": "Review Security Events And Alerts",
            "description": (
                f"Review recent Windows security activity on {hostname} and collect monitoring output that "
                f"supports the approved action: {recommended_action}"
            ),
            "commands": [
                "Get-WinEvent -LogName Security -MaxEvents 50",
                "Get-WinEvent -LogName System -MaxEvents 50",
            ],
            "expected_result": (
                f"Recent security and system events are available for analyst review and can be correlated "
                f"with monitoring activity for {vulnerability_name}."
            ),
            "output_type": "Log export / event log excerpt",
            "evidence_capture": (
                f"Export or screenshot the relevant Security and System log entries for {hostname}."
            ),
        },
        {
            "step_no": 3,
            "title": "Validate Exposure And Remediation Status",
            "description": (
                f"Check patch state, configuration state, or exposure indicators on {hostname} to confirm "
                f"whether {vulnerability_name}{cve_suffix} remains exposed while monitoring continues."
            ),
            "commands": [
                "Get-HotFix",
                "Get-NetFirewallRule | Select-Object DisplayName,Enabled,Direction,Action",
            ],
            "expected_result": (
                f"Patch and configuration evidence shows the current remediation state for {hostname} "
                f"and supports ongoing monitoring decisions."
            ),
            "output_type": "Patch list / firewall rule list / command output",
            "evidence_capture": (
                f"Capture patch validation output, firewall or configuration output, and any related scan result "
                f"used to confirm the current state on {hostname}."
            ),
        },
    ]


def _replace_monitoring_guide_for_evidence(
    year: int,
    control: dict,
    host: dict,
    evidence: dict,
    prefer_fallback: bool = False,
    guide_id_override: str | None = None,
) -> dict:
    evidence_id = _normalize_text(evidence.get("evidence_id"))
    if evidence_id == "":
        raise ValueError("Evidence item is missing evidence_id.")

    doc = _load_monitoring_implementation_guides_doc_or_blank(year)
    existing_guide = next(
        (
            guide
            for guide in _all_guides(doc)
            if _normalize_key(guide.get("evidence_id")) == _normalize_key(evidence_id)
        ),
        None,
    )
    preserved_guide_id = _normalize_text(guide_id_override)
    if preserved_guide_id == "" and isinstance(existing_guide, dict):
        preserved_guide_id = _normalize_text(existing_guide.get("guide_id"))

    doc["guides"] = [
        guide for guide in _all_guides(doc)
        if _normalize_key(guide.get("evidence_id")) != _normalize_key(evidence_id)
    ]

    try:
        if prefer_fallback:
            raise ValueError("Using deterministic monitoring guide path for bulk generation.")

        guide = _generate_flat_monitoring_implementation_guide(year, control, host, evidence)
        if preserved_guide_id != "":
            guide["guide_id"] = preserved_guide_id
        guide["generation_quality"] = "full"
        guide["generation_method"] = "llm_rag"
    except Exception:
        asset_host = _find_asset_inventory_host(year, _normalize_text(host.get("hostname")))
        hostname = _normalize_text(host.get("hostname"))
        role = _normalize_text(host.get("role")) or _normalize_text(asset_host.get("role"))
        department = _safe_department_from_asset(asset_host)
        os_version = _safe_os_version_from_asset(asset_host)
        control_id = _normalize_text(control.get("CVE"))
        control_name = _normalize_text(control.get("vulnerability"))
        cve_id = _normalize_text(host.get("cve") or control.get("CVE"))
        vulnerability_name = _normalize_text(host.get("vulnerability_name") or control_name)
        severity = _normalize_text(host.get("risk"))
        recommended_action = _normalize_text(control.get("recommended_action"))
        evidence_name = _derive_evidence_name_from_item(evidence)
        evidence_description = _normalize_text(evidence.get("desc")) or evidence_name

        guide = {
            "guide_id": preserved_guide_id or _next_monitoring_guide_id(year, doc),
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
            "recommended_action": recommended_action,
            "evidence_name": evidence_name,
            "evidence_description": evidence_description,
            "evidence_format": "PDF + Logs + Monitoring Export",
            "references": _build_monitoring_guide_references(
                year=year,
                control=control,
                host=host,
                evidence=evidence,
                asset_host=asset_host,
                generation_hints="Deterministic fallback monitoring guide steps generated from control, host, vulnerability, and monitoring context.",
                method_label="Deterministic fallback monitoring guide",
            ),
            "generation_quality": "fallback",
            "generation_method": "deterministic_fallback",
            "implementation_steps": _fallback_monitoring_implementation_steps(
                {
                    "hostname": hostname,
                    "role": role,
                    "control_id": control_id,
                    "control_name": control_name,
                    "vulnerability_name": vulnerability_name,
                    "cve_id": cve_id,
                    "recommended_action": recommended_action,
                }
            ),
        }

    steps = guide.get("implementation_steps")
    if not isinstance(steps, list) or len(steps) == 0:
        raise ValueError("Guide generation failed: no implementation steps returned.")

    doc["guides"].append(guide)
    _save_monitoring_implementation_guides_doc(year, doc)
    return guide


def _refresh_monitoring_guide_async(
    year: int,
    control_snapshot: dict,
    host_snapshot: dict,
    evidence_snapshot: dict,
    guide_id: str = "",
) -> None:
    try:
        _replace_monitoring_guide_for_evidence(
            year=year,
            control=control_snapshot,
            host=host_snapshot,
            evidence=evidence_snapshot,
            prefer_fallback=False,
            guide_id_override=guide_id,
        )
    except Exception:
        # Keep the already-saved draft guide if the full background refresh fails.
        return


def _find_monitoring_guide_by_id(year: int, guide_id: str) -> dict | None:
    normalized_guide_id = _normalize_key(guide_id)
    if normalized_guide_id == "":
        return None

    doc = _load_monitoring_implementation_guides_doc_or_blank(year)
    for guide in _all_guides(doc):
        if _normalize_key(guide.get("guide_id")) == normalized_guide_id:
            return guide
    return None


def _find_monitoring_control_host_evidence_for_guide(
    year: int,
    guide: dict,
) -> tuple[dict | None, dict | None, dict | None]:
    monitoring_doc = _load_monitoring_improvement_doc_or_blank(year)
    evidence_id = _normalize_key(guide.get("evidence_id"))
    control_id = _normalize_key(guide.get("control_id") or guide.get("cve_id"))
    hostname = _normalize_key(guide.get("hostname"))
    vulnerability_name = _normalize_key(guide.get("vulnerability_name"))
    evidence_desc = _normalize_key(guide.get("evidence_description"))

    for control in _all_cves(monitoring_doc):
        if control_id and _normalize_key(control.get("CVE")) != control_id:
            continue

        hosts = control.get("hosts", [])
        if not isinstance(hosts, list):
            continue

        for host in hosts:
            if not isinstance(host, dict):
                continue
            if hostname and _normalize_key(host.get("hostname")) != hostname:
                continue
            if vulnerability_name and _normalize_key(host.get("vulnerability_name")) not in {"", vulnerability_name}:
                continue

            evidence_list = _clean_evidence_list(year, monitoring_doc, host.get("evidence", []))
            for evidence in evidence_list:
                current_evidence_id = _normalize_key(evidence.get("evidence_id"))
                current_desc = _normalize_key(evidence.get("desc"))
                if evidence_id and current_evidence_id == evidence_id:
                    return control, host, evidence
                if (
                    not evidence_id
                    and evidence_desc
                    and current_desc != ""
                    and (
                        current_desc == evidence_desc
                        or current_desc in evidence_desc
                        or evidence_desc in current_desc
                    )
                ):
                    return control, host, evidence

    return None, None, None


def _guide_needs_full_generation(guide: dict) -> bool:
    generation_quality = _normalize_key(guide.get("generation_quality"))
    if generation_quality == "draft":
        return True

    if generation_quality in {"full", "fallback"}:
        return False

    steps = guide.get("implementation_steps", [])
    references = guide.get("references", [])
    if not isinstance(steps, list):
        steps = []
    if not isinstance(references, list):
        references = []

    return len(steps) <= 3 and len(references) <= 5


def ensure_monitoring_implementation_guide_ready(year: int, guide_id: str) -> dict | None:
    guide = _find_monitoring_guide_by_id(year, guide_id)
    if guide is None:
        return None

    if not _guide_needs_full_generation(guide):
        return guide

    control, host, evidence = _find_monitoring_control_host_evidence_for_guide(year, guide)
    if control is None or host is None or evidence is None:
        return guide

    try:
        return _replace_monitoring_guide_for_evidence(
            year,
            control,
            host,
            evidence,
            prefer_fallback=False,
            guide_id_override=_normalize_text(guide.get("guide_id")),
        )
    except Exception:
        return guide


def _build_host_lines_for_rag(hosts: list[dict]) -> list[str]:
    lines = []

    for h in hosts:
        if not isinstance(h, dict):
            continue

        lines.append(
            f"Hostname: {_normalize_text(h.get('hostname'))}, "
            f"Role: {_normalize_text(h.get('role'))}, "
            f"CIA: {_normalize_text(h.get('CIA rating'))}, "
            f"IP: {_normalize_text(h.get('ip_address'))}, "
            f"Vulnerability: {_normalize_text(h.get('vulnerability_name'))}"
        )

    return lines


def _generate_evidence_desc_with_llama3(
    year: int,
    control_id: str,
    control_name: str,
    justification: str,
    hostname: str,
    role: str,
    vulnerability_name: str,
    recommended_action: str,
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

Write one meaningful and brief evidence description for a Monitoring and Improvement evidence record.

STRICT RULES:
- Return only one paragraph
- 28 to 55 words
- No bullets
- No markdown
- Mention the host
- Mention the control context
- Mention the monitoring intent based on the recommended action
- Must be auditor-friendly
- Must reflect the vulnerability and role context
- Do not leave it generic
- Do not mention 'RAG' or 'LLM'

Control ID: {control_id}
Control Name: {control_name}
Justification: {justification}
Hostname: {hostname}
Host Role: {role}
Vulnerability: {vulnerability_name}
Recommended Monitoring Action: {recommended_action}

Relevant ISO References:
{retrieved_text or "NA"}
""".strip()

    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "think": False,
        "options": {
            "temperature": 0.1,
            "top_p": 0.9,
            "num_predict": 90,
        },
    }

    try:
        with performance_span(
            year=year,
            operation_id="monitoring.evidence_description",
            llm_configuration=safe_llm_configuration(model=OLLAMA_MODEL, payload=payload),
        ) as span:
            res = requests.post(OLLAMA_URL, json=payload, timeout=45)
            res.raise_for_status()
            data = res.json()
            span.set_ollama_metrics(data)
        safe_increment_llm_counter(year, ollama_total_tokens(data))
        text = _normalize_text(data.get("response"))
        if text:
            return text
    except Exception:
        pass

    return _fallback_monitoring_evidence_desc(
        control_id=control_id,
        control_name=control_name,
        hostname=hostname,
        role=role,
        vulnerability_name=vulnerability_name,
        recommended_action=recommended_action,
    )


def _fallback_monitoring_evidence_desc(
    control_id: str,
    control_name: str,
    hostname: str,
    role: str,
    vulnerability_name: str,
    recommended_action: str,
) -> str:
    host_value = _normalize_text(hostname) or "the host"
    role_value = _normalize_text(role) or "the assigned role"
    control_value = _normalize_text(control_name) or _normalize_text(control_id) or "the relevant control context"
    vuln_value = _normalize_text(vulnerability_name) or _normalize_text(control_name) or "the identified vulnerability"
    action_value = _normalize_text(recommended_action) or "the defined monitoring action"
    return (
        f"Evidence for {host_value} documents monitoring activities for {vuln_value} on the {role_value} host "
        f"within {control_value}, supporting {action_value.lower()} and follow-up review by the ISMS auditor team."
    )


def _generate_bulk_evidence_descs_with_llama3(
    year: int,
    control_id: str,
    control_name: str,
    justification: str,
    recommended_action: str,
    hosts: list[dict],
    retrieved_controls: list[dict],
) -> dict[str, str]:
    pending_hosts = [host for host in hosts if isinstance(host, dict)]
    if not pending_hosts:
        return {}

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

    host_lines = []
    fallback_map: dict[str, str] = {}
    for host in pending_hosts:
        hostname = _normalize_text(host.get("hostname"))
        role = _normalize_text(host.get("role"))
        vulnerability_name = _normalize_text(host.get("vulnerability_name")) or _normalize_text(control_name)
        if hostname == "":
            continue
        host_lines.append(
            f"- Hostname: {hostname} | Role: {role or 'Unknown Role'} | Vulnerability: {vulnerability_name}"
        )
        fallback_map[_normalize_key(hostname)] = _fallback_monitoring_evidence_desc(
            control_id=control_id,
            control_name=control_name,
            hostname=hostname,
            role=role,
            vulnerability_name=vulnerability_name,
            recommended_action=recommended_action,
        )

    if not host_lines:
        return {}

    prompt = f"""
You are an ISO 27001:2022 and ISO 27002:2022 expert.

Generate one brief monitoring evidence description for each host below.

STRICT RULES:
- Return valid JSON only
- Return an object where each key is the hostname and each value is the description
- Each description must be a single paragraph
- Each description must be 24 to 45 words
- Mention the host
- Mention the monitoring purpose
- Reflect the host role and vulnerability context
- Be auditor-friendly
- No markdown
- No bullets
- No explanations outside JSON

Control ID: {control_id}
Control Name: {control_name}
Justification: {justification or "NA"}
Recommended Monitoring Action: {recommended_action or "NA"}

Hosts:
{chr(10).join(host_lines)}

Relevant ISO References:
{retrieved_text or "NA"}
""".strip()

    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "think": False,
        "options": {
            "temperature": 0.1,
            "top_p": 0.9,
            "num_predict": max(220, len(host_lines) * 80),
        },
    }

    try:
        with performance_span(
            year=year,
            operation_id="monitoring.bulk_evidence_descriptions",
            llm_configuration=safe_llm_configuration(model=OLLAMA_MODEL, payload=payload),
        ) as span:
            res = requests.post(OLLAMA_URL, json=payload, timeout=60)
            res.raise_for_status()
            data = res.json()
            span.set_ollama_metrics(data)
        safe_increment_llm_counter(year, ollama_total_tokens(data))
        raw_text = _normalize_text(data.get("response"))
        parsed = json.loads(raw_text)
        if not isinstance(parsed, dict):
            raise ValueError("Bulk evidence description response was not a JSON object.")

        result: dict[str, str] = {}
        for host in pending_hosts:
            hostname = _normalize_text(host.get("hostname"))
            if hostname == "":
                continue
            value = parsed.get(hostname)
            if not isinstance(value, str):
                value = parsed.get(hostname.lower())
            text = _normalize_text(value)
            result[_normalize_key(hostname)] = text or fallback_map[_normalize_key(hostname)]
        return result
    except Exception:
        return fallback_map

# =========================================================
# MONITORING & IMPROVEMENT DOCUMENT HELPERS
# =========================================================
def _load_risk_evaluation_treatment_doc_or_blank(year: int) -> dict:
    path = _risk_evaluation_treatment_file(year)

    if not path.exists():
        return {"hosts": []}

    try:
        data = _load_json(path)
        if not isinstance(data, dict):
            return {"hosts": []}
        return data
    except Exception:
        return {"hosts": []}


def _build_monitoring_improvement_from_risk_evaluation_treatment(year: int) -> dict:
    source_doc = _load_risk_evaluation_treatment_doc_or_blank(year)

    source_records = source_doc.get("hosts", [])
    if not isinstance(source_records, list):
        source_records = []

    cve_map: dict[str, dict] = {}

    for item in source_records:
        if not isinstance(item, dict):
            continue

        evaluation = _normalize_text(item.get("evaluation"))
        treatment = _normalize_text(item.get("treatment"))

        if evaluation != "Monitor" or treatment != "-":
            continue

        cve_value = _normalize_text(item.get("CVE") or item.get("cve"))
        if cve_value == "":
            continue

        vulnerability_value = _normalize_text(item.get("vulnerability") or item.get("vulnerability_name"))

        if cve_value not in cve_map:
            cve_map[cve_value] = {
                "CVE": cve_value,
                "vulnerability": vulnerability_value,
                "implementation_status": "In Progress",
                "justification": "",
                "recommended_action": "",
                "hosts": [],
            }


        user_behavior_data = {}
        if cve_value.startswith("UB-WS-"):
            user_behavior_data = _find_user_behavior_from_risk_analysis(
                year=year,
                hostname=_normalize_text(item.get("hostname")),
                cve_value=cve_value,
            )
        host_obj = {
            "hostname": _normalize_text(item.get("hostname")),
            "ip_address": _normalize_text(item.get("ip_address")),
            "role": _normalize_text(item.get("role")),
            "CIA rating": _normalize_text(item.get("CIA rating") or item.get("cia_rating")),
            "vulnerability_name": vulnerability_value,
            "risk": _normalize_text(item.get("risk")),
            "riskid": _normalize_text(item.get("riskid")),
            "evaluation": evaluation,
            "treatment": treatment,
            
            "user_behavior": user_behavior_data,  
            
            "evidence": [],
        }

        existing_hosts = cve_map[cve_value]["hosts"]
        duplicate = any(
            _normalize_key(h.get("hostname")) == _normalize_key(host_obj["hostname"])
            and _normalize_key(h.get("ip_address")) == _normalize_key(host_obj["ip_address"])
            for h in existing_hosts
        )

        if not duplicate:
            existing_hosts.append(host_obj)

    return {"cves": list(cve_map.values())}


def _all_cves(doc: dict) -> list[dict]:
    cves = doc.get("cves", [])
    if not isinstance(cves, list):
        return []
    return [c for c in cves if isinstance(c, dict)]


def _load_monitoring_improvement_doc_or_blank(year: int) -> dict:
    output_path = _monitoring_improvement_file(year)

    if not output_path.exists():
        legacy_path = _legacy_monitoring_improvement_file(year)
        if legacy_path.exists():
            try:
                legacy_doc = _load_json(legacy_path)
                if isinstance(legacy_doc, dict) and isinstance(legacy_doc.get("cves"), list):
                    doc = legacy_doc
                    if not isinstance(doc.get("meta"), dict):
                        doc["meta"] = {"submitted": False, "read_only": False}
                    if not _normalize_text(doc.get("status")):
                        doc["status"] = "In Progress" if doc["cves"] else "Not Started"
                    return doc
            except Exception:
                pass
        return _blank_monitoring_improvement_doc()

    try:
        doc = _load_json(output_path)
    except Exception:
        return _blank_monitoring_improvement_doc()

    if not isinstance(doc, dict):
        return _blank_monitoring_improvement_doc()

    if not isinstance(doc.get("cves"), list):
        doc["cves"] = []

    if not isinstance(doc.get("meta"), dict):
        doc["meta"] = {"submitted": False, "read_only": False}

    if not _normalize_text(doc.get("status")):
        doc["status"] = "In Progress" if doc["cves"] else "Not Started"

    return doc


def _derive_monitoring_improvement_status_from_doc(doc: dict) -> str:
    explicit_status = _normalize_text(doc.get("status"))
    if explicit_status == "Completed":
        return "Completed"

    meta = doc.get("meta", {})
    if isinstance(meta, dict) and (meta.get("submitted") or meta.get("read_only")):
        return "Completed"

    if explicit_status == "In Progress":
        return "In Progress"

    if explicit_status == "Not Started":
        return "Not Started"

    return "Not Started" if len(_all_cves(doc)) == 0 else "In Progress"


def _sync_monitoring_improvement_status(year: int, doc: dict | None = None) -> str:
    if doc is None:
        doc = _load_monitoring_improvement_doc_or_blank(year)

    new_status = _derive_monitoring_improvement_status_from_doc(doc)
    if new_status == "Completed":
        _set_monitoring_improvement_doc_state(
            doc,
            status="Completed",
            submitted=True,
            read_only=True,
        )
    else:
        _set_monitoring_improvement_doc_state(
            doc,
            status=new_status,
            submitted=False,
            read_only=False,
        )
    _save_json(_monitoring_improvement_file(year), doc)
    _set_section_status(year, "monitoring_improvement", new_status)
    return new_status


def _find_cve(doc: dict, cve_id: str) -> tuple[int | None, dict | None]:
    target = _normalize_key(cve_id)
    cves = _all_cves(doc)

    for idx, item in enumerate(cves):
        if _normalize_key(item.get("CVE")) == target:
            return idx, item

    return None, None


def _format_cve_label(item: dict) -> str:
    cve_value = _normalize_text(item.get("CVE")) or "Unknown CVE"
    vulnerability = _normalize_text(item.get("vulnerability"))
    return cve_value if vulnerability == "" else f"{cve_value} ({vulnerability})"


def _preview_labels(labels: list[str], limit: int = 8) -> str:
    preview = labels[:limit]
    suffix = "" if len(labels) <= limit else f", and {len(labels) - limit} more"
    return ", ".join(preview) + suffix


def _monitoring_guides_by_evidence_id(year: int) -> dict[str, dict]:
    guides_doc = _load_monitoring_implementation_guides_doc_or_blank(year)
    return {
        _normalize_key(guide.get("evidence_id")): guide
        for guide in _all_guides(guides_doc)
        if _normalize_key(guide.get("evidence_id")) != ""
    }


def _monitoring_guide_matches_evidence_row(
    guide: dict,
    control: dict,
    host: dict,
) -> bool:
    guide_control = _normalize_key(guide.get("control_id") or guide.get("cve_id"))
    row_control = _normalize_key(control.get("CVE"))
    guide_host = _normalize_key(guide.get("hostname"))
    row_host = _normalize_key(host.get("hostname"))
    guide_vulnerability = _normalize_key(guide.get("vulnerability_name") or guide.get("control_name"))
    row_vulnerability = _normalize_key(host.get("vulnerability_name") or control.get("vulnerability"))

    if guide_control and row_control and guide_control != row_control:
        return False
    if guide_host and row_host and guide_host != row_host:
        return False
    if guide_vulnerability and row_vulnerability and guide_vulnerability != row_vulnerability:
        return False

    return True


def ensure_monitoring_guides_for_evidence_rows(
    year: int,
    monitoring_doc: dict | None = None,
    *,
    prefer_fallback: bool = True,
) -> dict:
    doc = monitoring_doc if isinstance(monitoring_doc, dict) else _load_monitoring_improvement_doc_or_blank(year)
    guides_by_evidence_id = _monitoring_guides_by_evidence_id(year)
    created_labels: list[str] = []
    failed_labels: list[str] = []
    doc_changed = False

    for control in _all_cves(doc):
        control_label = _normalize_text(control.get("CVE")) or "Unknown CVE"
        hosts = control.get("hosts", [])
        if not isinstance(hosts, list):
            continue

        for host in hosts:
            if not isinstance(host, dict):
                continue

            if _ensure_monitoring_evidence_ids_for_host(year, doc, host):
                doc_changed = True

            hostname = _normalize_text(host.get("hostname")) or "Unknown Host"
            evidence_list = host.get("evidence", [])
            if not isinstance(evidence_list, list):
                continue

            for evidence in evidence_list:
                if not isinstance(evidence, dict):
                    continue
                if not _evidence_has_meaningful_content(evidence):
                    continue

                evidence_id = _normalize_text(evidence.get("evidence_id"))
                if evidence_id == "":
                    evidence["evidence_id"] = _next_monitoring_evidence_id(year, doc)
                    evidence_id = _normalize_text(evidence.get("evidence_id"))
                    doc_changed = True

                evidence_key = _normalize_key(evidence_id)
                existing_guide = guides_by_evidence_id.get(evidence_key)
                if isinstance(existing_guide, dict) and _monitoring_guide_matches_evidence_row(
                    existing_guide,
                    control,
                    host,
                ):
                    continue

                row_label = f"{control_label} / {hostname}"
                try:
                    guide = _replace_monitoring_guide_for_evidence(
                        year,
                        control,
                        host,
                        evidence,
                        prefer_fallback=prefer_fallback,
                        guide_id_override=(
                            _normalize_text(existing_guide.get("guide_id"))
                            if isinstance(existing_guide, dict)
                            else None
                        ),
                    )
                    guides_by_evidence_id[evidence_key] = guide
                    created_labels.append(row_label)
                except Exception:
                    failed_labels.append(row_label)

    if doc_changed:
        _save_json(_monitoring_improvement_file(year), doc)

    return {
        "doc": doc,
        "created_count": len(created_labels),
        "created": created_labels,
        "failed": failed_labels,
    }


# =========================================================
# NVD / RAG / LLM HELPERS
# =========================================================
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


def _get_nvd_cve_details(cve_id: str) -> dict:
    params = {"cveId": cve_id}
    data = _nvd_get(params)

    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        return {
            "cve_id": cve_id,
            "description": "",
            "cwes": [],
            "severity": "",
            "cpes": [],
            "published": "",
            "last_modified": "",
        }

    return _parse_cve_item(vulnerabilities[0])


def _generate_monitoring_justification_with_llama3(
    year: int,
    cve_id: str,
    vulnerability_name: str,
    nvd_record: dict,
    hosts: list[dict],
) -> str:
    host_lines = []
    for h in hosts:
        if not isinstance(h, dict):
            continue
        host_lines.append(
            f"- Hostname: {_normalize_text(h.get('hostname'))}, "
            f"IP: {_normalize_text(h.get('ip_address'))}, "
            f"Role: {_normalize_text(h.get('role'))}, "
            f"CIA: {_normalize_text(h.get('CIA rating'))}"
        )

    prompt = f"""
You are an ISO 27001:2022 monitoring and improvement expert.

Write one short justification for the "justification" field in MonitoringImprovement.json.

GOAL:
Explain how monitoring could help remediate, contain, reduce, or control the vulnerability risk.

STRICT RULES:
- Return only one paragraph
- 60 to 110 words
- No bullet points
- No markdown
- Do NOT start with phrases like:
  "Monitoring this vulnerability..."
  "Monitoring this control..."
  "Monitoring of this..."
- Start directly with the benefit or remediation outcome
- Focus on how monitoring supports detection, patch verification, exposure tracking, containment, and faster corrective action
- Must be practical, concise, and auditor-friendly
- Do not simply restate the CVE description

CVE: {cve_id}
Vulnerability Name: {vulnerability_name or "NA"}

NVD Context:
Description: {_normalize_text(nvd_record.get('description')) or "NA"}
Severity: {_normalize_text(nvd_record.get('severity')) or "NA"}
CWEs: {", ".join(nvd_record.get("cwes", [])) or "NA"}
Affected CPEs: {", ".join(nvd_record.get("cpes", [])[:8]) or "NA"}
Published: {_normalize_text(nvd_record.get('published')) or "NA"}
Last Modified: {_normalize_text(nvd_record.get('last_modified')) or "NA"}

Affected Hosts:
{chr(10).join(host_lines) or "NA"}
""".strip()

    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.2,
            "top_p": 0.9,
            "num_predict": 300
        }
    }
    with performance_span(
        year=year,
        operation_id="monitoring.justification",
        llm_configuration=safe_llm_configuration(model=OLLAMA_MODEL, payload=payload),
    ) as span:
        res = requests.post(OLLAMA_URL, json=payload, timeout=180)
        res.raise_for_status()
        data = res.json()
        span.set_ollama_metrics(data)
    safe_increment_llm_counter(year, ollama_total_tokens(data))

    return _normalize_text(data.get("response"))


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
    with performance_span(
        year=year,
        operation_id="monitoring.retrieve_controls",
        model_configuration=safe_embedding_configuration(model=OLLAMA_EMBED_MODEL),
    ):
        return _retrieve_relevant_iso_controls_impl(
            year=year,
            control_id=control_id,
            control_name=control_name,
            justification=justification,
            host_lines=host_lines,
            top_k=top_k,
        )


def _retrieve_relevant_iso_controls_impl(
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
        with performance_span(
            year=year,
            operation_id="monitoring.query_embedding",
            model_configuration=safe_embedding_configuration(model=OLLAMA_EMBED_MODEL),
        ):
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
                    with performance_span(
                        year=year,
                        operation_id="monitoring.record_embedding",
                        model_configuration=safe_embedding_configuration(model=OLLAMA_EMBED_MODEL),
                    ):
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
    retrieved = [item[1] for item in scored[:top_k]]
    safe_increment_rag_counter(year, success=bool(retrieved))
    return retrieved


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


def _monitoring_action_needs_repair(value: Any) -> bool:
    text = _normalize_text(value)
    if not text.startswith("Recommended monitoring actions:"):
        return True

    bullets = [
        line.strip()
        for line in text.splitlines()[1:]
        if line.strip().startswith("-")
    ]
    if len(bullets) < 3:
        return True

    generic_starts = (
        "- Review security logs and alerts related to",
        "- Track patch, configuration, and exposure status until",
        "- Collect monitoring evidence such as scan results",
        "- Escalate repeated suspicious activity or failed remediation",
    )
    generic_hits = 0
    for bullet in bullets:
        bullet_l = bullet.lower()
        if any(bullet_l.startswith(item.lower()) for item in generic_starts):
            generic_hits += 1

    if generic_hits >= 2:
        return True

    unique_normalized = {
        re.sub(r"\b(cve-\d{4}-\d{4,7}|ub-ws-\d+)\b", "<id>", bullet.lower())
        for bullet in bullets
    }
    return len(unique_normalized) < max(2, len(bullets) - 1)


def _generate_monitoring_action_with_llama3(
    year: int,
    control_id: str,
    control_name: str,
    justification: str,
    host_lines: list[str],
    retrieved_controls: list[dict],
    nvd_record: dict | None = None,
) -> str:
    nvd_record = nvd_record if isinstance(nvd_record, dict) else {}
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
/no_think

You are an ISO 27001:2022 and ISO 27002:2022 expert.

Generate recommended monitoring actions for the given vulnerability using LLM reasoning and the retrieved ISO guidance.

FORMAT REQUIREMENTS (STRICT):
- First line MUST be exactly:
  Recommended monitoring actions:
- Then provide bullet points using "-" (dash)
- Provide 4 to 6 bullet points
- Each action must be practical, monitoring-oriented, and specific to this vulnerability
- Focus on detection, alerting, log review, exposure tracking, validation, escalation, and follow-up
- Every bullet must mention at least one concrete signal, telemetry source, exposure condition, affected technology, host role, or vulnerability behavior from the context
- Avoid generic repeated actions such as "review security logs", "track patch status", or "collect monitoring evidence" unless the bullet explains exactly which logs, exposure, service, or detection condition applies
- No explanations
- No paragraphs
- No numbering
- No markdown symbols like *
- Do not mention RAG or LLM

Target CVE / record:
CVE: {control_id}
Vulnerability / Context: {control_name}
Justification: {justification or "NA"}

Vulnerability intelligence:
Description: {_normalize_text(nvd_record.get("description")) or "NA"}
Severity: {_normalize_text(nvd_record.get("severity")) or "NA"}
Weaknesses: {", ".join(nvd_record.get("cwes", [])) if isinstance(nvd_record.get("cwes"), list) else "NA"}
Affected platforms: {", ".join(nvd_record.get("cpes", [])[:8]) if isinstance(nvd_record.get("cpes"), list) else "NA"}

Affected hosts:
{_safe_join_lines(host_lines) or "NA"}

ISO guidance:
{retrieved_text or "NA"}
""".strip()

    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "think": False,
        "options": {
            "temperature": 0.25,
            "top_p": 0.9,
            "num_predict": 600
        }
    }
    with performance_span(
        year=year,
        operation_id="monitoring.action_primary",
        llm_configuration=safe_llm_configuration(model=OLLAMA_MODEL, payload=payload),
    ) as span:
        res = requests.post(OLLAMA_URL, json=payload, timeout=180)
        res.raise_for_status()
        data = res.json()
        span.set_ollama_metrics(data)
    safe_increment_llm_counter(year, ollama_total_tokens(data))

    response_text = _normalize_text(data.get("response"))
    
    if not response_text.startswith("Recommended monitoring actions:"):
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
                if part:
                    clean_bullets.append(f"- {part}")
    
        seen = set()
        final_bullets = []
        for b in clean_bullets:
            if b not in seen:
                seen.add(b)
                final_bullets.append(b)
    
        response_text = "Recommended monitoring actions:\n" + "\n".join(final_bullets)
    
    if _monitoring_action_needs_repair(response_text):
        repair_prompt = f"""
/no_think

Rewrite the monitoring action output so it is specific to this vulnerability and audit context.

Return only this format:
Recommended monitoring actions:
- ...
- ...
- ...
- ...

Rules:
- 4 to 6 bullets only.
- No generic repeated bullets.
- Each bullet must reference a concrete technology, service, signal, log source, host role, exposure condition, or vulnerability behavior from the context.
- Do not mention CVE IDs except the target record identifier if necessary.

Target: {control_id} / {control_name}
NVD description: {_normalize_text(nvd_record.get("description")) or "NA"}
Severity: {_normalize_text(nvd_record.get("severity")) or "NA"}
Hosts: {_safe_join_lines(host_lines) or "NA"}
Justification: {justification or "NA"}
ISO guidance: {retrieved_text or "NA"}

Previous output:
{response_text or "NA"}
""".strip()
        repair_payload = {
            "model": OLLAMA_MODEL,
            "prompt": repair_prompt,
            "stream": False,
            "think": False,
            "options": {
                "temperature": 0.2,
                "top_p": 0.9,
                "num_predict": 600,
            },
        }
        with performance_span(
            year=year,
            operation_id="monitoring.action_repair",
            llm_configuration=safe_llm_configuration(model=OLLAMA_MODEL, payload=repair_payload),
        ) as span:
            repair_res = requests.post(OLLAMA_URL, json=repair_payload, timeout=180)
            repair_res.raise_for_status()
            repair_data = repair_res.json()
            span.set_ollama_metrics(repair_data)
        safe_increment_llm_counter(year, ollama_total_tokens(repair_data))
        repaired_text = _normalize_text(repair_data.get("response"))
        if not repaired_text.startswith("Recommended monitoring actions:"):
            repaired_lines = [line.strip() for line in repaired_text.splitlines() if line.strip()]
            repaired_bullets = []
            for line in repaired_lines:
                cleaned = re.sub(r"^[\-\*\d\.\)\(]+\s*", "", line)
                if cleaned:
                    repaired_bullets.append(f"- {cleaned}")
            repaired_text = "Recommended monitoring actions:\n" + "\n".join(repaired_bullets[:6])
        response_text = repaired_text

    if _monitoring_action_needs_repair(response_text):
        raise ValueError("LLM returned generic or unusable recommended monitoring actions.")
    
    return response_text

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
        "options": {
            "temperature": 0.2,
            "top_p": 0.9,
            "num_predict": 300
        }
    }

    with performance_span(
        year=year,
        operation_id="monitoring.evidence_recommendations",
        llm_configuration=safe_llm_configuration(model=OLLAMA_MODEL, payload=payload),
    ) as span:
        res = requests.post(OLLAMA_URL, json=payload, timeout=180)
        res.raise_for_status()
        data = res.json()
        span.set_ollama_metrics(data)
    safe_increment_llm_counter(year, ollama_total_tokens(data))

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


# =========================================================
# ROUTES
# =========================================================
@router.get("/inventory")
def get_monitoring_improvement_inventory(year: int = Query(2026)):
    doc = _load_monitoring_improvement_doc_or_blank(int(year))
    _sync_monitoring_improvement_status(int(year), doc)
    return doc


@router.post("/create")
def create_monitoring_improvement(year: int = 2026):
    new_doc = _build_monitoring_improvement_from_risk_evaluation_treatment(int(year))

    cves = new_doc.get("cves", [])
    if not isinstance(cves, list) or len(cves) == 0:
        return {
            "success": False,
            "message": (
                "No records found in RiskEvaluationTreatment.json with "
                "evaluation = 'Monitor' and treatment = '-'."
            ),
            "inventory": {"cves": []},
        }

    enriched_cves = []

    for item in cves:
        if not isinstance(item, dict):
            continue

        cve_id = _normalize_text(item.get("CVE"))
        vulnerability_name = _normalize_text(item.get("vulnerability"))
        hosts = item.get("hosts", [])
        if not isinstance(hosts, list):
            hosts = []

        # =====================================================
        # SPECIAL CASE: UB-WS-XX
        # =====================================================
        if cve_id.startswith("UB-WS-"):
            item["justification"] = _generate_ub_ws_xx_justification(hosts)
            enriched_cves.append(item)
            continue

        try:
            nvd_record = _get_nvd_cve_details(cve_id)
        except Exception:
            nvd_record = {
                "cve_id": cve_id,
                "description": "",
                "cwes": [],
                "severity": "",
                "cpes": [],
                "published": "",
                "last_modified": "",
            }

        try:
            justification = _generate_monitoring_justification_with_llama3(
                year=year,
                cve_id=cve_id,
                vulnerability_name=vulnerability_name,
                nvd_record=nvd_record,
                hosts=hosts,
            )
        except Exception:
            justification = (
                f"Early detection of affected or exposed systems, verification of patch and configuration status, "
                f"and faster corrective action help reduce the likelihood that {cve_id} can be exploited successfully. "
                f"Ongoing review of vulnerability findings, security events, and remediation progress improves containment "
                f"and shortens the time the weakness remains present in the environment."
            )

        item["justification"] = justification
        enriched_cves.append(item)

    new_doc["cves"] = enriched_cves

    _save_json(_monitoring_improvement_file(int(year)), new_doc)
    _reset_monitoring_implementation_guides(int(year))
    _set_section_status(int(year), "monitoring_improvement", "In Progress")

    return {
        "success": True,
        "message": "New Monitoring Improvement table created successfully.",
        "inventory": new_doc,
    }

@router.get("/details")
def get_monitoring_improvement_details(control_id: str = Query(...), year: int = Query(2026)):
    doc = _load_monitoring_improvement_doc_or_blank(int(year))
    idx, control = _find_cve(doc, control_id)

    if control is None or idx is None:
        return {
            "success": False,
            "message": f"CVE '{control_id}' was not found.",
            "control": None,
        }

    return {
        "success": True,
        "control": control,
    }


@router.post("/update-status")
def update_monitoring_improvement_status(payload: UpdateStatusRequest):
    year = int(payload.year or 2026)
    doc = _load_monitoring_improvement_doc_or_blank(year)

    if _monitoring_improvement_section_is_read_only(year):
        return {
            "success": False,
            "message": "Monitoring and Improvement has already been submitted and is now read-only.",
            "inventory": doc,
        }

    status_value = _normalize_text(payload.implementation_status)
    if status_value not in VALID_MONITORING_STATUSES:
        return {
            "success": False,
            "message": (
                "Invalid implementation_status. Allowed values are: "
                "Not Implemented, Planned, In Progress, Implemented, Not Applicable."
            ),
            "inventory": doc,
        }

    idx, control = _find_cve(doc, payload.control_id)
    if control is None or idx is None:
        return {
            "success": False,
            "message": f"CVE '{payload.control_id}' was not found.",
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

    cves = doc.get("cves", [])
    if isinstance(cves, list):
        cves[idx] = control
        doc["cves"] = cves

    _save_json(_monitoring_improvement_file(year), doc)
    _sync_monitoring_improvement_status(year, doc)

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
def reset_monitoring_improvement(payload: ResetRequest):
    year = int(payload.year or 2026)
    doc = _load_monitoring_improvement_doc_or_blank(year)

    if _monitoring_improvement_section_is_read_only(year):
        return {
            "success": False,
            "message": "Monitoring and Improvement has already been submitted and is now read-only.",
            "inventory": doc,
        }

    if not payload.confirm:
        return {
            "success": True,
            "requires_confirmation": True,
            "message": "All implementation status values will be reset, are you sure?",
            "inventory": doc,
        }

    cves = _all_cves(doc)
    for cve in cves:
        cve["implementation_status"] = ""

        hosts = cve.get("hosts", [])
        if isinstance(hosts, list):
            for host in hosts:
                if isinstance(host, dict):
                    host["implementation_status"] = ""
            cve["hosts"] = hosts

    doc["cves"] = cves
    _sync_monitoring_improvement_status(year, doc)

    return {
        "success": True,
        "message": "Monitoring and Improvement implementation status values have been reset.",
        "inventory": doc,
    }


@router.post("/delete")
def delete_monitoring_improvement_control(payload: DeleteRequest):
    year = int(payload.year or 2026)
    doc = _load_monitoring_improvement_doc_or_blank(year)

    if _monitoring_improvement_section_is_read_only(year):
        return {
            "success": False,
            "message": "Monitoring and Improvement has already been submitted and is now read-only.",
            "inventory": doc,
        }

    cves = _all_cves(doc)
    new_cves = [
        c for c in cves
        if _normalize_key(c.get("CVE")) != _normalize_key(payload.control_id)
    ]

    if len(new_cves) == len(cves):
        return {
            "success": False,
            "message": f"CVE '{payload.control_id}' was not found.",
            "inventory": doc,
        }

    doc["cves"] = new_cves
    _save_json(_monitoring_improvement_file(year), doc)
    _sync_monitoring_improvement_status(year, doc)

    return {
        "success": True,
        "message": f"CVE {payload.control_id} deleted successfully.",
        "inventory": doc,
    }


@router.post("/submit")
def submit_monitoring_improvement(payload: SubmitRequest):
    year = int(payload.year or 2026)
    ensure_previous_steps_completed(year, "monitoring_improvement")
    doc = _load_monitoring_improvement_doc_or_blank(year)

    if _monitoring_improvement_section_is_read_only(year):
        return {
            "success": False,
            "message": "Monitoring and Improvement has already been submitted and is now read-only.",
            "inventory": doc,
        }

    if not payload.confirm:
        return {
            "success": True,
            "requires_confirmation": True,
            "message": "The Monitoring and Improvement results will be finalized and locked, are you sure?",
            "inventory": doc,
        }

    cves = _all_cves(doc)
    if len(cves) == 0:
        return {
            "success": False,
            "message": "The Monitoring and Improvement table is empty.",
            "inventory": doc,
        }

    missing_status = []
    invalid_status = []

    for cve in cves:
        status_value = _normalize_text(cve.get("implementation_status"))

        if status_value in {"", "-- Select --", "-- select --"}:
            missing_status.append(_format_cve_label(cve))
            continue

        if status_value not in VALID_MONITORING_STATUSES:
            invalid_status.append(f"{_format_cve_label(cve)} -> {status_value}")

    if missing_status:
        return {
            "success": False,
            "message": (
                "Please select an implementation status for every CVE before submitting the "
                f"Monitoring and Improvement table. Missing selections: {', '.join(missing_status)}"
            ),
            "inventory": doc,
        }

    if invalid_status:
        return {
            "success": False,
            "message": (
                "One or more CVEs have an invalid implementation status value. "
                f"Please update these rows and try again: {', '.join(invalid_status)}"
            ),
            "inventory": doc,
        }

    _set_monitoring_improvement_doc_state(
        doc,
        status="Completed",
        submitted=True,
        read_only=True,
    )
    _sync_monitoring_improvement_status(year, doc)
    return {
        "success": True,
        "message": "The Monitoring / Improvement table data submitted succcesfully.",
        "records_finalized": len(cves),
        "inventory": doc,
    }


def _generate_recommended_action_for_control(year: int, control: dict) -> str:
    control_id = _normalize_text(control.get("CVE"))
    control_name = _normalize_text(control.get("vulnerability"))
    justification = _normalize_text(control.get("justification"))

    hosts = control.get("hosts", [])
    if not isinstance(hosts, list):
        hosts = []

    host_lines = []
    for host in hosts:
        if isinstance(host, dict):
            host_lines.append(
                f"Host={_normalize_text(host.get('hostname'))}, "
                f"Role={_normalize_text(host.get('role'))}, "
                f"CIA={_normalize_text(host.get('CIA rating'))}, "
                f"CVE={control_id}, "
                f"Vulnerability={_normalize_text(host.get('vulnerability_name') or control_name)}, "
                f"Risk={_normalize_text(host.get('risk'))}"
            )

    retrieved_controls = _retrieve_relevant_iso_controls(
        year=year,
        control_id=control_id,
        control_name=control_name,
        justification=justification,
        host_lines=host_lines,
        top_k=5,
    )

    if control_id.startswith("UB-WS-"):
        return _generate_user_behavior_monitoring_action_with_llama3(
            year=year,
            control_id=control_id,
            control_name=control_name,
            justification=justification,
            hosts=hosts,
            retrieved_controls=retrieved_controls,
        )

    try:
        nvd_record = _get_nvd_cve_details(control_id) if control_id.startswith("CVE-") else {}
    except Exception:
        nvd_record = {}

    return _generate_monitoring_action_with_llama3(
        year=year,
        control_id=control_id,
        control_name=control_name,
        justification=justification,
        host_lines=host_lines,
        retrieved_controls=retrieved_controls,
        nvd_record=nvd_record,
    )


@router.post("/recommend")
def recommend_monitoring_action(payload: RecommendTreatmentRequest):
    year = int(payload.year or 2026)
    doc = _load_monitoring_improvement_doc_or_blank(year)

    if _monitoring_improvement_section_is_read_only(year):
        return {
            "success": False,
            "message": "Monitoring and Improvement has already been submitted and is now read-only.",
            "inventory": doc,
        }

    idx, control = _find_cve(doc, payload.control_id)
    if control is None or idx is None:
        return {
            "success": False,
            "message": f"CVE '{payload.control_id}' was not found.",
            "inventory": doc,
        }

    try:
        generated_recommended_action = _generate_recommended_action_for_control(year, control)
    except Exception as e:
        return {
            "success": False,
            "message": f"Failed to generate recommended monitoring action via RAG + Llama3: {str(e)}",
            "inventory": doc,
        }

    control_id = _normalize_text(control.get("CVE"))
    control["recommended_action"] = generated_recommended_action

    cves = doc.get("cves", [])
    if isinstance(cves, list):
        cves[idx] = control
        doc["cves"] = cves

    _save_json(_monitoring_improvement_file(year), doc)
    _sync_monitoring_improvement_status(year, doc)

    return {
        "success": True,
        "message": f"Recommended monitoring action generated for CVE {control_id}.",
        "control": control,
        "inventory": doc,
    }

@router.post("/add-evidence")
def add_evidence_to_monitoring_host(payload: AddEvidenceRequest):
    year = int(payload.year or 2026)
    doc = _load_monitoring_improvement_doc_or_blank(year)

    if _monitoring_improvement_section_is_read_only(year):
        return {
            "success": False,
            "message": "Monitoring and Improvement has already been submitted and is now read-only.",
            "inventory": doc,
        }

    idx, control = _find_cve(doc, payload.control_id)
    if control is None or idx is None:
        return {
            "success": False,
            "message": f"CVE '{payload.control_id}' was not found.",
            "inventory": doc,
        }

    hosts = control.get("hosts", [])
    if not isinstance(hosts, list):
        hosts = []

    target_host_index = None
    for host_idx, host in enumerate(hosts):
        if not isinstance(host, dict):
            continue
        if _normalize_key(host.get("hostname")) == _normalize_key(payload.hostname):
            if (
                _normalize_key(host.get("vulnerability_name")) in {"", _normalize_key(payload.vulnerability_name)}
                or _normalize_key(payload.vulnerability_name) == ""
            ):
                target_host_index = host_idx
                break

    if target_host_index is None:
        return {
            "success": False,
            "message": f"Host '{payload.hostname}' was not found under CVE '{payload.control_id}'.",
            "inventory": doc,
        }

    host = hosts[target_host_index]
    _ensure_monitoring_evidence_ids_for_host(year, doc, host)
    existing_evidence = _clean_evidence_list(year, doc, host.get("evidence", []))

    control_id = _normalize_text(control.get("CVE"))
    control_name = _normalize_text(control.get("vulnerability"))
    justification = _normalize_text(control.get("justification"))
    recommended_action = _normalize_text(control.get("recommended_action"))

    hostname = _normalize_text(host.get("hostname"))
    role = _normalize_text(host.get("role"))
    vulnerability_name = _normalize_text(
        host.get("vulnerability_name") or payload.vulnerability_name or control_name
    )

    provided_responsible = _normalize_text(payload.evidence.responsible)
    provided_resources = _normalize_text(payload.evidence.resources)
    provided_desc = _normalize_text(payload.evidence.desc)

    auto_responsible = provided_responsible or _map_responsible_from_role(role)
    auto_resources = provided_resources or _build_resources_value(hostname, role)
    auto_desc = provided_desc

    if auto_desc == "":
        host_lines = _build_host_lines_for_rag(hosts)
        try:
            retrieved_controls = _retrieve_relevant_iso_controls(
                year=year,
                control_id=control_id,
                control_name=control_name,
                justification=justification,
                host_lines=host_lines,
                top_k=3,
            )
        except Exception:
            retrieved_controls = []

        auto_desc = _generate_evidence_desc_with_llama3(
            year=year,
            control_id=control_id,
            control_name=control_name,
            justification=justification,
            hostname=hostname,
            role=role,
            vulnerability_name=vulnerability_name,
            recommended_action=recommended_action,
            retrieved_controls=retrieved_controls,
        )

    new_evidence = {
        "evidence_id": _next_monitoring_evidence_id(year, doc),
        "responsible": auto_responsible,
        "resources": auto_resources,
        "date": _normalize_text(payload.evidence.date),
        "url": _normalize_text(payload.evidence.url),
        "desc": auto_desc,
    }

    if not any(new_evidence.values()):
        return {
            "success": False,
            "message": "At least one evidence field must be provided.",
            "inventory": doc,
        }

    existing_evidence.append(new_evidence)
    host["evidence"] = existing_evidence
    hosts[target_host_index] = host
    control["hosts"] = hosts

    cves = doc.get("cves", [])
    if isinstance(cves, list):
        cves[idx] = control
        doc["cves"] = cves

    _save_json(_monitoring_improvement_file(year), doc)

    _sync_monitoring_improvement_status(year, doc)

    return {
        "success": True,
        "message": (
            f"Evidence added for host {payload.hostname} under CVE {payload.control_id}. "
            "Guide document will be generated from the Monitoring & Improvement report."
        ),
        "inventory": doc,
    }


@router.post("/upload-evidence")
async def upload_monitoring_evidence(file: UploadFile = File(...), year: int = 2026):
    save_dir = _work_dir(year) / "monitoring_evidence"
    save_dir.mkdir(parents=True, exist_ok=True)

    file_path = save_dir / file.filename

    with open(file_path, "wb") as f:
        f.write(await file.read())

    return {
        "success": True,
        "path": str(file_path),
    }


@router.post("/delete-evidence")
def delete_monitoring_evidence(payload: DeleteEvidenceRequest):
    year = int(payload.year or 2026)
    doc = _load_monitoring_improvement_doc_or_blank(year)

    if _monitoring_improvement_section_is_read_only(year):
        return {
            "success": False,
            "message": "Monitoring and Improvement has already been submitted and is now read-only.",
            "inventory": doc,
        }

    idx, control = _find_cve(doc, payload.control_id)
    if control is None or idx is None:
        return {
            "success": False,
            "message": f"CVE '{payload.control_id}' was not found.",
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
            and (
                _normalize_key(host.get("vulnerability_name")) in {"", _normalize_key(payload.vulnerability_name)}
                or _normalize_key(payload.vulnerability_name) == ""
            )
        ):
            target_host_index = host_idx
            break

    if target_host_index is None:
        return {
            "success": False,
            "message": f"Host '{payload.hostname}' was not found under CVE '{payload.control_id}'.",
            "inventory": doc,
        }

    host = hosts[target_host_index]
    _ensure_monitoring_evidence_ids_for_host(year, doc, host)
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

    cves = doc.get("cves", [])
    if isinstance(cves, list):
        cves[idx] = control
        doc["cves"] = cves

    _save_json(_monitoring_improvement_file(year), doc)
    guide_deleted = _remove_monitoring_guide_by_key(year, removed_evidence_id) if removed_evidence_id else False
    _sync_monitoring_improvement_status(year, doc)

    return {
        "success": True,
        "message": "Selected evidence and its linked monitoring guide were deleted successfully.",
        "guide_deleted": guide_deleted,
        "inventory": doc,
    }


@router.post("/edit-evidence")
def edit_monitoring_evidence(payload: EditEvidenceRequest):
    year = int(payload.year or 2026)
    doc = _load_monitoring_improvement_doc_or_blank(year)

    if _monitoring_improvement_section_is_read_only(year):
        return {
            "success": False,
            "message": "Monitoring and Improvement has already been submitted and is now read-only.",
            "inventory": doc,
        }

    idx, control = _find_cve(doc, payload.control_id)
    if control is None or idx is None:
        return {
            "success": False,
            "message": f"CVE '{payload.control_id}' was not found.",
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
            and (
                _normalize_key(host.get("vulnerability_name")) in {"", _normalize_key(payload.vulnerability_name)}
                or _normalize_key(payload.vulnerability_name) == ""
            )
        ):
            target_host_index = host_idx
            break

    if target_host_index is None:
        return {
            "success": False,
            "message": (
                f"Host '{payload.hostname}' with vulnerability "
                f"'{payload.vulnerability_name}' was not found under CVE '{payload.control_id}'."
            ),
            "inventory": doc,
        }

    host = hosts[target_host_index]
    _ensure_monitoring_evidence_ids_for_host(year, doc, host)
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
    evidence_id = _normalize_text(old_item.get("evidence_id")) or _next_monitoring_evidence_id(year, doc)
    updated_url = _normalize_text(payload.evidence.url)
    updated_date = _default_date_when_url_present(payload.evidence.date, updated_url)

    updated_evidence = {
        "evidence_id": evidence_id,
        "responsible": _normalize_text(payload.evidence.responsible),
        "resources": _normalize_text(payload.evidence.resources),
        "date": updated_date,
        "url": updated_url,
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

    cves = doc.get("cves", [])
    if isinstance(cves, list):
        cves[idx] = control
        doc["cves"] = cves

    _save_json(_monitoring_improvement_file(year), doc)

    if evidence_id:
        _remove_monitoring_guide_by_key(year, evidence_id)

    _sync_monitoring_improvement_status(year, doc)

    return {
        "success": True,
        "message": (
            f"Evidence updated for host '{payload.hostname}'. "
            "Guide document will be regenerated from the Monitoring & Improvement report."
        ),
        "inventory": doc,
    }

@router.post("/evidence-defaults")
def get_monitoring_evidence_defaults(payload: EvidenceDefaultsRequest):
    year = int(payload.year or 2026)
    doc = _load_monitoring_improvement_doc_or_blank(year)

    idx, control = _find_cve(doc, payload.control_id)
    if control is None or idx is None:
        return {
            "success": False,
            "message": f"CVE '{payload.control_id}' was not found.",
            "evidence": {
                "responsible": "",
                "resources": "",
                "date": "",
                "url": "",
                "desc": "",
            },
            "inventory": doc,
        }

    hosts = control.get("hosts", [])
    if not isinstance(hosts, list):
        hosts = []

    selected_host = None
    for host in hosts:
        if not isinstance(host, dict):
            continue
        if _normalize_key(host.get("hostname")) == _normalize_key(payload.hostname):
            if (
                _normalize_key(host.get("vulnerability_name")) in {"", _normalize_key(payload.vulnerability_name)}
                or _normalize_key(payload.vulnerability_name) == ""
            ):
                selected_host = host
                break

    if not isinstance(selected_host, dict):
        return {
            "success": False,
            "message": f"Host '{payload.hostname}' was not found under '{payload.control_id}'.",
            "evidence": {
                "responsible": "",
                "resources": "",
                "date": "",
                "url": "",
                "desc": "",
            },
            "inventory": doc,
        }

    control_id = _normalize_text(control.get("CVE"))
    control_name = _normalize_text(control.get("vulnerability"))
    justification = _normalize_text(control.get("justification"))
    recommended_action = _normalize_text(control.get("recommended_action"))

    hostname = _normalize_text(selected_host.get("hostname"))
    role = _normalize_text(selected_host.get("role"))
    vulnerability_name = _normalize_text(
        selected_host.get("vulnerability_name") or payload.vulnerability_name or control_name
    )

    host_lines = _build_host_lines_for_rag(hosts)

    try:
        retrieved_controls = _retrieve_relevant_iso_controls(
            year=year,
            control_id=control_id,
            control_name=control_name,
            justification=justification,
            host_lines=host_lines,
            top_k=3,
        )
    except Exception:
        retrieved_controls = []

    evidence = {
        "responsible": _map_responsible_from_role(role),
        "resources": _build_resources_value(hostname, role),
        "date": "",
        "url": "",
        "desc": _generate_evidence_desc_with_llama3(
            year=year,
            control_id=control_id,
            control_name=control_name,
            justification=justification,
            hostname=hostname,
            role=role,
            vulnerability_name=vulnerability_name,
            recommended_action=recommended_action,
            retrieved_controls=retrieved_controls,
        ),
    }

    return {
        "success": True,
        "message": f"Evidence defaults generated for host {hostname} under {control_id}.",
        "evidence": evidence,
        "inventory": doc,
    }


@router.post("/add-evidence-all")
def add_evidence_to_all_monitoring_hosts(payload: EvidenceAllRequest):
    year = int(payload.year or 2026)
    doc = _load_monitoring_improvement_doc_or_blank(year)

    if _monitoring_improvement_section_is_read_only(year):
        return {
            "success": False,
            "message": "Monitoring and Improvement has already been submitted and is now read-only.",
            "inventory": doc,
        }

    cves = doc.get("cves", [])
    if not isinstance(cves, list) or len(cves) == 0:
        return {
            "success": False,
            "message": "No Monitoring and Improvement rows are available.",
            "inventory": doc,
        }

    candidate_count = 0
    for control in cves:
        if not isinstance(control, dict):
            continue
        hosts = control.get("hosts", [])
        if not isinstance(hosts, list):
            continue
        for host in hosts:
            if isinstance(host, dict) and _normalize_text(host.get("hostname")) != "":
                candidate_count += 1

    if candidate_count == 0:
        return {
            "success": False,
            "message": "No valid host rows are available for evidence generation.",
            "inventory": doc,
        }

    added_count = 0
    recommended_created_count = 0
    skipped_count = 0
    failed_count = 0
    failed_items: list[str] = []
    for control_idx, control in enumerate(cves):
        if not isinstance(control, dict):
            continue

        control_id = _normalize_text(control.get("CVE"))
        control_name = _normalize_text(control.get("vulnerability"))
        justification = _normalize_text(control.get("justification"))
        recommended_action = _normalize_text(control.get("recommended_action"))
        hosts = control.get("hosts", [])

        if control_id == "" or not isinstance(hosts, list):
            continue

        if recommended_action == "":
            try:
                recommended_action = _generate_recommended_action_for_control(year, control)
                control["recommended_action"] = recommended_action
                cves[control_idx] = control
                doc["cves"] = cves
                _save_json(_monitoring_improvement_file(year), doc)
                recommended_created_count += 1
            except Exception:
                failed_count += len(
                    [
                        host for host in hosts
                        if isinstance(host, dict)
                        and _normalize_text(host.get("hostname")) != ""
                        and len(_clean_evidence_list(year, doc, host.get("evidence", []))) == 0
                    ]
                )
                failed_items.append(f"{control_id} / recommended action")
                continue

        host_lines = _build_host_lines_for_rag(hosts)
        try:
            retrieved_controls = _retrieve_relevant_iso_controls(
                year=year,
                control_id=control_id,
                control_name=control_name,
                justification=justification,
                host_lines=host_lines,
                top_k=3,
            )
        except Exception:
            retrieved_controls = []

        pending_host_entries: list[tuple[int, dict]] = []
        for host_idx, host in enumerate(hosts):
            if not isinstance(host, dict):
                continue

            hostname = _normalize_text(host.get("hostname"))
            if hostname == "":
                continue

            _ensure_monitoring_evidence_ids_for_host(year, doc, host)
            existing_evidence = _clean_evidence_list(year, doc, host.get("evidence", []))
            host["evidence"] = existing_evidence

            if len(existing_evidence) > 0:
                skipped_count += 1
                hosts[host_idx] = host
                continue

            pending_host_entries.append((host_idx, host))

        desc_map = _generate_bulk_evidence_descs_with_llama3(
            year=year,
            control_id=control_id,
            control_name=control_name,
            justification=justification,
            recommended_action=recommended_action,
            hosts=[host for _, host in pending_host_entries],
            retrieved_controls=retrieved_controls,
        )

        for host_idx, host in pending_host_entries:
            role = _normalize_text(host.get("role"))
            hostname = _normalize_text(host.get("hostname"))
            vulnerability_name = _normalize_text(
                host.get("vulnerability_name") or control_name
            )

            new_evidence = {
                "evidence_id": _next_monitoring_evidence_id(year, doc),
                "responsible": _map_responsible_from_role(role),
                "resources": _build_resources_value(hostname, role),
                "date": "",
                "url": "",
                "desc": desc_map.get(_normalize_key(hostname)) or _fallback_monitoring_evidence_desc(
                    control_id=control_id,
                    control_name=control_name,
                    hostname=hostname,
                    role=role,
                    vulnerability_name=vulnerability_name,
                    recommended_action=recommended_action,
                ),
            }

            if not any(new_evidence.values()):
                failed_count += 1
                failed_items.append(f"{control_id} / {hostname}")
                continue

            host["evidence"] = [new_evidence]
            hosts[host_idx] = host
            control["hosts"] = hosts
            cves[control_idx] = control
            doc["cves"] = cves
            _save_json(_monitoring_improvement_file(year), doc)
            added_count += 1

        control["hosts"] = hosts
        cves[control_idx] = control

    doc["cves"] = cves
    _save_json(_monitoring_improvement_file(year), doc)
    _sync_monitoring_improvement_status(year, doc)

    message = (
        f"Evidence generation completed. Generated {recommended_created_count} recommended action(s), "
        f"added {added_count} evidence item(s). "
        "Guide documents will be generated from the Monitoring & Improvement report. "
        f"Skipped {skipped_count} host row(s) that already had evidence."
    )
    if failed_count > 0:
        preview = ", ".join(failed_items[:5])
        if len(failed_items) > 5:
            preview += ", ..."
        message += f" {failed_count} host row(s) failed: {preview}"

    return {
        "success": failed_count == 0,
        "message": message,
        "recommended_created_count": recommended_created_count,
        "added_count": added_count,
        "skipped_count": skipped_count,
        "failed_count": failed_count,
        "inventory": doc,
    }

@router.post("/recommend-all")
def recommend_all(year: int = 2026):
    doc = _load_monitoring_improvement_doc_or_blank(year)

    for cve in doc.get("cves", []):
        # call existing recommend logic internally
        _recommend_for_single_cve(cve)

    _save_json(_monitoring_improvement_file(year), doc)

    return {
        "success": True,
        "message": "Recommended actions generated for all controls",
        "inventory": doc
    }
