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
import requests


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
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3")
OLLAMA_EMBED_URL = os.getenv("OLLAMA_EMBED_URL", "http://localhost:11434/api/embeddings")
OLLAMA_EMBED_MODEL = os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text")


def _work_dir(year: int) -> Path:
    return BASE_DIR / "data" / "work" / str(year)


def _risk_evaluation_treatment_file(year: int) -> Path:
    return _work_dir(year) / "RiskEvaluationTreatment.json"


def _iso_csv_path(year: int) -> Path:
    return _work_dir(year) / "iso27002_controls_2022.csv"


def _iso_embedding_cache_path(year: int) -> Path:
    return _work_dir(year) / "iso27002_local_embeddings.pkl"


def _action_plan_implementation_file(year: int) -> Path:
    return _work_dir(year) / "ActionPlanImplementation.json"


def _monitoring_improvement_file(year: int) -> Path:
    return _work_dir(year) / "MonitoringImprovement.json"


def _legacy_monitoring_improvement_file(year: int) -> Path:
    return _work_dir(year) / "MonitoringAndImprovement.json"


def _system_status_file(year: int) -> Path:
    return _work_dir(year) / "SystemStatus.json"


# =========================================================
# BASIC HELPERS
# =========================================================
def _load_json(path: Path) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _blank_monitoring_improvement_doc() -> dict:
    return {"cves": []}


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
            "action_plan_implementation": {"status": "Completed"},
            "monitoring_improvement": {"status": "Blocked"},
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
    doc = _load_system_status_or_default(year)
    return doc.get("sections", {}).get("monitoring_improvement", {}).get("status") == "Completed"


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
    }

    res = requests.post(OLLAMA_URL, json=payload, timeout=180)
    res.raise_for_status()
    data = res.json()

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
    }

    try:
        res = requests.post(OLLAMA_URL, json=payload, timeout=180)
        res.raise_for_status()
        data = res.json()
        text = _normalize_text(data.get("response"))
        if text:
            return text
    except Exception:
        pass

    # fallback
    host_value = _normalize_text(hostname) or "the host"
    vuln_value = _normalize_text(vulnerability_name) or _normalize_text(control_name) or "the identified vulnerability"
    action_value = _normalize_text(recommended_action) or "the defined monitoring action"
    return (
        f"Evidence for {host_value} shows monitoring activities implemented for {vuln_value} "
        f"under control {control_id}, supporting {action_value.lower()} and follow-up review by the ISMS auditor team."
    )

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
                    return legacy_doc
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

    return doc


def _derive_monitoring_improvement_status_from_doc(doc: dict) -> str:
    return "Not Started" if len(_all_cves(doc)) == 0 else "In Progress"


def _sync_monitoring_improvement_status(year: int, doc: dict | None = None) -> str:
    if _monitoring_improvement_section_is_read_only(year):
        _set_section_status(year, "monitoring_improvement", "Completed")
        return "Completed"

    if doc is None:
        doc = _load_monitoring_improvement_doc_or_blank(year)

    new_status = _derive_monitoring_improvement_status_from_doc(doc)
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
    }

    res = requests.post(OLLAMA_URL, json=payload, timeout=180)
    res.raise_for_status()
    data = res.json()

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


def _generate_monitoring_action_with_llama3(
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

Generate recommended monitoring actions for the given vulnerability.

FORMAT REQUIREMENTS (STRICT):
- First line MUST be exactly:
  Recommended monitoring actions:
- Then provide bullet points using "-" (dash)
- Each action must be practical and monitoring-oriented
- Focus on detection, alerting, log review, exposure tracking, validation, escalation, and follow-up
- No explanations
- No paragraphs
- No numbering
- No markdown symbols like *

Target CVE / record:
CVE: {control_id}
Vulnerability / Context: {control_name}
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
    _save_json(_monitoring_improvement_file(year), doc)
    _set_section_status(year, "monitoring_improvement", "In Progress")

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

    _save_json(_monitoring_improvement_file(year), doc)

    status_doc = _load_system_status_or_default(year)
    
    current_status = status_doc["sections"]["monitoring_improvement"].get("status")
    
    # Rule: keep In Progress, otherwise set to In Progress
    if current_status == "In Progress":
        status_doc["sections"]["monitoring_improvement"]["status"] = "In Progress"
    else:
        status_doc["sections"]["monitoring_improvement"]["status"] = "In Progress"
    
    _save_json(_system_status_file(year), status_doc)
    return {
        "success": True,
        "message": "The Monitoring / Improvement table data submitted succcesfully.",
        "records_finalized": len(cves),
        "inventory": doc,
    }


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
                f"CVE={control_id}"
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

        # SPECIAL CASE: USER ACTIVITY BEHAVIOR
        if control_id.startswith("UB-WS-"):
            generated_recommended_action = _generate_user_behavior_monitoring_action_with_llama3(
                control_id=control_id,
                control_name=control_name,
                justification=justification,
                hosts=hosts,
                retrieved_controls=retrieved_controls,
            )
        else:
            generated_recommended_action = _generate_monitoring_action_with_llama3(
                control_id=control_id,
                control_name=control_name,
                justification=justification,
                host_lines=host_lines,
                retrieved_controls=retrieved_controls,
            )

    except Exception as e:
        return {
            "success": False,
            "message": f"Failed to generate recommended monitoring action via RAG + Llama3: {str(e)}",
            "inventory": doc,
        }

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
    existing_evidence = host.get("evidence", [])
    if not isinstance(existing_evidence, list):
        existing_evidence = []

    control_id = _normalize_text(control.get("CVE"))
    control_name = _normalize_text(control.get("vulnerability"))
    justification = _normalize_text(control.get("justification"))
    recommended_action = _normalize_text(control.get("recommended_action"))

    hostname = _normalize_text(host.get("hostname"))
    role = _normalize_text(host.get("role"))
    vulnerability_name = _normalize_text(
        host.get("vulnerability_name") or payload.vulnerability_name or control_name
    )

    host_lines = _build_host_lines_for_rag(hosts)

    try:
        retrieved_controls = _retrieve_relevant_iso_controls(
            year=year,
            control_id=control_id,
            control_name=control_name,
            justification=justification,
            host_lines=host_lines,
            top_k=5,
        )
    except Exception:
        retrieved_controls = []

    auto_responsible = _map_responsible_from_role(role)
    auto_resources = _build_resources_value(hostname, role)
    auto_desc = _generate_evidence_desc_with_llama3(
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
        "responsible": _normalize_text(payload.evidence.responsible) or auto_responsible,
        "resources": _normalize_text(payload.evidence.resources) or auto_resources,
        "date": _normalize_text(payload.evidence.date),
        "url": _normalize_text(payload.evidence.url),
        "desc": _normalize_text(payload.evidence.desc) or auto_desc,
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
        "message": f"Evidence added for host {payload.hostname} under CVE {payload.control_id}.",
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
    evidence = host.get("evidence", [])
    if not isinstance(evidence, list):
        evidence = []

    if payload.evidence_index < 0 or payload.evidence_index >= len(evidence):
        return {
            "success": False,
            "message": "Selected evidence index is invalid.",
            "inventory": doc,
        }

    evidence.pop(payload.evidence_index)
    host["evidence"] = evidence
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
        "message": "Selected evidence was deleted successfully.",
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

    updated_evidence = {
        "responsible": _normalize_text(payload.evidence.responsible),
        "resources": _normalize_text(payload.evidence.resources),
        "date": _normalize_text(payload.evidence.date),
        "url": _normalize_text(payload.evidence.url),
        "desc": _normalize_text(payload.evidence.desc),
    }

    if not any(updated_evidence.values()):
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
    _sync_monitoring_improvement_status(year, doc)

    return {
        "success": True,
        "message": f"Evidence updated for host '{payload.hostname}'.",
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
            top_k=5,
        )
    except Exception:
        retrieved_controls = []

    evidence = {
        "responsible": _map_responsible_from_role(role),
        "resources": _build_resources_value(hostname, role),
        "date": "",
        "url": "",
        "desc": _generate_evidence_desc_with_llama3(
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