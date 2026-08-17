from fastapi import APIRouter, Query
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from app.api.routes_system_status import _load_status, _atomic_write_json
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import LabelEncoder
from sklearn.impute import SimpleImputer
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.ensemble import RandomForestClassifier
from app.api.aiml_kpi_telemetry import (
    append_aiml_kpi_event,
    append_aiml_kpi_events,
    safe_increment_manual_correction_counter,
)
from app.behavior.aggregate_user_behavior import merge_many_hosts

router = APIRouter(prefix="/api/risk-analysis", tags=["risk-analysis"])


VALID_STEP_STATUSES = {"Blocked", "Not Started", "In Progress", "Completed"}
VALID_RISK_VALUES = {"Critical", "High", "Medium", "Low", "Unscanned"}


class AnalysisRequest(BaseModel):
    year: int | None = 2026


class SetRiskRequest(BaseModel):
    year: int | None = 2026
    hostname: str
    cve: str
    risk: str


class SubmitRequest(BaseModel):
    year: int | None = 2026
    confirm: bool = False

class TrainRequest(BaseModel):
    model_config = {"protected_namespaces": ()}

    year: int | None = 2026
    dataset_path: str | None = None
    model_dir: str | None = None


class DeleteRequest(BaseModel):
    year: int | None = 2026
    hostname: str
    cve: str


def find_project_root() -> Path:
    current = Path(__file__).resolve()
    for parent in [current] + list(current.parents):
        if (parent / "data" / "work").exists():
            return parent
    raise RuntimeError("Could not find project root containing data/work")


BASE_DIR = find_project_root()

def _ml_dir() -> Path:
    return BASE_DIR / "data" / "ml"


def _ml_models_dir() -> Path:
    return _ml_dir() / "models"


def _default_behavior_dataset_path() -> Path:
    return _ml_dir() / "user_behavior_training_dataset.parquet"


def _default_behavior_model_path() -> Path:
    return _ml_models_dir() / "rf_behavior_model.joblib"


def _default_behavior_label_encoder_path() -> Path:
    return _ml_models_dir() / "label_encoder.joblib"
    

def _work_dir(year: int) -> Path:
    return BASE_DIR / "data" / "work" / str(year)


def _risk_analysis_file(year: int) -> Path:
    return _work_dir(year) / "RiskAnalysis.json"


def _asset_vuln_file(year: int) -> Path:
    return _work_dir(year) / "AssetVulnerabilitiesThreats.json"


def _controls_postures_file(year: int) -> Path:
    return _work_dir(year) / "ExistingControlsPostures.json"


def _system_status_file(year: int) -> Path:
    return _work_dir(year) / "SystemStatus.json"


def _dashboard_file() -> Path:
    return BASE_DIR / "data" / "raw" / "dashboard.json"


def _has_submitted_scope_document() -> bool:
    path = _dashboard_file()
    if not path.exists():
        return False

    try:
        dashboard = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return False

    if not isinstance(dashboard, dict):
        return False

    scope_file_name = str(dashboard.get("scope_file_name") or "").strip().lower()
    return bool(scope_file_name) and not re.search(r"-v0\.json$", scope_file_name)


def _load_json(path: Path) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def _safe_append_aiml_kpi_event(year: int, bucket: str, event: dict) -> None:
    try:
        append_aiml_kpi_event(year, bucket, event)
    except Exception as e:
        print(f"[aiml-kpi] failed to append {bucket}: {e}")


def _safe_append_aiml_kpi_events(year: int, bucket: str, events: list[dict]) -> None:
    try:
        append_aiml_kpi_events(year, bucket, events)
    except Exception as e:
        print(f"[aiml-kpi] failed to append {bucket}: {e}")


def _record_behavior_training_telemetry(year: int, result: dict, source_endpoint: str) -> None:
    _safe_append_aiml_kpi_event(year, "behavior_model_training_runs", {
        "run_id": f"behavior_train_{datetime.now().astimezone().strftime('%Y-%m-%d_%H-%M-%S')}",
        "model_type": "user_behavior",
        "dataset_path": result.get("dataset_path"),
        "model_path": result.get("model_path"),
        "label_encoder_path": result.get("label_encoder_path"),
        "accuracy": result.get("accuracy"),
        "accuracy_pct": (
            round(float(result["accuracy"]) * 100, 4)
            if result.get("accuracy") is not None
            else None
        ),
        "classification_report": result.get("classification_report"),
        "confusion_matrix": result.get("confusion_matrix"),
        "feature_importance": result.get("feature_importance"),
        "sample_predictions": result.get("sample_predictions"),
        "source_endpoint": source_endpoint,
    })


def _behavior_model_is_ready() -> bool:
    return _default_behavior_model_path().exists() and _default_behavior_label_encoder_path().exists()


def _ensure_behavior_model_ready(year: int) -> tuple[bool, str | None]:
    if _behavior_model_is_ready():
        return False, None

    dataset_path = _default_behavior_dataset_path()
    model_dir = _ml_models_dir()
    result = _train_user_behavior_model(dataset_path, model_dir)
    _record_behavior_training_telemetry(year, result, "/api/risk-analysis/analysis:auto-train")
    return True, result.get("message") or "User behavior model trained successfully."


def _build_behavior_prediction_telemetry_events(inventory: dict, source_endpoint: str) -> list[dict]:
    events: list[dict] = []
    timestamp = datetime.now().astimezone().strftime("%Y-%m-%d_%H-%M-%S")

    for record in _all_hosts(inventory):
        user_behavior = record.get("user_behavior")
        if not isinstance(user_behavior, dict):
            continue

        hostname = str(record.get("hostname") or "").strip()
        if not hostname:
            continue

        events.append({
            "event_id": f"behavior_{hostname}_{timestamp}",
            "hostname": hostname,
            "cve": record.get("cve", ""),
            "model_type": "user_behavior",
            "failedLoginAttempts": user_behavior.get("failedLoginAttempts"),
            "accessFrequency": user_behavior.get("accessFrequency"),
            "loginConsistency": user_behavior.get("loginConsistency"),
            "passwordResets": user_behavior.get("passwordResets"),
            "sessionDuration": user_behavior.get("sessionDuration"),
            "rule_score": user_behavior.get("rule_score"),
            "ml_score": user_behavior.get("ml_score"),
            "behaviorRiskScore": user_behavior.get("behaviorRiskScore"),
            "likelihood": user_behavior.get("likelihood") or record.get("likelihood", ""),
            "risk": record.get("risk", ""),
            "source_endpoint": source_endpoint,
        })

    return events


def _user_behavior_activity_file(year: int) -> Path:
    return _work_dir(year) / "UserBehaviorActivity.json"


def _is_workstation_record(host_obj: dict) -> bool:
    hostname = str(host_obj.get("hostname") or "").strip().lower()
    role = _extract_role(host_obj).strip().lower()

    if hostname.startswith("ws-") or hostname.startswith("ws_"):
        return True

    return "workstation" in role


def _safe_div(a: float, b: float) -> float:
    if b == 0:
        return 0.0
    return a / b


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def _normalize_failed_login_attempts(v: Any) -> float:
    return _clamp01(_to_float(v, 0.0) / 10.0)


def _normalize_access_frequency(v: Any) -> float:
    return _clamp01(_to_float(v, 0.0) / 20.0)


def _normalize_login_consistency(v: Any) -> float:
    # higher inconsistency = higher risk
    return _clamp01(_to_float(v, 0.0))


def _normalize_password_resets(v: Any) -> float:
    return _clamp01(_to_float(v, 0.0) / 5.0)


def _normalize_session_duration(v: Any) -> float:
    return _clamp01(_to_float(v, 0.0) / 12.0)


def _normalize_hostname(value: str) -> str:
    return (value or "").strip().lower()

def _compute_behavior_rule_score(user_behavior: dict) -> float:
    failed_login_score = _normalize_failed_login_attempts(user_behavior.get("failedLoginAttempts"))
    access_anomaly_score = _normalize_access_frequency(user_behavior.get("accessFrequency"))
    login_variance_score = _normalize_login_consistency(user_behavior.get("loginConsistency"))
    password_reset_score = _normalize_password_resets(user_behavior.get("passwordResets"))
    session_anomaly_score = _normalize_session_duration(user_behavior.get("sessionDuration"))

    score = (
        0.15 * failed_login_score +
        0.30 * access_anomaly_score +
        0.10 * login_variance_score +
        0.20 * password_reset_score +
        0.25 * session_anomaly_score
    )

    return round(_clamp01(score), 4)

def _predict_behavior_ml_score(user_behavior: dict) -> float:
    model_path = _default_behavior_model_path()
    encoder_path = _default_behavior_label_encoder_path()

    if not model_path.exists() or not encoder_path.exists():
        return 0.0

    try:
        pipeline = joblib.load(model_path)
        label_encoder = joblib.load(encoder_path)

        row = pd.DataFrame([{
            "failedLoginAttempts": _to_float(user_behavior.get("failedLoginAttempts"), 0.0),
            "accessFrequency": _to_float(user_behavior.get("accessFrequency"), 0.0),
            "loginConsistency": _to_float(user_behavior.get("loginConsistency"), 0.0),
            "passwordResets": _to_float(user_behavior.get("passwordResets"), 0.0),
            "sessionDuration": _to_float(user_behavior.get("sessionDuration"), 0.0),
        }])

        proba = pipeline.predict_proba(row)[0]
        predicted_idx = int(proba.argmax())
        predicted_label = str(label_encoder.inverse_transform([predicted_idx])[0]).strip().lower()
        confidence = float(proba[predicted_idx])

        label_to_score = {
            "low": 0.25,
            "medium": 0.60,
            "high": 0.85,
            "critical": 1.00,
        }

        return round(label_to_score.get(predicted_label, confidence), 4)
    except Exception:
        return 0.0

def _behavior_likelihood_from_score(score: float) -> str:
    if score >= 0.90:
        return "Critical"
    if score >= 0.80:
        return "High"
    if score >= 0.55:
        return "Medium"
    return "Low"


def _build_user_behavior_payload(raw: dict) -> dict:
    payload = {
        "failedLoginAttempts": int(_to_float(raw.get("failedLoginAttempts"), 0)),
        "accessFrequency": round(_to_float(raw.get("accessFrequency"), 0.0), 4),
        "loginConsistency": round(_to_float(raw.get("loginConsistency"), 0.0), 4),
        "passwordResets": int(_to_float(raw.get("passwordResets"), 0)),
        "sessionDuration": round(_to_float(raw.get("sessionDuration"), 0.0), 4),
    }

    rule_score = _compute_behavior_rule_score(payload)
    ml_score = _predict_behavior_ml_score(payload)
    behavior_risk_score = round((0.60 * rule_score) + (0.40 * ml_score), 4)
    likelihood = _behavior_likelihood_from_score(behavior_risk_score)

    payload["rule_score"] = rule_score
    payload["ml_score"] = ml_score
    payload["behaviorRiskScore"] = behavior_risk_score
    payload["likelihood"] = likelihood

    return payload

def _build_user_activity_behavior_record(host_obj: dict, activity_obj: dict) -> dict:
    hostname = str(host_obj.get("hostname", "") or "")
    ip_address = _extract_ip_address(host_obj)
    role = _extract_role(host_obj)
    cia_rating = _extract_cia_rating(host_obj)

    user_behavior = _build_user_behavior_payload(activity_obj or {})
    likelihood_label = user_behavior["likelihood"]

    likelihood_score_map = {
        "Low": 0.25,
        "Medium": 0.60,
        "High": 0.85,
        "Critical": 1.00,
    }
    likelihood_score = likelihood_score_map.get(likelihood_label, 0.25)

    record = {
        "hostname": hostname,
        "ip_address": ip_address,
        "role": role,
        "CIA rating": cia_rating,
        "vulnerability_name": "User Activity Behavior",
        "severity": "",
        "cvss_score": 0.0,
        "exploit_available": "",
        "patch_status": 0,
        "cve": f"UB-{hostname}",
        "open_ports": [],
        "override": 0,
        "likelihood": likelihood_label,
        "risk": "",
        "likelihood_score": round(likelihood_score, 4),
        "risk_score": 0.0,
        "exposure": "",
        "user_behavior": user_behavior,
    }

    record["risk_score"] = _compute_risk_score(record, record["likelihood_score"])
    record["risk"] = _risk_label_from_score(record["risk_score"])
    return record

def _load_user_behavior_activity_map(year: int) -> dict[str, dict]:
    path = _user_behavior_activity_file(year)
    if not path.exists():
        return {}

    try:
        data = _load_json(path)
    except Exception:
        return {}

    if isinstance(data, dict) and isinstance(data.get("records"), list):
        items = data["records"]
    elif isinstance(data, dict) and isinstance(data.get("hosts"), list):
        items = data["hosts"]
    elif isinstance(data, list):
        items = data
    else:
        items = []

    latest_by_host: dict[str, dict] = {}

    for item in items:
        if not isinstance(item, dict):
            continue

        hostname = _normalize_hostname(str(item.get("hostname", "")))
        if not hostname:
            continue

        existing = latest_by_host.get(hostname)
        current_date = str(item.get("date", "") or "")

        if existing is None:
            latest_by_host[hostname] = item
            continue

        existing_date = str(existing.get("date", "") or "")
        if current_date >= existing_date:
            latest_by_host[hostname] = item

    results: dict[str, dict] = {}

    for hostname, item in latest_by_host.items():
        summary = item.get("dailyBehaviorSummary")
        if not isinstance(summary, dict):
            summary = {}

        results[hostname] = {
            "hostname": item.get("hostname", ""),
            "date": item.get("date", ""),
            "ip_address": item.get("ip_address", ""),
            "failedLoginAttempts": _to_float(summary.get("failedLoginAttempts"), 0),
            "accessFrequency": _to_float(summary.get("accessFrequency"), 0.0),
            "loginConsistency": _to_float(summary.get("loginConsistency"), 0.0),
            "passwordResets": _to_float(summary.get("passwordResets"), 0),
            "sessionDuration": _to_float(summary.get("sessionDuration"), 0.0),
            "successfulLoginCount": _to_float(summary.get("successfulLoginCount"), 0.0),
        }

    return results

def _remove_existing_user_behavior_risks(inventory: dict) -> dict:
    hosts = inventory.get("hosts", [])
    inventory["hosts"] = [
        h for h in hosts
        if str(h.get("vulnerability_name", "")).lower() != "user activity behavior"
    ]
    return inventory
    
def _append_user_behavior_risks(year: int, inventory: dict) -> dict:
    path = _asset_vuln_file(year)
    if not path.exists():
        return inventory

    source = _load_json(path)
    source_hosts = _source_hosts_from_asset_vuln_doc(source)
    behavior_map = _load_user_behavior_activity_map(year)

    hosts = inventory.get("hosts", [])
    if not isinstance(hosts, list):
        hosts = []

    for host_obj in source_hosts:
        if not _is_workstation_record(host_obj):
            continue

        hostname_key = _normalize_hostname(str(host_obj.get("hostname", "")))
        activity_obj = behavior_map.get(hostname_key, {})

        hosts.append(_build_user_activity_behavior_record(host_obj, activity_obj))

    inventory["hosts"] = hosts
    return inventory

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


def _blank_risk_inventory() -> dict:
    return {"hosts": []}


def _load_risk_inventory_or_blank(year: int) -> dict:
    path = _risk_analysis_file(year)

    if not path.exists():
        return _blank_risk_inventory()

    try:
        data = _load_json(path)
        if not isinstance(data, dict):
            return _blank_risk_inventory()

        hosts = data.get("hosts")
        if not isinstance(hosts, list):
            data["hosts"] = []

        return data
    except Exception:
        return _blank_risk_inventory()


def _all_hosts(inventory: dict) -> list[dict]:
    hosts = inventory.get("hosts", [])
    if not isinstance(hosts, list):
        return []
    return [h for h in hosts if isinstance(h, dict)]


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

    if not isinstance(data["sections"].get("scope_context"), dict):
        data["sections"]["scope_context"] = {"status": "Not Started"}

    if not isinstance(data["sections"].get("assets_cia"), dict):
        data["sections"]["assets_cia"] = {"status": "Not Started"}

    if not isinstance(data["sections"].get("risk_analysis"), dict):
        data["sections"]["risk_analysis"] = {"status": "Not Started"}

    if not isinstance(data["sections"].get("risk_evaluation_treatment"), dict):
        data["sections"]["risk_evaluation_treatment"] = {"status": "Not Started"}

    return data


def _set_section_status(year: int, section_name: str, new_status: str) -> None:
    if new_status not in VALID_STEP_STATUSES:
        raise ValueError(f"Invalid status: {new_status}")

    doc = _load_system_status_or_default(year)

    if section_name not in doc["sections"] or not isinstance(doc["sections"][section_name], dict):
        doc["sections"][section_name] = {}

    doc["sections"][section_name]["status"] = new_status
    _save_json(_system_status_file(year), doc)


def _set_risk_analysis_status(year: int, new_status: str) -> None:
    _set_section_status(year, "risk_analysis", new_status)


def _risk_analysis_is_read_only(year: int) -> bool:
    doc = _load_system_status_or_default(year)
    status = doc.get("sections", {}).get("risk_analysis", {}).get("status")
    return status == "Completed"


def _derive_risk_analysis_status_from_inventory(inventory: dict) -> str:
    if not isinstance(inventory, dict):
        return "Not Started"

    if len(_all_hosts(inventory)) == 0:
        return "Not Started"

    return "In Progress"


def _risk_eval_treatment_file(year: int) -> Path:
    return _work_dir(year) / "RiskEvaluationTreatment.json"


def _build_risk_evaluation_treatment(inventory: dict) -> dict:
    hosts = inventory.get("hosts", [])
    if not isinstance(hosts, list):
        hosts = []

    output = []
    for idx, r in enumerate(hosts, start=1):
        cve = str(r.get("cve", "")).strip()
        risk = str(r.get("risk", "")).strip().lower()

        # 🔥 YOUR RULE
        evaluation = ""
        if cve.startswith("UB-WS-") and risk == "low":
            evaluation = "Monitor"

        output.append({
            "hostname": r.get("hostname", ""),
            "ip_address": r.get("ip_address", ""),
            "role": r.get("role", ""),
            "CIA rating": r.get("CIA rating", ""),
            "vulnerability_name": r.get("vulnerability_name", ""),
            "cve": cve,
            "riskid": f"R-{idx:03d}",
            "risk": r.get("risk", ""),
            "evaluation": evaluation,
            "treatment": "",
        })

    return {"hosts": output}
    
def _sync_risk_analysis_status(year: int, inventory: dict | None = None) -> str:
    if _risk_analysis_is_read_only(year):
        _set_risk_analysis_status(year, "Completed")
        return "Completed"

    if inventory is None:
        inventory = _load_risk_inventory_or_blank(year)

    new_status = _derive_risk_analysis_status_from_inventory(inventory)
    _set_risk_analysis_status(year, new_status)
    return new_status


def _find_risk_record_by_hostname_and_cve(
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
    
def _find_host_by_hostname(inventory: dict, hostname: str) -> tuple[int | None, dict | None]:
    target_key = _normalize_hostname(hostname)

    hosts = _all_hosts(inventory)
    for idx, host in enumerate(hosts):
        current_hostname = _normalize_hostname(str(host.get("hostname", "")))
        if current_hostname == target_key:
            return idx, host

    return None, None


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None or value == "":
            return default
        return float(value)
    except Exception:
        return default


def _to_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)

    raw = str(value or "").strip().lower()
    return raw in {"true", "1", "yes", "y"}


def _extract_open_ports(host_obj: dict, vuln_obj: dict | None = None) -> list[int | str]:
    vuln_obj = vuln_obj or {}

    evidence = vuln_obj.get("evidence") or {}
    if isinstance(evidence.get("open_ports"), list):
        return evidence.get("open_ports")

    for candidate in [
        vuln_obj.get("open_ports"),
        host_obj.get("open_ports"),
        ((host_obj.get("detail") or {}).get("technical_indicators") or {}).get("open_ports"),
    ]:
        if isinstance(candidate, list):
            return candidate

    return []


def _extract_ip_address(host_obj: dict) -> str:
    for candidate in [
        host_obj.get("ip_address"),
        ((host_obj.get("location") or {}).get("ip_address")),
        host_obj.get("ip"),
    ]:
        if candidate not in (None, ""):
            return str(candidate)

    return ""


def _extract_role(host_obj: dict) -> str:
    for candidate in [
        host_obj.get("role"),
        ((host_obj.get("selected_role") or {}).get("role")),
        ((host_obj.get("detail") or {}).get("selected_role") or {}).get("role"),
    ]:
        if candidate not in (None, ""):
            return str(candidate)

    return ""


def _extract_cia_rating(host_obj: dict) -> str:
    if host_obj.get("CIA rating") not in (None, ""):
        return str(host_obj.get("CIA rating"))

    cia_rating = host_obj.get("cia_rating")
    if isinstance(cia_rating, dict):
        criticality = cia_rating.get("criticality")
        if criticality not in (None, ""):
            return str(criticality)

    for candidate in [host_obj.get("cia"), host_obj.get("criticality")]:
        if candidate not in (None, ""):
            return str(candidate)

    return ""


def _find_patch_management_value(obj: Any) -> Any:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k).strip().lower() == "vulnerability & patch management":
                return v

        for v in obj.values():
            found = _find_patch_management_value(v)
            if found is not None:
                return found

    elif isinstance(obj, list):
        for item in obj:
            found = _find_patch_management_value(item)
            if found is not None:
                return found

    return None


def _patch_status_from_controls(year: int) -> int:
    path = _controls_postures_file(year)
    if not path.exists():
        return 0

    try:
        data = _load_json(path)
    except Exception:
        return 0

    value = _find_patch_management_value(data)

    if value is None:
        return 0

    if isinstance(value, str):
        return 1 if value.strip() else 0

    if isinstance(value, (list, dict)):
        return 1 if len(value) > 0 else 0

    return 1 if value else 0


def _source_hosts_from_asset_vuln_doc(doc: dict) -> list[dict]:
    results: list[dict] = []

    if not isinstance(doc, dict):
        return results

    hosts = doc.get("hosts")
    if isinstance(hosts, list):
        results.extend([h for h in hosts if isinstance(h, dict)])

    subnets = doc.get("subnets")
    if isinstance(subnets, list):
        for subnet in subnets:
            if not isinstance(subnet, dict):
                continue
            assets = subnet.get("assets", [])
            if isinstance(assets, list):
                results.extend([a for a in assets if isinstance(a, dict)])

    assets = doc.get("assets")
    if isinstance(assets, list):
        results.extend([a for a in assets if isinstance(a, dict)])

    return results


def _host_vulnerability_entries(host_obj: dict) -> list[dict]:
    candidate_lists = [
        host_obj.get("vulnerabilities_threats"),
        host_obj.get("vulnerabilities"),
        host_obj.get("threats_vulnerabilities"),
    ]

    for candidate in candidate_lists:
        if isinstance(candidate, list):
            return [v for v in candidate if isinstance(v, dict)]

    if any(
        key in host_obj
        for key in [
            "vulnerability_name",
            "severity",
            "cvss_score",
            "exploit_available",
            "cve",
        ]
    ):
        return [host_obj]

    return []


# ---------------------------
# Likelihood / Risk helpers
# ---------------------------

def _clamp(value: float, minimum: float = 0.0, maximum: float = 1.0) -> float:
    return max(minimum, min(maximum, float(value)))


def _is_private_ip(ip_address: str) -> bool:
    ip = (ip_address or "").strip()
    return ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.")


def _normalize_port(value: Any) -> int | None:
    try:
        return int(value)
    except Exception:
        return None


def _has_critical_ports(open_ports: list[Any]) -> bool:
    critical_ports = {3389, 445, 22, 80, 443, 1433}
    normalized = {_normalize_port(p) for p in (open_ports or [])}
    return any(p in critical_ports for p in normalized if p is not None)


def _infer_exposure_level(record: dict) -> str:
    ip_address = str(record.get("ip_address") or "")
    role = str(record.get("role") or "").strip().lower()
    open_ports = record.get("open_ports") or []
    ml_probability = _to_float(record.get("ml_probability"), 0.0)

    score = 0.0

    # A. internet-facing best guess
    # Private IP => internal unless role/ports strongly suggest exposure
    if ip_address and not _is_private_ip(ip_address):
        score += 5.0
    else:
        score += 1.5

    # B. more open ports => more exposure
    score += min(len(open_ports) * 0.5, 2.0)

    # critical ports
    if _has_critical_ports(open_ports):
        score += 1.5

    # C. role-aware heuristics
    if "web server" in role:
        score += 1.5
    elif "domain controller" in role:
        score += 1.0
    elif "dns" in role:
        score += 0.8
    elif "file server" in role:
        score += 0.8
    elif "workstation" in role:
        score += 0.5

    # Optional small ML-driven bump
    score += min(max(ml_probability, 0.0), 1.0) * 0.5

    score = min(score, 5.0)

    if score <= 1.0:
        return "Very Low"
    if score <= 2.0:
        return "Low"
    if score <= 3.0:
        return "Medium"
    if score <= 4.0:
        return "High"
    return "Critical"


def _map_exposure_to_normalized(level: str) -> float:
    level_key = (level or "").strip().lower()
    mapping = {
        "very low": 0.05,
        "low": 0.25,
        "medium": 0.50,
        "high": 0.70,
        "critical": 1.00,
    }
    return mapping.get(level_key, 0.50)


def _map_exploit_to_normalized(exploit_available: Any) -> float:
    return 0.60 if _to_bool(exploit_available) else 0.10


def _map_patch_to_normalized(patch_status: Any) -> float:
    # Best guess based on your current file:
    # patch_status == 1 appears to mean "patch exists / available"
    raw = _to_float(patch_status, 0.0)

    if raw >= 1:
        return 0.70
    if raw > 0:
        return 0.50
    return 1.00


def _map_role_to_normalized(role: str) -> float:
    role_key = (role or "").strip().lower()

    if any(x in role_key for x in ["domain controller", "identity", "vpn", "email server"]):
        return 0.90
    if any(x in role_key for x in ["dns server", "web server", "file server", "application server"]):
        return 0.60
    if "security" in role_key or "backup" in role_key:
        return 1.00
    if "workstation" in role_key:
        return 0.35

    return 0.20


def _map_cia_to_normalized(cia_rating: str) -> float:
    rating = (cia_rating or "").strip().lower()
    mapping = {
        "critical": 1.00,
        "high": 0.80,
        "medium": 0.50,
        "low": 0.20,
    }
    return mapping.get(rating, 0.20)


def _map_cia_to_numeric_weight(cia_rating: str) -> int:
    rating = (cia_rating or "").strip().lower()

    mapping = {
        "critical": 9,
        "high": 8,
        "medium": 6,
        "low": 3,
    }

    return mapping.get(rating, 3)  # default = low

def _compute_likelihood_score(record: dict) -> float:
    cvss_n = _clamp(_to_float(record.get("cvss_score"), 0.0) / 10.0)
    exploit_n = _clamp(_map_exploit_to_normalized(record.get("exploit_available")))
    patch_n = _clamp(_map_patch_to_normalized(record.get("patch_status")))
    exposure_level = _infer_exposure_level(record)
    exposure_n = _clamp(_map_exposure_to_normalized(exposure_level))
    role_n = _clamp(_map_role_to_normalized(str(record.get("role") or "")))
    cia_n = _clamp(_map_cia_to_normalized(str(record.get("CIA rating") or "")))
    ml_probability = max(_to_float(record.get("ml_probability"), 0.0), 0.0)

    weighted_sum = (
        0.20 * cvss_n +
        0.35 * exploit_n +
        0.15 * patch_n +
        0.15 * exposure_n +
        0.10 * role_n +
        0.05 * cia_n
    )

    likelihood_score = weighted_sum * (1.0 + ml_probability)
    return round(_clamp(likelihood_score, 0.0, 1.0), 4)


def _likelihood_label_from_score(score: float) -> str:
    # Your prompt says >=5.5 medium, but that is not possible for normalized likelihood.
    # Using >=0.55 instead.
    if score >= 0.90:
        return "Critical"
    if score >= 0.80:
        return "High"
    if score >= 0.55:
        return "Medium"
    return "Low"


def _compute_risk_score(record: dict, likelihood_score: float) -> float:
    cia_weight = _map_cia_to_numeric_weight(str(record.get("CIA rating") or ""))
    score = cia_weight * likelihood_score
    return round(score, 4)


def _risk_label_from_score(score: float) -> str:
    if score >= 8.5:
        return "Critical"
    if score >= 6.5:
        return "High"
    if score >= 3.5:
        return "Medium"
    return "Low"

def _enrich_record_with_likelihood_and_risk(record: dict) -> dict:
    out = dict(record)

    likelihood_score = _compute_likelihood_score(out)
    risk_score = _compute_risk_score(out, likelihood_score)

    out["likelihood_score"] = likelihood_score
    out["likelihood"] = _likelihood_label_from_score(likelihood_score)
    out["risk_score"] = risk_score
    out["risk"] = _risk_label_from_score(risk_score)
    out["exposure"] = _infer_exposure_level(out)

    return out


def _build_record_from_host_and_vuln(host_obj: dict, vuln_obj: dict, patch_status: int) -> dict:
    hostname = str(host_obj.get("hostname", "") or "")
    ip_address = _extract_ip_address(host_obj)
    role = _extract_role(host_obj)
    cia_rating = _extract_cia_rating(host_obj)

    vulnerability_name = str(
        vuln_obj.get("vulnerability_name")
        or vuln_obj.get("name")
        or ""
    )

    severity = str(vuln_obj.get("severity") or "")
    cvss_score = _to_float(vuln_obj.get("cvss_score"), 0.0)
    exploit_available = _to_bool(vuln_obj.get("exploit_available"))
    cve = str(vuln_obj.get("cve") or "")
    open_ports = _extract_open_ports(host_obj, vuln_obj)

    base_record = {
        "hostname": hostname,
        "ip_address": ip_address,
        "role": role,
        "CIA rating": cia_rating,
        "vulnerability_name": vulnerability_name,
        "severity": severity,
        "cvss_score": cvss_score,
        "exploit_available": exploit_available,
        "patch_status": patch_status,
        "cve": cve,
        "open_ports": open_ports,
        "ml_probability": _to_float(vuln_obj.get("ml_probability", host_obj.get("ml_probability", 0.3)), 0.3),
        "override": 0,
        "likelihood": "Unscanned",
        "risk": "Unscanned",
    }

    return _enrich_record_with_likelihood_and_risk(base_record)


def _build_risk_inventory_from_asset_vulnerabilities(year: int) -> dict:
    path = _asset_vuln_file(year)
    if not path.exists():
        raise FileNotFoundError("AssetVulnerabilitiesThreats.json was not found.")

    source = _load_json(path)
    source_hosts = _source_hosts_from_asset_vuln_doc(source)
    patch_status = _patch_status_from_controls(year)

    output_hosts: list[dict] = []

    for host_obj in source_hosts:
        vulnerabilities = _host_vulnerability_entries(host_obj)
        for vuln_obj in vulnerabilities:
            output_hosts.append(
                _build_record_from_host_and_vuln(host_obj, vuln_obj, patch_status)
            )

    return {"hosts": output_hosts}

def _train_user_behavior_model(dataset_path: Path, model_dir: Path) -> dict:
    feature_columns = [
        "failedLoginAttempts",
        "accessFrequency",
        "loginConsistency",
        "passwordResets",
        "sessionDuration",
    ]
    target_column = "risk_level"

    if not dataset_path.exists():
        raise FileNotFoundError(f"Training dataset not found: {dataset_path}")

    df = pd.read_parquet(dataset_path)

    required_columns = feature_columns + [target_column]
    missing_columns = [c for c in required_columns if c not in df.columns]
    if missing_columns:
        raise ValueError(
            "Dataset is missing required columns: " + ", ".join(missing_columns)
        )

    df = df[required_columns].copy()

    for col in feature_columns:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    df = df.dropna(subset=[target_column]).copy()

    if len(df) < 2:
        raise ValueError("Dataset does not contain enough rows to train a model.")

    X = df[feature_columns].copy()
    y = df[target_column].astype(str).copy()

    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)

    if len(set(y_encoded)) < 2:
        raise ValueError("Training requires at least two target classes in risk_level.")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y_encoded,
        test_size=0.2,
        random_state=42,
        stratify=y_encoded,
    )

    preprocessor = ColumnTransformer([
        ("num", SimpleImputer(strategy="median"), feature_columns)
    ])

    model = RandomForestClassifier(
        n_estimators=400,
        max_depth=10,
        random_state=42,
        n_jobs=1,
    )

    pipeline = Pipeline([
        ("preprocessor", preprocessor),
        ("model", model),
    ])

    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)

    accuracy = float(accuracy_score(y_test, y_pred))

    report = classification_report(
        y_test,
        y_pred,
        target_names=label_encoder.classes_,
        output_dict=True,
        zero_division=0,
    )

    cm = confusion_matrix(y_test, y_pred).tolist()

    importances = pipeline.named_steps["model"].feature_importances_
    feature_importance = [
        {"feature": feature, "importance": float(importance)}
        for feature, importance in sorted(
            zip(feature_columns, importances),
            key=lambda x: x[1],
            reverse=True,
        )
    ]

    model_dir.mkdir(parents=True, exist_ok=True)

    model_path = model_dir / "rf_behavior_model.joblib" 
    label_encoder_path = model_dir / "label_encoder.joblib"

    joblib.dump(pipeline, model_path)
    joblib.dump(label_encoder, label_encoder_path)

    predicted_labels = label_encoder.inverse_transform(y_pred)
    ml_probability = y_proba.max(axis=1)

    sample_predictions = []
    for i in range(min(5, len(predicted_labels))):
        class_probs = {
            cls: float(prob)
            for cls, prob in zip(label_encoder.classes_, y_proba[i])
        }
        sample_predictions.append({
            "predicted_risk_level": str(predicted_labels[i]),
            "ml_probability": float(ml_probability[i]),
            "class_probabilities": class_probs,
        })
        
    return {
        "success": True,
        "message": "User behavior model trained successfully.",
        "dataset_path": str(dataset_path),
        "model_path": str(model_path),
        "label_encoder_path": str(label_encoder_path),
        "accuracy": accuracy,
        "classification_report": report,
        "confusion_matrix": cm,
        "feature_importance": feature_importance,
        "sample_predictions": sample_predictions,
    }
    
@router.get("/inventory")
def get_risk_inventory(year: int = Query(2026)):
    return _load_risk_inventory_or_blank(int(year))


@router.post("/inventory/new")
def create_new_risk_inventory(
    year: int = Query(2026),
    force: bool = Query(False),
):
    year = int(year)

    if not _has_submitted_scope_document():
        return {
            "success": False,
            "message": "Submit the Scope & Context document first before starting Risk Analysis.",
            "inventory": _blank_risk_inventory(),
        }

    current = _load_risk_inventory_or_blank(year)

    if len(_all_hosts(current)) > 0 and not force:
        return {
            "success": False,
            "message": "RiskAnalysis.json already exists and contains data. Pass force=true to replace it.",
            "inventory": current,
        }

    new_doc = {"hosts": []}

    _save_json(_risk_analysis_file(year), new_doc)
    _set_risk_analysis_status(year, "Not Started")

    return {
        "success": True,
        "message": "RiskAnalysis.json created successfully.",
        "inventory": new_doc,
    }


@router.post("/analysis")
def run_risk_analysis(payload: AnalysisRequest):
    year = int(payload.year or 2026)

    current = _load_risk_inventory_or_blank(year)
    auto_train_message = ""

    if not _has_submitted_scope_document():
        return {
            "success": False,
            "message": "Submit the Scope & Context document first before starting Risk Analysis.",
            "inventory": current,
        }

    if _risk_analysis_is_read_only(year):
        return {
            "success": False,
            "message": "Risk analysis has already been submitted and is now read-only.",
            "inventory": current,
        }

    try:
        auto_trained, auto_train_message = _ensure_behavior_model_ready(year)
        risk_inventory = _build_risk_inventory_from_asset_vulnerabilities(year)
        
        risk_inventory = _remove_existing_user_behavior_risks(risk_inventory)
        risk_inventory = _append_user_behavior_risks(year, risk_inventory)
    except FileNotFoundError as e:
        return {
            "success": False,
            "message": str(e),
            "inventory": current,
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Risk analysis failed: {e}",
            "inventory": current,
        }

    if len(_all_hosts(risk_inventory)) == 0:
        return {
            "success": False,
            "message": "No risk records were generated.",
            "inventory": current,
        }

    _save_json(_risk_analysis_file(year), risk_inventory)
    _set_risk_analysis_status(year, "In Progress")
    behavior_events = _build_behavior_prediction_telemetry_events(
        risk_inventory,
        source_endpoint="/api/risk-analysis/analysis",
    )
    _safe_append_aiml_kpi_events(year, "behavior_prediction_events", behavior_events)

    return {
        "success": True,
        "message": (
            f"{auto_train_message}\nRisk analysis completed successfully."
            if auto_train_message
            else "Risk analysis completed successfully."
        ),
        "processed_hosts": len(_all_hosts(risk_inventory)),
        "aiml_kpi_events_appended": len(behavior_events),
        "auto_trained_model": bool(auto_train_message),
        "inventory": risk_inventory,
    }
    
@router.post("/setrisk")
def set_risk(payload: SetRiskRequest):
    year = int(payload.year or 2026)

    inventory = _load_risk_inventory_or_blank(year)

    if _risk_analysis_is_read_only(year):
        return {
            "success": False,
            "message": "Risk analysis has already been submitted and is now read-only.",
            "inventory": inventory,
        }

    normalized_risk = _normalize_risk(payload.risk)
    if normalized_risk not in {"High", "Medium", "Low"}:
        return {
            "success": False,
            "message": "Invalid risk value. Allowed values are High, Medium, or Low.",
            "inventory": inventory,
        }

    idx, record = _find_risk_record_by_hostname_and_cve(
        inventory,
        payload.hostname,
        payload.cve,
    )

    if record is None or idx is None:
        return {
            "success": False,
            "message": f"Risk record not found for host '{payload.hostname}' and CVE '{payload.cve}'.",
            "inventory": inventory,
        }

    old_risk = str(record.get("risk", "")).strip()

    record["risk"] = normalized_risk
    record["override"] = 1 if old_risk != normalized_risk else 0

    hosts = inventory.get("hosts", [])
    if isinstance(hosts, list):
        hosts[idx] = record
        inventory["hosts"] = hosts

    _save_json(_risk_analysis_file(year), inventory)
    _sync_risk_analysis_status(year, inventory)
    if old_risk != normalized_risk:
        safe_increment_manual_correction_counter(year, "risk")

    return {
        "success": True,
        "message": (
            f"Risk updated for {payload.hostname} / {payload.cve}. "
            f"Old Risk: {old_risk or 'NA'} | New Risk: {normalized_risk}"
        ),
        "hostname": payload.hostname,
        "cve": payload.cve,
        "risk": normalized_risk,
        "inventory": inventory,
    }

@router.post("/delete")
def delete_risk_record(payload: DeleteRequest):
    year = int(payload.year or 2026)

    inventory = _load_risk_inventory_or_blank(year)

    if _risk_analysis_is_read_only(year):
        return {
            "success": False,
            "message": "Risk analysis has already been submitted and is now read-only.",
            "inventory": inventory,
        }

    hosts = inventory.get("hosts", [])
    if not isinstance(hosts, list) or len(hosts) == 0:
        return {
            "success": False,
            "message": "No records found to delete.",
            "inventory": inventory,
        }

    idx, record = _find_risk_record_by_hostname_and_cve(
        inventory,
        payload.hostname,
        payload.cve,
    )

    if record is None or idx is None:
        return {
            "success": False,
            "message": f"Record not found for host '{payload.hostname}' and CVE '{payload.cve}'.",
            "inventory": inventory,
        }

    deleted_record = hosts.pop(idx)
    inventory["hosts"] = hosts

    _save_json(_risk_analysis_file(year), inventory)

    _sync_risk_analysis_status(year, inventory)

    return {
        "success": True,
        "message": (
            f"Deleted record:\n"
            f"Host: {deleted_record.get('hostname')}\n"
            f"CVE: {deleted_record.get('cve')}"
        ),
        "hostname": deleted_record.get("hostname"),
        "cve": deleted_record.get("cve"),
        "inventory": inventory,
    }

@router.post("/train")
def train_user_behavior_model(payload: TrainRequest):
    year = int(payload.year or 2026)
    try:
        dataset_path = (
            Path(payload.dataset_path)
            if payload.dataset_path
            else _default_behavior_dataset_path()
        )

        model_dir = (
            Path(payload.model_dir)
            if payload.model_dir
            else _ml_models_dir()
        )

        if not dataset_path.is_absolute():
            dataset_path = BASE_DIR / dataset_path

        if not model_dir.is_absolute():
            model_dir = BASE_DIR / model_dir

        result = _train_user_behavior_model(dataset_path, model_dir)
        _record_behavior_training_telemetry(year, result, "/api/risk-analysis/train")
        return result

    except Exception as e:
        return {
            "success": False,
            "message": f"Training failed: {e}",
            "dataset_path": str(dataset_path) if 'dataset_path' in locals() else None,
            "model_path": None,
            "label_encoder_path": None,
            "accuracy": None,
        }


@router.post("/collect-uab")
def collect_user_activity_behavior(payload: AnalysisRequest):
    year = int(payload.year or 2026)

    try:
        result = merge_many_hosts(retention_days=30)
        collected_hosts = sum(
            1
            for host_result in result.get("hosts", [])
            if str(host_result.get("status", "")).strip().lower() == "ok"
        )
        live_fallback_hosts = [
            host_result.get("hostname", "")
            for host_result in result.get("hosts", [])
            if str(host_result.get("status", "")).strip().lower() == "populated_from_assetdetails_live_host"
        ]
        unreachable_fallback_hosts = [
            host_result.get("hostname", "")
            for host_result in result.get("hosts", [])
            if str(host_result.get("status", "")).strip().lower() == "populated_from_assetdetails_unreachable_host"
        ]
        unreachable_hosts = [
            host_result.get("hostname", "")
            for host_result in result.get("hosts", [])
            if str(host_result.get("status", "")).strip().lower() == "unreachable"
        ]
        live_non_workstation_targets = [
            target.get("hostname", "")
            for target in result.get("non_workstation_targets", [])
            if bool(target.get("reachable"))
        ]
        populated_hosts = len(result.get("backfilled_hosts", []))
        live_detected_hosts = live_fallback_hosts + [
            host_result.get("hostname", "")
            for host_result in result.get("hosts", [])
            if str(host_result.get("status", "")).strip().lower() == "ok"
        ]

        lines = ["User activity behavior data collection completed."]

        if live_detected_hosts:
            lines.append("Live workstation hosts detected:")
            lines.extend(f"- {hostname}" for hostname in live_detected_hosts if str(hostname).strip())

        if live_non_workstation_targets:
            lines.append("Live non-workstation lab hosts detected (outside UAB scope):")
            lines.extend(f"- {hostname}" for hostname in live_non_workstation_targets if str(hostname).strip())

        if collected_hosts > 0:
            lines.append(f"Direct live behavior records collected from {collected_hosts} workstation host(s).")
        else:
            lines.append("Direct live behavior records collected from 0 workstation host(s).")

        if live_fallback_hosts:
            lines.append("Live workstation hosts populated from AssetDetails because direct behavior-file access failed:")
            lines.extend(f"- {hostname}" for hostname in live_fallback_hosts if str(hostname).strip())

        if unreachable_fallback_hosts:
            lines.append("Configured workstation hosts populated from AssetDetails after reachability checks failed:")
            lines.extend(f"- {hostname}" for hostname in unreachable_fallback_hosts if str(hostname).strip())

        if unreachable_hosts:
            lines.append("Configured workstation hosts unreachable and not populated:")
            lines.extend(f"- {hostname}" for hostname in unreachable_hosts if str(hostname).strip())

        if not live_detected_hosts and populated_hosts <= 0 and not unreachable_hosts:
            lines.append("No workstation records were collected or populated.")

        message = "\n".join(lines)

        return {
            "success": True,
            "message": message,
            "year": year,
            "total_records": result.get("total_records", 0),
            "collected_hosts": collected_hosts,
            "populated_hosts": populated_hosts,
            "live_detected_hosts": len(live_detected_hosts),
            "live_fallback_hosts": live_fallback_hosts,
            "live_non_workstation_targets": live_non_workstation_targets,
            "unreachable_hosts": unreachable_hosts,
            "details": result,
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"User activity behavior data collection failed: {e}",
            "year": year,
        }


@router.post("/submit")
def submit_risk_analysis(payload: SubmitRequest):
    year = int(payload.year or 2026)

    inventory = _load_risk_inventory_or_blank(year)

    # 1. Ask confirmation first
    if not payload.confirm:
        return {
            "success": True,
            "requires_confirmation": True,
            "message": "The risk analysis results will be finalized, are you sure?"
        }

    # 2. Validate data exists
    if len(_all_hosts(inventory)) == 0:
        return {
            "success": False,
            "message": "RiskAnalysis.json is empty. Run /analysis first.",
            "inventory": inventory,
        }

    # 3. Retrain the user behavior model again before finalizing
    try:
        training_result = _train_user_behavior_model(
            _default_behavior_dataset_path(),
            _ml_models_dir(),
        )
        _record_behavior_training_telemetry(year, training_result, "/api/risk-analysis/submit")
    except Exception as e:
        return {
            "success": False,
            "message": f"Risk analysis finalization failed during model retraining: {e}",
            "inventory": inventory,
        }

    # 4. Build RiskEvaluationTreatment.json
    risk_eval_doc = _build_risk_evaluation_treatment(inventory)

    _save_json(_risk_eval_treatment_file(year), risk_eval_doc)

    # 5. Update system status
    status_doc = _load_system_status_or_default(year)

    status_doc["sections"]["risk_analysis"]["status"] = "Completed"
    status_doc["sections"]["risk_evaluation_treatment"]["status"] = "In Progress"

    _save_json(_system_status_file(year), status_doc)

    return {
        "success": True,
        "message": "User behavior model retrained successfully.\nRisk analysis finalized.",
        "records_created": len(risk_eval_doc["hosts"])
    }
