from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Literal
import json
import os
import re
import tempfile

from fastapi import APIRouter, Query

router = APIRouter(prefix="/api/system", tags=["system"])

StepStatus = Literal["Not Started", "In Progress", "Completed"]


def project_root() -> Path:
    current = Path(__file__).resolve()
    for parent in [current] + list(current.parents):
        if (parent / "data" / "work").exists():
            return parent
    raise RuntimeError("Could not find project root containing data/work")


BASE_DIR = project_root()


def get_system_year() -> int:
    work_dir = BASE_DIR / "data" / "work"
    years = [int(p.name) for p in work_dir.iterdir() if p.is_dir() and p.name.isdigit()]
    if not years:
        raise RuntimeError("No audit year folder found in data/work")
    return max(years)


def _work_dir(year: int | None = None) -> Path:
    return BASE_DIR / "data" / "work" / str(year if year is not None else get_system_year())


def _system_status_file(year: int | None = None) -> Path:
    return _work_dir(year) / "SystemStatus.json"


def _dashboard_file() -> Path:
    return BASE_DIR / "data" / "raw" / "dashboard.json"


def _asset_inventory_file(year: int) -> Path:
    return _work_dir(year) / "AssetInventory.json"


def _threats_file(year: int) -> Path:
    return _work_dir(year) / "AssetVulnerabilitiesThreats.json"


def _controls_postures_file(year: int) -> Path:
    return _work_dir(year) / "ExistingControlsPostures.json"


def _risk_analysis_file(year: int) -> Path:
    return _work_dir(year) / "RiskAnalysis.json"


def _risk_evaluation_file(year: int) -> Path:
    return _work_dir(year) / "RiskEvaluationTreatment.json"


def _annex_soa_file(year: int) -> Path:
    return _work_dir(year) / "AnnexA_SoA.json"


def _action_plan_file(year: int) -> Path:
    return _work_dir(year) / "ActionPlanImplementation.json"


def _monitoring_file(year: int) -> Path:
    return _work_dir(year) / "MonitoringImprovement.json"


DEFAULT_SECTIONS: Dict[str, Dict[str, Any]] = {
    "scope_context": {"status": "Not Started", "scope_file_name": "2026-Scope-Draft-v0.json"},
    "assets_cia": {"status": "Not Started"},
    "threats_vulns": {"status": "Not Started"},
    "existing_controls_postures": {"status": "Not Started"},
    "risk_analysis": {"status": "Not Started"},
    "risk_evaluation_treatment": {"status": "Not Started"},
    "annex_a_soa": {"status": "Not Started"},
    "action_plan_implementation": {"status": "Not Started"},
    "monitoring_improvement": {"status": "Not Started"},
    "reports": {"status": "Not Started"},
    "controls_posture": {"status": "Not Started"},
    "risk_evaluation": {"status": "Not Started"},
    "risk_treatment": {"status": "Not Started"},
    "soa": {"status": "Not Started"},
    "action_plan": {"status": "Not Started"},
    "monitoring": {"status": "Not Started"},
}


def _atomic_write_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.stem + "_", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, ensure_ascii=False)
        os.replace(tmp, path)
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass


def _default_status(year: int) -> Dict[str, Any]:
    sections = json.loads(json.dumps(DEFAULT_SECTIONS))
    sections["scope_context"]["scope_file_name"] = f"{year}-Scope-Draft-v0.json"
    return {
        "meta": {"name": "SystemStatus", "version": "1.0"},
        "updated_at": datetime.utcnow().isoformat() + "Z",
        "year": year,
        "sections": sections,
    }


def _read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        raw = path.read_text(encoding="utf-8")
        if not raw.strip():
            return default
        return json.loads(raw)
    except Exception:
        return default


def _normalize_text(value: Any) -> str:
    return str(value or "").strip()


def _has_submitted_scope_document(year: int) -> bool:
    dashboard = _read_json(_dashboard_file(), {})
    scope_file_name = str((dashboard or {}).get("scope_file_name") or "").strip().lower()
    return bool(scope_file_name) and re.search(r"-v0\.json$", scope_file_name) is None


def _asset_inventory_status_from_file(year: int) -> str:
    raw = _read_json(_asset_inventory_file(year), {})
    if not isinstance(raw, dict):
        return "Not Started"

    meta = raw.get("meta", {})
    if isinstance(meta, dict) and (meta.get("submitted") or meta.get("read_only")):
        return "Completed"

    subnets = raw.get("subnets", []) if isinstance(raw, dict) else []
    for subnet in subnets if isinstance(subnets, list) else []:
        assets = subnet.get("assets", []) if isinstance(subnet, dict) else []
        if isinstance(assets, list) and assets:
            return "In Progress"
    return "Not Started"


def _threats_status_from_file(year: int) -> str:
    raw = _read_json(_threats_file(year), {})
    if not isinstance(raw, dict):
        return "Not Started"

    meta = raw.get("meta", {})
    if isinstance(meta, dict) and (meta.get("submitted") or meta.get("read_only")):
        return "Completed"

    hosts = raw.get("hosts", []) if isinstance(raw, dict) else []
    if not isinstance(hosts, list) or not hosts:
        return "Not Started"
    for host in hosts:
        items = host.get("vulnerabilities_threats", []) if isinstance(host, dict) else []
        if isinstance(items, list) and items:
            return "In Progress"
    return "In Progress"


def _controls_status_from_file(year: int) -> str:
    raw = _read_json(_controls_postures_file(year), {})
    if not isinstance(raw, dict):
        return "Not Started"

    explicit_status = str(raw.get("status") or "").strip()
    if explicit_status == "Completed":
        return "Completed"

    meta = raw.get("meta", {})
    if isinstance(meta, dict) and (meta.get("submitted") or meta.get("read_only")):
        return "Completed"

    if explicit_status == "In Progress":
        return "In Progress"

    if explicit_status == "Not Started":
        return "Not Started"

    hosts = raw.get("hosts", []) if isinstance(raw, dict) else []
    if not isinstance(hosts, list) or not hosts:
        return "Not Started"
    for host in hosts:
        if not isinstance(host, dict):
            continue
        controls = host.get("existing_controls", {})
        if isinstance(controls, dict) and any(isinstance(values, list) and values for values in controls.values()):
            return "In Progress"
        if isinstance(controls, list) and controls:
            return "In Progress"
    return "In Progress"


def _risk_analysis_status_from_file(year: int) -> str:
    raw = _read_json(_risk_analysis_file(year), {})
    if not isinstance(raw, dict):
        return "Not Started"

    explicit_status = str(raw.get("status") or "").strip()
    if explicit_status == "Completed":
        return "Completed"

    meta = raw.get("meta", {})
    if isinstance(meta, dict) and (meta.get("submitted") or meta.get("read_only")):
        return "Completed"

    if explicit_status == "In Progress":
        return "In Progress"

    if explicit_status == "Not Started":
        return "Not Started"

    hosts = raw.get("hosts", [])
    return "In Progress" if isinstance(hosts, list) and hosts else "Not Started"


def _risk_evaluation_status_from_file(year: int) -> str:
    raw = _read_json(_risk_evaluation_file(year), {})
    if not isinstance(raw, dict):
        return "Not Started"

    explicit_status = str(raw.get("status") or "").strip()
    if explicit_status == "Completed":
        return "Completed"

    meta = raw.get("meta", {})
    if isinstance(meta, dict) and (meta.get("submitted") or meta.get("read_only")):
        return "Completed"

    if explicit_status == "In Progress":
        return "In Progress"

    if explicit_status == "Not Started":
        return "Not Started"

    hosts = raw.get("hosts", [])
    return "In Progress" if isinstance(hosts, list) and hosts else "Not Started"


def _annex_status_from_file(year: int) -> str:
    raw = _read_json(_annex_soa_file(year), {})
    if not isinstance(raw, dict):
        return "Not Started"

    explicit_status = str(raw.get("status") or "").strip()
    if explicit_status == "Completed":
        return "Completed"

    meta = raw.get("meta", {})
    if isinstance(meta, dict) and (meta.get("submitted") or meta.get("read_only")):
        return "Completed"

    if explicit_status == "In Progress":
        return "In Progress"

    if explicit_status == "Not Started":
        return "Not Started"

    controls = raw.get("controls", [])
    return "In Progress" if isinstance(controls, list) and controls else "Not Started"


def _action_plan_status_from_file(year: int) -> str:
    raw = _read_json(_action_plan_file(year), {})
    if not isinstance(raw, dict):
        return "Not Started"

    explicit_status = str(raw.get("status") or "").strip()
    if explicit_status == "Completed":
        return "Completed"

    meta = raw.get("meta", {})
    if isinstance(meta, dict) and (meta.get("submitted") or meta.get("read_only")):
        return "Completed"

    if explicit_status == "In Progress":
        return "In Progress"

    if explicit_status == "Not Started":
        return "Not Started"

    controls = raw.get("controls", [])
    return "In Progress" if isinstance(controls, list) and controls else "Not Started"


def _monitoring_status_from_file(year: int) -> str:
    raw = _read_json(_monitoring_file(year), {})
    if not isinstance(raw, dict):
        return "Not Started"
    explicit_status = _normalize_text(raw.get("status"))
    if explicit_status == "Completed":
        return "Completed"
    meta = raw.get("meta", {})
    if isinstance(meta, dict) and (meta.get("submitted") or meta.get("read_only")):
        return "Completed"
    if explicit_status == "In Progress":
        return "In Progress"
    if explicit_status == "Not Started":
        return "Not Started"
    controls = raw.get("controls", [])
    if isinstance(controls, list) and controls:
        return "In Progress"
    cves = raw.get("cves", [])
    if isinstance(cves, list) and cves:
        return "In Progress"
    hosts = raw.get("hosts", [])
    if isinstance(hosts, list) and hosts:
        return "In Progress"
    return "Not Started"


def _reports_status_from_artifacts(year: int) -> str:
    if _action_plan_status_from_file(year) != "Not Started" and _monitoring_status_from_file(year) != "Not Started":
        return "In Progress"
    return "Not Started"


def _sync_status_from_artifacts(data: Dict[str, Any], year: int) -> Dict[str, Any]:
    sections = data.get("sections")
    if not isinstance(sections, dict):
        sections = {}
        data["sections"] = sections

    synced = {
        "scope_context": "Completed" if _has_submitted_scope_document(year) else "Not Started",
        "assets_cia": _asset_inventory_status_from_file(year),
        "threats_vulns": _threats_status_from_file(year),
        "existing_controls_postures": _controls_status_from_file(year),
        "risk_analysis": _risk_analysis_status_from_file(year),
        "risk_evaluation_treatment": _risk_evaluation_status_from_file(year),
        "annex_a_soa": _annex_status_from_file(year),
        "action_plan_implementation": _action_plan_status_from_file(year),
        "monitoring_improvement": _monitoring_status_from_file(year),
        "reports": _reports_status_from_artifacts(year),
    }

    aliases = {
        "controls_posture": synced["existing_controls_postures"],
        "risk_evaluation": synced["risk_evaluation_treatment"],
        "risk_treatment": synced["risk_evaluation_treatment"],
        "soa": synced["annex_a_soa"],
        "action_plan": synced["action_plan_implementation"],
        "monitoring": synced["monitoring_improvement"],
    }

    for key, status in {**synced, **aliases}.items():
        section = sections.get(key)
        if not isinstance(section, dict):
            section = {}
            sections[key] = section
        section["status"] = status

    scope_section = sections.get("scope_context")
    if isinstance(scope_section, dict):
        dashboard = _read_json(_dashboard_file(), {})
        scope_section["scope_file_name"] = (
            str((dashboard or {}).get("scope_file_name") or "")
            if synced["scope_context"] == "Completed"
            else f"{year}-Scope-Draft-v0.json"
        )

    data["sections"] = sections
    data["updated_at"] = datetime.utcnow().isoformat() + "Z"
    return data


def _load_status(year: int) -> Dict[str, Any]:
    path = _system_status_file(year)
    data = _default_status(year)

    if not path.exists():
        _atomic_write_json(path, data)
        return data

    raw = path.read_text(encoding="utf-8")
    if not raw.strip():
        _atomic_write_json(path, data)
        return data

    try:
        return json.loads(raw)
    except Exception:
        # System status is derived from project artifacts, so recover from a
        # blank/corrupt file instead of surfacing a blocking 500 in the UI.
        _atomic_write_json(path, data)
        return data


def _normalize_status(data: Dict[str, Any], year: int) -> Dict[str, Any]:
    allowed = {"Not Started", "In Progress", "Completed"}

    if not isinstance(data.get("meta"), dict):
        data["meta"] = {"name": "SystemStatus", "version": "1.0"}

    sections = data.get("sections")
    if not isinstance(sections, dict):
        sections = {}

    defaults = json.loads(json.dumps(DEFAULT_SECTIONS))
    defaults["scope_context"]["scope_file_name"] = f"{year}-Scope-Draft-v0.json"

    for key, value in defaults.items():
        if key not in sections or not isinstance(sections.get(key), dict):
            sections[key] = dict(value)
        else:
            for default_key, default_value in value.items():
                sections[key].setdefault(default_key, default_value)

    for key, value in list(sections.items()):
        if not isinstance(value, dict):
            sections[key] = {"status": "Not Started"}
            continue
        status = value.get("status")
        value["status"] = status if status in allowed else "Not Started"
        sections[key] = value

    data["sections"] = sections
    data["year"] = year
    data.setdefault("updated_at", datetime.utcnow().isoformat() + "Z")
    return data


@router.get("/status")
def get_status(year: int = Query(2026)) -> Dict[str, Any]:
    data = _normalize_status(_load_status(year), year)
    data = _sync_status_from_artifacts(data, year)
    _atomic_write_json(_system_status_file(year), data)
    data["_debug_path"] = str(_system_status_file(year))
    return data


@router.post("/reset-audit")
def reset_audit(year: int = Query(2026)) -> Dict[str, Any]:
    data = _default_status(year)
    _atomic_write_json(_system_status_file(year), data)
    return data
