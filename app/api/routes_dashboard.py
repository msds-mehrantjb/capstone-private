from fastapi import APIRouter, Query
from pydantic import BaseModel
from pathlib import Path
from typing import Any
import json

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


class ResetAuditRequest(BaseModel):
    year: int | None = None


def find_project_root() -> Path:
    current = Path(__file__).resolve()
    for parent in [current] + list(current.parents):
        if (parent / "data").exists():
            return parent
    raise RuntimeError("Could not find project root containing data")


BASE_DIR = find_project_root()


def _dashboard_file() -> Path:
    return BASE_DIR / "data" / "raw" / "dashboard.json"


def get_system_year() -> int:
    work_dir = BASE_DIR / "data" / "work"

    if not work_dir.exists():
        raise RuntimeError("data/work directory not found")

    years = [
        int(p.name)
        for p in work_dir.iterdir()
        if p.is_dir() and p.name.isdigit()
    ]

    if not years:
        raise RuntimeError("No audit year folder found in data/work")

    return max(years)


def _work_dir(year: int | None = None) -> Path:
    if year is None:
        year = get_system_year()
    return BASE_DIR / "data" / "work" / str(year)


def _system_status_file(year: int | None = None) -> Path:
    return _work_dir(year) / "SystemStatus.json"


def _read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def _get_scope_status(year: int | None = None) -> str:
    path = _system_status_file(year)

    data = _read_json(path, {})
    if not isinstance(data, dict):
        return "Not Started"

    sections = data.get("sections")
    if not isinstance(sections, dict):
        return "Not Started"

    scope_context = sections.get("scope_context")
    if not isinstance(scope_context, dict):
        return "Not Started"

    return str(scope_context.get("status", "Not Started"))


def _set_scope_status(year: int | None, status: str) -> None:
    path = _system_status_file(year)

    data = _read_json(path, None)
    if not isinstance(data, dict):
        raise ValueError(f"Invalid SystemStatus.json structure: {path}")

    sections = data.get("sections")
    if not isinstance(sections, dict):
        raise ValueError(f"SystemStatus.json missing 'sections': {path}")

    if "scope_context" not in sections or not isinstance(sections["scope_context"], dict):
        raise ValueError(f"SystemStatus.json missing 'sections.scope_context': {path}")

    sections["scope_context"]["status"] = status
    _write_json(path, data)


# =========================================================
# KPI HELPERS
# =========================================================
def _asset_inventory_file(year: int) -> Path:
    return _work_dir(year) / "AssetInventoryCIA.json"


def _threats_vulns_file(year: int) -> Path:
    return _work_dir(year) / "ThreatsVulnerabilities.json"


def _controls_posture_file(year: int) -> Path:
    return _work_dir(year) / "ExistingControlsPosture.json"


def _risk_analysis_file(year: int) -> Path:
    return _work_dir(year) / "RiskAnalysis.json"


def _risk_evaluation_treatment_file(year: int) -> Path:
    return _work_dir(year) / "RiskEvaluationTreatment.json"


def _annex_a_soa_file(year: int) -> Path:
    return _work_dir(year) / "AnnexA_SoA.json"


def _action_plan_implementation_file(year: int) -> Path:
    return _work_dir(year) / "ActionPlanImplementation.json"


def _monitoring_improvement_file(year: int) -> Path:
    return _work_dir(year) / "MonitoringImprovement.json"


def _safe_list(value: Any) -> list:
    return value if isinstance(value, list) else []


def _count_rows(doc: Any, top_key: str) -> int:
    if not isinstance(doc, dict):
        return 0
    return len([x for x in _safe_list(doc.get(top_key)) if isinstance(x, dict)])


def _scope_exists(scope_file_name: str) -> bool:
    value = str(scope_file_name or "").strip().lower()
    if not value:
        return False
    return "v0" not in value


def _build_evidence_coverage(action_plan_doc: dict) -> dict:
    controls = action_plan_doc.get("controls", [])

    total_controls = len(controls)
    controls_with_evidence = 0

    total_hosts = 0
    hosts_with_evidence = 0

    for control in controls:
        hosts = control.get("hosts", [])

        control_has_evidence = False

        for host in hosts:
            total_hosts += 1

            evidence = host.get("evidence", [])
            if isinstance(evidence, list) and len(evidence) > 0:
                hosts_with_evidence += 1
                control_has_evidence = True

        if control_has_evidence:
            controls_with_evidence += 1

    percent = (
        (hosts_with_evidence / total_hosts) * 100
        if total_hosts > 0
        else 0
    )

    return {
        "percent": round(percent, 1),
        "have": controls_with_evidence,
        "total": total_controls,
    }

def _build_readiness_score(data: dict, year: int) -> dict:
    scope_file_name = str(data.get("scope_file_name", "") or "").strip()

    asset_doc = _read_json(_asset_inventory_file(year), {})
    threats_doc = _read_json(_threats_vulns_file(year), {})
    controls_doc = _read_json(_controls_posture_file(year), {})
    risk_analysis_doc = _read_json(_risk_analysis_file(year), {})
    risk_eval_treatment_doc = _read_json(_risk_evaluation_treatment_file(year), {})
    annex_doc = _read_json(_annex_a_soa_file(year), {})
    action_plan_doc = _read_json(_action_plan_implementation_file(year), {})
    monitoring_doc = _read_json(_monitoring_improvement_file(year), {})

    score = 0

    if _scope_exists(scope_file_name):
        score += 5

    if _count_rows(asset_doc, "hosts") > 0:
        score += 10

    if _count_rows(threats_doc, "hosts") > 0:
        score += 10

    if _count_rows(controls_doc, "hosts") > 0:
        score += 5

    if _count_rows(risk_analysis_doc, "hosts") > 0:
        score += 10

    if _count_rows(risk_eval_treatment_doc, "hosts") > 0:
        score += 10

    if _count_rows(annex_doc, "controls") > 0:
        score += 10

    if _count_rows(action_plan_doc, "controls") > 0:
        score += 10

    if _count_rows(monitoring_doc, "cves") > 0:
        score += 10

    if score == 0:
        label = "Blocked"
    elif score < 80:
        label = "In Progress"
    else:
        label = "Completed"

    # normalize score to 100 scale
    normalized_score = int((score / 80) * 100)
    
    return {
        "value": normalized_score,
        "max": 100,
        "label": "In Progress" if normalized_score < 100 else "Completed",
        "delta_7d": 0,
    }

def _normalize_scope(scope: Any, year: int | None = None) -> dict:
    if not isinstance(scope, dict):
        scope = {}

    return {
        "name": scope.get("name", "NA"),
        "asset_count": scope.get("asset_count", 0),
        "status": _get_scope_status(year),
    }


def _normalize_section2(section2: Any) -> dict:
    if not isinstance(section2, dict):
        section2 = {}

    bullets = section2.get("bullets", [])
    if not isinstance(bullets, list):
        bullets = []

    normalized_bullets = [str(item).strip() for item in bullets if str(item).strip()]

    return {
        "title": section2.get(
            "title",
            "Scope & Context — Section 2 (Organizational Boundaries)",
        ),
        "bullets": normalized_bullets,
        "body": str(section2.get("body", "") or "").strip(),
    }


def _normalize_kpis(kpis: Any) -> dict:
    if not isinstance(kpis, dict):
        kpis = {}

    return {
        "readiness_score": kpis.get("readiness_score", {}),
        "evidence_coverage": kpis.get("evidence_coverage", {}),
        "open_high_critical": kpis.get("open_high_critical", {}),
        "soa": kpis.get("soa", {}),
    }

def _build_high_risk_critical_impact(year: int) -> dict:
    doc = _read_json(_risk_evaluation_treatment_file(year), {})

    hosts = doc.get("hosts", []) if isinstance(doc, dict) else []

    high_risk_count = 0
    critical_impact_count = 0

    for h in hosts:
        if not isinstance(h, dict):
            continue

        risk = str(h.get("risk", "")).strip()
        cia = str(h.get("CIA rating", "")).strip()

        if risk == "High":
            high_risk_count += 1

        if cia in ("Critical", "High"):
            critical_impact_count += 1

    return {
        "high_risk_count": high_risk_count,
        "critical_impact_count": critical_impact_count
    }

def _build_soa_status(year: int) -> dict:
    doc = _read_json(_annex_a_soa_file(year), {})

    controls = doc.get("controls", []) if isinstance(doc, dict) else []
    controls = [c for c in controls if isinstance(c, dict)]

    total_controls = len(controls)

    if total_controls == 0:
        return {
            "status": "Not Started",
            "count": 0,
        }

    all_defined = all(str(c.get("implementation_status", "")).strip() != "" for c in controls)

    if all_defined:
        return {
            "status": "Completed",
            "count": total_controls,
        }

    return {
        "status": "In Progress",
        "count": total_controls,
    }

def _normalize_dashboard_payload(
    data: Any,
    env: str = "Production",
    year: int | None = None,
) -> dict:
    if not isinstance(data, dict):
        data = {}

    blockers = data.get("blockers", [])
    if not isinstance(blockers, list):
        blockers = []

    scopes = data.get("scopes", [])
    if not isinstance(scopes, list):
        scopes = []

    resolved_year = year if year is not None else get_system_year()

    normalized_kpis = _normalize_kpis(data.get("kpis"))

    action_plan_doc = _read_json(_action_plan_implementation_file(resolved_year), {})

    normalized_kpis["evidence_coverage"] = _build_evidence_coverage(action_plan_doc)

    normalized_kpis["readiness_score"] = _build_readiness_score(data, resolved_year)

    normalized_kpis["soa"] = _build_soa_status(resolved_year)
    
    normalized_kpis["high_risk_critical_impact"] = _build_high_risk_critical_impact(resolved_year)

    return {
        "environment": data.get("environment", env),
        "year": resolved_year,
        "scope": _normalize_scope(data.get("scope"), resolved_year),
        "scope_context_section2": _normalize_section2(data.get("scope_context_section2")),
        "kpis": normalized_kpis,
        "blockers": blockers,
        "scopes": scopes,
        "scope_file_name": data.get("scope_file_name", ""),
        "system_status_file": str(_system_status_file(resolved_year)),
    }


@router.get("/system-year")
def get_system_year_api():
    year = get_system_year()
    return {
        "success": True,
        "year": year,
        "system_status_file": str(_system_status_file(year)),
    }


@router.get("/summary")
def get_dashboard_summary(
    env: str = Query("Production"),
    year: int | None = Query(None),
):
    resolved_year = year if year is not None else get_system_year()
    data = _read_json(_dashboard_file(), {})
    return _normalize_dashboard_payload(data, env, resolved_year)


@router.get("/raw")
def get_dashboard_raw(
    year: int | None = Query(None),
    env: str = Query("Production"),
):
    resolved_year = year if year is not None else get_system_year()
    data = _read_json(_dashboard_file(), {})
    return _normalize_dashboard_payload(data, env, resolved_year)


@router.post("/reset-audit")
def reset_audit(payload: ResetAuditRequest):
    year = payload.year if payload.year is not None else get_system_year()

    path = _dashboard_file()
    data = _read_json(path, {})

    if not isinstance(data, dict):
        data = {}

    base_scope_file = f"{year}-Scope-Draft-v0.json"

    scope = data.get("scope", {})
    if not isinstance(scope, dict):
        scope = {}

    scope["name"] = "NA"
    scope["asset_count"] = 0
    data["scope"] = scope

    data["scope_file_name"] = base_scope_file

    section2 = data.get("scope_context_section2", {})
    if not isinstance(section2, dict):
        section2 = {}

    section2["title"] = section2.get(
        "title",
        "Scope & Context — Section 2 (Organizational Boundaries)",
    )
    section2["bullets"] = []
    section2["body"] = ""
    data["scope_context_section2"] = section2

    _write_json(path, data)
    _set_scope_status(year, "Not Started")

    return _normalize_dashboard_payload(data, "Production", year)