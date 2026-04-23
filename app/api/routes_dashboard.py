from fastapi import APIRouter, Query
from pydantic import BaseModel
from pathlib import Path
from typing import Any
from datetime import datetime
from copy import deepcopy
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


SYSTEM_STATUS_SECTION_KEYS = (
    "scope_context",
    "assets_cia",
    "threats_vulns",
    "existing_controls_postures",
    "risk_analysis",
    "risk_evaluation_treatment",
    "annex_a_soa",
    "action_plan_implementation",
    "monitoring_improvement",
    "controls_posture",
)


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
    return _work_dir(year) / "AssetInventory.json"


def _threats_vulns_file(year: int) -> Path:
    return _work_dir(year) / "AssetVulnerabilitiesThreats.json"


def _controls_posture_file(year: int) -> Path:
    return _work_dir(year) / "ExistingControlsPostures.json"


def _risk_analysis_file(year: int) -> Path:
    return _work_dir(year) / "RiskAnalysis.json"


def _risk_evaluation_treatment_file(year: int) -> Path:
    return _work_dir(year) / "RiskEvaluationTreatment.json"


def _annex_a_soa_file(year: int) -> Path:
    return _work_dir(year) / "AnnexA_SoA.json"


def _action_plan_implementation_file(year: int) -> Path:
    return _work_dir(year) / "ActionPlanImplementation.json"


def _action_implementation_guides_file(year: int) -> Path:
    return _work_dir(year) / "ActionImplementationGuides.json"


def _monitoring_improvement_file(year: int) -> Path:
    return _work_dir(year) / "MonitoringImprovement.json"


def _monitoring_implementation_guides_file(year: int) -> Path:
    return _work_dir(year) / "MonitoringImplementationGuides.json"


def _aiml_kpi_inputs_file(year: int) -> Path:
    return _work_dir(year) / "AIMLKPIInputs.json"


def _aiml_dashboard_file(year: int) -> Path:
    return _work_dir(year) / "AIMLDashboard.json"


def _blank_aiml_kpi_inputs(year: int) -> dict:
    return {
        "meta": {
            "year": year,
            "name": "AI_ML_KPI_Inputs",
            "version": 1,
        },
        "role_model_training_runs": [],
        "role_prediction_events": [],
        "cia_prediction_events": [],
        "behavior_model_training_runs": [],
        "behavior_prediction_events": [],
        "manual_correction_events": [],
        "rag_events": [],
        "llm_events": [],
        "rag_llm_counters": {
            "rag_query_count": 0,
            "rag_success_count": 0,
            "rag_failure_count": 0,
            "llm_reasoning_calls": 0,
            "llm_total_tokens": 0,
        },
        "human_trust_counters": {
            "manual_role_corrections": 0,
            "manual_risk_corrections": 0,
            "evaluated_role_predictions": 0,
            "overridden_role_predictions": 0,
            "predictions_with_confidence": 0,
            "low_confidence_predictions": 0,
        },
    }


def _latest_aiml_snapshot_for_year(data: Any, year: int) -> dict:
    if not isinstance(data, dict):
        return {}

    snapshots = data.get("snapshots")
    if not isinstance(snapshots, list):
        return {}

    year_snapshots = [
        item for item in snapshots
        if isinstance(item, dict) and int(item.get("year", year) or year) == year
    ]
    if not year_snapshots:
        return {}

    latest_snapshot_id = str(data.get("latest_snapshot_id", "") or "").strip()
    if latest_snapshot_id:
        for item in reversed(year_snapshots):
            if str(item.get("snapshot_id", "") or "").strip() == latest_snapshot_id:
                return item

    return year_snapshots[-1]


def _reset_aiml_metric(metric_key: str) -> dict:
    return {
        "value": 0,
        "computed": False,
        "source": "reset_audit",
        "calculation": {
            "method": "reset_for_new_audit",
            "formula": "No KPI value is carried into a new audit.",
            "source_files": [],
            "inputs": {},
            "notes": [
                "This KPI was reset when Start New Audit was used.",
            ],
            "what_this_means": (
                f"{metric_key.replace('_', ' ')} was reset for the new audit and will update "
                "again after new telemetry or table data becomes available."
            ),
            "readable_formula": (
                "This KPI was reset for the new audit and will update after new "
                "telemetry or table data becomes available."
            ),
        },
    }


def _reset_aiml_kpis(kpis: Any) -> dict:
    if not isinstance(kpis, dict):
        return {}

    reset_groups: dict[str, dict] = {}
    for group_key, group_metrics in kpis.items():
        if not isinstance(group_metrics, dict):
            reset_groups[group_key] = {}
            continue

        reset_groups[group_key] = {
            metric_key: _reset_aiml_metric(metric_key)
            for metric_key in group_metrics.keys()
        }

    return reset_groups


def _reset_aiml_files(year: int) -> None:
    _write_json(_aiml_kpi_inputs_file(year), _blank_aiml_kpi_inputs(year))

    path = _aiml_dashboard_file(year)
    current_data = _read_json(path, {})
    latest_snapshot = deepcopy(_latest_aiml_snapshot_for_year(current_data, year))

    if not isinstance(current_data, dict):
        current_data = {}

    if not latest_snapshot:
        latest_snapshot = {
            "snapshot_id": f"aiml_reset_{year}",
            "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "year": year,
            "scope": {
                "name": "AI/ML Dashboard",
                "asset_count": 0,
            },
            "kpis": {},
            "dataset_provenance": {},
            "rag": {
                "vector_database": "ChromaDB",
                "text_embedding_model": "nomic-embed-text:latest",
            },
            "llm": {
                "model": "Qwen 33",
                "version": "Qwen 33",
                "parameters": "14B",
                "deployment_style": "Local LLM - Llama",
            },
        }

    scope = latest_snapshot.get("scope")
    if not isinstance(scope, dict):
        scope = {}
    scope["name"] = str(scope.get("name", "AI/ML Dashboard") or "AI/ML Dashboard")
    scope["asset_count"] = 0
    latest_snapshot["scope"] = scope
    latest_snapshot["year"] = year
    latest_snapshot["kpis"] = _reset_aiml_kpis(latest_snapshot.get("kpis"))
    latest_snapshot["creation_source"] = "reset_audit"
    latest_snapshot["reset_at"] = datetime.now().astimezone().isoformat(timespec="seconds")

    reset_data = {
        "meta": current_data.get("meta", {
            "name": "AI_ML_KPI_History",
            "description": "Historical KPI snapshots for the AI/ML dashboard.",
            "year": year,
        }),
        "latest_snapshot_id": str(latest_snapshot.get("snapshot_id", "") or ""),
        "snapshots": [latest_snapshot],
    }

    if not isinstance(reset_data["meta"], dict):
        reset_data["meta"] = {
            "name": "AI_ML_KPI_History",
            "description": "Historical KPI snapshots for the AI/ML dashboard.",
            "year": year,
        }

    reset_data["meta"]["year"] = year
    _write_json(path, reset_data)


def _reset_all_system_statuses(year: int) -> None:
    path = _system_status_file(year)
    data = _read_json(path, {})

    if not isinstance(data, dict):
        data = {}

    if not isinstance(data.get("meta"), dict):
        data["meta"] = {"name": "System Status", "version": "1.0"}

    sections = data.get("sections")
    if not isinstance(sections, dict):
        sections = {}

    for key in SYSTEM_STATUS_SECTION_KEYS:
        section = sections.get(key)
        if not isinstance(section, dict):
            section = {}
        if key == "scope_context":
            section["scope_file_name"] = f"{year}-Scope-Draft-v0.json"
        section["status"] = "Not Started"
        sections[key] = section

    for key, section in list(sections.items()):
        if not isinstance(section, dict):
            section = {}
        section["status"] = "Not Started"
        sections[key] = section

    data["sections"] = sections
    data["year"] = year
    data["updated_at"] = datetime.utcnow().isoformat() + "Z"
    _write_json(path, data)


def _reset_working_files(year: int) -> None:
    reset_docs = (
        (_action_implementation_guides_file(year), {"guides": []}),
        (_action_plan_implementation_file(year), {"controls": []}),
        (_annex_a_soa_file(year), {"controls": []}),
        (_asset_inventory_file(year), {
            "meta": {
                "year": year,
                "name": "Asset Inventory & CIA",
                "submitted": False,
                "read_only": False,
            },
            "network_mask": None,
            "subnets": [],
        }),
        (_threats_vulns_file(year), {"hosts": []}),
        (_controls_posture_file(year), {"hosts": []}),
        (_monitoring_improvement_file(year), {"cves": []}),
        (_monitoring_implementation_guides_file(year), {"guides": []}),
        (_risk_analysis_file(year), {"hosts": []}),
        (_risk_evaluation_treatment_file(year), {"hosts": []}),
    )

    for path, data in reset_docs:
        _write_json(path, data)


def _safe_list(value: Any) -> list:
    return value if isinstance(value, list) else []


def _count_asset_inventory_assets(doc: Any) -> int:
    if not isinstance(doc, dict):
        return 0

    subnets = doc.get("subnets", [])
    if not isinstance(subnets, list):
        return 0

    total = 0
    for subnet in subnets:
        if not isinstance(subnet, dict):
            continue
        assets = subnet.get("assets", [])
        if isinstance(assets, list):
            total += len([a for a in assets if isinstance(a, dict)])
    return total
    
def _scope_exists(scope_file_name: str) -> bool:
    value = str(scope_file_name or "").strip().lower()
    if not value:
        return False
    return "v0" not in value


def _value_has_meaningful_content(value: Any) -> bool:
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, dict):
        return any(_value_has_meaningful_content(v) for v in value.values())
    if isinstance(value, list):
        return any(_value_has_meaningful_content(v) for v in value)
    return False


def _host_has_meaningful_evidence(host: dict) -> bool:
    evidence = host.get("evidence", [])
    if not isinstance(evidence, list):
        return False
    return any(_value_has_meaningful_content(entry) for entry in evidence if isinstance(entry, dict))


def _build_evidence_coverage(action_plan_doc: dict, monitoring_doc: dict) -> dict:
    total_hosts = 0
    hosts_with_evidence = 0

    for control in _safe_list(action_plan_doc.get("controls", [])):
        for host in _safe_list(control.get("hosts", [])):
            if not isinstance(host, dict):
                continue
            total_hosts += 1
            if _host_has_meaningful_evidence(host):
                hosts_with_evidence += 1

    for cve_entry in _safe_list(monitoring_doc.get("cves", [])):
        for host in _safe_list(cve_entry.get("hosts", [])):
            if not isinstance(host, dict):
                continue
            total_hosts += 1
            if _host_has_meaningful_evidence(host):
                hosts_with_evidence += 1

    percent = ((hosts_with_evidence / total_hosts) * 100) if total_hosts > 0 else 0

    return {
        "percent": round(percent, 1),
        "have": hosts_with_evidence,
        "total": total_hosts,
    }

def _count_rows(doc: Any, key: str) -> int:
    if not isinstance(doc, dict):
        return 0

    items = doc.get(key, [])
    if not isinstance(items, list):
        return 0

    return len([x for x in items if isinstance(x, dict)])


# (only showing the cleaned critical part to keep it readable)

def _status_multiplier(status: str) -> float:
    normalized = str(status or "").strip().lower()
    if normalized == "completed":
        return 1.0
    if normalized == "in progress":
        return 0.5
    return 0.0


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
    system_status_doc = _read_json(_system_status_file(year), {})
    status_sections = system_status_doc.get("sections", {}) if isinstance(system_status_doc, dict) else {}
    evidence_coverage = _build_evidence_coverage(action_plan_doc, monitoring_doc)

    weighted_score = 0.0

    # Stages 1-7 are driven by data presence + section status and contribute 87%
    # of the total readiness score. The final 13% comes from actual evidence
    # completion across Action Plan / Implementation and Monitoring Improvement,
    # because those sections intentionally remain In Progress while evidence is gathered.
    stage_rules = [
        ("scope_context", 7.25, _scope_exists(scope_file_name)),
        ("assets_cia", 14.5, _count_asset_inventory_assets(asset_doc) > 0),
        ("threats_vulns", 14.5, _count_rows(threats_doc, "hosts") > 0),
        ("existing_controls_postures", 7.25, _count_rows(controls_doc, "hosts") > 0),
        ("risk_analysis", 14.5, _count_rows(risk_analysis_doc, "hosts") > 0),
        ("risk_evaluation_treatment", 14.5, _count_rows(risk_eval_treatment_doc, "hosts") > 0),
        ("annex_a_soa", 14.5, _count_rows(annex_doc, "controls") > 0),
    ]

    for section_key, weight, has_data in stage_rules:
        if not has_data:
            continue

        section = status_sections.get(section_key, {}) if isinstance(status_sections, dict) else {}
        status = section.get("status", "") if isinstance(section, dict) else ""
        weighted_score += weight * _status_multiplier(status)

    evidence_total = evidence_coverage.get("total", 0) or 0
    evidence_have = evidence_coverage.get("have", 0) or 0
    evidence_ratio = (evidence_have / evidence_total) if evidence_total > 0 else 0.0
    weighted_score += 13.0 * evidence_ratio

    normalized_score = int(round(weighted_score))

    return {
        "value": normalized_score,
        "max": 100,
        "label": "Completed" if normalized_score == 100 else "In Progress",
        "delta_7d": 0,
    }
    
def _normalize_scope(scope: Any, year: int | None = None, scope_file_name: str = "") -> dict:
    if not isinstance(scope, dict):
        scope = {}

    resolved_year = year if year is not None else get_system_year()
    scope_is_submitted = _scope_exists(scope_file_name)

    asset_doc = _read_json(_asset_inventory_file(resolved_year), {})

    asset_count = 0
    if scope_is_submitted and isinstance(asset_doc, dict):
        subnets = asset_doc.get("subnets", [])
        if isinstance(subnets, list):
            for subnet in subnets:
                if isinstance(subnet, dict):
                    assets = subnet.get("assets", [])
                    if isinstance(assets, list):
                        asset_count += len([a for a in assets if isinstance(a, dict)])

    return {
        "name": scope.get("name", "NA") if scope_is_submitted else "NA",
        "asset_count": asset_count,
        "status": _get_scope_status(resolved_year),
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
    doc = _read_json(_risk_analysis_file(year), {})

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
    scope_file_name = str(data.get("scope_file_name", "") or "").strip()
    scope_is_submitted = _scope_exists(scope_file_name)

    normalized_kpis = _normalize_kpis(data.get("kpis"))

    action_plan_doc = _read_json(_action_plan_implementation_file(resolved_year), {})
    monitoring_doc = _read_json(_monitoring_improvement_file(resolved_year), {})

    normalized_kpis["evidence_coverage"] = _build_evidence_coverage(
        action_plan_doc,
        monitoring_doc,
    )

    normalized_kpis["readiness_score"] = _build_readiness_score(data, resolved_year)

    normalized_kpis["soa"] = _build_soa_status(resolved_year)
    
    normalized_kpis["high_risk_critical_impact"] = _build_high_risk_critical_impact(resolved_year)

    return {
        "environment": data.get("environment", env),
        "year": resolved_year,
        "scope": _normalize_scope(data.get("scope"), resolved_year, scope_file_name),
        "scope_context_section2": (
            _normalize_section2(data.get("scope_context_section2"))
            if scope_is_submitted
            else _normalize_section2({"bullets": [], "body": ""})
        ),
        "kpis": normalized_kpis,
        "blockers": blockers,
        "scopes": scopes,
        "scope_file_name": scope_file_name,
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
    _reset_all_system_statuses(year)
    _reset_working_files(year)
    _reset_aiml_files(year)

    return _normalize_dashboard_payload(data, "Production", year)
