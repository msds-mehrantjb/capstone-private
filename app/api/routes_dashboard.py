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

    return {
        "environment": data.get("environment", env),
        "year": resolved_year,
        "scope": _normalize_scope(data.get("scope"), resolved_year),
        "scope_context_section2": _normalize_section2(data.get("scope_context_section2")),
        "kpis": _normalize_kpis(data.get("kpis")),
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