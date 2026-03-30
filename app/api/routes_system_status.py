from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query
from pathlib import Path
from typing import Any, Dict, Literal
from datetime import datetime
import json
import os
import tempfile

router = APIRouter(prefix="/api/system", tags=["system"])

StepStatus = Literal["Blocked", "Not Started", "In Progress", "Completed"]


def project_root() -> Path:
    current = Path(__file__).resolve()
    for parent in [current] + list(current.parents):
        if (parent / "data" / "work").exists():
            return parent
    raise RuntimeError("Could not find project root containing data/work")


BASE_DIR = project_root()


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


DEFAULT_SECTIONS: Dict[str, Dict[str, Any]] = {
    "scope_context": {"status": "Not Started", "scope_file_name": "2026-Scope-Draft-v0.json"},
    "assets_cia": {"status": "Blocked"},
    "threats_vulns": {"status": "Blocked"},
    "controls_posture": {"status": "Blocked"},
    "risk_analysis": {"status": "Blocked"},
    "risk_evaluation": {"status": "Blocked"},
    "risk_treatment": {"status": "Blocked"},
    "soa": {"status": "Blocked"},
    "action_plan": {"status": "Blocked"},
    "monitoring": {"status": "Blocked"},
    "reports": {"status": "Blocked"},
}


def _atomic_write_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.stem + "_", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp, path)
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
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


def _load_status(year: int) -> Dict[str, Any]:
    path = _system_status_file(year)

    if not path.exists():
        data = _default_status(year)
        _atomic_write_json(path, data)
        return data

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read SystemStatus.json: {e}")


def _normalize_status(data: Dict[str, Any], year: int) -> Dict[str, Any]:
    allowed = {"Blocked", "Not Started", "In Progress", "Completed"}

    if not isinstance(data.get("meta"), dict):
        data["meta"] = {"name": "SystemStatus", "version": "1.0"}

    sections = data.get("sections")
    if not isinstance(sections, dict):
        sections = {}

    defaults = json.loads(json.dumps(DEFAULT_SECTIONS))
    defaults["scope_context"]["scope_file_name"] = f"{year}-Scope-Draft-v0.json"

    for k, v in defaults.items():
        if k not in sections or not isinstance(sections.get(k), dict):
            sections[k] = dict(v)
        else:
            for dk, dv in v.items():
                sections[k].setdefault(dk, dv)

    for k, v in list(sections.items()):
        if not isinstance(v, dict):
            sections[k] = {"status": "Blocked"}
            continue

        st = v.get("status")
        v["status"] = st if st in allowed else "Blocked"
        sections[k] = v

    data["sections"] = sections
    data["year"] = year

    if "updated_at" not in data:
        data["updated_at"] = datetime.utcnow().isoformat() + "Z"

    return data


@router.get("/status")
def get_status(year: int = Query(2026)) -> Dict[str, Any]:
    data = _normalize_status(_load_status(year), year)
    data["_debug_path"] = str(_system_status_file(year))
    return data


@router.post("/reset-audit")
def reset_audit(year: int = Query(2026)) -> Dict[str, Any]:
    data = _normalize_status(_load_status(year), year)
    sections = data["sections"]

    for k in list(sections.keys()):
        sections[k]["status"] = "Blocked"

    sections["scope_context"]["status"] = "Not Started"
    sections["scope_context"]["scope_file_name"] = f"{year}-Scope-Draft-v0.json"

    data["sections"] = sections
    data["year"] = year
    data["updated_at"] = datetime.utcnow().isoformat() + "Z"

    _atomic_write_json(_system_status_file(year), data)
    return data