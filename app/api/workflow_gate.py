from __future__ import annotations

from typing import Any

from fastapi import HTTPException

from app.api.routes_system_status import _load_status


WORKFLOW_STEPS: tuple[tuple[str, str], ...] = (
    ("scope_context", "Scope & Context"),
    ("assets_cia", "Asset Inventory & CIA"),
    ("threats_vulns", "Threats & Vulnerabilities"),
    ("existing_controls_postures", "Existing Controls & Postures"),
    ("risk_analysis", "Risk Analysis"),
    ("risk_evaluation_treatment", "Risk Evaluation & Treatment"),
    ("annex_a_soa", "Annex A & SoA"),
    ("action_plan_implementation", "Action Plan / Implementation"),
    ("monitoring_improvement", "Monitoring / Improvement"),
)

STEP_LABELS = dict(WORKFLOW_STEPS)
STEP_ORDER = [key for key, _label in WORKFLOW_STEPS]


def _section_status(status_doc: dict[str, Any], section_key: str) -> str:
    sections = status_doc.get("sections")
    if not isinstance(sections, dict):
        return "Not Started"

    section = sections.get(section_key)
    if not isinstance(section, dict):
        return "Not Started"

    status = str(section.get("status") or "").strip()
    return status or "Not Started"


def ensure_previous_steps_completed(
    year: int,
    current_section: str,
    action_name: str = "/submit",
) -> None:
    if current_section not in STEP_ORDER:
        raise ValueError(f"Unknown workflow section: {current_section}")

    status_doc = _load_status(year)
    current_index = STEP_ORDER.index(current_section)
    incomplete_steps = [
        (section_key, _section_status(status_doc, section_key))
        for section_key in STEP_ORDER[:current_index]
        if _section_status(status_doc, section_key) != "Completed"
    ]

    if not incomplete_steps:
        return

    first_key, first_status = incomplete_steps[0]
    raise HTTPException(
        status_code=400,
        detail=(
            f"Cannot process {action_name} for {STEP_LABELS[current_section]} until "
            f"{STEP_LABELS[first_key]} is Completed. Current status: {first_status}."
        ),
    )
