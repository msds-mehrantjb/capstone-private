from fastapi import APIRouter, HTTPException, Query
from fastapi import Request
from fastapi.responses import Response
from pydantic import BaseModel
from pathlib import Path
from typing import Any
import json
import os
import shutil
import subprocess
import tempfile

from app.api.sections.executive_summary import build_executive_summary_markdown
from app.api.sections.asset_inventory import build_asset_inventory_markdown
from app.api.sections.risk_register import build_risk_register_markdown
from app.api.sections.risk_treatment_plan import build_risk_treatment_plan_markdown
from app.api.sections.annex_a_soa import build_annex_a_soa_markdown
from app.api.sections.action_plan_implementation import build_action_plan_implementation_markdown
from app.api.sections.monitoring_improvement import build_monitoring_improvement_markdown

router = APIRouter(prefix="/api/final-deliveries", tags=["final-deliveries"])


class ExportPdfRequest(BaseModel):
    section: str
    year: int | None = None


def find_project_root() -> Path:
    current = Path(__file__).resolve()
    for parent in [current] + list(current.parents):
        if (parent / "data").exists():
            return parent
    raise RuntimeError("Could not find project root containing data")


BASE_DIR = find_project_root()


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


def _dashboard_file() -> Path:
    return BASE_DIR / "data" / "raw" / "dashboard.json"


def _system_status_file(year: int | None = None) -> Path:
    return _work_dir(year) / "SystemStatus.json"


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


def _monitoring_improvement_file(year: int) -> Path:
    return _work_dir(year) / "MonitoringImprovement.json"

def _action_plan_implementation_guides_file(year: int) -> Path:
    return _work_dir(year) / "ActionImplementationGuides.json"


def _monitoring_implementation_guides_file(year: int) -> Path:
    return _work_dir(year) / "MonitoringImplementationGuides.json"

def _read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def _safe_list(value: Any) -> list:
    return value if isinstance(value, list) else []


def _safe_dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _escape_md(value: Any) -> str:
    text = str(value if value is not None else "").strip()
    return text.replace("|", "\\|")


def _md_table(headers: list[str], rows: list[list[Any]]) -> str:
    if not rows:
        return "_No data available._"

    header_line = "| " + " | ".join(_escape_md(h) for h in headers) + " |"

    # ✅ FORCE LEFT ALIGNMENT FOR ALL COLUMNS
    separator_line = "| " + " | ".join([":---"] * len(headers)) + " |"

    body_lines = []
    for row in rows:
        normalized = list(row) + [""] * (len(headers) - len(row))
        body_lines.append(
            "| " + " | ".join(_escape_md(v) for v in normalized[: len(headers)]) + " |"
        )

    return "\n".join([header_line, separator_line, *body_lines])


def _get_section(scope_doc: dict, section_id: str) -> dict:
    sections = scope_doc.get("sections", [])
    if not isinstance(sections, list):
        return {}

    for sec in sections:
        if isinstance(sec, dict) and sec.get("id") == section_id:
            return sec

    return {}


def _render_section(section: dict) -> str:
    if not section:
        return ""

    lines = []

    body = section.get("body")
    if isinstance(body, str) and body.strip():
        lines.append(body.strip())

    bullets = section.get("bullets", [])
    if isinstance(bullets, list) and bullets:
        lines.append("")
        for b in bullets:
            lines.append(f"- {str(b).strip()}")

    return "\n".join(lines)


def _get_scope_status(year: int | None = None) -> str:
    data = _read_json(_system_status_file(year), {})
    if not isinstance(data, dict):
        return "Not Started"

    sections = data.get("sections")
    if not isinstance(sections, dict):
        return "Not Started"

    scope_context = sections.get("scope_context")
    if not isinstance(scope_context, dict):
        return "Not Started"

    return str(scope_context.get("status", "Not Started"))


def _normalize_scope(scope: Any, year: int | None = None) -> dict:
    if not isinstance(scope, dict):
        scope = {}

    resolved_year = year if year is not None else get_system_year()
    asset_doc = _read_json(_asset_inventory_file(resolved_year), {})

    asset_count = 0
    hosts_count = 0

    if isinstance(asset_doc, dict):
        hosts = _safe_list(asset_doc.get("hosts"))
        if hosts:
            hosts_count = len([h for h in hosts if isinstance(h, dict)])
            asset_count = hosts_count
        else:
            subnets = _safe_list(asset_doc.get("subnets"))
            for subnet in subnets:
                if isinstance(subnet, dict):
                    assets = _safe_list(subnet.get("assets"))
                    asset_count += len([a for a in assets if isinstance(a, dict)])

    return {
        "name": scope.get("name", "NA"),
        "asset_count": asset_count,
        "hosts_count": hosts_count,
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


def _load_dashboard_context(year: int) -> dict:
    data = _read_json(_dashboard_file(), {})
    if not isinstance(data, dict):
        data = {}

    return {
        "dashboard": data,
        "scope": _normalize_scope(data.get("scope"), year),
        "section2": _normalize_section2(data.get("scope_context_section2")),
    }


def _scope_file_from_dashboard(year: int) -> Path | None:
    dashboard = _read_json(_dashboard_file(), {})
    scope_file_name = str(dashboard.get("scope_file_name", "")).strip()

    if scope_file_name:
        work_path = _work_dir(year) / scope_file_name
        if work_path.exists():
            return work_path

    raw_path = BASE_DIR / "data" / "raw" / scope_file_name
    if raw_path.exists():
        return raw_path

    for file in _work_dir(year).glob("*Scope*.json"):
        return file

    for file in (BASE_DIR / "data" / "raw").glob("*Scope*.json"):
        return file

    return None


def _load_scope_file_payload(year: int) -> dict:
    path = _scope_file_from_dashboard(year)
    if path is None:
        return {}
    data = _read_json(path, {})
    return data if isinstance(data, dict) else {}


def _first_non_empty(*values: Any, default: str = "NA") -> str:
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return default



def _extract_scope_text_block(scope_doc: dict, keys: list[str]) -> str:
    for key in keys:
        value = scope_doc.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()

        if isinstance(value, list):
            cleaned = [str(x).strip() for x in value if str(x).strip()]
            if cleaned:
                return "\n".join(f"- {x}" for x in cleaned)

        if isinstance(value, dict):
            parts: list[str] = []
            for sub_key, sub_value in value.items():
                if isinstance(sub_value, str) and sub_value.strip():
                    parts.append(f"- **{sub_key.replace('_', ' ').title()}:** {sub_value.strip()}")
                elif isinstance(sub_value, list):
                    cleaned = [str(x).strip() for x in sub_value if str(x).strip()]
                    if cleaned:
                        parts.append(f"- **{sub_key.replace('_', ' ').title()}:**")
                        parts.extend([f"  - {x}" for x in cleaned])
            if parts:
                return "\n".join(parts)

    return ""


def _safe_md(text: str, fallback: str) -> str:
    return text.strip() if text.strip() else fallback


def _extract_scope_summary(scope_doc: dict, dashboard_ctx: dict, year: int) -> dict:
    scope_meta = _safe_dict(scope_doc.get("scope"))
    org_meta = _safe_dict(scope_doc.get("organization"))
    company_meta = _safe_dict(scope_doc.get("company"))
    audit_meta = _safe_dict(scope_doc.get("audit"))
    isms_meta = _safe_dict(scope_doc.get("isms"))

    return {
        "organization_name": _first_non_empty(
            org_meta.get("name"),
            company_meta.get("name"),
            scope_doc.get("organization_name"),
            scope_doc.get("company_name"),
            default="NA",
        ),
        "assessment_year": str(year),
        "scope_name": _first_non_empty(
            scope_meta.get("name"),
            scope_doc.get("scope_name"),
            dashboard_ctx["scope"].get("name"),
            default="NA",
        ),
        "scope_statement": _first_non_empty(
            scope_meta.get("statement"),
            scope_doc.get("scope_statement"),
            scope_doc.get("statement"),
            default="NA",
        ),
        "assessment_standard": _first_non_empty(
            audit_meta.get("standard"),
            isms_meta.get("standard"),
            scope_doc.get("standard"),
            "ISO/IEC 27001:2022",
            default="ISO/IEC 27001:2022",
        ),
        "environment": _first_non_empty(
            scope_meta.get("environment"),
            scope_doc.get("environment"),
            dashboard_ctx["dashboard"].get("environment"),
            default="NA",
        ),
        "scope_status": dashboard_ctx["scope"].get("status", "NA"),
        "included_assets": str(dashboard_ctx["scope"].get("asset_count", 0)),
        "organizational_boundaries": _extract_scope_text_block(
            scope_doc,
            ["organizational_boundaries", "boundaries", "organizational_scope"],
        ),
        "included_items": _extract_scope_text_block(
            scope_doc,
            ["included_items", "in_scope", "included_assets", "included_systems"],
        ),
        "excluded_items": _extract_scope_text_block(
            scope_doc,
            ["excluded_items", "out_of_scope", "excluded_assets", "excluded_systems"],
        ),
        "interested_parties": _extract_scope_text_block(
            scope_doc,
            ["interested_parties", "stakeholders"],
        ),
        "assumptions": _extract_scope_text_block(
            scope_doc,
            ["assumptions", "constraints", "dependencies"],
        ),
    }


def _extract_asset_rows(doc: dict) -> list[dict]:
    if not isinstance(doc, dict):
        return []

    hosts = [h for h in _safe_list(doc.get("hosts")) if isinstance(h, dict)]
    if hosts:
        return hosts

    rows: list[dict] = []
    for subnet in _safe_list(doc.get("subnets")):
        if not isinstance(subnet, dict):
            continue

        subnet_name = subnet.get("subnet", subnet.get("name", ""))
        for asset in _safe_list(subnet.get("assets")):
            if isinstance(asset, dict):
                item = dict(asset)
                if "subnet" not in item and subnet_name:
                    item["subnet"] = subnet_name
                rows.append(item)

    return rows


def _extract_risk_rows(doc: dict) -> list[dict]:
    if not isinstance(doc, dict):
        return []
    return [h for h in _safe_list(doc.get("hosts")) if isinstance(h, dict)]


def _extract_controls_rows(doc: dict) -> list[dict]:
    if not isinstance(doc, dict):
        return []
    return [c for c in _safe_list(doc.get("controls")) if isinstance(c, dict)]


def _asset_row_to_markdown_row(row: dict) -> list[Any]:
    return [
        row.get("hostname", row.get("host", row.get("name", "NA"))),
        row.get("ip", row.get("ip_address", "NA")),
        row.get("role", row.get("predicted_role", "NA")),
        row.get("CIA rating", row.get("cia_rating", "NA")),
        row.get("status", "NA"),
        row.get("subnet", "NA"),
    ]


def _risk_register_row_to_markdown_row(row: dict) -> list[Any]:
    return [
        row.get("hostname", row.get("host", row.get("name", "NA"))),
        row.get("asset", row.get("role", row.get("predicted_role", "NA"))),
        row.get("threat", "NA"),
        row.get("vulnerability", "NA"),
        row.get("likelihood", row.get("Likelihood", "NA")),
        row.get("impact", row.get("impact", row.get("CIA rating", "NA"))),
        row.get("risk", row.get("risk_level", "NA")),
    ]


def _risk_treatment_row_to_markdown_row(row: dict) -> list[Any]:
    return [
        row.get("hostname", row.get("host", row.get("name", "NA"))),
        row.get("risk", row.get("risk_level", "NA")),
        row.get("evaluation", row.get("risk_decision", row.get("decision", "NA"))),
        row.get("treatment", row.get("treatment_plan", row.get("treatment_action", "NA"))),
        row.get("owner", row.get("risk_owner", "NA")),
        row.get("target_date", row.get("due_date", "NA")),
    ]


def _annex_row_to_markdown_row(row: dict) -> list[Any]:
    return [
        row.get("control_id", row.get("control", "NA")),
        row.get("control_name", "NA"),
        row.get("domain", "NA"),
        row.get("applicable", "NA"),
        row.get("implementation_status", "NA"),
        row.get("justification", "NA"),
    ]


def _action_plan_row_to_markdown_row(row: dict) -> list[Any]:
    return [
        row.get("control_id", row.get("control", "NA")),
        row.get("control_name", "NA"),
        row.get("implementation_status", "NA"),
        row.get("owner", "NA"),
        row.get("target_date", row.get("due_date", "NA")),
    ]


def _monitoring_row_to_markdown_row(row: dict) -> list[Any]:
    return [
        row.get("cve", row.get("CVE", row.get("id", "NA"))),
        row.get("title", row.get("name", row.get("vulnerability", "NA"))),
        row.get("status", row.get("implementation_status", "NA")),
        row.get("owner", "NA"),
        row.get("review_date", row.get("target_date", "NA")),
    ]


SECTION_BUILDERS = {
    "executive-summary": build_executive_summary_markdown,
    "asset-inventory": build_asset_inventory_markdown,
    "risk-register": build_risk_register_markdown,
    "risk-treatment-plan": build_risk_treatment_plan_markdown,
    "annex-a-soa": build_annex_a_soa_markdown,
    "action-plan-implementation": build_action_plan_implementation_markdown,
    "monitoring-improvement": build_monitoring_improvement_markdown,
}

SECTION_EMPTY_MESSAGES = {
    "executive-summary": {
        "title": "Executive Summary",
        "message": "No final deliverable data is available yet.",
        "next_step": "Complete and submit the audit lifecycle sections before generating the executive summary.",
    },
    "asset-inventory": {
        "title": "Asset Inventory",
        "message": "No asset inventory records are available yet.",
        "next_step": "Start an Asset Inventory & CIA assessment and submit the results first.",
    },
    "risk-register": {
        "title": "Risk Register",
        "message": "No risk analysis records are available yet.",
        "next_step": "Run and submit the Risk Analysis section first.",
    },
    "risk-treatment-plan": {
        "title": "Risk Treatment Plan",
        "message": "No risk treatment records are available yet.",
        "next_step": "Finalize Risk Analysis, then complete and submit Risk Evaluation/Treatment.",
    },
    "annex-a-soa": {
        "title": "Annex A & Statement of Applicability",
        "message": "No Annex A & SoA control records are available yet.",
        "next_step": "Submit the Risk Evaluation/Treatment results, then create and submit the Annex A & SoA table.",
    },
    "action-plan-implementation": {
        "title": "Action Plan / Implementation",
        "message": "No action plan records are available yet.",
        "next_step": "Submit the Annex A & SoA table first.",
    },
    "monitoring-improvement": {
        "title": "Monitoring & Improvement",
        "message": "No monitoring and improvement records are available yet.",
        "next_step": "Submit the Action Plan / Implementation results, then create Monitoring & Improvement records.",
    },
}


def _asset_inventory_table_row_count(year: int) -> int:
    doc = _read_json(_asset_inventory_file(year), {})
    if not isinstance(doc, dict):
        return 0

    total = 0
    for subnet in _safe_list(doc.get("subnets")):
        if isinstance(subnet, dict):
            total += len([asset for asset in _safe_list(subnet.get("assets")) if isinstance(asset, dict)])
    return total


def _grouped_host_table_row_count(doc: Any) -> int:
    if not isinstance(doc, dict):
        return 0

    hostnames = set()
    for host in _safe_list(doc.get("hosts")):
        if not isinstance(host, dict):
            continue
        hostname = str(host.get("hostname") or "").strip().lower()
        if hostname:
            hostnames.add(hostname)
    return len(hostnames)


def _controls_table_row_count(doc: Any) -> int:
    if not isinstance(doc, dict):
        return 0
    return len([row for row in _safe_list(doc.get("controls")) if isinstance(row, dict)])


def _monitoring_table_row_count(year: int) -> int:
    doc = _read_json(_monitoring_improvement_file(year), {})
    if not isinstance(doc, dict):
        return 0
    return len([row for row in _safe_list(doc.get("cves")) if isinstance(row, dict)])


def _section_table_row_count(section: str, year: int) -> int:
    if section == "asset-inventory":
        return _asset_inventory_table_row_count(year)

    if section == "risk-register":
        return _grouped_host_table_row_count(_read_json(_risk_analysis_file(year), {}))

    if section == "risk-treatment-plan":
        return _grouped_host_table_row_count(_read_json(_risk_evaluation_treatment_file(year), {}))

    if section == "annex-a-soa":
        return _controls_table_row_count(_read_json(_annex_a_soa_file(year), {}))

    if section == "action-plan-implementation":
        return _controls_table_row_count(_read_json(_action_plan_implementation_file(year), {}))

    if section == "monitoring-improvement":
        return _monitoring_table_row_count(year)

    if section == "executive-summary":
        return sum(
            [
                _section_table_row_count("asset-inventory", year),
                _section_table_row_count("risk-register", year),
                _section_table_row_count("risk-treatment-plan", year),
                _section_table_row_count("annex-a-soa", year),
                _section_table_row_count("action-plan-implementation", year),
                _section_table_row_count("monitoring-improvement", year),
            ]
        )

    return 0


def _empty_section_markdown(section: str, year: int) -> str:
    config = SECTION_EMPTY_MESSAGES.get(section, SECTION_EMPTY_MESSAGES["executive-summary"])
    title = config["title"]
    message = config["message"]
    next_step = config["next_step"]

    return "\n".join(
        [
            f"# {title}",
            "",
            f"**Assessment Year:** {year}",
            "",
            "## Not Ready Yet",
            "",
            message,
            "",
            f"**Next step:** {next_step}",
            "",
        ]
    )


def _section_is_empty(section: str, year: int) -> bool:
    return _section_table_row_count(section, year) == 0


def _find_action_implementation_guide(year: int, guide_id: str) -> dict | None:
    doc = _read_json(_action_plan_implementation_guides_file(year), {})
    guides = doc.get("guides", [])
    if not isinstance(guides, list):
        return None

    for guide in guides:
        if isinstance(guide, dict) and str(guide.get("guide_id", "")).strip() == guide_id:
            return guide

    return None


def _normalize_lookup(value: Any) -> str:
    return str(value if value is not None else "").strip().lower()


def _find_action_implementation_guide_by_evidence_id(
    year: int,
    evidence_id: str,
) -> dict | None:
    evidence_key = _normalize_lookup(evidence_id)
    if not evidence_key:
        return None

    doc = _read_json(_action_plan_implementation_guides_file(year), {})
    guides = doc.get("guides", [])
    if not isinstance(guides, list):
        return None

    for guide in guides:
        if (
            isinstance(guide, dict)
            and _normalize_lookup(guide.get("evidence_id")) == evidence_key
        ):
            return guide

    return None


def _find_action_implementation_evidence_context(
    year: int,
    evidence_id: str,
) -> tuple[dict, dict, dict] | None:
    evidence_key = _normalize_lookup(evidence_id)
    if not evidence_key:
        return None

    doc = _read_json(_action_plan_implementation_file(year), {})
    controls = doc.get("controls", [])
    if not isinstance(controls, list):
        return None

    for control in controls:
        if not isinstance(control, dict):
            continue
        hosts = control.get("hosts", [])
        if not isinstance(hosts, list):
            continue
        for host in hosts:
            if not isinstance(host, dict):
                continue
            evidence_rows = host.get("evidence", [])
            if not isinstance(evidence_rows, list):
                continue
            for evidence in evidence_rows:
                if (
                    isinstance(evidence, dict)
                    and _normalize_lookup(evidence.get("evidence_id")) == evidence_key
                ):
                    return control, host, evidence

    return None


def _ensure_action_implementation_guide_for_evidence(
    year: int,
    evidence_id: str,
) -> dict | None:
    existing = _find_action_implementation_guide_by_evidence_id(year, evidence_id)
    if existing is not None:
        return existing

    context = _find_action_implementation_evidence_context(year, evidence_id)
    if context is None:
        return None

    control, host, evidence = context
    from app.api.routes_action_plan_implementation import _replace_guide_for_evidence

    return _replace_guide_for_evidence(
        year=year,
        control=control,
        host=host,
        evidence=evidence,
        prefer_fallback=True,
    )


def _find_monitoring_implementation_guide(year: int, guide_id: str) -> dict | None:
    from app.api.routes_monitoring_improvement import (
        ensure_monitoring_implementation_guide_ready,
    )

    return ensure_monitoring_implementation_guide_ready(year, guide_id)


def _find_monitoring_implementation_guide_by_evidence_id(
    year: int,
    evidence_id: str,
) -> dict | None:
    evidence_key = _normalize_lookup(evidence_id)
    if not evidence_key:
        return None

    doc = _read_json(_monitoring_implementation_guides_file(year), {})
    guides = doc.get("guides", [])
    if not isinstance(guides, list):
        return None

    for guide in guides:
        if (
            isinstance(guide, dict)
            and _normalize_lookup(guide.get("evidence_id")) == evidence_key
        ):
            return guide

    return None


def _monitoring_rows(doc: Any) -> list[dict]:
    if isinstance(doc, list):
        return [row for row in doc if isinstance(row, dict)]
    if not isinstance(doc, dict):
        return []
    for key in ["cves", "items", "records", "monitoring_items"]:
        rows = doc.get(key)
        if isinstance(rows, list):
            return [row for row in rows if isinstance(row, dict)]
    return []


def _find_monitoring_implementation_evidence_context(
    year: int,
    evidence_id: str,
) -> tuple[dict, dict, dict] | None:
    evidence_key = _normalize_lookup(evidence_id)
    if not evidence_key:
        return None

    doc = _read_json(_monitoring_improvement_file(year), {})
    for control in _monitoring_rows(doc):
        hosts = control.get("hosts", [])
        if (
            (not isinstance(hosts, list) or not hosts)
            and any(control.get(key) for key in ("hostname", "ip_address", "role", "evidence"))
        ):
            hosts = [control]
        if not isinstance(hosts, list):
            continue

        for host in hosts:
            if not isinstance(host, dict):
                continue
            evidence_rows = host.get("evidence", [])
            if not isinstance(evidence_rows, list):
                continue
            for evidence in evidence_rows:
                if (
                    isinstance(evidence, dict)
                    and _normalize_lookup(evidence.get("evidence_id")) == evidence_key
                ):
                    return control, host, evidence

    return None


def _ensure_monitoring_implementation_guide_for_evidence(
    year: int,
    evidence_id: str,
) -> dict | None:
    existing = _find_monitoring_implementation_guide_by_evidence_id(year, evidence_id)
    existing_quality = _normalize_lookup(existing.get("generation_quality")) if isinstance(existing, dict) else ""
    if existing is not None and existing_quality != "draft":
        return existing

    context = _find_monitoring_implementation_evidence_context(year, evidence_id)
    if context is None:
        return existing

    control, host, evidence = context
    from app.api.routes_monitoring_improvement import _replace_monitoring_guide_for_evidence

    return _replace_monitoring_guide_for_evidence(
        year=year,
        control=control,
        host=host,
        evidence=evidence,
        prefer_fallback=True,
        guide_id_override=(
            str(existing.get("guide_id", "")).strip()
            if isinstance(existing, dict)
            else None
        ),
    )


def _html_escape(value: Any) -> str:
    text = "" if value is None else str(value)
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _runtime_api_base_url(request: Request) -> str:
    base = str(request.base_url).rstrip("/")
    return base


def _normalize_markdown_api_base(markdown: str, request: Request) -> str:
    active_base = _runtime_api_base_url(request)
    normalized = str(markdown)
    for known_base in [
        "http://127.0.0.1:8000",
        "http://localhost:8000",
        "http://127.0.0.1:8002",
        "http://localhost:8002",
        "http://127.0.0.1:8003",
        "http://localhost:8003",
    ]:
        normalized = normalized.replace(known_base, active_base)
    return normalized


def _list_to_html(items: list[str]) -> str:
    if not items:
        return "<p>-</p>"
    lis = "".join(f"<li>{_html_escape(item)}</li>" for item in items)
    return f"<ul>{lis}</ul>"


def _guide_to_printable_html(guide_doc: dict) -> str:
    def _html_escape(value):
        text = "" if value is None else str(value)
        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    # NEW STRUCTURE (flat)
    guide_id = guide_doc.get("guide_id", "-")
    hostname = guide_doc.get("hostname", "-")
    role = guide_doc.get("role", "-")
    control_id = guide_doc.get("control_id", "-")
    control_name = guide_doc.get("control_name", "-")
    vulnerability = guide_doc.get("vulnerability_name", "-")

    steps = guide_doc.get("implementation_steps", [])
    references = guide_doc.get("references", [])
    evidence_name = guide_doc.get("evidence_name", "-")
    evidence_description = guide_doc.get("evidence_description", "-")
    evidence_format = guide_doc.get("evidence_format", "-")

    # -------- Steps HTML --------
    steps_html = ""
    for step in steps:
        commands_html = ""
        if step.get("commands"):
            commands_html = "".join(
                f"<pre>{_html_escape(cmd)}</pre>"
                for cmd in step.get("commands", [])
            )

        steps_html += f"""
        <div class="step-card">
            <div class="step-header">Step {step.get("step_no", "-")}: {_html_escape(step.get("title", "-"))}</div>
            <p>{_html_escape(step.get("description", "-"))}</p>
            {commands_html}
            <p><strong>Expected Result:</strong> {_html_escape(step.get("expected_result", "-"))}</p>
            <p><strong>Output Type:</strong> {_html_escape(step.get("output_type", "-"))}</p>
            <p><strong>Evidence Capture:</strong> {_html_escape(step.get("evidence_capture", "-"))}</p>
        </div>
        """

    # -------- References --------
    refs_html = ""
    for ref in references:
        refs_html += f"""
        <tr>
            <td>{_html_escape(ref.get("ref_id", "-"))}</td>
            <td>{_html_escape(ref.get("source", "-"))}</td>
        </tr>
        """

    return f"""
    <html>
    <head>
        <style>
            body {{ font-family: Arial; padding: 20px; }}
            h1 {{ text-align: center; }}
            table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
            th, td {{ border: 1px solid #999; padding: 8px; }}
            .step-card {{ border: 1px solid #ccc; padding: 10px; margin-bottom: 10px; }}
            pre {{background: #f5f5f5; color: #000; padding: 10px; border: 1px solid #ddd; border-radius: 4px;
                 font-size: 11px; line-height: 1.4; white-space: pre-wrap; word-break: break-word;
                 overflow-wrap: anywhere; overflow-x: visible; max-width: 100%; box-sizing: border-box;
                 font-family: Consolas, "Courier New", monospace; font-style: normal; font-weight: normal; }}
            pre, code {{font-style: normal !important; font-weight: normal !important; color: #000 !important;}}     
        </style>
    </head>
    <body>

    <h1>Implementation Guide</h1>

    <table>
        <tr>
            <th>Guide ID</th><td>{_html_escape(guide_id)}</td>
            <th>Host</th><td>{_html_escape(hostname)}</td>
        </tr>
        <tr>
            <th>Role</th><td>{_html_escape(role)}</td>
            <th>Control</th><td>{_html_escape(control_id)} - {_html_escape(control_name)}</td>
        </tr>
        <tr>
            <th>Vulnerability</th>
            <td colspan="3">{_html_escape(vulnerability)}</td>
        </tr>
    </table>

    <h2>Implementation Steps</h2>
    {steps_html if steps_html else "<p>No steps available.</p>"}

    <h2>Expected Final Output</h2>
    <table>
        <tr><th>Name</th><td>{_html_escape(evidence_name)}</td></tr>
        <tr><th>Description</th><td>{_html_escape(evidence_description)}</td></tr>
        <tr><th>Format</th><td>{_html_escape(evidence_format)}</td></tr>
    </table>

    <h2>References</h2>
    <table>
        <tr><th>Ref ID</th><th>Source</th></tr>
        {refs_html if refs_html else "<tr><td colspan='2'>No references</td></tr>"}
    </table>

    </body>
    </html>
    """


@router.get("/action-plan-implementation/guide/evidence/{evidence_id}")
def get_action_implementation_guide_for_evidence(
    evidence_id: str,
    year: int | None = Query(None),
):
    resolved_year = year if year is not None else get_system_year()
    guide = _ensure_action_implementation_guide_for_evidence(resolved_year, evidence_id)

    if guide is None:
        raise HTTPException(status_code=404, detail="Evidence row not found.")

    return {
        "success": True,
        "year": resolved_year,
        "guide": guide,
    }


@router.get("/action-plan-implementation/guide/evidence/{evidence_id}/document")
def get_action_implementation_guide_document_for_evidence(
    evidence_id: str,
    year: int | None = Query(None),
):
    resolved_year = year if year is not None else get_system_year()
    guide = _ensure_action_implementation_guide_for_evidence(resolved_year, evidence_id)

    if guide is None:
        raise HTTPException(status_code=404, detail="Evidence row not found.")

    html = _guide_to_printable_html(guide)
    return Response(content=html, media_type="text/html")


@router.get("/action-plan-implementation/guide/{guide_id}")
def get_action_implementation_guide(
    guide_id: str,
    year: int | None = Query(None),
):
    resolved_year = year if year is not None else get_system_year()
    guide = _find_action_implementation_guide(resolved_year, guide_id)

    if guide is None:
        raise HTTPException(status_code=404, detail="Guide not found.")

    return {
        "success": True,
        "year": resolved_year,
        "guide": guide,
    }


@router.get("/monitoring-improvement/guide/{guide_id}")
def get_monitoring_implementation_guide(
    guide_id: str,
    year: int | None = Query(None),
):
    resolved_year = year if year is not None else get_system_year()
    guide = _find_monitoring_implementation_guide(resolved_year, guide_id)

    if guide is None:
        raise HTTPException(status_code=404, detail="Guide not found.")

    return {
        "success": True,
        "year": resolved_year,
        "guide": guide,
    }


@router.get("/monitoring-improvement/guide/evidence/{evidence_id}")
def get_monitoring_implementation_guide_for_evidence(
    evidence_id: str,
    year: int | None = Query(None),
):
    resolved_year = year if year is not None else get_system_year()
    guide = _ensure_monitoring_implementation_guide_for_evidence(resolved_year, evidence_id)

    if guide is None:
        raise HTTPException(status_code=404, detail="Evidence row not found.")

    return {
        "success": True,
        "year": resolved_year,
        "guide": guide,
    }


@router.get("/action-plan-implementation/guide/{guide_id}/document")
def get_action_implementation_guide_document(
    guide_id: str,
    year: int | None = Query(None),
):
    resolved_year = year if year is not None else get_system_year()
    guide = _find_action_implementation_guide(resolved_year, guide_id)

    if guide is None:
        raise HTTPException(status_code=404, detail="Guide not found.")

    html = _guide_to_printable_html(guide)
    return Response(content=html, media_type="text/html")


@router.get("/monitoring-improvement/guide/evidence/{evidence_id}/document")
def get_monitoring_implementation_guide_document_for_evidence(
    evidence_id: str,
    year: int | None = Query(None),
):
    resolved_year = year if year is not None else get_system_year()
    guide = _ensure_monitoring_implementation_guide_for_evidence(resolved_year, evidence_id)

    if guide is None:
        raise HTTPException(status_code=404, detail="Evidence row not found.")

    html = _guide_to_printable_html(guide)
    return Response(content=html, media_type="text/html")


@router.get("/monitoring-improvement/guide/{guide_id}/document")
def get_monitoring_implementation_guide_document(
    guide_id: str,
    year: int | None = Query(None),
):
    resolved_year = year if year is not None else get_system_year()
    guide = _find_monitoring_implementation_guide(resolved_year, guide_id)

    if guide is None:
        raise HTTPException(status_code=404, detail="Guide not found.")

    html = _guide_to_printable_html(guide)
    return Response(content=html, media_type="text/html")


@router.get("/system-year")
def get_final_deliveries_system_year():
    year = get_system_year()
    return {
        "success": True,
        "year": year,
        "work_dir": str(_work_dir(year)),
    }


@router.get("/{section}")
def get_final_delivery_section(
    request: Request,
    section: str,
    year: int | None = Query(None),
):
    resolved_year = year if year is not None else get_system_year()

    builder = SECTION_BUILDERS.get(section)
    if builder is None:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown final delivery section: {section}",
        )

    if _section_is_empty(section, resolved_year):
        markdown = _empty_section_markdown(section, resolved_year)
    else:
        markdown = builder(resolved_year)

    markdown = _normalize_markdown_api_base(markdown, request)

    return {
        "success": True,
        "year": resolved_year,
        "section": section,
        "markdown": markdown,
    }

def _find_wkhtmltopdf() -> str | None:
    configured_path = os.getenv("WKHTMLTOPDF_PATH", "").strip()
    candidates = [
        configured_path,
        shutil.which("wkhtmltopdf"),
        str(Path(os.getenv("ProgramFiles", r"C:\Program Files")) / "wkhtmltopdf" / "bin" / "wkhtmltopdf.exe"),
        str(Path(os.getenv("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "wkhtmltopdf" / "bin" / "wkhtmltopdf.exe"),
    ]

    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return str(Path(candidate))

    return None


def _render_html_to_pdf(html: str, output_pdf: Path) -> None:
    wkhtmltopdf_path = _find_wkhtmltopdf()

    if not wkhtmltopdf_path:
        raise HTTPException(
            status_code=500,
            detail="Guide PDF export is not available because wkhtmltopdf is not installed.",
        )

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        html_path = tmpdir_path / "guide.html"

        html_path.write_text(html, encoding="utf-8")

        cmd = [
            wkhtmltopdf_path,
            "--enable-local-file-access",
            "--margin-top", "8mm",
            "--margin-bottom", "8mm",
            "--margin-left", "8mm",
            "--margin-right", "8mm",
            str(html_path),
            str(output_pdf),
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
        )

        if result.returncode != 0:
            raise HTTPException(
                status_code=500,
                detail=result.stderr.strip() or "Failed to generate guide PDF.",
            )

def _render_markdown_to_pdf(markdown: str, output_pdf: Path) -> None:
    pandoc_path = shutil.which("pandoc")
    wkhtmltopdf_path = _find_wkhtmltopdf()

    if not pandoc_path:
        raise HTTPException(
            status_code=500,
            detail="PDF export is not available because pandoc is not installed.",
        )

    if not wkhtmltopdf_path:
        raise HTTPException(
            status_code=500,
            detail="PDF export is not available because wkhtmltopdf is not installed.",
        )

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        md_path = tmpdir_path / "document.md"
        css_path = tmpdir_path / "pdf_style.css"

        md_path.write_text(markdown, encoding="utf-8")

        css_path.write_text(
            """
            @page {
              size: A4;
              margin: 3mm 3mm 3mm 3mm;
            }
        
            html, body {
              width: 100%;
              max-width: 100%;
              margin: 0;
              padding: 0;
              font-family: Arial, sans-serif;
              font-size: 12px;
              line-height: 1.4;
            }
        
            body {
              box-sizing: border-box;
            }
        
            h1, h2, h3, h4 {
              margin-top: 10px;
              margin-bottom: 8px;
              page-break-after: avoid;
              break-after: avoid;
              page-break-inside: avoid;
              break-inside: avoid;
            }
        
            h1 + *, h2 + *, h3 + *, h4 + * {
              page-break-before: avoid;
              break-before: avoid;
            }
        
            p, ul, ol, blockquote, pre, table {
              page-break-inside: avoid;
              break-inside: avoid;
            }
        
            p, ul, ol {
              margin-top: 0;
              margin-bottom: 8px;
            }
        
            table {
              width: 100%;
              border-collapse: collapse;
              table-layout: fixed;
              margin-bottom: 12px;
            }
        
            th, td {
              border: 1px solid #999;
              padding: 6px;
              vertical-align: top;
              word-wrap: break-word;
              overflow-wrap: break-word;
            }
        
            img {
              max-width: 100%;
            }
            """,
            encoding="utf-8",
        )

        cmd = [
            pandoc_path,
            str(md_path),
            "-o",
            str(output_pdf),
            "--pdf-engine=wkhtmltopdf",
            "--css",
            str(css_path),
            "-V",
            "margin-top=8mm",
            "-V",
            "margin-bottom=8mm",
            "-V",
            "margin-left=8mm",
            "-V",
            "margin-right=8mm",
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
        )

        if result.returncode != 0:
            raise HTTPException(
                status_code=500,
                detail=result.stderr.strip() or "Failed to generate PDF.",
            )

@router.post("/export-pdf")
def export_final_delivery_pdf(payload: ExportPdfRequest):
    resolved_year = payload.year if payload.year is not None else get_system_year()

    section = str(payload.section or "").strip()
    if not section:
        raise HTTPException(status_code=400, detail="Section is required.")

    builder = SECTION_BUILDERS.get(section)
    if builder is None:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown final delivery section: {section}",
        )

    if _section_is_empty(section, resolved_year):
        markdown = _empty_section_markdown(section, resolved_year)
    elif section == "action-plan-implementation":
        markdown = build_action_plan_implementation_markdown(
            resolved_year,
            include_guide_column=False,
        )
    elif section == "monitoring-improvement":
        markdown = build_monitoring_improvement_markdown(
            resolved_year,
            include_guide_column=False,
        )
    else:
        markdown = builder(resolved_year)
    if not str(markdown).strip():
        raise HTTPException(status_code=400, detail="No markdown content available for export.")

    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path = Path(tmpdir) / f"{section}-{resolved_year}.pdf"
        _render_markdown_to_pdf(markdown, pdf_path)
        pdf_bytes = pdf_path.read_bytes()

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{section}-{resolved_year}.pdf"'
        },
    )

from fastapi.responses import Response

@router.get(
    "/action-plan-implementation/guide/{guide_id}/pdf",
    response_class=Response,
    responses={
        200: {
            "content": {"application/pdf": {}},
            "description": "PDF file"
        }
    }
)
def download_action_implementation_guide_pdf(
    guide_id: str,
    year: int | None = Query(None),
):
    resolved_year = year if year is not None else get_system_year()

    guide = _find_action_implementation_guide(resolved_year, guide_id)
    if guide is None:
        raise HTTPException(status_code=404, detail="Guide not found.")

    html = _guide_to_printable_html(guide)

    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path = Path(tmpdir) / f"{guide_id}.pdf"
        _render_html_to_pdf(html, pdf_path)
        pdf_bytes = pdf_path.read_bytes()

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{guide_id}.pdf"'
        },
    )


@router.get(
    "/action-plan-implementation/guide/evidence/{evidence_id}/pdf",
    response_class=Response,
    responses={
        200: {
            "content": {"application/pdf": {}},
            "description": "PDF file"
        }
    }
)
def download_action_implementation_guide_pdf_for_evidence(
    evidence_id: str,
    year: int | None = Query(None),
):
    resolved_year = year if year is not None else get_system_year()

    guide = _ensure_action_implementation_guide_for_evidence(resolved_year, evidence_id)
    if guide is None:
        raise HTTPException(status_code=404, detail="Evidence row not found.")

    guide_id = str(guide.get("guide_id") or evidence_id).strip() or evidence_id
    html = _guide_to_printable_html(guide)

    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path = Path(tmpdir) / f"{guide_id}.pdf"
        _render_html_to_pdf(html, pdf_path)
        pdf_bytes = pdf_path.read_bytes()

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{guide_id}.pdf"'
        },
    )


@router.get(
    "/monitoring-improvement/guide/{guide_id}/pdf",
    response_class=Response,
    responses={
        200: {
            "content": {"application/pdf": {}},
            "description": "PDF file"
        }
    }
)
def download_monitoring_implementation_guide_pdf(
    guide_id: str,
    year: int | None = Query(None),
):
    resolved_year = year if year is not None else get_system_year()

    guide = _find_monitoring_implementation_guide(resolved_year, guide_id)
    if guide is None:
        raise HTTPException(status_code=404, detail="Guide not found.")

    html = _guide_to_printable_html(guide)

    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path = Path(tmpdir) / f"{guide_id}.pdf"
        _render_html_to_pdf(html, pdf_path)
        pdf_bytes = pdf_path.read_bytes()

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{guide_id}.pdf"'
        },
    )


@router.get(
    "/monitoring-improvement/guide/evidence/{evidence_id}/pdf",
    response_class=Response,
    responses={
        200: {
            "content": {"application/pdf": {}},
            "description": "PDF file"
        }
    }
)
def download_monitoring_implementation_guide_pdf_for_evidence(
    evidence_id: str,
    year: int | None = Query(None),
):
    resolved_year = year if year is not None else get_system_year()

    guide = _ensure_monitoring_implementation_guide_for_evidence(resolved_year, evidence_id)
    if guide is None:
        raise HTTPException(status_code=404, detail="Evidence row not found.")

    guide_id = str(guide.get("guide_id") or evidence_id).strip() or evidence_id
    html = _guide_to_printable_html(guide)

    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path = Path(tmpdir) / f"{guide_id}.pdf"
        _render_html_to_pdf(html, pdf_path)
        pdf_bytes = pdf_path.read_bytes()

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{guide_id}.pdf"'
        },
    )
