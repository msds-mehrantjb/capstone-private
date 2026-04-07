from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel
from pathlib import Path
from typing import Any
import json
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
    separator_line = "| " + " | ".join(["---"] * len(headers)) + " |"

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

    markdown = builder(resolved_year)

    return {
        "success": True,
        "year": resolved_year,
        "section": section,
        "markdown": markdown,
    }


def _render_markdown_to_pdf(markdown: str, output_pdf: Path) -> None:
    pandoc_path = shutil.which("pandoc")
    wkhtmltopdf_path = shutil.which("wkhtmltopdf")

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