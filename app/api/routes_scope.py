from fastapi import APIRouter, HTTPException
from pathlib import Path
import json
from datetime import datetime, timezone
import re

router = APIRouter(prefix="/api/scope", tags=["scope"])


def _default_scope(year: int) -> dict:
    return {
        "meta": {
            "year": year,
            "version": "v0",
            "title": "ISO 27001 Scope Statement",
            "template_name": "ISO 27001 Scope Statement Template",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "placeholders_retained": True,
            "source_file": f"{year}-Scope-Draft-v0.json",
        },
        "sections": [
            {
                "id": "1_introduction_purpose",
                "title": "1. Introduction and Purpose",
                "body": "The Information Security Management System (ISMS) of [Organization Name] is established to protect the confidentiality, integrity, and availability of information assets supporting the [Primary Business Function, e.g., Financial Services / Software Development] operations.",
                "bullets": [],
            },
            {
                "id": "2_organizational_boundaries",
                "title": "2. Organizational Boundaries",
                "body": "The ISMS applies to the following departments and business units within [Organization Name]:",
                "bullets": [
                    "[Department A, e.g., Information Technology]",
                    "[Department B, e.g., Human Resources]",
                    "[Specific Project Team, e.g., Managed Services Division]",
                ],
            },
            {
                "id": "3_geographic_physical_boundaries",
                "title": "3. Geographic and Physical Boundaries",
                "body": "The scope includes all information processing facilities located at:",
                "bullets": [
                    "[Main Office Address]: Including the primary server room housing the Windows-based server cluster.",
                    "[Secondary Site/Data Center Address]: Hosting backup domain controllers and disaster recovery systems.",
                    "[Remote Work Policy]: The scope extends to the secure management of corporate-issued Windows workstations used by remote employees via [VPN/Zero Trust solution].",
                ],
            },
            {
                "id": "4_technical_logical_boundaries",
                "title": "4. Technical and Logical Boundaries",
                "body": "This ISMS encompasses the Windows-based enterprise ecosystem, specifically:",
                "bullets": [
                    "Identity Management: All user accounts, groups, and permissions managed via [Active Directory Domain Name / Azure AD tenant].",
                    "Server Infrastructure: All Windows Server instances (including [Web, SQL, File, and Application Servers]) hosted on [Physical Hardware / Hyper-V / VMware].",
                    "Endpoint Management: All enterprise-managed Windows workstations and laptops managed via [Microsoft Endpoint Manager / Intune / Group Policy].",
                    "Network Infrastructure: The local area network (LAN), wireless networks, and firewalls securing the Windows environment.",
                ],
            },
            {
                "id": "5_exclusions_justifications",
                "title": "5. Exclusions and Justifications",
                "body": "The following areas are excluded from the scope of the ISMS:",
                "bullets": [
                    "[Excluded Asset/Location]: Justified because [Reason, e.g., this facility is managed by a third-party landlord and does not store corporate data].",
                    "[Specific Business Unit]: Justified because it operates on a completely air-gapped network with no interaction with the primary enterprise domain.",
                ],
            },
            {
                "id": "6_stakeholders_external_dependencies",
                "title": "6. Stakeholders and External Dependencies",
                "body": "The scope also accounts for the security requirements of:",
                "bullets": [
                    "Customers: Specifically those utilizing the [Specific Service Name].",
                    "Regulators: Compliance with [Local/Industry Law, e.g., GDPR, HIPAA].",
                    "Third-Party Vendors: Specifically [Cloud Provider Name, e.g., Microsoft Azure] for hybrid identity services.",
                ],
            },
        ],
    }


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _scope_data_dir() -> Path:
    d = _project_root() / "data" / "raw"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _dashboard_path() -> Path:
    return _project_root() / "data" / "raw" / "dashboard.json"


def _system_status_path(year: int) -> Path:
    return _project_root() / "data" / "work" / str(year) / "systemstatus.json"


def _read_dashboard() -> dict:
    p = _dashboard_path()
    if not p.exists():
        raise HTTPException(status_code=404, detail=f"dashboard.json not found at: {p}")

    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read dashboard.json: {e}")


def _scope_status_prefers_working_draft(year: int) -> bool:
    p = _system_status_path(year)
    if not p.exists():
        return False

    try:
        status_doc = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return False

    status = (
        ((status_doc.get("sections") or {}).get("scope_context") or {}).get("status") or ""
    ).strip()
    return status.lower() in {"not started", "in progress"}


_SCOPE_FILE_RE = re.compile(r"^\d{4}-Scope(?:-[A-Za-z0-9_]+)?-v\d+\.json$")
_SCOPE_VERSION_RE = re.compile(r"^(\d{4}-Scope(?:-[A-Za-z0-9_]+)?)-v(\d+)\.json$")


def _default_draft_filename(year: int) -> str:
    return f"{year}-Scope-Draft-v0.json"


def _ensure_default_draft_exists(year: int) -> Path:
    p = _scope_data_dir() / _default_draft_filename(year)
    if not p.exists():
        p.write_text(
            json.dumps(_default_scope(year), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    return p


def _validate_scope_filename(year: int, filename: str) -> str:
    filename = (filename or "").strip()

    if not filename:
        raise HTTPException(status_code=400, detail="filename is required")

    if not _SCOPE_FILE_RE.match(filename):
        raise HTTPException(status_code=400, detail=f"Invalid scope filename: {filename}")

    if not filename.startswith(f"{year}-Scope"):
        raise HTTPException(status_code=400, detail=f"Filename year mismatch: {filename}")

    return filename


def _latest_scope_filename(year: int) -> str | None:
    scope_dir = _scope_data_dir()
    latest_name = None
    latest_version = -1

    for p in scope_dir.glob(f"{year}-Scope*.json"):
        m = _SCOPE_VERSION_RE.match(p.name)
        if not m:
            continue

        version_num = int(m.group(2))
        if version_num > latest_version:
            latest_version = version_num
            latest_name = p.name

    return latest_name


def _scope_filename_from_dashboard(year: int) -> str | None:
    dashboard = _read_dashboard()

    filename = (dashboard.get("scope_file_name") or "").strip()
    if filename:
        return _validate_scope_filename(year, filename)

    scope = dashboard.get("scope") or {}
    filename = (scope.get("scope_file_name") or "").strip()
    if filename:
        return _validate_scope_filename(year, filename)

    return None


def _load_or_create(year: int, filename: str) -> dict:
    scope_dir = _scope_data_dir()
    p = scope_dir / filename

    if not p.exists():
        if filename == _default_draft_filename(year):
            _ensure_default_draft_exists(year)
        else:
            raise HTTPException(status_code=404, detail=f"Scope file not found: {filename}")

    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read scope file {filename}: {e}")

    doc.setdefault("meta", {})
    doc["meta"]["source_file"] = filename
    return doc


@router.get("/context")
def get_scope_context(year: int = 2026):
    default_filename = _default_draft_filename(year)
    _ensure_default_draft_exists(year)

    if _scope_status_prefers_working_draft(year):
        doc = _load_or_create(year, default_filename)
        doc.setdefault("meta", {})
        doc["meta"]["fallback_used"] = False
        doc["meta"]["missing_saved_file"] = None
        doc["meta"]["popup_message"] = None
        return doc

    filename = _scope_filename_from_dashboard(year)
    if filename:
        p = _scope_data_dir() / filename

        if p.exists():
            doc = _load_or_create(year, filename)
            doc.setdefault("meta", {})
            doc["meta"]["fallback_used"] = False
            doc["meta"]["missing_saved_file"] = None
            doc["meta"]["popup_message"] = None
            return doc

        doc = _load_or_create(year, default_filename)
        doc.setdefault("meta", {})
        doc["meta"]["fallback_used"] = True
        doc["meta"]["missing_saved_file"] = filename
        doc["meta"]["popup_message"] = (
            f'The scope file "{filename}" is missing. '
            f'Load the default scope template "{default_filename}".'
        )
        return doc

    latest = _latest_scope_filename(year)
    if latest:
        return _load_or_create(year, latest)

    doc = _load_or_create(year, default_filename)
    doc.setdefault("meta", {})
    doc["meta"]["fallback_used"] = False
    doc["meta"]["missing_saved_file"] = None
    doc["meta"]["popup_message"] = None
    return doc


@router.get("/file")
def get_scope_by_filename(year: int = 2026, filename: str = ""):
    filename = _validate_scope_filename(year, filename)
    return _load_or_create(year, filename)
