from pathlib import Path
from typing import Any
import json
import re
import subprocess
import sys
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from app.api.workflow_gate import ensure_previous_steps_completed

router = APIRouter(
    prefix="/api/controls-postures",
    tags=["controls-postures"],
)

VALID_STEP_STATUSES = {"Blocked", "Not Started", "In Progress", "Completed"}

class CreateControlsPosturesRequest(BaseModel):
    year: int = 2026
    force_reset: bool = False


class ResetControlsPosturesRequest(BaseModel):
    year: int = 2026


class AssessControlsPosturesRequest(BaseModel):
    year: int = 2026


class SubmitControlsPosturesRequest(BaseModel):
    year: int = 2026


def find_project_root() -> Path:
    current = Path(__file__).resolve()
    for parent in [current] + list(current.parents):
        if (parent / "data").exists():
            return parent
    raise RuntimeError("Could not find project root containing data folder")


BASE_DIR = find_project_root()


def _work_dir(year: int) -> Path:
    return BASE_DIR / "data" / "work" / str(year)


def _controls_file(year: int) -> Path:
    return _work_dir(year) / "ExistingControlsPostures.json"


def _asset_inventory_file(year: int) -> Path:
    return _work_dir(year) / "assetinventory.json"


def _asset_details_file(year: int) -> Path:
    work = _work_dir(year)
    lower_name = work / "assetdetails.json"
    proper_name = work / "AssetDetails.json"

    if lower_name.exists():
        return lower_name
    return proper_name


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


def _targets_file() -> Path:
    return BASE_DIR / "lab-scanner" / "config" / "targets.json"


def _vm_controls_output_file(year: int) -> Path:
    return BASE_DIR / "data" / "work" / str(year) / "VMControlsPostures.json"


def _lab_scanner_script() -> Path:
    return BASE_DIR / "lab-scanner" / "scripts" / "ControslPosturesScanner.py"


def _read_json(path: Path, default: Any):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def _write_json(path: Path, data: Any):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def _normalize_hosts(data: Any) -> list[dict]:
    if isinstance(data, dict):
        hosts = data.get("hosts", [])
        if isinstance(hosts, list):
            return [x for x in hosts if isinstance(x, dict)]
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    return []


def _controls_file_has_records(path: Path) -> bool:
    if not path.exists():
        return False

    data = _read_json(path, {})
    hosts = _normalize_hosts(data)
    return len(hosts) > 0


def _get_cia_rating(host: dict) -> str:
    return (
        str(host.get("CIA rating") or "").strip()
        or str(host.get("cia_rating") or "").strip()
        or str(host.get("cia") or "").strip()
    )


def _safe_existing_controls(host: dict) -> dict[str, list[str]]:
    raw = host.get("existing_controls", {})
    if not isinstance(raw, dict):
        return {}

    cleaned: dict[str, list[str]] = {}

    for category, values in raw.items():
        category_name = str(category).strip()
        if not category_name:
            continue

        if isinstance(values, list):
            cleaned_values = [
                str(v).strip()
                for v in values
                if str(v).strip()
            ]
        else:
            cleaned_values = []

        cleaned[category_name] = cleaned_values

    return cleaned


def _extract_control_rows(host: dict) -> list[dict]:
    rows: list[dict] = []
    controls = _safe_existing_controls(host)

    for category, values in controls.items():
        if not values:
            continue

        rows.append(
            {
                "category": category,
                "name": ", ".join(values),
            }
        )

    return rows


def _count_controls(host: dict) -> int:
    controls = _safe_existing_controls(host)
    total = 0

    for values in controls.values():
        total += len(values)

    return total


def _update_system_status(year: int, new_status: str):
    if new_status not in VALID_STEP_STATUSES:
        raise ValueError(f"Invalid status: {new_status}")

    path = _system_status_file(year)

    if not path.exists():
        raise FileNotFoundError(f"SystemStatus.json not found: {path}")

    data = _read_json(path, None)

    if not isinstance(data, dict):
        raise ValueError(f"Invalid SystemStatus.json structure: {path}")

    sections = data.get("sections")
    if not isinstance(sections, dict):
        raise ValueError(f"Missing 'sections' in: {path}")

    if "existing_controls_postures" not in sections or not isinstance(sections["existing_controls_postures"], dict):
        sections["existing_controls_postures"] = {}

    sections["existing_controls_postures"]["status"] = new_status
    _write_json(path, data)

def _extract_assets_from_inventory(data: Any) -> list[dict]:
    assets: list[dict] = []

    if not isinstance(data, dict):
        return assets

    subnets = data.get("subnets", [])
    if not isinstance(subnets, list):
        return assets

    for subnet in subnets:
        if not isinstance(subnet, dict):
            continue

        subnet_assets = subnet.get("assets", [])
        if not isinstance(subnet_assets, list):
            continue

        for asset in subnet_assets:
            if isinstance(asset, dict):
                assets.append(asset)

    return assets


def _load_asset_inventory_host_map(year: int) -> dict[str, dict]:
    data = _read_json(_asset_inventory_file(year), {})
    result: dict[str, dict] = {}

    for asset in _extract_assets_from_inventory(data):
        hostname = _normalize_hostname(asset.get("hostname", ""))
        if hostname:
            result[hostname] = asset

    return result


def _build_controls_file_from_inventory(inventory_data: Any) -> dict:
    hosts: list[dict] = []

    for asset in _extract_assets_from_inventory(inventory_data):
        location = asset.get("location", {})
        if not isinstance(location, dict):
            location = {}

        cia_rating = asset.get("cia_rating", {})
        if not isinstance(cia_rating, dict):
            cia_rating = {}

        existing_controls = asset.get("existing_controls", {})
        if not isinstance(existing_controls, dict):
            existing_controls = {}

        hosts.append(
            {
                "hostname": str(asset.get("hostname", "")).strip(),
                "ip_address": str(location.get("ip_address", "")).strip(),
                "role": str(asset.get("role", "")).strip(),
                "CIA rating": str(cia_rating.get("criticality", "")).strip(),
                "existing_controls": existing_controls,
            }
        )

    return {
        "status": "In Progress",
        "meta": {
            "submitted": False,
            "read_only": False,
        },
        "hosts": hosts,
    }


def _read_current_controls_status(year: int) -> str:
    data = _read_json(_system_status_file(year), {})
    if not isinstance(data, dict):
        return "Not Started"

    sections = data.get("sections", {})
    if not isinstance(sections, dict):
        return "Not Started"

    section = sections.get("existing_controls_postures", {})
    if not isinstance(section, dict):
        return "Not Started"

    status = section.get("status", "Not Started")
    if status not in VALID_STEP_STATUSES:
        return "Not Started"

    return status


def _normalize_hostname(value: str) -> str:
    return str(value or "").strip().lower()


def _load_assetdetails_host_map(year: int) -> dict[str, dict]:
    path = _asset_details_file(year)
    data = _read_json(path, {})
    result: dict[str, dict] = {}

    if not isinstance(data, dict):
        return result

    networks = data.get("networks", [])
    if not isinstance(networks, list):
        return result

    for network in networks:
        if not isinstance(network, dict):
            continue

        subnets = network.get("subnets", [])
        if not isinstance(subnets, list):
            continue

        for subnet in subnets:
            if not isinstance(subnet, dict):
                continue

            hosts = subnet.get("hosts", [])
            if not isinstance(hosts, list):
                continue

            for host in hosts:
                if not isinstance(host, dict):
                    continue

                hostname = _normalize_hostname(host.get("hostname", ""))
                if hostname:
                    result[hostname] = host

    return result


def _extract_existing_control_from_assetdetails(asset_host: dict) -> dict[str, list[str]]:
    if not isinstance(asset_host, dict):
        return {}

    detail = asset_host.get("detail", {})
    if not isinstance(detail, dict):
        return {}

    existing_control = detail.get("existing_control", {})
    if not isinstance(existing_control, dict):
        return {}

    cleaned: dict[str, list[str]] = {}

    for category, values in existing_control.items():
        category_name = str(category).strip()
        if not category_name:
            continue

        if isinstance(values, list):
            cleaned_values = [str(v).strip() for v in values if str(v).strip()]
        else:
            cleaned_values = []

        cleaned[category_name] = cleaned_values

    return cleaned


def _extract_live_controls_from_inventory_asset(asset: dict) -> dict[str, list[str]]:
    if not isinstance(asset, dict):
        return {}

    role = str(asset.get("role", "")).strip()
    role_lower = role.lower()

    detail = asset.get("detail", {})
    if not isinstance(detail, dict):
        detail = {}

    indicators = detail.get("technical_indicators", {})
    if not isinstance(indicators, dict):
        indicators = {}

    open_ports = indicators.get("open_ports", [])
    if not isinstance(open_ports, list):
        open_ports = []

    running_services = indicators.get("running_services", [])
    if not isinstance(running_services, list):
        running_services = []
    running_text = " | ".join(str(x).strip().lower() for x in running_services if str(x).strip())

    installed_roles = indicators.get("installed_roles", [])
    if not isinstance(installed_roles, list):
        installed_roles = []
    installed_roles_text = " | ".join(str(x).strip().lower() for x in installed_roles if str(x).strip())

    installed_software = indicators.get("installed_software", [])
    if not isinstance(installed_software, list):
        installed_software = []
    installed_software_text = " | ".join(str(x).strip().lower() for x in installed_software if str(x).strip())

    controls: dict[str, list[str]] = {}

    def add(category: str, value: str) -> None:
        if not value:
            return
        controls.setdefault(category, [])
        if value not in controls[category]:
            controls[category].append(value)

    add("Identity & Access Management", "Password Policies (complexity, rotation)")

    if (
        "domain controller" in role_lower
        or "active directory" in role_lower
        or "active directory domain services" in running_text
        or "ad ds" in installed_roles_text
        or 88 in open_ports
        or 389 in open_ports
        or 636 in open_ports
    ):
        add("Identity & Access Management", "Active Directory Domain Services (AD DS)")
        add("Identity & Access Management", "Group Policy Objects (GPO)")
        add("Identity & Access Management", "Role-Based Access Control (RBAC)")

    if "dns server" in running_text or "dns server" in installed_roles_text or 53 in open_ports:
        add("Network Security Controls", "DNS Security (DNS filtering / logging)")

    if (
        "windows server" in str(asset.get("operating_system", "")).strip().lower()
        or "server" in role_lower
        or "vmware tools" in installed_software_text
    ):
        add("Endpoint Security Controls", "Secure Boot")
        add("Physical & Environmental Controls", "Server Room Access Control")

    add("Endpoint Security Controls", "Antivirus / Anti-malware")

    if open_ports or running_services:
        add("Network Security Controls", "Windows Firewall (Host-based)")

    if running_services or installed_roles or installed_software:
        add("Logging, Monitoring & Detection", "Windows Event Logging")

    if "server" in role_lower or "domain controller" in role_lower or "dns server" in role_lower:
        add("Vulnerability & Patch Management", "Patch Management (WSUS / SCCM)")

    return controls


def _load_vm_targets_map() -> dict[str, dict]:
    path = _targets_file()
    data = _read_json(path, {})
    result: dict[str, dict] = {}

    if not isinstance(data, dict):
        return result

    hosts = data.get("hosts", [])
    if not isinstance(hosts, list):
        return result

    for host in hosts:
        if not isinstance(host, dict):
            continue

        hostname = _normalize_hostname(host.get("hostname", ""))
        if hostname:
            result[hostname] = host

    return result


def _run_vm_controls_scanner(year: int) -> dict[str, dict]:
    script_path = _lab_scanner_script()
    output_path = _vm_controls_output_file(year)

    if not script_path.exists():
        raise FileNotFoundError(f"Scanner script not found: {script_path}")

    result = subprocess.run(
        [sys.executable, str(script_path)],
        cwd=str(BASE_DIR),
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        raise RuntimeError(
            "VM controls scanner failed.\n"
            f"STDOUT:\n{result.stdout}\n\nSTDERR:\n{result.stderr}"
        )

    output_data = _read_json(output_path, {})
    hosts = _normalize_hosts(output_data)

    vm_map: dict[str, dict] = {}
    for host in hosts:
        hostname = _normalize_hostname(host.get("hostname", ""))
        if hostname:
            vm_map[hostname] = host

    return vm_map


def _is_vm_target_reachable(ip_address: str, hostname: str = "") -> bool:
    candidates: list[str] = []

    if str(hostname).strip():
        candidates.append(str(hostname).strip())
    if str(ip_address).strip() and str(ip_address).strip() not in candidates:
        candidates.append(str(ip_address).strip())

    for target in candidates:
        try:
            result = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    f"try {{ Test-WSMan -ComputerName '{target}' | Out-Null; exit 0 }} catch {{ exit 1 }}",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except Exception:
            continue

        if result.returncode == 0:
            return True

    return False


@router.post("/new")
def create_new_controls_postures(req: CreateControlsPosturesRequest):
    if not _has_submitted_scope_document():
        raise HTTPException(
            status_code=400,
            detail="Submit the Scope & Context document first before starting Existing Controls & Postures.",
        )

    inventory_path = _asset_inventory_file(req.year)
    controls_path = _controls_file(req.year)

    if not inventory_path.exists():
        raise HTTPException(status_code=404, detail=f"Inventory file not found: {inventory_path}")

    existed_before = _controls_file_has_records(controls_path)

    if existed_before and not req.force_reset:
        raise HTTPException(status_code=409, detail="FILE_ALREADY_EXISTS_CONFIRM_RESET")

    inventory_data = _read_json(inventory_path, {})
    controls_data = _build_controls_file_from_inventory(inventory_data)
    _write_json(controls_path, controls_data)

    try:
        _update_system_status(req.year, "In Progress")
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to update SystemStatus.json: {e}",
        ) from e

    return {
        "success": True,
        "existed_before": existed_before,
        "recreated": existed_before and req.force_reset,
        "created_file": str(controls_path),
        "status": "In Progress",
        "message": "New existing controls and postures assessment Started",
    }


@router.post("/assess")
def assess_controls_postures(req: AssessControlsPosturesRequest):
    if not _has_submitted_scope_document():
        raise HTTPException(
            status_code=400,
            detail="Submit the Scope & Context document first before starting Existing Controls & Postures.",
        )

    live_vm_hosts: list[str] = []
    direct_vm_controls_hosts: list[str] = []
    live_inventory_fallback_vm_hosts: list[str] = []
    assetdetails_fallback_vm_hosts: list[str] = []
    unreachable_vm_hosts: list[str] = []

    controls_path = _controls_file(req.year)

    if not controls_path.exists():
        raise HTTPException(status_code=404, detail=f"Controls/Postures file not found: {controls_path}")

    raw = _read_json(controls_path, None)
    if not isinstance(raw, dict):
        raise HTTPException(status_code=500, detail=f"Invalid JSON structure in: {controls_path}")

    hosts = raw.get("hosts")
    if not isinstance(hosts, list):
        raise HTTPException(status_code=500, detail=f"Missing or invalid 'hosts' list in: {controls_path}")

    targets_map = _load_vm_targets_map()
    assetdetails_map = _load_assetdetails_host_map(req.year)
    inventory_host_map = _load_asset_inventory_host_map(req.year)

    vm_results_map: dict[str, dict] = {}
    if targets_map:
        try:
            vm_results_map = _run_vm_controls_scanner(req.year)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"VM scanning failed: {e}") from e

    other_hosts: list[str] = []

    for host in hosts:
        if not isinstance(host, dict):
            continue

        hostname = str(host.get("hostname", "")).strip()
        normalized_hostname = _normalize_hostname(hostname)

        if normalized_hostname in targets_map:
            target_host = targets_map.get(normalized_hostname, {})
            target_ip = str(target_host.get("ip_address", "")).strip()
            if _is_vm_target_reachable(target_ip, hostname):
                live_vm_hosts.append(hostname)
            else:
                unreachable_vm_hosts.append(hostname)

            vm_host = vm_results_map.get(normalized_hostname, {})
            vm_controls = _safe_existing_controls(vm_host)

            if vm_controls:
                host["existing_controls"] = vm_controls
                direct_vm_controls_hosts.append(hostname)
            else:
                inventory_asset = inventory_host_map.get(normalized_hostname, {})
                fallback_controls = _extract_live_controls_from_inventory_asset(inventory_asset)
                if not fallback_controls:
                    asset_host = assetdetails_map.get(normalized_hostname, {})
                    fallback_controls = _extract_existing_control_from_assetdetails(asset_host)
                    if fallback_controls:
                        assetdetails_fallback_vm_hosts.append(hostname)
                else:
                    live_inventory_fallback_vm_hosts.append(hostname)
                host["existing_controls"] = fallback_controls
        else:
            asset_host = assetdetails_map.get(normalized_hostname, {})
            host["existing_controls"] = _extract_existing_control_from_assetdetails(asset_host)
            other_hosts.append(hostname)

    raw["hosts"] = hosts
    raw["status"] = "In Progress"
    _write_json(controls_path, raw)

    try:
        _update_system_status(req.year, "In Progress")
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Assessment completed, but failed to update SystemStatus.json: {e}",
        ) from e

    lines = [
        "Existing Controls & Postures assessment completed succesfully.",
        "Live VM machines detected:",
    ]

    if live_vm_hosts:
        lines.extend([f"- {name}" for name in live_vm_hosts])
    else:
        lines.append("- None")

    lines.append("VM hosts with direct live controls collection:")
    if direct_vm_controls_hosts:
        lines.extend([f"- {name}" for name in direct_vm_controls_hosts])
    else:
        lines.append("- None")

    lines.append("VM hosts populated using live inventory fallback:")
    if live_inventory_fallback_vm_hosts:
        lines.extend([f"- {name}" for name in live_inventory_fallback_vm_hosts])
    else:
        lines.append("- None")

    lines.append("VM hosts populated using AssetDetails fallback:")
    if assetdetails_fallback_vm_hosts:
        lines.extend([f"- {name}" for name in assetdetails_fallback_vm_hosts])
    else:
        lines.append("- None")

    lines.append("Configured VM targets not reachable:")
    if unreachable_vm_hosts:
        lines.extend([f"- {name}" for name in unreachable_vm_hosts])
    else:
        lines.append("- None")

    lines.append("Other hosts:")
    if other_hosts:
        lines.extend([f"- {name}" for name in other_hosts])
    else:
        lines.append("- None")

    return {
        "success": True,
        "year": req.year,
        "status": "In Progress",
        "live_vm_hosts": live_vm_hosts,
        "direct_vm_controls_hosts": direct_vm_controls_hosts,
        "live_inventory_fallback_vm_hosts": live_inventory_fallback_vm_hosts,
        "assetdetails_fallback_vm_hosts": assetdetails_fallback_vm_hosts,
        "unreachable_vm_hosts": unreachable_vm_hosts,
        "other_hosts": other_hosts,
        "message": "\n".join(lines),
    }


@router.post("/reset")
def reset_controls_postures(req: ResetControlsPosturesRequest):
    controls_path = _controls_file(req.year)

    if not controls_path.exists():
        raise HTTPException(status_code=404, detail=f"Controls/Postures file not found: {controls_path}")

    raw = _read_json(controls_path, None)

    if not isinstance(raw, dict):
        raise HTTPException(status_code=500, detail=f"Invalid JSON structure in: {controls_path}")

    hosts = raw.get("hosts")
    if not isinstance(hosts, list):
        raise HTTPException(status_code=500, detail=f"Missing or invalid 'hosts' list in: {controls_path}")

    cleared_items = 0

    for host in hosts:
        if not isinstance(host, dict):
            continue

        controls = host.get("existing_controls", {})
        if isinstance(controls, dict):
            for values in controls.values():
                if isinstance(values, list):
                    cleared_items += len(values)

        host["existing_controls"] = {}

    raw["hosts"] = hosts
    raw["status"] = "Not Started"
    meta = raw.get("meta", {})
    if not isinstance(meta, dict):
        meta = {}
        raw["meta"] = meta
    meta["submitted"] = False
    meta["read_only"] = False
    _write_json(controls_path, raw)

    try:
        _update_system_status(req.year, "Not Started")
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Controls/Postures reset succeeded, but failed to update SystemStatus.json: {e}",
        ) from e

    return {
        "success": True,
        "year": req.year,
        "status": "Not Started",
        "message": "Existing Controls and Postures Assessment restarted.",
        "cleared_items": cleared_items,
    }


@router.post("/submit")
def submit_controls_postures(req: SubmitControlsPosturesRequest):
    ensure_previous_steps_completed(req.year, "existing_controls_postures")
    controls_path = _controls_file(req.year)

    if not controls_path.exists():
        raise HTTPException(status_code=404, detail=f"Controls/Postures file not found: {controls_path}")

    raw = _read_json(controls_path, None)
    if not isinstance(raw, dict):
        raise HTTPException(status_code=500, detail=f"Invalid JSON structure in: {controls_path}")

    hosts = _normalize_hosts(raw)
    if not hosts:
        raise HTTPException(
            status_code=400,
            detail="There are no Existing Controls & Postures hosts to submit yet. Run /assess first.",
        )

    total_controls = sum(_count_controls(host) for host in hosts if isinstance(host, dict))
    if total_controls == 0:
        raise HTTPException(
            status_code=400,
            detail="Existing Controls & Postures has no control records yet. Run /assess before /submit.",
        )

    meta = raw.get("meta", {})
    if not isinstance(meta, dict):
        meta = {}
        raw["meta"] = meta
    raw["status"] = "Completed"
    meta["submitted"] = True
    meta["read_only"] = True
    _write_json(controls_path, raw)

    try:
        _update_system_status(req.year, "Completed")
        status_doc = _read_json(_system_status_file(req.year), {})
        if isinstance(status_doc, dict):
            sections = status_doc.get("sections")
            if not isinstance(sections, dict):
                sections = {}
                status_doc["sections"] = sections

            next_section = sections.get("risk_analysis")
            if not isinstance(next_section, dict):
                next_section = {}
                sections["risk_analysis"] = next_section

            if next_section.get("status") != "Completed":
                next_section["status"] = "In Progress"

            _write_json(_system_status_file(req.year), status_doc)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Existing Controls & Postures submit succeeded logically, but failed to update SystemStatus.json: {e}",
        ) from e

    return {
        "success": True,
        "year": req.year,
        "status": "Completed",
        "message": "Existing Controls & Postures assessment submitted successfully.",
    }


@router.get("/summary")
def get_controls_postures_summary(year: int = Query(2026)):
    path = _controls_file(year)
    raw = _read_json(path, {"hosts": []})
    hosts = _normalize_hosts(raw)

    total_controls = 0
    host_rows: list[dict] = []

    for host in hosts:
        rows = _extract_control_rows(host)
        item_count = _count_controls(host)
        total_controls += item_count

        host_rows.append(
            {
                "hostname": str(host.get("hostname", "")).strip(),
                "role": str(host.get("role", "")).strip(),
                "ip_address": str(host.get("ip_address", "")).strip(),
                "cia_rating": _get_cia_rating(host),
                "items_count": item_count,
                "rows": rows,
                "existing_controls": _safe_existing_controls(host),
            }
        )

    status = _read_current_controls_status(year)

    return {
        "success": True,
        "year": year,
        "status": status,
        "kpis": {
            "hosts": len(hosts),
            "controls": total_controls,
        },
        "hosts": host_rows,
    }


@router.get("/items")
def get_controls_postures_items(year: int = Query(2026)):
    path = _controls_file(year)
    raw = _read_json(path, {"hosts": []})
    hosts = _normalize_hosts(raw)

    status = _read_current_controls_status(year)

    return {
        "success": True,
        "year": year,
        "status": status,
        "hosts": hosts,
    }


@router.get("/host-details")
def get_host_controls_postures_details(
    hostname: str = Query(...),
    year: int = Query(2026),
):
    path = _controls_file(year)
    raw = _read_json(path, {"hosts": []})
    hosts = _normalize_hosts(raw)

    normalized_hostname = hostname.strip().lower()

    for host in hosts:
        host_name = str(host.get("hostname", "")).strip().lower()
        if host_name == normalized_hostname:
            return {
                "success": True,
                "host": {
                    "hostname": str(host.get("hostname", "")).strip(),
                    "role": str(host.get("role", "")).strip(),
                    "ip_address": str(host.get("ip_address", "")).strip(),
                    "cia_rating": _get_cia_rating(host),
                    "existing_controls": _safe_existing_controls(host),
                    "rows": _extract_control_rows(host),
                },
            }

    raise HTTPException(status_code=404, detail=f"Host '{hostname}' not found.")
