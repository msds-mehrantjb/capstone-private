from pathlib import Path
from typing import Any, Optional

import json
import requests
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

router = APIRouter(
    prefix="/api/threat-vulnerabilities",
    tags=["threat-vulnerabilities"],
)

VALID_STEP_STATUSES = {"Blocked", "Not Started", "In Progress", "Completed"}


class CreateThreatAssessmentRequest(BaseModel):
    year: int = 2026
    force_reset: bool = False


class ResetThreatAssessmentRequest(BaseModel):
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


def _tv_file(year: int) -> Path:
    return _work_dir(year) / "AssetVulnerabilitiesThreats.json"


def _asset_inventory_file(year: int) -> Path:
    return _work_dir(year) / "assetinventory.json"


def _system_status_file(year: int) -> Path:
    return _work_dir(year) / "systemstatus.json"


def _nvd_cve_file() -> Path:
    return BASE_DIR / "data" / "ml" / "nvdcve-2.0-modified.json"


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


def _safe_vulns(host: dict) -> list[dict]:
    vuls = host.get("vulnerabilities_threats", [])
    if not isinstance(vuls, list):
        return []
    return [item for item in vuls if isinstance(item, dict)]


def _get_cia_rating(host: dict) -> str:
    return (
        host.get("CIA rating")
        or host.get("cia_rating")
        or host.get("cia")
        or "Unscanned"
    )


def _extract_vuln_rows(host: dict) -> list[dict]:
    rows: list[dict] = []

    for item in _safe_vulns(host):
        rows.append(
            {
                "vulnerability_name": item.get("vulnerability_name", ""),
                "public_exploit_name": item.get("public_exploit_name", ""),
                "severity": item.get("severity", ""),
                "cvss_score": item.get("cvss_score", ""),
                "cve": item.get("cve", ""),
            }
        )

    return rows


def _update_system_status(year: int, new_status: str):
    if new_status not in VALID_STEP_STATUSES:
        raise ValueError(f"Invalid status: {new_status}")

    path = _system_status_file(year)

    if not path.exists():
        raise FileNotFoundError(f"systemstatus.json not found: {path}")

    data = _read_json(path, None)

    if not isinstance(data, dict):
        raise ValueError(f"Invalid systemstatus.json structure: {path}")

    sections = data.get("sections")
    if not isinstance(sections, dict):
        raise ValueError(f"Missing 'sections' in: {path}")

    if "threats_vulns" not in sections or not isinstance(sections["threats_vulns"], dict):
        sections["threats_vulns"] = {}

    sections["threats_vulns"]["status"] = new_status
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


def _build_threat_file_from_inventory(inventory_data: Any) -> dict:
    hosts: list[dict] = []

    for asset in _extract_assets_from_inventory(inventory_data):
        location = asset.get("location", {})
        if not isinstance(location, dict):
            location = {}

        cia_rating = asset.get("cia_rating", {})
        if not isinstance(cia_rating, dict):
            cia_rating = {}

        hosts.append(
            {
                "hostname": str(asset.get("hostname", "")).strip(),
                "ip_address": str(location.get("ip_address", "")).strip(),
                "role": str(asset.get("role", "")).strip(),
                "CIA rating": str(cia_rating.get("criticality", "Unscanned")).strip() or "Unscanned",
                "vulnerabilities_threats": [],
            }
        )

    return {"hosts": hosts}


def _load_nvd_cve_data() -> list[dict]:
    path = _nvd_cve_file()

    if not path.exists():
        raise FileNotFoundError(f"NVD CVE file not found: {path}")

    raw = _read_json(path, {})
    vulnerabilities = raw.get("vulnerabilities", [])

    if not isinstance(vulnerabilities, list):
        raise ValueError(f"Invalid NVD file structure: {path}")

    return [item for item in vulnerabilities if isinstance(item, dict)]


def _extract_cvss_metrics(cve_data: dict) -> dict:
    metrics = cve_data.get("metrics", {})
    if not isinstance(metrics, dict):
        return {}

    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(key, [])
        if isinstance(metric_list, list) and metric_list:
            metric = metric_list[0]
            if isinstance(metric, dict):
                return metric

    return {}


def _parse_nvd_item(item: dict) -> Optional[dict]:
    cve = item.get("cve", {})
    if not isinstance(cve, dict):
        return None

    current_id = str(cve.get("id", "")).strip().upper()
    if not current_id:
        return None

    descriptions = cve.get("descriptions", [])
    description_text = ""
    if isinstance(descriptions, list):
        for desc in descriptions:
            if isinstance(desc, dict) and desc.get("lang") == "en":
                description_text = str(desc.get("value", "")).strip()
                break

    weaknesses = []
    weakness_data = cve.get("weaknesses", [])
    if isinstance(weakness_data, list):
        for weakness in weakness_data:
            if not isinstance(weakness, dict):
                continue
            descs = weakness.get("description", [])
            if isinstance(descs, list):
                for d in descs:
                    if isinstance(d, dict) and d.get("lang") == "en":
                        value = str(d.get("value", "")).strip()
                        if value:
                            weaknesses.append(value)

    references = []
    ref_data = cve.get("references", [])
    if isinstance(ref_data, list):
        for ref in ref_data:
            if isinstance(ref, dict):
                references.append(
                    {
                        "url": str(ref.get("url", "")).strip(),
                        "source": str(ref.get("source", "")).strip(),
                        "tags": ref.get("tags", []) if isinstance(ref.get("tags", []), list) else [],
                    }
                )

    metric = _extract_cvss_metrics(cve)
    cvss_data = metric.get("cvssData", {}) if isinstance(metric, dict) else {}

    return {
        "cve": current_id,
        "source_identifier": str(cve.get("sourceIdentifier", "")).strip(),
        "published": cve.get("published", ""),
        "last_modified": cve.get("lastModified", ""),
        "status": cve.get("vulnStatus", ""),
        "description": description_text,
        "severity": metric.get("baseSeverity", ""),
        "cvss_score": cvss_data.get("baseScore", ""),
        "exploitability_score": metric.get("exploitabilityScore", ""),
        "impact_score": metric.get("impactScore", ""),
        "attack_vector": cvss_data.get("attackVector", ""),
        "attack_complexity": cvss_data.get("attackComplexity", ""),
        "privileges_required": cvss_data.get("privilegesRequired", ""),
        "user_interaction": cvss_data.get("userInteraction", ""),
        "scope": cvss_data.get("scope", ""),
        "confidentiality_impact": cvss_data.get("confidentialityImpact", ""),
        "integrity_impact": cvss_data.get("integrityImpact", ""),
        "availability_impact": cvss_data.get("availabilityImpact", ""),
        "weaknesses": weaknesses,
        "references": references,
    }


def _find_cve_details_local(cve_id: str) -> Optional[dict]:
    normalized = cve_id.strip().upper()

    for item in _load_nvd_cve_data():
        cve = item.get("cve", {})
        if not isinstance(cve, dict):
            continue

        current_id = str(cve.get("id", "")).strip().upper()
        if current_id == normalized:
            parsed = _parse_nvd_item(item)
            if parsed:
                parsed["retrieval_source"] = "local_json"
                return parsed

    return None


def _find_cve_details_from_nvd_api(cve_id: str) -> Optional[dict]:
    normalized = cve_id.strip().upper()

    response = requests.get(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"cveId": normalized},
        timeout=20,
    )
    response.raise_for_status()

    raw = response.json()
    vulnerabilities = raw.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list) or not vulnerabilities:
        return None

    parsed = _parse_nvd_item(vulnerabilities[0])
    if parsed:
        parsed["retrieval_source"] = "nvd_api"
    return parsed


def _ollama_format_cve(cve_data: dict) -> str:
    prompt = f"""
You are a cybersecurity analyst.

Format the following CVE data exactly in this structure:

CVE: <id>
Severity: <severity> (<score>)

Description:
<description>

Exploitability:
- Attack Vector: <value>
- Complexity: <value>
- Privileges Required: <value>
- User Interaction: <value>

Impact:
- Confidentiality: <value>
- Integrity: <value>
- Availability: <value>

Weakness:
<comma-separated weaknesses or N/A>

References:
- <short source or tag list>
- <short source or tag list>

Rules:
- Do not invent facts.
- If a value is missing, write N/A.
- Keep wording concise.
- Use only the provided data.

CVE DATA:
{json.dumps(cve_data, indent=2, ensure_ascii=False)}
"""

    response = requests.post(
        "http://127.0.0.1:11434/api/generate",
        json={
            "model": "llama3",
            "prompt": prompt,
            "stream": False,
        },
        timeout=60,
    )
    response.raise_for_status()

    raw = response.json()
    text = str(raw.get("response", "")).strip()

    if not text:
        raise RuntimeError("Ollama returned empty response")

    return text


def _get_cve_detail_with_fallback(cve_id: str) -> dict:
    result = _find_cve_details_local(cve_id)
    if result:
        return result

    result = _find_cve_details_from_nvd_api(cve_id)
    if result:
        return result

    raise HTTPException(
        status_code=404,
        detail=f"CVE '{cve_id}' not found in local dataset or NVD API.",
    )


@router.post("/new")
def create_new_threat_assessment(req: CreateThreatAssessmentRequest):
    inventory_path = _asset_inventory_file(req.year)
    threat_path = _tv_file(req.year)

    if not inventory_path.exists():
        raise HTTPException(status_code=404, detail=f"Inventory file not found: {inventory_path}")

    existed_before = threat_path.exists()

    if existed_before and not req.force_reset:
        raise HTTPException(status_code=409, detail="FILE_ALREADY_EXISTS_CONFIRM_RESET")

    inventory_data = _read_json(inventory_path, {})
    threat_data = _build_threat_file_from_inventory(inventory_data)
    _write_json(threat_path, threat_data)

    try:
        _update_system_status(req.year, "In Progress")
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to update systemstatus.json: {e}",
        ) from e

    return {
        "success": True,
        "existed_before": existed_before,
        "recreated": existed_before and req.force_reset,
        "created_file": str(threat_path),
        "status": "In Progress",
        "message": "New vulnerability and threat assessment started",
    }


@router.post("/reset")
def reset_threat_assessment(req: ResetThreatAssessmentRequest):
    threat_path = _tv_file(req.year)

    if not threat_path.exists():
        raise HTTPException(status_code=404, detail=f"Threat assessment file not found: {threat_path}")

    raw = _read_json(threat_path, None)

    if not isinstance(raw, dict):
        raise HTTPException(status_code=500, detail=f"Invalid JSON structure in: {threat_path}")

    hosts = raw.get("hosts")
    if not isinstance(hosts, list):
        raise HTTPException(status_code=500, detail=f"Missing or invalid 'hosts' list in: {threat_path}")

    cleared_count = 0

    for host in hosts:
        if not isinstance(host, dict):
            continue

        existing = host.get("vulnerabilities_threats", [])
        if isinstance(existing, list) and len(existing) > 0:
            cleared_count += len(existing)

        host["vulnerabilities_threats"] = []

    raw["hosts"] = hosts
    _write_json(threat_path, raw)

    try:
        _update_system_status(req.year, "Not Started")
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Threat file reset succeeded, but failed to update systemstatus.json: {e}",
        ) from e

    return {
        "success": True,
        "year": req.year,
        "status": "Not Started",
        "message": "Threat and Vulnerability Assessment restarted.",
        "cleared_items": cleared_count,
    }


def _read_current_threat_status(year: int) -> str:
    data = _read_json(_system_status_file(year), {})
    if not isinstance(data, dict):
        return "Not Started"

    sections = data.get("sections", {})
    if not isinstance(sections, dict):
        return "Not Started"

    section = sections.get("threats_vulns", {})
    if not isinstance(section, dict):
        return "Not Started"

    status = section.get("status", "Not Started")
    if status not in VALID_STEP_STATUSES:
        return "Not Started"

    return status


@router.get("/summary")
def get_threat_vulnerability_summary(year: int = Query(2026)):
    path = _tv_file(year)
    raw = _read_json(path, {"hosts": []})
    hosts = _normalize_hosts(raw)

    vulnerabilities_count = 0
    threats_count = 0
    host_rows: list[dict] = []

    for host in hosts:
        vuls = _safe_vulns(host)
        vulnerabilities_count += len(vuls)

        for item in vuls:
            if str(item.get("public_exploit_name", "")).strip():
                threats_count += 1

        host_rows.append(
            {
                "hostname": str(host.get("hostname", "")).strip(),
                "role": str(host.get("role", "")).strip(),
                "ip_address": str(host.get("ip_address", "")).strip(),
                "cia_rating": _get_cia_rating(host),
                "items_count": len(vuls),
                "rows": _extract_vuln_rows(host),
                "vulnerabilities_threats": vuls,
            }
        )

    status = _read_current_threat_status(year)

    return {
        "success": True,
        "year": year,
        "status": status,
        "kpis": {
            "vulnerabilities": vulnerabilities_count,
            "threats": threats_count,
            "hosts": len(hosts),
        },
        "hosts": host_rows,
    }


@router.get("/items")
def get_threat_vulnerability_items(year: int = Query(2026)):
    path = _tv_file(year)
    raw = _read_json(path, {"hosts": []})
    hosts = _normalize_hosts(raw)

    status = _read_current_threat_status(year)

    return {
        "success": True,
        "year": year,
        "status": status,
        "hosts": hosts,
    }


@router.get("/host-details")
def get_host_threat_vulnerability_details(
    hostname: str = Query(...),
    year: int = Query(2026),
):
    path = _tv_file(year)
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
                    "vulnerabilities_threats": _safe_vulns(host),
                },
            }

    raise HTTPException(status_code=404, detail=f"Host '{hostname}' not found.")


@router.get("/cve-detail")
def get_cve_detail(cve_id: str = Query(...)):
    try:
        raw_result = _get_cve_detail_with_fallback(cve_id)
        formatted_detail = _ollama_format_cve(raw_result)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    except requests.HTTPError as e:
        raise HTTPException(status_code=502, detail=f"External CVE lookup failed: {e}") from e
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"Network error during CVE lookup: {e}") from e
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve CVE details: {e}") from e

    return {
        "success": True,
        "data": raw_result,
        "formatted_detail": formatted_detail,
    }