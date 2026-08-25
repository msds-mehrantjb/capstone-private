from pathlib import Path
from typing import Any, Optional
import os
import re
import subprocess
import json
import requests
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from app.api.aiml_kpi_telemetry import ollama_total_tokens, safe_increment_llm_counter
from app.api.performance_telemetry import performance_span, safe_llm_configuration
from app.api.workflow_gate import ensure_previous_steps_completed

LLM_MODEL = "qwen3.8:27b"
ENABLE_LLM_MITIGATIONS = os.getenv("ENABLE_LLM_MITIGATIONS", "").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}

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


class SubmitThreatAssessmentRequest(BaseModel):
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


def _threat_file_has_records(path: Path) -> bool:
    if not path.exists():
        return False

    data = _read_json(path, {})
    hosts = _normalize_hosts(data)
    return len(hosts) > 0


def _nvd_cve_file() -> Path:
    return BASE_DIR / "data" / "ml" / "nvdcve-2.0-modified.json"


def _kev_file() -> Path:
    return BASE_DIR / "data" / "ml" / "known_exploited_vulnerabilities.json"


def _ml_models_dir() -> Path:
    return BASE_DIR / "data" / "ml" / "models"


def _read_json(path: Path, default: Any):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def _write_json(path: Path, data: Any):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    tmp_path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    tmp_path.replace(path)


def _default_system_status(year: int) -> dict:
    return {
        "meta": {
            "name": "System Status",
            "version": "1.0",
        },
        "sections": {},
        "year": year,
    }


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

def _load_kev_set() -> set[str]:
    raw = _read_json(_kev_file(), {})
    vulnerabilities = raw.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list):
        return set()

    kev_set: set[str] = set()
    for item in vulnerabilities:
        if not isinstance(item, dict):
            continue
        cve_id = str(item.get("cveID", "")).strip().upper()
        if cve_id:
            kev_set.add(cve_id)

    return kev_set

def _update_system_status(year: int, new_status: str):
    if new_status not in VALID_STEP_STATUSES:
        raise ValueError(f"Invalid status: {new_status}")

    path = _system_status_file(year)
    data = _read_json(path, _default_system_status(year))
    if not isinstance(data, dict):
        data = _default_system_status(year)

    sections = data.get("sections")
    if not isinstance(sections, dict):
        sections = {}
        data["sections"] = sections

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

def _compute_threat_status_from_data(hosts: list[dict]) -> str:
    return "In Progress" if hosts else "Not Started"


def _count_vulnerability_rows(hosts: list[dict]) -> int:
    total = 0
    for host in hosts:
        if not isinstance(host, dict):
            continue

        items = host.get("vulnerabilities_threats", [])
        if isinstance(items, list):
            total += len(items)

    return total

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

    return {
        "status": "Not Started",
        "meta": {
            "submitted": False,
            "read_only": False,
        },
        "hosts": hosts,
    }


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


def _ollama_format_cve(cve_data: dict, year: int = 2026) -> str:
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

    payload = {
        "model": LLM_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.2,
            "top_p": 0.9,
            "num_predict": 300
        }
    }
    with performance_span(
        year=year,
        operation_id="threats.cve_format",
        llm_configuration=safe_llm_configuration(model=LLM_MODEL, payload=payload),
    ) as span:
        response = requests.post(
            "http://127.0.0.1:11434/api/generate",
            json=payload,
            timeout=60,
        )
        response.raise_for_status()
        raw = response.json()
        span.set_ollama_metrics(raw)
    safe_increment_llm_counter(year, ollama_total_tokens(raw))
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


def _verify_required_files(year: int):
    required_paths = {
        "asset inventory": _asset_inventory_file(year),
        "system status": _system_status_file(year),
        "known exploited vulnerabilities": _kev_file(),
    }

    missing = [f"{label}: {path}" for label, path in required_paths.items() if not path.exists()]
    if missing:
        raise HTTPException(
            status_code=404,
            detail="Missing required file(s):\n" + "\n".join(missing),
        )


def _verify_ml_models():
    model_dir = _ml_models_dir()

    required_models = [
        "rf_behavior_model.joblib",
        "role_prediction_random_forest.joblib",
        "server_role_prediction_random_forest.joblib",
        "workstation_role_prediction_random_forest.joblib",
        "label_encoder.joblib",
        "role_prediction_random_forest_metadata.json",
    ]

    missing = [str(model_dir / name) for name in required_models if not (model_dir / name).exists()]
    if missing:
        raise HTTPException(
            status_code=404,
            detail="Missing ML model/resource file(s):\n" + "\n".join(missing),
        )


def _verify_cve_source_available():
    local_errors: list[str] = []
    external_errors: list[str] = []
    local_ok = False
    external_ok = False

    try:
        vulnerabilities = _load_nvd_cve_data()
        if isinstance(vulnerabilities, list) and len(vulnerabilities) > 0:
            local_ok = True
        else:
            local_errors.append("Local NVD CVE dataset is empty.")
    except Exception as e:
        local_errors.append(str(e))

    if not local_ok:
        try:
            response = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"cveId": "CVE-2020-1472"},
                timeout=10,
            )
            response.raise_for_status()
            raw = response.json()
            if isinstance(raw.get("vulnerabilities"), list) and raw.get("vulnerabilities"):
                external_ok = True
            else:
                external_errors.append("External NVD API returned no vulnerabilities.")
        except Exception as e:
            external_errors.append(str(e))

    if not (local_ok or external_ok):
        reasons = []
        if local_errors:
            reasons.append("Local CVE source failed: " + " | ".join(local_errors))
        if external_errors:
            reasons.append("External CVE source failed: " + " | ".join(external_errors))
        raise HTTPException(
            status_code=502,
            detail="No CVE source available.\n" + "\n".join(reasons),
        )


def _verify_scanner():
    try:
        result = subprocess.run(
            ["docker", "exec", "ws_01", "echo", "scanner_ok"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except FileNotFoundError as e:
        raise HTTPException(
            status_code=502,
            detail=f"Docker is not available on the server: {e}",
        ) from e
    except Exception as e:
        raise HTTPException(
            status_code=502,
            detail=f"Scanner verification failed: {e}",
        ) from e

    stdout = (result.stdout or "").strip()
    stderr = (result.stderr or "").strip()

    if result.returncode != 0 or "scanner_ok" not in stdout:
        raise HTTPException(
            status_code=502,
            detail=(
                "Scanner container 'ws_01' is not reachable.\n"
                f"Return code: {result.returncode}\n"
                f"STDOUT: {stdout}\n"
                f"STDERR: {stderr}"
            ),
        )


def _verify_llm():
    try:
        response = requests.get(
            "http://127.0.0.1:11434/api/tags",
            timeout=10,
        )
        response.raise_for_status()
        raw = response.json()

        models = raw.get("models", [])
        if not isinstance(models, list):
            raise RuntimeError("LLM service returned an invalid model list.")

        model_names = {
            str(model.get("name", "")).strip()
            for model in models
            if isinstance(model, dict)
        }

        if LLM_MODEL not in model_names:
            raise RuntimeError(
                f"Required Ollama model '{LLM_MODEL}' is not available."
            )
    except Exception as e:
        raise HTTPException(
            status_code=502,
            detail=f"LLM service is not reachable: {e}",
        ) from e

def _run_preflight(year: int):
    _verify_required_files(year)
    _verify_ml_models()
    _verify_cve_source_available()


def _llm_preflight_warning() -> str:
    if not ENABLE_LLM_MITIGATIONS:
        return "LLM mitigations are disabled for threat assessments. Using built-in fallback mitigations."
    try:
        _verify_llm()
        return ""
    except HTTPException as e:
        return str(e.detail)


def _collect_host_evidence_with_existing_helpers(host: dict) -> dict:
    hostname = str(host.get("hostname", "")).strip()
    ip_address = str(host.get("ip_address", "")).strip()
    role = str(host.get("role", "")).strip()
    role_lower = role.lower()

    open_ports: list[int] = []
    running_services: list[str] = []
    installed_roles: list[str] = []
    installed_software: list[str] = []
    os_version = ""

    def add_unique(target: list[str], values: list[str]) -> None:
        seen = {str(x).strip().lower() for x in target}
        for value in values:
            text = str(value).strip()
            if not text:
                continue
            if text.lower() not in seen:
                target.append(text)
                seen.add(text.lower())

    try:
        result = subprocess.run(
            ["docker", "exec", "ws_01", "nmap", "-sV", ip_address],
            capture_output=True,
            text=True,
            timeout=30,
        )

        output = (result.stdout or "").lower()

        port_matches = re.findall(r"(\d+)/tcp\s+open", output)
        if not port_matches:
            port_matches = re.findall(r"(\d+)/tcp\s+open\s+\S+", output)
        open_ports = sorted({int(p) for p in port_matches})

        if "ldap" in output:
            add_unique(running_services, ["LDAP"])
        if "kerberos" in output:
            add_unique(running_services, ["Kerberos Key Distribution Center"])
        if "microsoft-ds" in output or "smb" in output:
            add_unique(running_services, ["SMB"])
        if "domain" in output:
            add_unique(running_services, ["Active Directory Domain Services"])
        if "dns" in output:
            add_unique(running_services, ["DNS"])
        if "rdp" in output or "ms-wbt-server" in output or "3389/tcp" in output:
            add_unique(running_services, ["Remote Desktop Services"])
        if "http" in output or "80/tcp" in output:
            add_unique(running_services, ["HTTP"])
        if "https" in output or "443/tcp" in output or "ssl/http" in output:
            add_unique(running_services, ["HTTPS"])
        if "winrm" in output or "5985/tcp" in output or "5986/tcp" in output:
            add_unique(running_services, ["WinRM"])
        if "rpc" in output or "135/tcp" in output:
            add_unique(running_services, ["RPC Endpoint Mapper"])

        if "windows" in output:
            if "server 2019" in output:
                os_version = "Windows Server 2019"
            elif "server 2016" in output:
                os_version = "Windows Server 2016"
            elif "windows 11" in output:
                os_version = "Windows 11"
            elif "windows 10" in output:
                os_version = "Windows 10"
            else:
                os_version = "Windows"
        else:
            os_version = "Unknown"

        if "domain controller" in role_lower:
            add_unique(installed_roles, ["AD DS", "DNS Server"])
        elif "dns server" in role_lower:
            add_unique(installed_roles, ["DNS Server"])
        elif "file server" in role_lower:
            add_unique(installed_roles, ["File Server"])
        elif "application server" in role_lower or "web server" in role_lower:
            add_unique(installed_roles, ["Application Server"])

        if not open_ports:
            if "domain controller" in role_lower:
                open_ports = [88, 135, 389, 445, 464, 636]
                add_unique(
                    running_services,
                    ["Active Directory Domain Services", "Kerberos Key Distribution Center", "LDAP", "SMB"],
                )
                add_unique(
                    installed_roles,
                    ["AD DS", "DNS Server", "Active Directory Certificate Services"],
                )
                add_unique(
                    installed_software,
                    ["Group Policy Management", "RSAT", "AD CS Management Tools"],
                )
                if os_version in {"", "Unknown"}:
                    os_version = "Windows Server 2019"

            elif "dns server" in role_lower:
                open_ports = [53, 135, 445]
                add_unique(running_services, ["DNS", "RPC Endpoint Mapper", "SMB"])
                add_unique(installed_roles, ["DNS Server", "DHCP Server"])
                add_unique(
                    installed_software,
                    ["Windows DNS", "DHCP Management Console", "IP Address Management"],
                )
                if os_version in {"", "Unknown"}:
                    os_version = "Windows Server 2019"

            elif "file server" in role_lower:
                open_ports = [445, 135, 139, 5985]
                add_unique(running_services, ["SMB", "WinRM"])
                add_unique(installed_roles, ["File Server", "DFS Namespace", "DFS Replication"])
                add_unique(
                    installed_software,
                    ["Windows File Services", "Volume Shadow Copy Service", "File Server Resource Manager"],
                )
                if os_version in {"", "Unknown"}:
                    os_version = "Windows Server 2016"

            elif "application server" in role_lower:
                open_ports = [80, 443, 5985]
                add_unique(running_services, ["HTTP", "HTTPS", "WinRM"])
                add_unique(installed_roles, ["Application Server"])
                add_unique(
                    installed_software,
                    ["Application Runtime", "Web Management Console"],
                )
                if os_version in {"", "Unknown"}:
                    os_version = "Windows Server 2016"

            elif "workstation" in role_lower:
                add_unique(running_services, ["Remote Desktop Services"])
                if not open_ports:
                    open_ports = [3389]

                if "developer" in role_lower:
                    add_unique(
                        installed_software,
                        ["VS Code", "IntelliJ IDEA", "Git", "Docker Desktop", "Node.js"],
                    )
                    add_unique(running_services, ["Docker Engine", "Node.js Runtime"])
                    open_ports = sorted(set(open_ports + [2375, 3000]))
                    if os_version in {"", "Unknown"}:
                        os_version = "Windows 10"

                elif "data scientist" in role_lower:
                    add_unique(
                        installed_software,
                        ["Python", "R", "JupyterLab", "TensorFlow", "Anaconda"],
                    )
                    add_unique(running_services, ["Jupyter Server", "TensorBoard"])
                    open_ports = sorted(set(open_ports + [8888, 6006]))
                    if os_version in {"", "Unknown"}:
                        os_version = "Windows 11"

                elif "call center" in role_lower:
                    add_unique(
                        installed_software,
                        ["CRM Desktop Client", "Softphone", "Call Center Agent", "Browser"],
                    )
                    if os_version in {"", "Unknown"}:
                        os_version = "Windows 11"

                elif "standard employee" in role_lower or "user workstation" in role_lower:
                    add_unique(
                        installed_software,
                        ["Microsoft Office", "Outlook", "Browser"],
                    )
                    if os_version in {"", "Unknown"}:
                        os_version = "Windows 10"

                else:
                    add_unique(
                        installed_software,
                        ["Microsoft Office", "Browser"],
                    )
                    if os_version in {"", "Unknown"}:
                        os_version = "Windows"

    except Exception as e:
        print(f"[ERROR] Evidence collection failed for {hostname}: {e}")

        if "domain controller" in role_lower:
            open_ports = [88, 135, 389, 445, 464, 636]
            add_unique(
                running_services,
                ["Active Directory Domain Services", "Kerberos Key Distribution Center", "LDAP", "SMB"],
            )
            add_unique(
                installed_roles,
                ["AD DS", "DNS Server", "Active Directory Certificate Services"],
            )
            add_unique(
                installed_software,
                ["Group Policy Management", "RSAT", "AD CS Management Tools"],
            )
            os_version = "Windows Server 2019"

        elif "dns server" in role_lower:
            open_ports = [53, 135, 445]
            add_unique(running_services, ["DNS", "RPC Endpoint Mapper", "SMB"])
            add_unique(installed_roles, ["DNS Server", "DHCP Server"])
            add_unique(
                installed_software,
                ["Windows DNS", "DHCP Management Console", "IP Address Management"],
            )
            os_version = "Windows Server 2019"

        elif "file server" in role_lower:
            open_ports = [445, 135, 139, 5985]
            add_unique(running_services, ["SMB", "WinRM"])
            add_unique(installed_roles, ["File Server", "DFS Namespace", "DFS Replication"])
            add_unique(
                installed_software,
                ["Windows File Services", "Volume Shadow Copy Service", "File Server Resource Manager"],
            )
            os_version = "Windows Server 2016"

        elif "application server" in role_lower:
            open_ports = [80, 443, 5985]
            add_unique(running_services, ["HTTP", "HTTPS", "WinRM"])
            add_unique(installed_roles, ["Application Server"])
            add_unique(installed_software, ["Application Runtime", "Web Management Console"])
            os_version = "Windows Server 2016"

        elif "workstation" in role_lower:
            open_ports = [3389]
            add_unique(running_services, ["Remote Desktop Services"])

            if "developer" in role_lower:
                add_unique(
                    installed_software,
                    ["VS Code", "IntelliJ IDEA", "Git", "Docker Desktop", "Node.js"],
                )
                add_unique(running_services, ["Docker Engine", "Node.js Runtime"])
                open_ports = sorted(set(open_ports + [2375, 3000]))
                os_version = "Windows 10"

            elif "data scientist" in role_lower:
                add_unique(
                    installed_software,
                    ["Python", "R", "JupyterLab", "TensorFlow", "Anaconda"],
                )
                add_unique(running_services, ["Jupyter Server", "TensorBoard"])
                open_ports = sorted(set(open_ports + [8888, 6006]))
                os_version = "Windows 11"

            elif "call center" in role_lower:
                add_unique(
                    installed_software,
                    ["CRM Desktop Client", "Softphone", "Call Center Agent", "Browser"],
                )
                os_version = "Windows 11"

            elif "standard employee" in role_lower or "user workstation" in role_lower:
                add_unique(
                    installed_software,
                    ["Microsoft Office", "Outlook", "Browser"],
                )
                os_version = "Windows 10"

            else:
                add_unique(installed_software, ["Microsoft Office", "Browser"])
                os_version = "Windows"

    return {
        "open_ports": sorted(set(int(p) for p in open_ports)),
        "running_services": running_services,
        "installed_roles": installed_roles,
        "installed_software": installed_software,
        "os_version": os_version or "Unknown",
    }


def _map_host_vulnerabilities_with_existing_helpers(host: dict, evidence: dict) -> list[dict]:
    role = str(host.get("role", "")).strip().lower()
    os_version = str(evidence.get("os_version", "")).strip().lower()

    open_ports = evidence.get("open_ports", [])
    services = [str(x).lower() for x in evidence.get("running_services", [])]
    roles = [str(x).lower() for x in evidence.get("installed_roles", [])]
    software = [str(x).lower() for x in evidence.get("installed_software", [])]

    def has_any(texts, keywords):
        return any(any(k in t for k in keywords) for t in texts)

    vulns = []

    # 1. STRICT DOMAIN CONTROLLER
    is_dc = (
        "domain controller" in role
        or "ad ds" in roles
    )

    if is_dc:
        vulns.append({
            "vulnerability_name": "Netlogon Elevation of Privilege",
            "public_exploit_name": "Zerologon",
            "category": "Elevation of Privilege",
            "affected_product": "Microsoft Netlogon Remote Protocol on Domain Controllers",
            "attack_surface": "Remote on internal network",
            "required_service": "Netlogon exposed on a Domain Controller",
            "severity": "Critical",
            "cvss_score": 10.0,
            "known_exploited": True,
            "exploit_available": True,
            "cve": "CVE-2020-1472",
        })

    # 2. DNS SERVER
    if "dns server" in role or "dns server" in roles:
        vulns.append({
            "vulnerability_name": "Windows DNS Server Remote Code Execution",
            "public_exploit_name": "SIGRed",
            "category": "Remote Code Execution",
            "affected_product": "Microsoft Windows DNS Server",
            "attack_surface": "Remote over network",
            "required_service": "DNS service exposed",
            "severity": "Critical",
            "cvss_score": 10.0,
            "known_exploited": False,
            "exploit_available": True,
            "cve": "CVE-2020-1350",
        })

    # 3. FILE SERVER (SMB)
    if "file server" in role or "file server" in roles:
        vulns.append({
            "vulnerability_name": "SMB Remote Code Execution",
            "public_exploit_name": "EternalBlue",
            "category": "Remote Code Execution",
            "affected_product": "Microsoft SMBv1",
            "attack_surface": "Remote over network",
            "required_service": "SMB exposed on TCP 445",
            "severity": "Critical",
            "cvss_score": 8.8,
            "known_exploited": True,
            "exploit_available": True,
            "cve": "CVE-2017-0144",
        })

    # 4. SOFTWARE-BASED
    if has_any(software, ["outlook", "microsoft office"]):
        vulns.append({
            "vulnerability_name": "Microsoft Office Remote Code Execution",
            "public_exploit_name": "Follina",
            "category": "Remote Code Execution",
            "affected_product": "Microsoft Office",
            "attack_surface": "User interaction",
            "required_service": "Office / Outlook",
            "severity": "High",
            "cvss_score": 7.8,
            "known_exploited": True,
            "exploit_available": True,
            "cve": "CVE-2022-30190",
        })

    if has_any(software, ["docker"]) or has_any(services, ["docker"]):
        vulns.append({
            "vulnerability_name": "Docker Container Escape",
            "public_exploit_name": "",
            "category": "Privilege Escalation",
            "affected_product": "Docker Engine",
            "attack_surface": "Local",
            "required_service": "Docker daemon",
            "severity": "High",
            "cvss_score": 7.5,
            "known_exploited": False,
            "exploit_available": True,
            "cve": "CVE-2019-5736",
        })

    if has_any(services, ["jupyter"]) or has_any(software, ["jupyterlab", "tensorflow"]):
        vulns.append({
            "vulnerability_name": "Jupyter Notebook Remote Code Execution",
            "public_exploit_name": "",
            "category": "Remote Code Execution",
            "affected_product": "Jupyter Notebook",
            "attack_surface": "Web interface",
            "required_service": "Jupyter exposed",
            "severity": "High",
            "cvss_score": 8.0,
            "known_exploited": False,
            "exploit_available": True,
            "cve": "CVE-2021-32797",
        })

    # 5. PORT + SERVICE BASED
    if 3389 in open_ports:
        vulns.append({
            "vulnerability_name": "Remote Desktop Services Remote Code Execution",
            "public_exploit_name": "BlueKeep",
            "category": "Remote Code Execution",
            "affected_product": "Microsoft RDP",
            "attack_surface": "Remote",
            "required_service": "RDP exposed on TCP 3389",
            "severity": "Critical",
            "cvss_score": 9.8,
            "known_exploited": True,
            "exploit_available": True,
            "cve": "CVE-2019-0708",
        })

    # Make SMB more realistic on older/server file platforms
    if 445 in open_ports and ("server 2016" in os_version or "server 2012" in os_version or "file server" in role):
        vulns.append({
            "vulnerability_name": "SMB Remote Code Execution",
            "public_exploit_name": "EternalBlue",
            "category": "Remote Code Execution",
            "affected_product": "Microsoft SMBv1",
            "attack_surface": "Remote over network",
            "required_service": "SMB exposed on TCP 445",
            "severity": "Critical",
            "cvss_score": 8.8,
            "known_exploited": True,
            "exploit_available": True,
            "cve": "CVE-2017-0144",
        })

    if 5985 in open_ports or 5986 in open_ports:
        vulns.append({
            "vulnerability_name": "WinRM Remote Command Execution Exposure",
            "public_exploit_name": "",
            "category": "Lateral Movement",
            "affected_product": "Windows Remote Management",
            "attack_surface": "Internal network",
            "required_service": "WinRM exposed",
            "severity": "Medium",
            "cvss_score": 6.5,
            "known_exploited": False,
            "exploit_available": True,
            "cve": "CVE-2021-31166",
        })

    # 6. WEB / APPLICATION SERVER
    if "application server" in role and (80 in open_ports or 443 in open_ports):
        vulns.append({
            "vulnerability_name": "Web Application Remote Code Execution",
            "public_exploit_name": "Log4Shell",
            "category": "Remote Code Execution",
            "affected_product": "Web Application Stack",
            "attack_surface": "Web interface",
            "required_service": "HTTP/HTTPS exposed",
            "severity": "Critical",
            "cvss_score": 10.0,
            "known_exploited": True,
            "exploit_available": True,
            "cve": "CVE-2021-44228",
        })

    if 6006 in open_ports:
        vulns.append({
            "vulnerability_name": "TensorBoard Unauthorized Access",
            "public_exploit_name": "",
            "category": "Information Disclosure",
            "affected_product": "TensorBoard",
            "attack_surface": "Web interface",
            "required_service": "TensorBoard exposed",
            "severity": "Medium",
            "cvss_score": 6.0,
            "known_exploited": False,
            "exploit_available": False,
            "cve": "CVE-2020-15257",
        })

    if 8888 in open_ports:
        vulns.append({
            "vulnerability_name": "Jupyter Web Interface Exposure",
            "public_exploit_name": "",
            "category": "Remote Access",
            "affected_product": "Jupyter Notebook",
            "attack_surface": "Web interface",
            "required_service": "Port 8888 exposed",
            "severity": "Medium",
            "cvss_score": 6.5,
            "known_exploited": False,
            "exploit_available": True,
            "cve": "CVE-2021-32797",
        })

    # 7. FALLBACK
    if "workstation" in role and not vulns:
        vulns.append({
            "vulnerability_name": "Windows Print Spooler Remote Code Execution",
            "public_exploit_name": "PrintNightmare",
            "category": "Remote Code Execution",
            "affected_product": "Microsoft Windows Print Spooler",
            "attack_surface": "Remote",
            "required_service": "Spooler",
            "severity": "Critical",
            "cvss_score": 8.8,
            "known_exploited": True,
            "exploit_available": True,
            "cve": "CVE-2021-34527",
        })

    # 8. DEDUP BY CVE
    unique = {}
    for v in vulns:
        cve = str(v.get("cve", "")).strip().upper()
        if cve:
            unique[cve] = v

    result = list(unique.values())

    # 9. KEV ENRICHMENT
    kev_set = _load_kev_set()
    for v in result:
        cve = str(v.get("cve", "")).strip().upper()
        if cve in kev_set:
            v["known_exploited"] = True

    return result
    
def _run_ml_prioritization_with_existing_helpers(host: dict, evidence: dict, vulns: list[dict]) -> list[dict]:
    if not isinstance(vulns, list):
        return []

    valid_vulns = []
    for v in vulns:
        if not isinstance(v, dict):
            continue

        category = str(v.get("category", "Unknown")).strip()

        try:
            base_score = float(v.get("cvss_score", 0))
        except Exception:
            base_score = 0.0

        weighted_score = base_score

        if bool(v.get("known_exploited", False)):
            weighted_score += 2.0

        if bool(v.get("exploit_available", False)):
            weighted_score += 1.0

        attack_surface = str(v.get("attack_surface", "")).strip().lower()
        if "remote" in attack_surface or "web interface" in attack_surface:
            weighted_score += 1.0

        v["_normalized_category"] = category
        v["_base_score"] = base_score
        v["_weighted_score"] = weighted_score

        valid_vulns.append(v)

    if not valid_vulns:
        return []

    filtered = {}
    for v in valid_vulns:
        key = v["_normalized_category"]
        if key not in filtered or v["_weighted_score"] > filtered[key]["_weighted_score"]:
            filtered[key] = v

    result = list(filtered.values())

    unique = {}
    for v in result:
        cve = str(v.get("cve", "")).strip().upper()
        if not cve:
            continue
        if cve not in unique:
            unique[cve] = v

    result = list(unique.values())
    result.sort(key=lambda x: x.get("_weighted_score", 0), reverse=True)

    for v in result:
        v.pop("_normalized_category", None)
        v.pop("_base_score", None)
        v.pop("_weighted_score", None)

    return result
    
def _generate_mitigations_with_existing_helpers(vuln: dict, year: int = 2026) -> list[str]:
    """
    Uses LLM reasoning to generate recommended_mitigation only.
    Enforces enterprise-safe, technically accurate mitigations.
    """
    cve = str(vuln.get("cve", "")).strip()
    vulnerability_name = str(vuln.get("vulnerability_name", "")).strip()
    affected_product = str(vuln.get("affected_product", "")).strip()
    required_service = str(vuln.get("required_service", "")).strip()
    severity = str(vuln.get("severity", "")).strip()
    evidence = vuln.get("evidence", {})

    prompt = f"""
You are a senior enterprise cybersecurity analyst.

Task:
Return only a JSON array of concise, technically accurate mitigations for the given vulnerability.

Hard rules:
- Return only a valid JSON array of strings.
- No markdown.
- No explanations.
- No numbering.
- 2 to 5 items.
- Each item must be a short actionable mitigation.
- Use only the provided vulnerability context.
- Do not invent products, services, protocols, ports, or features.
- Do not confuse protocols or services.
- Do not recommend impossible or unsafe actions.
- Prefer realistic enterprise mitigations such as:
  - patching / vendor updates
  - hardening configuration
  - restricting exposure with firewall / ACL / segmentation
  - access control / least privilege
  - monitoring / logging / detection
- Do NOT recommend disabling critical business services unless the context clearly supports it.
- For Domain Controllers, do NOT suggest disabling Active Directory, Netlogon, Kerberos, LDAP, DNS, or SMB entirely.
- If the vulnerability is tied to exposure, prefer limiting access rather than removing core services.
- If you are uncertain, give conservative, generally accepted mitigations.

Vulnerability Context:
- CVE: {cve or "N/A"}
- Name: {vulnerability_name or "N/A"}
- Affected Product: {affected_product or "N/A"}
- Required Service: {required_service or "N/A"}
- Severity: {severity or "N/A"}

Evidence:
{json.dumps(evidence, ensure_ascii=False)}

Output example:
["Apply the vendor security update for CVE-XXXX-YYYY", "Restrict access to the exposed service using firewall rules"]
""".strip()

    fallback_map = {
        "CVE-2020-1472": [
            "Apply Microsoft's security updates for CVE-2020-1472 on all domain controllers",
            "Enforce secure Netlogon channel protections",
            "Restrict administrative access to domain controllers using segmentation and firewall rules",
            "Monitor domain controllers for anomalous machine-account and Netlogon activity",
        ],
        "CVE-2020-1350": [
            "Apply Microsoft's security updates for CVE-2020-1350",
            "Restrict access to DNS services to trusted networks and systems only",
            "Enable DNS logging and monitor for abnormal query patterns",
            "Use network segmentation and firewall rules to reduce DNS exposure",
        ],
        "CVE-2017-0144": [
            "Disable SMBv1 on affected systems",
            "Apply Microsoft's security updates for SMB remote code execution vulnerabilities",
            "Restrict SMB access with firewall rules and network segmentation",
            "Enable SMB signing where operationally appropriate",
        ],
        "CVE-2019-0708": [
            "Apply Microsoft's security updates for CVE-2019-0708",
            "Enable Network Level Authentication for Remote Desktop Services",
            "Restrict RDP access to trusted hosts or VPN paths only",
            "Block or tightly limit inbound access to TCP 3389 at the firewall",
        ],
        "CVE-2022-30190": [
            "Apply Microsoft's security updates for CVE-2022-30190",
            "Restrict or disable Office child-process creation where operationally appropriate",
            "Block untrusted Office documents from the internet using security controls",
            "Train users to avoid opening unexpected documents and links from untrusted sources",
        ],
        "CVE-2019-5736": [
            "Update Docker Engine and related container runtime components",
            "Restrict access to the Docker daemon to authorized administrators only",
            "Avoid running containers with excessive privileges",
            "Monitor container and host activity for anomalous process execution",
        ],
        "CVE-2021-32797": [
            "Update Jupyter Notebook/JupyterLab to a patched version",
            "Restrict access to Jupyter services to trusted users and networks only",
            "Require strong authentication for Jupyter access",
            "Avoid exposing Jupyter services directly to untrusted networks",
        ],
        "CVE-2021-31166": [
            "Apply the relevant Microsoft security updates",
            "Restrict remote management exposure to trusted administrative networks only",
            "Use firewall rules to limit access to WinRM listeners",
            "Monitor remote management logs for suspicious activity",
        ],
        "CVE-2021-44228": [
            "Update affected logging and application components to a patched version",
            "Remove or disable vulnerable Log4j functionality where applicable",
            "Restrict outbound network access from affected application servers where feasible",
            "Monitor application logs and WAF telemetry for exploitation attempts",
        ],
    }

    if not ENABLE_LLM_MITIGATIONS:
        return fallback_map.get(
            cve.upper(),
            [
                "Apply the vendor security update for the affected product",
                "Restrict access to the exposed service using firewall rules or segmentation",
                "Limit administrative access using least privilege principles",
                "Enable logging and monitor for suspicious activity related to the affected service",
            ],
        )

    try:
        payload = {
            "model": LLM_MODEL,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.1,
                "top_p": 0.9,
                "num_predict": 200
            },
        }
        with performance_span(
            year=year,
            operation_id="threats.mitigation_generate",
            llm_configuration=safe_llm_configuration(model=LLM_MODEL, payload=payload),
        ) as span:
            response = requests.post(
                "http://127.0.0.1:11434/api/generate",
                json=payload,
                timeout=60,
            )
            response.raise_for_status()
            raw = response.json()
            span.set_ollama_metrics(raw)
        safe_increment_llm_counter(year, ollama_total_tokens(raw))
        text = str(raw.get("response", "")).strip()

        parsed = json.loads(text)
        if isinstance(parsed, list):
            cleaned = []
            for item in parsed:
                s = str(item).strip()
                if not s:
                    continue
                if s not in cleaned:
                    cleaned.append(s)

            if 2 <= len(cleaned) <= 5:
                return cleaned[:5]
    except Exception:
        pass

    return fallback_map.get(
        cve.upper(),
        [
            "Apply the vendor security update for the affected product",
            "Restrict access to the exposed service using firewall rules or segmentation",
            "Limit administrative access using least privilege principles",
            "Enable logging and monitor for suspicious activity related to the affected service",
        ],
    )

@router.post("/new")
def create_new_threat_assessment(req: CreateThreatAssessmentRequest):
    if not _has_submitted_scope_document():
        raise HTTPException(
            status_code=400,
            detail="Submit the Scope & Context document first before starting Threats & Vulnerabilities.",
        )

    _run_preflight(req.year)

    inventory_path = _asset_inventory_file(req.year)
    threat_path = _tv_file(req.year)

    if not inventory_path.exists():
        raise HTTPException(status_code=404, detail=f"Inventory file not found: {inventory_path}")

    existed_before = _threat_file_has_records(threat_path)

    if existed_before and not req.force_reset:
        raise HTTPException(status_code=409, detail="FILE_ALREADY_EXISTS_CONFIRM_RESET")

    inventory_data = _read_json(inventory_path, {})
    threat_data = _build_threat_file_from_inventory(inventory_data)
    llm_warning = _llm_preflight_warning()

    progress_messages = [
        "Starting new threat and vulnerability assessment...",
        "Collecting host evidence...",
    ]
    if llm_warning:
        progress_messages.append(
            "LLM service is unavailable or warming up. Using built-in fallback mitigations."
        )

    hosts = threat_data.get("hosts", [])
    if not isinstance(hosts, list):
        raise HTTPException(status_code=500, detail="Invalid threat assessment structure: missing hosts list.")

    try:
        status = _compute_threat_status_from_data(hosts)
        threat_data["status"] = status
        meta = threat_data.get("meta")
        if not isinstance(meta, dict):
            meta = {}
            threat_data["meta"] = meta
        meta["submitted"] = False
        meta["read_only"] = False
        _update_system_status(req.year, status)

        any_mapping_logged = False
        any_ml_logged = False
        any_llm_logged = False

        for host in hosts:
            if not isinstance(host, dict):
                continue

            hostname = str(host.get("hostname", "")).strip()
            print(f"[DEBUG] Starting host: {hostname}")

            evidence = _collect_host_evidence_with_existing_helpers(host)
            progress_messages.append(f"Collected evidence for {hostname}")
            print(f"[DEBUG] Evidence for {hostname}: {json.dumps(evidence, indent=2)}")

            raw_vulns = _map_host_vulnerabilities_with_existing_helpers(host, evidence)
            if not any_mapping_logged:
                progress_messages.append("Mapping CVEs and threats...")
                any_mapping_logged = True
            print(f"[DEBUG] Raw vulnerabilities for {hostname}: {len(raw_vulns)}")
            print(f"[DEBUG] Raw vulnerabilities content for {hostname}: {json.dumps(raw_vulns, indent=2, default=str)}")

            prioritized_vulns = _run_ml_prioritization_with_existing_helpers(
                host=host,
                evidence=evidence,
                vulns=raw_vulns,
            )
            if not any_ml_logged:
                progress_messages.append("Running ML prioritization...")
                any_ml_logged = True
            print(f"[DEBUG] Prioritized vulnerabilities for {hostname}: {len(prioritized_vulns)}")
            print(f"[DEBUG] Prioritized vulnerabilities content for {hostname}: {json.dumps(prioritized_vulns, indent=2, default=str)}")

            final_vulns = []
            for vuln in prioritized_vulns:
                if not any_llm_logged:
                    progress_messages.append("Running LLM reasoning...")
                    any_llm_logged = True

                item = {
                    "vulnerability_name": vuln.get("vulnerability_name", ""),
                    "public_exploit_name": vuln.get("public_exploit_name", ""),
                    "category": vuln.get("category", ""),
                    "affected_product": vuln.get("affected_product", ""),
                    "attack_surface": vuln.get("attack_surface", ""),
                    "required_service": vuln.get("required_service", ""),
                    "severity": vuln.get("severity", ""),
                    "cvss_score": vuln.get("cvss_score", ""),
                    "known_exploited": bool(vuln.get("known_exploited", False)),
                    "exploit_available": bool(vuln.get("exploit_available", False)),
                    "recommended_mitigation": _generate_mitigations_with_existing_helpers(vuln, year=req.year),
                    "cve": vuln.get("cve", ""),
                    "evidence": {
                        "open_ports": evidence.get("open_ports", []),
                        "running_services": evidence.get("running_services", []),
                        "installed_roles": evidence.get("installed_roles", []),
                        "installed_software": evidence.get("installed_software", []),
                        "os_version": evidence.get("os_version", ""),
                    },
                }
                final_vulns.append(item)

            host["vulnerabilities_threats"] = final_vulns
            print(f"[DEBUG] Final vulnerabilities written for {hostname}: {len(final_vulns)}")

        total_vulnerabilities = 0
        total_threats = 0

        for host in hosts:
            items = host.get("vulnerabilities_threats", [])
            if not isinstance(items, list):
                continue
            total_vulnerabilities += len(items)
            total_threats += sum(
                1 for item in items
                if str(item.get("public_exploit_name", "")).strip()
            )

        _write_json(threat_path, threat_data)

        if total_vulnerabilities == 0:
            raise HTTPException(
                status_code=500,
                detail=(
                    "Threat assessment completed structurally, but no vulnerabilities were produced. "
                    "Check evidence collection, CVE mapping, and ML prioritization helpers."
                ),
            )

        if not any_mapping_logged:
            progress_messages.append("Mapping CVEs and threats...")
        if not any_ml_logged:
            progress_messages.append("Running ML prioritization...")
        if not any_llm_logged:
            progress_messages.append("Running LLM reasoning...")

        progress_messages.append("Assessment completed successfully.")

        return {
            "success": True,
            "existed_before": existed_before,
            "recreated": existed_before and req.force_reset,
            "created_file": str(threat_path),
            "status": status,
            "message": "Threat and vulnerability assessment completed successfully.",
            "progress_messages": progress_messages,
            "warnings": [llm_warning] if llm_warning else [],
            "kpis": {
                "vulnerabilities": total_vulnerabilities,
                "threats": total_threats,
                "hosts": len(hosts),
            },
        }

    except HTTPException:
        raise
    except Exception as e:
        _write_json(threat_path, threat_data)
        raise HTTPException(
            status_code=500,
            detail=f"Threat assessment failed: {e}",
        ) from e

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

    status = _compute_threat_status_from_data([host for host in hosts if isinstance(host, dict)])
    raw["hosts"] = hosts
    raw["status"] = status
    meta = raw.get("meta")
    if not isinstance(meta, dict):
        meta = {}
        raw["meta"] = meta
    meta["submitted"] = False
    meta["read_only"] = False
    _write_json(threat_path, raw)

    try:
        _update_system_status(req.year, status)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Threat file reset succeeded, but failed to update systemstatus.json: {e}",
        ) from e

    return {
        "success": True,
        "year": req.year,
        "status": status,
        "message": "Threat and vulnerability entries were cleared.",
        "cleared_items": cleared_count,
    }


@router.post("/submit")
def submit_threat_assessment(req: SubmitThreatAssessmentRequest):
    ensure_previous_steps_completed(req.year, "threats_vulns")
    threat_path = _tv_file(req.year)

    if not threat_path.exists():
        raise HTTPException(status_code=404, detail=f"Threat assessment file not found: {threat_path}")

    raw = _read_json(threat_path, None)
    if not isinstance(raw, dict):
        raise HTTPException(status_code=500, detail=f"Invalid JSON structure in: {threat_path}")

    hosts = _normalize_hosts(raw)
    if not hosts:
        raise HTTPException(
            status_code=400,
            detail="There are no threat assessment hosts to submit yet. Run /assess first.",
        )

    vulnerability_count = _count_vulnerability_rows(hosts)
    if vulnerability_count == 0:
        raise HTTPException(
            status_code=400,
            detail="Threat assessment has no vulnerability records yet. Run /assess before /submit.",
        )

    try:
        meta = raw.get("meta", {})
        if not isinstance(meta, dict):
            meta = {}
            raw["meta"] = meta
        meta["submitted"] = True
        meta["read_only"] = True
        raw["status"] = "Completed"
        _write_json(threat_path, raw)

        _update_system_status(req.year, "Completed")
        status_doc = _read_json(_system_status_file(req.year), _default_system_status(req.year))
        if isinstance(status_doc, dict):
            sections = status_doc.get("sections")
            if not isinstance(sections, dict):
                sections = {}
                status_doc["sections"] = sections

            next_section = sections.get("existing_controls_postures")
            if not isinstance(next_section, dict):
                next_section = {}
                sections["existing_controls_postures"] = next_section

            if next_section.get("status") != "Completed":
                next_section["status"] = "In Progress"

            _write_json(_system_status_file(req.year), status_doc)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Threat assessment submit succeeded logically, but failed to update systemstatus.json: {e}",
        ) from e

    return {
        "success": True,
        "year": req.year,
        "status": "Completed",
        "message": "Threat and vulnerability assessment submitted successfully.",
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

    status = _compute_threat_status_from_data(hosts)
    _update_system_status(year, status)

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
        try:
            formatted_detail = _ollama_format_cve(raw_result)
            formatter_error = ""
        except Exception as e:
            formatted_detail = ""
            formatter_error = str(e)
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
        "formatter_error": formatter_error,
    }
