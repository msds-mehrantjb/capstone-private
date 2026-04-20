from fastapi import APIRouter, Query, HTTPException
import ast
import json
import ipaddress
import re
import traceback
import importlib.util
from pathlib import Path
from typing import Any, Tuple
import joblib
import pandas as pd
import subprocess
import yaml
from pydantic import BaseModel
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder
from app.api.routes_system_status import (
    _load_status,
    _atomic_write_json,
    _system_status_file,
)
from app.api.aiml_kpi_telemetry import (
    append_aiml_kpi_event,
    append_aiml_kpi_events,
    safe_increment_manual_correction_counter,
    safe_increment_role_prediction_quality_counters,
)
from datetime import datetime

router = APIRouter(prefix="/api/assets", tags=["assets"])

DISCOVERED_SUBNETS_SESSION: dict[int, list[dict]] = {}

VALID_STEP_STATUSES = {"Blocked", "Not Started", "In Progress", "Completed"}
VALID_HOST_STATUSES = {"Active", "Not Active", "Unknown"}
VALID_CIA_VALUES = {"Critical", "High", "Medium", "Low", "Unscanned"}

DATA_SOURCE_SYNTHETIC = "synthetic"
DATA_SOURCE_REAL = "real"
DATA_SOURCE_COLUMN = "data_source"

WORKSTATION_FEATURE_COLUMNS = [
    "operating_system",
    "criticality",
    "os_type",
    "os_version",
    "is_domain_joined",
    "hostname_pattern",
    "open_ports",
    "running_services",
    "installed_roles",
    "installed_software",
    "department",
    "business_function",
    "business_criticality",
]

class TrainModelRequest(BaseModel):
    year: int | None = None


class EditRoleRequest(BaseModel):
    year: int | None = 2026
    hostname: str
    role: str


class SubmitRequest(BaseModel):
    year: int | None = 2026
    confirm: bool = False


def chunk_list(items, chunk_size: int):
    for i in range(0, len(items), chunk_size):
        yield items[i:i + chunk_size]

def _find_first_matching_file(search_roots: list[Path], patterns: list[str]) -> Path | None:
    for root in search_roots:
        if not root.exists():
            continue

        for pattern in patterns:
            matches = list(root.rglob(pattern))
            if matches:
                return matches[0]

    return None

def _search_roots_for_kb() -> list[Path]:
    return [
        BASE_DIR / "data" / "knowledge_base",
        BASE_DIR / "data" / "ml",
        BASE_DIR / "app" / "rag" / "knowledge_base",
    ]
    
def find_project_root() -> Path:
    current = Path(__file__).resolve()
    for parent in [current] + list(current.parents):
        if (parent / "data" / "work").exists():
            return parent
    raise RuntimeError("Could not find project root containing data/work")


BASE_DIR = find_project_root()

def _chroma_db_path() -> Path:
    return BASE_DIR / "app" / "chroma_db"
    
def _work_dir(year: int) -> Path:
    return BASE_DIR / "data" / "work" / str(year)


def _ml_dir() -> Path:
    return BASE_DIR / "data" / "ml"


def _knowledge_base_dir() -> Path:
    return BASE_DIR / "data" / "knowledge_base"


def _ou_file(year: int) -> Path:
    return _work_dir(year) / "OU.json"


def _asset_details_file(year: int) -> Path:
    work = _work_dir(year)
    lower_name = work / "assetdetails.json"
    proper_name = work / "AssetDetails.json"

    if lower_name.exists():
        return lower_name
    return proper_name


def _asset_file(year: int) -> Path:
    return _work_dir(year) / "AssetInventory.json"


def _system_status_file(year: int) -> Path:
    return _work_dir(year) / "SystemStatus.json"


def _server_dataset_path() -> Path:
    return _ml_dir() / "server_role_training_dataset.parquet"


def _workstation_dataset_path() -> Path:
    return _ml_dir() / "workstation_role_training_dataset.parquet"


def _server_role_model_path() -> Path:
    return _ml_dir() / "models" / "server_role_prediction_random_forest.joblib"

def _workstation_role_model_path() -> Path:
    return _ml_dir() / "models" / "workstation_role_prediction_random_forest.joblib"

def _blank_detail() -> dict:
    return {
        "device_profile": {
            "os_type": "",
            "os_version": "",
            "is_domain_joined": False,
            "hostname_pattern": ""
        },
        "technical_indicators": {
            "open_ports": [],
            "running_services": [],
            "installed_roles": [],
            "installed_software": []
        },
        "business_context": {
            "department": "",
            "business_function": "",
            "criticality": ""
        },
        "indicator_based_role_detection": {
            "detected_roles": [],
            "confidence": ""
        },
        "ml_role_prediction": {
            "predicted_roles": [],
            "confidence": ""
        },
        "rag_based_role_detection": {
            "detected_role": "",
            "confidence": ""
        },
        "selected_role": {
            "role": "",
            "method": ""
        }
    }

def _docker_lab_dir() -> Path:
    return BASE_DIR / "data" / "docker_lab"


def _docker_compose_file() -> Path:
    return _docker_lab_dir() / "docker-compose.yml"


def _load_docker_compose_yaml() -> dict:
    compose_file = _docker_compose_file()

    if not compose_file.exists():
        raise FileNotFoundError(f"Docker compose file not found: {compose_file}")

    try:
        with open(compose_file, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not isinstance(data, dict):
            raise ValueError("docker-compose.yml is not a valid YAML dictionary")

        return data

    except Exception as e:
        raise RuntimeError(f"Failed to read docker-compose.yml: {e}")

def _normalize_os_name(os_caption: str) -> str:
    text = os_caption.lower()

    if "windows server 2022" in text:
        return "Windows Server 2022"
    if "windows server 2019" in text:
        return "Windows Server 2019"
    if "windows server 2016" in text:
        return "Windows Server 2016"
    if "windows 11" in text:
        return "Windows 11"
    if "windows 10" in text:
        return "Windows 10"

    return os_caption.strip()

def _docker_available() -> tuple[bool, str]:
    try:
        result = subprocess.run(
            ["docker", "--version"],
            capture_output=True,
            text=True,
            check=False,
            timeout=20,
        )
        if result.returncode != 0:
            return False, (result.stderr or result.stdout or "docker command failed").strip()
        return True, (result.stdout or "docker available").strip()
    except Exception as e:
        return False, str(e)


def _docker_compose_available() -> tuple[bool, str]:
    try:
        result = subprocess.run(
            ["docker", "compose", "version"],
            capture_output=True,
            text=True,
            check=False,
            timeout=20,
        )
        if result.returncode != 0:
            return False, (result.stderr or result.stdout or "docker compose command failed").strip()
        return True, (result.stdout or "docker compose available").strip()
    except Exception as e:
        return False, str(e)


def _docker_lab_ps_q() -> list[str]:
    compose_file = _docker_compose_file()

    if not compose_file.exists():
        return []

    try:
        result = subprocess.run(
            ["docker", "compose", "-f", str(compose_file), "ps", "-q"],
            cwd=str(_docker_lab_dir()),
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        if result.returncode != 0:
            return []
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]
    except Exception:
        return []


def _docker_lab_is_running() -> bool:
    return len(_docker_lab_ps_q()) > 0


def _ensure_docker_lab_running() -> tuple[bool, str]:
    docker_ok, docker_msg = _docker_available()
    if not docker_ok:
        return False, f"Docker is not available: {docker_msg}"

    compose_ok, compose_msg = _docker_compose_available()
    if not compose_ok:
        return False, f"Docker Compose is not available: {compose_msg}"

    lab_dir = _docker_lab_dir()
    compose_file = _docker_compose_file()

    if not lab_dir.exists():
        return False, f"Docker lab folder not found: {lab_dir}"

    if not compose_file.exists():
        return False, f"Docker compose file not found: {compose_file}"

    if _docker_lab_is_running():
        return True, "Docker lab is already running."

    try:
        result = subprocess.run(
            ["docker", "compose", "up", "-d", "--build"],
            cwd=str(lab_dir),
            capture_output=True,
            text=True,
            check=False,
            timeout=300,
        )

        if result.returncode != 0:
            return False, (
                "Failed to create and start docker lab.\n"
                f"STDOUT:\n{result.stdout}\n\nSTDERR:\n{result.stderr}"
            )

        return True, "Docker lab created and started successfully."
    except Exception as e:
        return False, f"Failed to create and start docker lab: {e}"


def _compose_network_name_to_subnet_id(network_name: str, fallback_idx: int) -> str:
    normalized = str(network_name or "").strip().lower()

    if normalized.startswith("subnet_a"):
        return "Subnet_A"
    if normalized.startswith("subnet_b"):
        return "Subnet_B"

    return f"Subnet_{fallback_idx}"


def _extract_lab_subnets_from_docker_compose() -> list[dict]:
    compose_data = _load_docker_compose_yaml()
    compose_networks = compose_data.get("networks", {}) or {}
    compose_services = compose_data.get("services", {}) or {}

    discovered: list[dict] = []
    network_map: dict[str, dict] = {}

    for idx, (network_name, network_cfg) in enumerate(compose_networks.items(), start=1):
        network_cfg = network_cfg or {}
        ipam = network_cfg.get("ipam", {}) or {}
        ipam_config = ipam.get("config", []) or []

        subnet_cidr = ""
        gateway_ip = ""

        if ipam_config and isinstance(ipam_config[0], dict):
            subnet_cidr = str(ipam_config[0].get("subnet", "") or "").strip()
            gateway_ip = str(ipam_config[0].get("gateway", "") or "").strip()

        if not subnet_cidr:
            continue

        subnet_entry = {
            "id": _compose_network_name_to_subnet_id(network_name, idx),
            "label": subnet_cidr,
            "gateway": gateway_ip,
            "hosts": [],
        }

        network_map[network_name] = subnet_entry

    for service_name, service_cfg in compose_services.items():
        if str(service_name).strip().lower() == "gateway":
            continue
        service_cfg = service_cfg or {}
        attached_networks = service_cfg.get("networks", {}) or {}

        for network_name, attachment in attached_networks.items():
            subnet_entry = network_map.get(network_name)
            if not subnet_entry:
                continue

            ip_addr = ""
            if isinstance(attachment, dict):
                ip_addr = str(attachment.get("ipv4_address", "") or "").strip()

            if not ip_addr:
                continue

            subnet_entry["hosts"].append({
                "service": str(service_name).strip(),
                "ip_address": ip_addr,
            })

    for subnet in network_map.values():
        subnet["hosts"] = sorted(
            subnet["hosts"],
            key=lambda h: ipaddress.ip_address(h["ip_address"])
        )
        subnet["host_count"] = len(subnet["hosts"])
        discovered.append(subnet)

    discovered = sorted(
        discovered,
        key=lambda s: ipaddress.ip_network(s["label"], strict=False).network_address
    )

    return discovered


def _network_matches_lab(network_input: str, discovered_subnets: list[dict]) -> bool:
    try:
        if "/" in network_input:
            user_value = ipaddress.ip_network(network_input, strict=False)
        else:
            user_value = ipaddress.ip_address(network_input)
    except Exception:
        raise ValueError("Invalid network address format.")

    for subnet in discovered_subnets:
        subnet_cidr = str(subnet.get("label", "") or "").strip()
        if not subnet_cidr:
            continue

        subnet_net = ipaddress.ip_network(subnet_cidr, strict=False)

        if isinstance(user_value, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            if user_value in subnet_net:
                return True
        else:
            if (
                user_value == subnet_net
                or user_value.subnet_of(subnet_net)
                or subnet_net.subnet_of(user_value)
            ):
                return True

    return False


def _build_docker_explore_message(discovered_subnets: list[dict]) -> str:
    subnet_lines: list[str] = []
    server_lines: list[str] = []
    workstation_lines: list[str] = []
    vm_names = _active_vm_hostnames(discovered_subnets)

    for subnet in discovered_subnets:
        label = str(subnet.get("label", "")).strip()
        if label:
            subnet_lines.append(label)

        for host in subnet.get("hosts", []) or []:
            service_name = str(host.get("service", "")).strip()
            hostname = _service_name_to_hostname(service_name)
            ip_addr = str(host.get("ip_address", "")).strip()
        
            if not hostname or not ip_addr:
                continue
        
            if hostname in vm_names:
                line = f"{hostname} , {ip_addr}  - VM/Active"
            else:
                line = f"{hostname} , {ip_addr}"
        
            if _is_server_hostname(hostname):
                server_lines.append(line)
            elif _is_workstation_hostname(hostname):
                workstation_lines.append(line)
        
    subnet_lines = sorted(set(subnet_lines), key=lambda x: ipaddress.ip_network(x, strict=False).network_address)
    server_lines = sorted(set(server_lines), key=lambda x: x)
    workstation_lines = sorted(set(workstation_lines), key=lambda x: x)

    msg = "System finds:\n\n"

    msg += f"{len(subnet_lines)} subnets:\n"
    for subnet in subnet_lines:
        msg += f"   {subnet}\n"

    msg += f"\n{len(server_lines)} Servers:\n"
    for line in server_lines:
        msg += f"   {line}\n"

    msg += f"\n{len(workstation_lines)} Workstations:\n"
    for line in workstation_lines:
        msg += f"   {line}\n"

    msg += "\nUse /assess command to retrieve hosts profiles"

    return msg.strip()

def _service_name_to_hostname(service_name: str) -> str:
    raw = str(service_name or "").strip().lower()

    if raw.startswith("srv_"):
        suffix = raw.split("_", 1)[1]
        try:
            return f"SRV-{int(suffix):02d}"
        except Exception:
            return raw.replace("_", "-").upper()

    if raw.startswith("ws_"):
        suffix = raw.split("_", 1)[1]
        try:
            return f"WS-{int(suffix):02d}"
        except Exception:
            return raw.replace("_", "-").upper()

    return raw.replace("_", "-").upper()

def _run_nmap_host_discovery(subnet: str) -> str:
    nmap_exe = r"C:\Program Files (x86)\Nmap\nmap.exe"
    result = subprocess.run(
        [nmap_exe, "-sn", subnet],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout


def _parse_discovered_hosts(nmap_output: str) -> list[str]:
    hosts: list[str] = []

    for line in nmap_output.splitlines():
        line = line.strip()

        if "Nmap scan report for" not in line:
            continue

        m = re.search(r"\((\d{1,3}(?:\.\d{1,3}){3})\)", line)
        if m:
            hosts.append(m.group(1))
            continue

        m = re.search(r"for (\d{1,3}(?:\.\d{1,3}){3})$", line)
        if m:
            hosts.append(m.group(1))

    return hosts


def _active_vm_hostnames(discovered_subnets: list[dict]) -> set[str]:
    """
    Find active VM machines using the same Nmap host discovery logic
    used in scanner.py.
    """
    active_vm_names: set[str] = set()

    try:
        for subnet in discovered_subnets:
            subnet_cidr = str(subnet.get("label", "")).strip()
            if not subnet_cidr:
                continue

            discovery_output = _run_nmap_host_discovery(subnet_cidr)
            active_ips = set(_parse_discovered_hosts(discovery_output))

            for host in subnet.get("hosts", []) or []:
                service_name = str(host.get("service", "")).strip()
                hostname = _service_name_to_hostname(service_name)
                ip_addr = str(host.get("ip_address", "")).strip()

                if hostname and ip_addr and ip_addr in active_ips:
                    active_vm_names.add(hostname)

    except Exception:
        return set()

    return active_vm_names
    

def _targets_file_path() -> Path:
    return BASE_DIR / "lab-scanner" / "config" / "targets.json"


def _write_targets_json_for_vm_hosts(
    *,
    year: int,
    discovered_subnets: list[dict],
    username: str = r"CORP\Administrator",
    password: str = "!MT123456",
) -> Path:
    vm_names = _active_vm_hostnames(discovered_subnets)

    subnet_value = ""
    network_address = ""
    vm_hosts: list[dict] = []

    for subnet in discovered_subnets:
        subnet_label = str(subnet.get("label", "")).strip()
        if not subnet_label:
            continue

        for host in subnet.get("hosts", []) or []:
            service_name = str(host.get("service", "")).strip()
            hostname = _service_name_to_hostname(service_name)
            ip_addr = str(host.get("ip_address", "")).strip()

            if hostname in vm_names and ip_addr:
                if not subnet_value:
                    subnet_value = subnet_label
                    try:
                        network_address = str(ipaddress.ip_network(subnet_label, strict=False).network_address)
                    except Exception:
                        network_address = ""

                vm_hosts.append({
                    "hostname": hostname,
                    "ip_address": ip_addr,
                    "username": username,
                    "password": password,
                })

    vm_hosts = sorted(vm_hosts, key=lambda x: (_is_workstation_hostname(x["hostname"]), x["hostname"]))

    payload = {
        "year": year,
        "network_address": network_address,
        "subnet": subnet_value,
        "hosts": vm_hosts,
    }

    out_path = _targets_file_path()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    return out_path

def _store_discovered_subnets_session(year: int, discovered_subnets: list[dict]) -> None:
    DISCOVERED_SUBNETS_SESSION[year] = json.loads(json.dumps(discovered_subnets or []))


def _get_discovered_subnets_session(year: int) -> list[dict]:
    cached = DISCOVERED_SUBNETS_SESSION.get(year, [])
    return json.loads(json.dumps(cached))


def _normalize_discovered_subnet(subnet: dict) -> dict:
    if not isinstance(subnet, dict):
        return {}

    hosts_out: list[dict] = []
    for host in subnet.get("hosts", []) or []:
        if not isinstance(host, dict):
            continue
        hosts_out.append({
            "service": str(host.get("service", "") or "").strip(),
            "ip_address": str(host.get("ip_address", "") or "").strip(),
        })

    return {
        "id": str(subnet.get("id", "") or "").strip(),
        "label": str(subnet.get("label", "") or "").strip(),
        "hosts": hosts_out,
        "host_count": len(hosts_out),
    }


def _get_discovered_subnet_from_payload_or_session(year: int, payload: dict, subnet_id: str) -> dict | None:
    selected_subnet = _normalize_discovered_subnet(payload.get("selected_subnet") or {})
    if selected_subnet.get("id") == subnet_id and selected_subnet.get("hosts"):
        return selected_subnet

    for subnet in _get_discovered_subnets_session(year):
        normalized = _normalize_discovered_subnet(subnet)
        if normalized.get("id") == subnet_id:
            return normalized

    return None


def _scanner_script_path() -> Path:
    return BASE_DIR / "lab-scanner" / "scripts" / "scanner.py"


def _load_targets_json() -> dict:
    path = _targets_file_path()
    if not path.exists():
        return {}

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _get_matching_target_host(hostname: str, ip_address: str) -> dict | None:
    targets_doc = _load_targets_json()

    for host in targets_doc.get("hosts", []) or []:
        target_hostname = str(host.get("hostname", "")).strip().upper().replace("_", "-")
        current_hostname = str(hostname).strip().upper().replace("_", "-")

        target_ip = str(host.get("ip_address", "")).strip()
        current_ip = str(ip_address).strip()

        if target_hostname == current_hostname or target_ip == current_ip:
            return host

    return None

def _load_scanner_module():
    scanner_path = _scanner_script_path()
    if not scanner_path.exists():
        raise FileNotFoundError(f"scanner.py not found: {scanner_path}")

    spec = importlib.util.spec_from_file_location("lab_scanner_runtime", scanner_path)
    if not spec or not spec.loader:
        raise RuntimeError(f"Unable to load scanner.py from {scanner_path}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _merge_scanner_detail(existing_detail: dict, scanned_record: dict) -> dict:
    detail = _normalize_detail_payload(existing_detail)
    scanned_detail = scanned_record.get("detail") or {}

    device_profile = scanned_detail.get("device_profile", {}) or {}
    technical = scanned_detail.get("technical_indicators", {}) or {}

    detail["device_profile"]["os_type"] = str(device_profile.get("os_type", "") or "").strip()

    scanned_os = str(device_profile.get("os_version", "") or "").strip()
    if not scanned_os:
        scanned_os = str(scanned_record.get("os_caption", "") or "").strip()

    if scanned_os:
        detail["device_profile"]["os_version"] = _normalize_os_name(scanned_os)

    detail["device_profile"]["is_domain_joined"] = bool(device_profile.get("is_domain_joined", False))

    if not detail["device_profile"].get("hostname_pattern"):
        detail["device_profile"]["hostname_pattern"] = str(scanned_record.get("hostname", "") or "").strip()

    detail["technical_indicators"]["open_ports"] = list(technical.get("open_ports", []) or [])
    detail["technical_indicators"]["running_services"] = list(technical.get("running_services", []) or [])
    detail["technical_indicators"]["installed_roles"] = list(technical.get("installed_roles", []) or [])
    detail["technical_indicators"]["installed_software"] = list(technical.get("installed_software", []) or [])

    scanner_role = str(scanned_record.get("role", "") or "").strip()
    if scanner_role:
        detail["selected_role"]["role"] = scanner_role
        detail["selected_role"]["method"] = "scanner.py"

    return detail


def _assess_target_host_with_scanner(hostname: str, ip_address: str, target_host: dict) -> dict:
    scanner = _load_scanner_module()
    username = str(target_host.get("username", "") or "").strip()
    password = str(target_host.get("password", "") or "").strip()

    if not username or not password:
        raise ValueError("Matching target host is missing username or password.")

    windows_data = scanner.get_windows_data(ip_address, username, password)
    port_scan_output = scanner.run_nmap_port_scan(ip_address)
    open_ports = scanner.parse_open_ports(port_scan_output)

    return scanner.build_host_record(
        ip=ip_address,
        status="Active",
        windows_data=windows_data,
        open_ports=open_ports,
        fallback_hostname=hostname,
    )

def _count_hosts_by_status(inventory: dict) -> dict[str, int]:
    unknown_count = 0
    inactive_count = 0
    active_count = 0

    for asset in _all_assets(inventory):
        status = _normalize_status(asset.get("status") or "")
        if status == "Unknown":
            unknown_count += 1
        elif status == "Not Active":
            inactive_count += 1
        elif status == "Active":
            active_count += 1

    return {
        "unknown_count": unknown_count,
        "inactive_count": inactive_count,
        "active_count": active_count,
    }

def _is_server_hostname(hostname: str) -> bool:
    return str(hostname or "").strip().upper().startswith("SRV-")


def _is_workstation_hostname(hostname: str) -> bool:
    return str(hostname or "").strip().upper().startswith("WS-")


def _is_valid_asset_for_submit(asset: dict) -> bool:
    if not isinstance(asset, dict):
        return False

    status = _normalize_status(asset.get("status") or "")
    if status != "Active":
        return False

    hostname = str(asset.get("hostname", "")).strip().upper()
    if not hostname:
        return False

    if not (_is_server_hostname(hostname) or _is_workstation_hostname(hostname)):
        return False

    role = str(asset.get("role", "")).strip()
    if not role or role.lower() == "unassigned":
        return False

    return True


def _remove_invalid_assets_for_submit(inventory: dict) -> tuple[dict, dict]:
    removed_unknown = 0
    removed_inactive = 0
    removed_invalid_active = 0
    kept_valid = 0

    for subnet in inventory.get("subnets", []):
        assets = subnet.get("assets", [])
        if not isinstance(assets, list):
            subnet["assets"] = []
            continue

        kept_assets = []

        for asset in assets:
            status = _normalize_status(asset.get("status") or "")

            if status == "Unknown":
                removed_unknown += 1
                continue

            if status == "Not Active":
                removed_inactive += 1
                continue

            if not _is_valid_asset_for_submit(asset):
                removed_invalid_active += 1
                continue

            kept_assets.append(asset)
            kept_valid += 1

        subnet["assets"] = kept_assets

    return inventory, {
        "removed_unknown": removed_unknown,
        "removed_inactive": removed_inactive,
        "removed_invalid_active": removed_invalid_active,
        "kept_valid": kept_valid,
    }


def _remove_unknown_and_inactive_assets(inventory: dict) -> tuple[dict, int, int]:
    inventory, cleanup = _remove_invalid_assets_for_submit(inventory)
    return inventory, cleanup["removed_unknown"], cleanup["removed_inactive"]

def _set_submit_status_flow(year: int) -> None:
    system_doc = _load_system_status_or_default(year)
    sections = system_doc.get("sections", {})

    if "scope_context" not in sections or not isinstance(sections["scope_context"], dict):
        sections["scope_context"] = {}

    if "assets_cia" not in sections or not isinstance(sections["assets_cia"], dict):
        sections["assets_cia"] = {}

    if "threat_vul" not in sections or not isinstance(sections["threat_vul"], dict):
        sections["threat_vul"] = {}

    sections["scope_context"]["status"] = "Blocked"
    sections["assets_cia"]["status"] = "Completed"

    if sections["threat_vul"].get("status") != "Completed":
        sections["threat_vul"]["status"] = "In Progress"

    system_doc["sections"] = sections
    _save_json(_system_status_file(year), system_doc)

def _deep_merge_dict(base: dict, incoming: dict) -> dict:
    result = dict(base)

    for key, value in incoming.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge_dict(result[key], value)
        else:
            result[key] = value

    return result


def _safe_list(value: Any) -> list:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


def _normalize_detail_payload(detail: dict, fallback_hostname: str = "") -> dict:
    blank = _blank_detail()

    if not isinstance(detail, dict):
        return blank

    device_profile = detail.get("device_profile", {}) or {}
    technical = detail.get("technical_indicators", {}) or {}
    business = detail.get("business_context", {}) or {}
    indicator = detail.get("indicator_based_role_detection", {}) or {}
    ml_pred = detail.get("ml_role_prediction", {}) or {}
    rag_role = detail.get("rag_based_role_detection", {}) or {}
    selected_role = detail.get("selected_role", {}) or {}

    normalized = {
        "device_profile": {
            "os_type": str(device_profile.get("os_type", "") or "").strip(),
            "os_version": str(device_profile.get("os_version", "") or "").strip(),
            "is_domain_joined": bool(device_profile.get("is_domain_joined", False)),
            "hostname_pattern": str(
                device_profile.get("hostname_pattern", "") or fallback_hostname
            ).strip(),
        },
        "technical_indicators": {
            "open_ports": _safe_list(technical.get("open_ports", [])),
            "running_services": _safe_list(technical.get("running_services", [])),
            "installed_roles": _safe_list(technical.get("installed_roles", [])),
            "installed_software": _safe_list(technical.get("installed_software", [])),
        },
        "business_context": {
            "department": str(business.get("department", "") or "").strip(),
            "business_function": str(business.get("business_function", "") or "").strip(),
            "criticality": str(business.get("criticality", "") or "").strip(),
        },
        "indicator_based_role_detection": {
            "detected_roles": _safe_list(indicator.get("detected_roles", [])),
            "confidence": str(indicator.get("confidence", "") or "").strip(),
        },
        "ml_role_prediction": {
            "predicted_roles": _safe_list(ml_pred.get("predicted_roles", [])),
            "confidence": str(ml_pred.get("confidence", "") or "").strip(),
        },
        "rag_based_role_detection": {
            "detected_role": str(rag_role.get("detected_role", "") or "").strip(),
            "confidence": str(rag_role.get("confidence", "") or "").strip(),
        },
        "selected_role": {
            "role": str(selected_role.get("role", "") or "").strip(),
            "method": str(selected_role.get("method", "") or "").strip(),
        },
    }

    return _deep_merge_dict(blank, normalized)


def _blank_inventory(year: int) -> dict:
    return {
        "meta": {
            "year": year,
            "name": "Asset Inventory & CIA",
            "submitted": False,
            "read_only": False
        },
        "network_mask": None,
        "subnets": []
    }


def _load_json(path: Path) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def _load_system_status_or_default(year: int) -> dict:
    path = _system_status_file(year)

    if not path.exists():
        return {
            "meta": {
                "name": "System Status",
                "version": "1.0"
            },
            "sections": {
                "scope_context": {"status": "Not Started"},
                "assets_cia": {"status": "Not Started"}
            }
        }

    try:
        data = _load_json(path)
        if not isinstance(data, dict):
            data = {}
    except Exception:
        data = {}

    if not isinstance(data.get("meta"), dict):
        data["meta"] = {
            "name": "System Status",
            "version": "1.0"
        }

    if not isinstance(data.get("sections"), dict):
        data["sections"] = {}

    if not isinstance(data["sections"].get("scope_context"), dict):
        data["sections"]["scope_context"] = {"status": "Not Started"}

    if not isinstance(data["sections"].get("assets_cia"), dict):
        data["sections"]["assets_cia"] = {"status": "Not Started"}

    return data


def _set_section_status(year: int, section_name: str, new_status: str) -> None:
    if new_status not in VALID_STEP_STATUSES:
        raise ValueError(f"Invalid status: {new_status}")

    doc = _load_system_status_or_default(year)

    if section_name not in doc["sections"] or not isinstance(doc["sections"][section_name], dict):
        doc["sections"][section_name] = {}

    doc["sections"][section_name]["status"] = new_status
    _save_json(_system_status_file(year), doc)


def _set_assets_cia_status(year: int, new_status: str) -> None:
    _set_section_status(year, "assets_cia", new_status)


def _set_scope_context_status(year: int, new_status: str) -> None:
    _set_section_status(year, "scope_context", new_status)

def _derive_assets_cia_status_from_inventory(inventory: dict) -> str:
    if not isinstance(inventory, dict):
        return "Not Started"

    if _inventory_is_read_only(inventory):
        return "Completed"

    if len(_all_assets(inventory)) == 0:
        return "Not Started"

    return "In Progress"


def _sync_assets_cia_status(year: int, inventory: dict | None = None) -> str:
    if inventory is None:
        inventory = _load_inventory_or_blank(year)

    new_status = _derive_assets_cia_status_from_inventory(inventory)
    _set_assets_cia_status(year, new_status)
    return new_status

def _get_subnet_id(subnet: dict, idx: int) -> str:
    return subnet.get("id") or subnet.get("name") or f"Subnet_{idx}"


def _get_subnet_label(subnet: dict, idx: int) -> str:
    subnet_id = _get_subnet_id(subnet, idx)
    return (
        subnet.get("subnet_address")
        or subnet.get("subnet_mask")
        or subnet.get("subnet")
        or subnet.get("gateway_internal")
        or subnet_id
    )


def _get_hosts_from_subnet(subnet: dict) -> list:
    hosts = subnet.get("hosts", [])
    return hosts if isinstance(hosts, list) else []


def _extract_suffix(raw_id: str, fallback_idx: int) -> str:
    match = re.search(r"(\d+)$", raw_id or "")
    if match:
        return match.group(1).zfill(2)
    return str(fallback_idx).zfill(2)


def _format_hostname_and_role(host: dict, fallback_idx: int) -> Tuple[str, str]:
    raw_id = str(host.get("id") or host.get("name") or host.get("device_name") or "").strip()
    raw_upper = raw_id.upper()
    suffix = _extract_suffix(raw_id, fallback_idx)

    if raw_upper.startswith("SERVER"):
        return f"SRV-{suffix}", "Server"

    if raw_upper.startswith("WS") or raw_upper.startswith("WORKSTATION"):
        return f"WS-{suffix}", "Workstation"

    return f"HOST-{suffix}", "Unassigned"


def _load_inventory_or_blank(year: int) -> dict:
    asset_file = _asset_file(year)

    if not asset_file.exists():
        return _blank_inventory(year)

    try:
        data = _load_json(asset_file)
        if not isinstance(data, dict):
            return _blank_inventory(year)

        if not isinstance(data.get("meta"), dict):
            data["meta"] = {}

        data["meta"].setdefault("year", year)
        data["meta"].setdefault("name", "Asset Inventory & CIA")
        data["meta"].setdefault("submitted", False)
        data["meta"].setdefault("read_only", False)

        if not isinstance(data.get("subnets"), list):
            data["subnets"] = []

        return data
    except Exception:
        return _blank_inventory(year)


def _normalize_hostname(value: str) -> str:
    return (value or "").strip().lower()


def _normalize_status(value: str) -> str:
    raw = (value or "").strip().lower()

    if raw == "active":
        return "Active"
    if raw in {"inactive", "not active"}:
        return "Not Active"
    if raw == "unknown":
        return "Unknown"
    return ""


def _normalize_cia(value: str) -> str:
    raw = (value or "").strip().lower()
    if raw == "critical":
        return "Critical"
    if raw == "high":
        return "High"
    if raw == "medium":
        return "Medium"
    if raw == "low":
        return "Low"
    if raw == "unscanned":
        return "Unscanned"
    return ""


def _normalize_key(value: Any) -> str:
    text = str(value or "").strip().lower()
    return re.sub(r"[^a-z0-9]+", "", text)


def _possible_host_keys_from_ou_host(host: dict, generated_hostname: str) -> list[str]:
    candidates = [
        generated_hostname,
        host.get("hostname"),
        host.get("host_name"),
        host.get("name"),
        host.get("device_name"),
        host.get("computer_name"),
        host.get("id"),
        host.get("internal_ip"),
        host.get("ip_address"),
        host.get("ip"),
    ]

    out: list[str] = []
    seen = set()

    for item in candidates:
        s = str(item or "").strip()
        if not s:
            continue

        variants = {
            s,
            s.upper(),
            s.lower(),
            s.replace("_", "-"),
            s.replace("-", "_"),
        }

        for variant in variants:
            key = _normalize_key(variant)
            if key and key not in seen:
                seen.add(key)
                out.append(key)

    return out


def _extract_asset_detail_records(doc: Any) -> list[dict]:
    rows: list[dict] = []

    if isinstance(doc, list):
        return [x for x in doc if isinstance(x, dict)]

    if not isinstance(doc, dict):
        return []

    for key in ["assets", "hosts", "items", "devices", "records", "data"]:
        value = doc.get(key)
        if isinstance(value, list):
            rows.extend([x for x in value if isinstance(x, dict)])

    networks = doc.get("networks")
    if isinstance(networks, list):
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
                    if isinstance(host, dict):
                        rows.append(host)

    all_values_are_dict = bool(doc) and all(isinstance(v, dict) for v in doc.values())
    if not rows and all_values_are_dict:
        for k, v in doc.items():
            row = dict(v)
            row.setdefault("hostname", k)
            rows.append(row)

    return rows


def _extract_detail_from_assetdetails_record(record: dict) -> dict:
    if not isinstance(record, dict):
        return _blank_detail()

    detail = record.get("detail")
    if isinstance(detail, dict):
        return _normalize_detail_payload(
            detail,
            fallback_hostname=str(
                record.get("hostname")
                or record.get("host_name")
                or record.get("name")
                or record.get("device_name")
                or record.get("computer_name")
                or record.get("id")
                or ""
            ).strip()
        )

    return _blank_detail()


def _index_asset_details_by_hostname(year: int) -> dict[str, dict]:
    details_path = _asset_details_file(year)

    if not details_path.exists():
        print(f"[assets] assetdetails file not found: {details_path}")
        return {}

    try:
        raw_doc = _load_json(details_path)
    except Exception as e:
        print(f"[assets] failed reading assetdetails file: {e}")
        return {}

    records = _extract_asset_detail_records(raw_doc)
    index: dict[str, dict] = {}

    for record in records:
        if not isinstance(record, dict):
            continue

        detail = _extract_detail_from_assetdetails_record(record)

        hostname_candidates = [
            record.get("hostname"),
            record.get("host_name"),
            record.get("name"),
            record.get("device_name"),
            record.get("computer_name"),
            record.get("id"),
            record.get("ip_address"),
            record.get("internal_ip"),
            record.get("ip"),
        ]

        for candidate in hostname_candidates:
            raw = str(candidate or "").strip()
            if not raw:
                continue

            variants = {
                raw,
                raw.upper(),
                raw.lower(),
                raw.replace("_", "-"),
                raw.replace("-", "_"),
            }

            for variant in variants:
                key = _normalize_key(variant)
                if key:
                    index[key] = detail

    print(f"[assets] indexed {len(index)} host detail records from assetdetails file")
    return index


def _lookup_asset_detail(host: dict, generated_hostname: str, details_index: dict[str, dict]) -> dict:
    for key in _possible_host_keys_from_ou_host(host, generated_hostname):
        if key in details_index:
            return details_index[key]
    return _blank_detail()


def _find_target_column(df: pd.DataFrame) -> str:
    candidates = [
        "role",
        "server_role",
        "workstation_role",
        "predicted_role",
        "label",
        "target",
        "class",
    ]

    for col in candidates:
        if col in df.columns:
            return col

    raise HTTPException(
        status_code=400,
        detail=(
            "Could not find a role label column in the training datasets. "
            "Expected one of: role, server_role, workstation_role, "
            "predicted_role, label, target, class"
        ),
    )

def _rag_detect_role_from_chroma(asset: dict) -> tuple[str, float]:
    try:
        import chromadb
    except Exception:
        return "", 0.0

    chroma_path = _chroma_db_path()
    if not chroma_path.exists():
        return "", 0.0

    try:
        client = chromadb.PersistentClient(path=str(chroma_path))
        collection = client.get_collection("iso27001")
    except Exception:
        return "", 0.0

    query_text = _build_rag_query_text(asset)

    try:
        result = collection.query(
            query_texts=[query_text],
            n_results=5,
        )
    except Exception:
        return "", 0.0

    metadatas = result.get("metadatas", [[]])
    distances = result.get("distances", [[]])

    if not metadatas or not metadatas[0]:
        return "", 0.0

    best_role = ""
    best_score = 0.0

    for idx, meta in enumerate(metadatas[0]):
        if not isinstance(meta, dict):
            continue

        candidate_role = str(
            meta.get("role")
            or meta.get("workstation_role")
            or meta.get("server_role")
            or meta.get("category")
            or ""
        ).strip()

        if not candidate_role:
            continue

        distance = None
        if distances and distances[0] and idx < len(distances[0]):
            distance = distances[0][idx]

        score = 0.70
        if isinstance(distance, (int, float)):
            score = max(0.0, min(1.0, 1.0 - float(distance)))

        if score > best_score:
            best_role = candidate_role
            best_score = score

    return best_role, best_score

def _join_text_list(values: list[Any]) -> str:
    return ", ".join(str(v).strip() for v in values if str(v).strip())


def _build_rag_query_text(asset: dict) -> str:
    detail = _get_asset_detail(asset)
    device_profile = detail.get("device_profile", {}) or {}
    technical = detail.get("technical_indicators", {}) or {}
    business = detail.get("business_context", {}) or {}

    parts = [
        f"hostname: {asset.get('hostname', '')}",
        f"os_type: {device_profile.get('os_type', '')}",
        f"os_version: {device_profile.get('os_version', '')}",
        f"running_services: {_join_text_list(_safe_list(technical.get('running_services', [])))}",
        f"installed_roles: {_join_text_list(_safe_list(technical.get('installed_roles', [])))}",
        f"installed_software: {_join_text_list(_safe_list(technical.get('installed_software', [])))}",
        f"department: {business.get('department', '')}",
        f"business_function: {business.get('business_function', '')}",
    ]
    return " | ".join(parts)

def _normalize_training_dataframe(df: pd.DataFrame, target_col: str) -> pd.DataFrame:
    df = df.copy()
    df = df.dropna(how="all")
    df = df[df[target_col].notna()].copy()

    for col in df.columns:
        if col == target_col:
            continue

        df[col] = df[col].apply(
            lambda v: ", ".join(str(x) for x in v) if isinstance(v, list)
            else json.dumps(v, sort_keys=True) if isinstance(v, dict)
            else v
        )

    return df

def _normalize_cell_for_dedup(value: Any) -> str:
    if value is None:
        return ""

    if isinstance(value, list):
        cleaned = [str(x).strip().lower() for x in value if str(x).strip()]
        return " | ".join(cleaned)

    if isinstance(value, dict):
        try:
            return json.dumps(value, sort_keys=True, ensure_ascii=False).strip().lower()
        except Exception:
            return str(value).strip().lower()

    return str(value).strip().lower()


def _remove_duplicate_training_records(
    df: pd.DataFrame,
    target_col: str,
    dataset_name: str,
) -> tuple[pd.DataFrame, dict]:
    if df.empty:
        return df, {
            "before_rows": 0,
            "after_rows": 0,
            "duplicates_removed": 0,
        }

    work_df = df.copy()
    before_rows = len(work_df)

    # Remove fully empty rows
    work_df = work_df.dropna(how="all").copy()

    # Keep only rows that have a target label
    work_df = work_df[work_df[target_col].notna()].copy()
    work_df[target_col] = work_df[target_col].astype(str).str.strip()
    work_df = work_df[work_df[target_col] != ""].copy()

    # Build normalized copy only for duplicate detection
    dedup_df = work_df.copy()
    for col in dedup_df.columns:
        dedup_df[col] = dedup_df[col].apply(_normalize_cell_for_dedup)

    # Remove duplicates using all columns actually used for training
    dedup_mask = ~dedup_df.duplicated(keep="first")
    work_df = work_df.loc[dedup_mask].reset_index(drop=True)

    after_rows = len(work_df)
    duplicates_removed = before_rows - after_rows

    print(f"[train][{dataset_name}] before rows = {before_rows}")
    print(f"[train][{dataset_name}] after dedup = {after_rows}")
    print(f"[train][{dataset_name}] duplicates removed = {duplicates_removed}")

    return work_df, {
        "before_rows": int(before_rows),
        "after_rows": int(after_rows),
        "duplicates_removed": int(duplicates_removed),
    }

SERVER_BOOLEAN_PORTS = [53, 67, 68, 80, 88, 110, 135, 143, 389, 443, 445, 465, 587, 636, 993, 995, 1433, 1521, 3306, 3389, 5432, 5985, 5986]

SERVER_SERVICE_KEYWORDS = {
    "has_dns_service": ["dns"],
    "has_kerberos_service": ["kerberos"],
    "has_ad_ds_service": ["active directory", "ad ds", "domain services"],
    "has_dhcp_service": ["dhcp"],
    "has_iis_service": ["iis", "world wide web publishing", "w3svc"],
    "has_web_service": ["apache", "nginx", "http", "https", "web"],
    "has_sql_service": ["sql", "mssql", "mysql", "postgres", "oracle database", "database"],
    "has_file_service": ["file", "smb", "cifs"],
    "has_print_service": ["print", "spooler"],
    "has_rdp_service": ["remote desktop", "terminal services", "rdp"],
    "has_adfs_service": ["adfs", "active directory federation"],
    "has_exchange_service": ["exchange"],
    "has_hyperv_service": ["hyper-v"],
    "has_backup_service": ["backup", "veeam", "commvault"],
    "has_firewall_service": ["firewall", "utm", "fortigate", "palo alto", "checkpoint"],
    "has_mail_service": ["smtp", "imap", "pop3", "mail"],
    "has_vpn_service": ["vpn", "ipsec", "openvpn", "wireguard"],
}

SERVER_ROLE_KEYWORDS = {
    "has_ad_ds_role": ["ad ds", "active directory domain services"],
    "has_dns_role": ["dns"],
    "has_dhcp_role": ["dhcp"],
    "has_web_server_role": ["web server", "iis"],
    "has_file_server_role": ["file server"],
    "has_print_server_role": ["print server"],
    "has_hyperv_role": ["hyper-v"],
    "has_remote_desktop_role": ["remote desktop services", "terminal services"],
    "has_adcs_role": ["ad cs", "certificate services"],
    "has_wsus_role": ["wsus", "windows server update services"],
}

SERVER_SOFTWARE_KEYWORDS = {
    "has_gpmc_software": ["group policy management"],
    "has_sql_server_software": ["sql server"],
    "has_exchange_software": ["exchange"],
    "has_veeam_software": ["veeam"],
    "has_vmware_software": ["vmware"],
    "has_backup_software": ["backup exec", "commvault", "veeam"],
    "has_security_gateway_software": ["email security", "secure email", "mail gateway"],
}


def _ml_parse_listish(value: Any) -> list[str]:
    if value is None:
        return []

    if isinstance(value, list):
        return [str(x).strip() for x in value if str(x).strip()]

    text = str(value).strip()
    if not text:
        return []

    if text.startswith("[") and text.endswith("]"):
        try:
            parsed = ast.literal_eval(text)
            if isinstance(parsed, list):
                return [str(x).strip() for x in parsed if str(x).strip()]
        except Exception:
            pass

    parts = re.split(r"[|,;/]+", text)
    return [p.strip() for p in parts if p.strip()]


def _ml_parse_port_list(value: Any) -> list[int]:
    ports: list[int] = []
    for item in _ml_parse_listish(value):
        try:
            ports.append(int(str(item).strip()))
        except Exception:
            continue
    return ports


def _contains_any_keywords(text_values: list[str], keywords: list[str]) -> bool:
    joined = " | ".join(str(x).lower() for x in text_values if str(x).strip())
    return any(k.lower() in joined for k in keywords)


def _build_server_feature_row(
    *,
    os_type: Any,
    os_version: Any,
    hostname_pattern: Any,
    business_function: Any,
    department: Any,
    open_ports_value: Any,
    running_services_value: Any,
    installed_roles_value: Any,
    installed_software_value: Any,
) -> dict:
    ports = _ml_parse_port_list(open_ports_value)
    services = [x.lower() for x in _ml_parse_listish(running_services_value)]
    roles = [x.lower() for x in _ml_parse_listish(installed_roles_value)]
    software = [x.lower() for x in _ml_parse_listish(installed_software_value)]

    features = {
        "os_type": str(os_type or "").strip(),
        "os_version": str(os_version or "").strip(),
        "hostname_pattern": str(hostname_pattern or "").strip(),
        "business_function": str(business_function or "").strip(),
        "department": str(department or "").strip(),
        "open_ports_text": " ".join(str(p) for p in sorted(set(ports))),
        "running_services_text": " | ".join(services),
        "installed_roles_text": " | ".join(roles),
        "installed_software_text": " | ".join(software),
    }

    for port in SERVER_BOOLEAN_PORTS:
        features[f"has_port_{port}"] = int(port in ports)

    for col, keywords in SERVER_SERVICE_KEYWORDS.items():
        features[col] = int(_contains_any_keywords(services, keywords))

    for col, keywords in SERVER_ROLE_KEYWORDS.items():
        features[col] = int(_contains_any_keywords(roles, keywords))

    for col, keywords in SERVER_SOFTWARE_KEYWORDS.items():
        features[col] = int(_contains_any_keywords(software, keywords))

    return features


def _build_server_training_dataframe_for_model(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame()

    target_col = _find_target_column(df)
    rows: list[dict] = []

    for _, row in df.iterrows():
        role_name = str(row.get(target_col, "")).strip()
        if not role_name or role_name.lower() == "unassigned":
            continue

        features = _build_server_feature_row(
            os_type=row.get("os_type", ""),
            os_version=row.get("os_version", ""),
            hostname_pattern=row.get("hostname_pattern", ""),
            business_function=row.get("business_function", ""),
            department=row.get("department", ""),
            open_ports_value=row.get("open_ports", ""),
            running_services_value=row.get("running_services", ""),
            installed_roles_value=row.get("installed_roles", ""),
            installed_software_value=row.get("installed_software", ""),
        )
        features["role"] = role_name
        rows.append(features)

    if not rows:
        return pd.DataFrame()

    return pd.DataFrame(rows)


def _rebalance_server_training_dataframe(
    df: pd.DataFrame,
    label_col: str = "role",
    min_samples_per_class: int = 3,
    max_samples_per_class: int = 25,
) -> pd.DataFrame:
    if df.empty:
        return df

    counts = df[label_col].value_counts()
    valid_roles = counts[counts >= min_samples_per_class].index.tolist()
    filtered = df[df[label_col].isin(valid_roles)].copy()

    if filtered.empty:
        return filtered

    parts: list[pd.DataFrame] = []
    for _, group in filtered.groupby(label_col):
        if len(group) > max_samples_per_class:
            group = group.sample(n=max_samples_per_class, random_state=42)
        parts.append(group)

    return pd.concat(parts, ignore_index=True)


def _train_server_role_pipeline(server_df: pd.DataFrame) -> tuple[Pipeline, list[str], dict]:
    if server_df.empty:
        raise ValueError("No server training data available.")

    server_df = _rebalance_server_training_dataframe(
        server_df,
        label_col="role",
        min_samples_per_class=3,
        max_samples_per_class=25,
    )

    if server_df.empty:
        raise ValueError("No valid server classes remain after filtering/rebalancing.")

    y = server_df["role"].astype(str)
    X = server_df.drop(columns=["role"]).copy()

    categorical_features = [
        "os_type",
        "os_version",
        "hostname_pattern",
        "business_function",
        "department",
        "open_ports_text",
        "running_services_text",
        "installed_roles_text",
        "installed_software_text",
    ]

    numeric_features = [c for c in X.columns if c not in categorical_features]

    preprocessor = ColumnTransformer(
        transformers=[
            (
                "cat",
                Pipeline(
                    steps=[
                        ("imputer", SimpleImputer(strategy="constant", fill_value="")),
                        ("onehot", OneHotEncoder(handle_unknown="ignore")),
                    ]
                ),
                categorical_features,
            ),
            (
                "num",
                Pipeline(
                    steps=[
                        ("imputer", SimpleImputer(strategy="constant", fill_value=0)),
                    ]
                ),
                numeric_features,
            ),
        ],
        remainder="drop",
    )

    model = Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            (
                "classifier",
                RandomForestClassifier(
                    n_estimators=300,
                    max_depth=None,
                    min_samples_split=2,
                    min_samples_leaf=1,
                    class_weight="balanced",
                    random_state=42,
                    n_jobs=1,
                ),
            ),
        ]
    )

    model.fit(X, y)
    return model, list(X.columns), y.value_counts().to_dict()


def _server_feature_completeness_ratio(asset: dict) -> float:
    detail = _get_asset_detail(asset)
    device_profile = detail.get("device_profile", {}) or {}
    technical = detail.get("technical_indicators", {}) or {}
    business = detail.get("business_context", {}) or {}

    checks = [
        bool(str(device_profile.get("os_type", "")).strip()),
        bool(str(device_profile.get("os_version", "")).strip()),
        bool(str(device_profile.get("hostname_pattern", "")).strip()),
        bool(str(business.get("business_function", "")).strip()),
        bool(str(business.get("department", "")).strip()),
        len(_safe_list(technical.get("open_ports", []))) > 0,
        len(_safe_list(technical.get("running_services", []))) > 0,
        len(_safe_list(technical.get("installed_roles", []))) > 0,
        len(_safe_list(technical.get("installed_software", []))) > 0,
    ]

    return sum(1 for x in checks if x) / len(checks)


def _predict_server_role_for_asset(asset: dict, model) -> tuple[str, float]:
    detail = _get_asset_detail(asset)
    device_profile = detail.get("device_profile", {}) or {}
    technical = detail.get("technical_indicators", {}) or {}
    business = detail.get("business_context", {}) or {}

    features = _build_server_feature_row(
        os_type=device_profile.get("os_type", ""),
        os_version=device_profile.get("os_version", ""),
        hostname_pattern=device_profile.get("hostname_pattern", ""),
        business_function=business.get("business_function", ""),
        department=business.get("department", ""),
        open_ports_value=technical.get("open_ports", []),
        running_services_value=technical.get("running_services", []),
        installed_roles_value=technical.get("installed_roles", []),
        installed_software_value=technical.get("installed_software", []),
    )

    try:
        expected_cols = list(model.named_steps["preprocessor"].feature_names_in_)
    except Exception:
        expected_cols = list(features.keys())

    row = {}
    for col in expected_cols:
        if col in features:
            row[col] = features[col]
        elif col.startswith("has_"):
            row[col] = 0
        else:
            row[col] = ""

    X_pred = pd.DataFrame([row], columns=expected_cols)

    predicted_role = str(model.predict(X_pred)[0]).strip()

    confidence = 0.0
    if hasattr(model, "predict_proba"):
        try:
            probs = model.predict_proba(X_pred)[0]
            confidence = float(max(probs))
        except Exception:
            confidence = 0.0

    return predicted_role, confidence

def _build_training_pipeline(X: pd.DataFrame) -> Pipeline:

    # treat everything as categorical
    categorical_cols = list(X.columns)

    preprocessor = ColumnTransformer(
        transformers=[
            (
                "cat",
                Pipeline(
                    steps=[
                        ("imputer", SimpleImputer(strategy="constant", fill_value="Unknown")),
                        ("onehot", OneHotEncoder(handle_unknown="ignore")),
                    ]
                ),
                categorical_cols,
            ),
        ],
        remainder="drop",
    )

    return Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            (
                "classifier",
                RandomForestClassifier(
                    n_estimators=300,
                    max_depth=20,
                    random_state=42,
                    n_jobs=1,
                ),
            ),
        ]
    )
    
def _all_assets(inventory: dict) -> list[dict]:
    rows: list[dict] = []
    for subnet in inventory.get("subnets", []):
        assets = subnet.get("assets", [])
        if isinstance(assets, list):
            rows.extend([a for a in assets if isinstance(a, dict)])
    return rows


def _inventory_is_read_only(inventory: dict) -> bool:
    meta = inventory.get("meta", {})
    return bool(meta.get("submitted")) or bool(meta.get("read_only"))


def _count_unknown_status_hosts(inventory: dict) -> int:
    count = 0
    for asset in _all_assets(inventory):
        if _normalize_status(asset.get("status") or "") == "Unknown":
            count += 1
    return count


def _find_asset_by_hostname(inventory: dict, hostname: str) -> tuple[dict | None, dict | None]:
    target_key = _normalize_hostname(hostname)

    for subnet in inventory.get("subnets", []):
        assets = subnet.get("assets", [])
        if not isinstance(assets, list):
            continue

        for asset in assets:
            current_hostname = _normalize_hostname(asset.get("hostname") or "")
            if current_hostname == target_key:
                return subnet, asset

    return None, None


def _safe_append_aiml_kpi_event(year: int, bucket: str, event: dict) -> None:
    try:
        append_aiml_kpi_event(year, bucket, event)
    except Exception as e:
        print(f"[aiml-kpi] failed to append {bucket}: {e}")


def _safe_append_aiml_kpi_events(year: int, bucket: str, events: list[dict]) -> None:
    try:
        append_aiml_kpi_events(year, bucket, events)
    except Exception as e:
        print(f"[aiml-kpi] failed to append {bucket}: {e}")


def _first_text(value: Any) -> str:
    if isinstance(value, list):
        for item in value:
            text = str(item or "").strip()
            if text:
                return text
        return ""
    return str(value or "").strip()


def _asset_selected_role(asset: dict) -> str:
    detail = _get_asset_detail(asset)
    selected_block = detail.get("selected_role", {}) or {}
    if isinstance(selected_block, dict):
        selected_role = str(selected_block.get("role") or "").strip()
        if selected_role:
            return selected_role
    return str(asset.get("role") or "").strip()


def _asset_ml_role(asset: dict) -> str:
    detail = _get_asset_detail(asset)
    ml_block = detail.get("ml_role_prediction", {}) or {}
    if not isinstance(ml_block, dict):
        return ""
    return _first_text(ml_block.get("predicted_roles") or ml_block.get("predicted_role"))


def _asset_ml_confidence(asset: dict) -> float | None:
    detail = _get_asset_detail(asset)
    ml_block = detail.get("ml_role_prediction", {}) or {}
    if not isinstance(ml_block, dict):
        return None
    try:
        raw = str(ml_block.get("confidence") or "").strip()
        return float(raw) if raw else None
    except Exception:
        return None


def _build_role_prediction_telemetry_events(inventory: dict, source_endpoint: str) -> list[dict]:
    events: list[dict] = []
    for asset in _all_assets(inventory):
        hostname = str(asset.get("hostname") or "").strip()
        predicted_role = _asset_ml_role(asset)
        final_role = _asset_selected_role(asset)
        if not hostname or not predicted_role or not final_role:
            continue

        detail = _get_asset_detail(asset)
        selected_block = detail.get("selected_role", {}) or {}
        ml_block = detail.get("ml_role_prediction", {}) or {}

        events.append({
            "event_id": f"role_pred_{hostname}_{datetime.now().astimezone().strftime('%Y-%m-%d_%H-%M-%S')}",
            "hostname": hostname,
            "model_type": "role_prediction",
            "asset_type": "server" if _is_server_asset(asset) else "workstation",
            "predicted_role": predicted_role,
            "final_role": final_role,
            "confidence": _asset_ml_confidence(asset),
            "is_correct": predicted_role.strip().lower() == final_role.strip().lower(),
            "selected_method": (
                str(selected_block.get("method") or "").strip()
                if isinstance(selected_block, dict)
                else ""
            ),
            "model_error": (
                str(ml_block.get("error") or "").strip()
                if isinstance(ml_block, dict)
                else ""
            ),
            "source_endpoint": source_endpoint,
        })
    return events


def _flatten_asset_for_training(asset: dict) -> dict:
    detail = asset.get("detail", {}) or {}
    device_profile = detail.get("device_profile", {}) or {}
    technical = detail.get("technical_indicators", {}) or {}
    business = detail.get("business_context", {}) or {}
    indicator = detail.get("indicator_based_role_detection", {}) or {}
    ml_pred = detail.get("ml_role_prediction", {}) or {}
    rag_pred = detail.get("rag_based_role_detection", {}) or {}

    location = asset.get("location", {}) or {}
    cia = asset.get("cia_rating", {}) or {}

    def _join_list(v):
        if isinstance(v, list):
            return ", ".join(str(x) for x in v)
        return ""

    return {
        "hostname": asset.get("hostname", ""),
        "role": asset.get("role", ""),
        "operating_system": asset.get("operating_system", ""),
        "location_name": location.get("name", ""),
        "ip_address": location.get("ip_address", ""),
        "status": asset.get("status", ""),
        "criticality": cia.get("criticality", ""),
        "os_type": device_profile.get("os_type", ""),
        "os_version": device_profile.get("os_version", ""),
        "is_domain_joined": device_profile.get("is_domain_joined", False),
        "hostname_pattern": device_profile.get("hostname_pattern", ""),
        "open_ports": _join_list(technical.get("open_ports", [])),
        "running_services": _join_list(technical.get("running_services", [])),
        "installed_roles": _join_list(technical.get("installed_roles", [])),
        "installed_software": _join_list(technical.get("installed_software", [])),
        "department": business.get("department", ""),
        "business_function": business.get("business_function", ""),
        "business_criticality": business.get("criticality", ""),
        "indicator_detected_roles": _join_list(indicator.get("detected_roles", [])),
        "indicator_confidence": indicator.get("confidence", ""),
        "ml_predicted_roles": _join_list(ml_pred.get("predicted_roles", [])),
        "ml_confidence": ml_pred.get("confidence", ""),
        "rag_detected_role": rag_pred.get("detected_role", ""),
        "rag_confidence": rag_pred.get("confidence", ""),
        DATA_SOURCE_COLUMN: DATA_SOURCE_REAL,
    }

def _append_records_to_parquet(path: Path, rows: list[dict]) -> int:
    if not rows:
        return 0

    new_df = pd.DataFrame(rows)

    if DATA_SOURCE_COLUMN not in new_df.columns:
        new_df[DATA_SOURCE_COLUMN] = DATA_SOURCE_REAL
    else:
        new_df[DATA_SOURCE_COLUMN] = DATA_SOURCE_REAL

    for col in new_df.columns:
        new_df[col] = new_df[col].astype(str)

    if path.exists():
        try:
            old_df = pd.read_parquet(path)

            if DATA_SOURCE_COLUMN not in old_df.columns:
                old_df[DATA_SOURCE_COLUMN] = DATA_SOURCE_SYNTHETIC
            else:
                missing_mask = old_df[DATA_SOURCE_COLUMN].isna() | (old_df[DATA_SOURCE_COLUMN].astype(str).str.strip() == "")
                if missing_mask.any():
                    old_df.loc[missing_mask, DATA_SOURCE_COLUMN] = DATA_SOURCE_SYNTHETIC

            for col in old_df.columns:
                old_df[col] = old_df[col].astype(str)

            all_cols = sorted(set(old_df.columns) | set(new_df.columns))

            for col in all_cols:
                if col not in old_df.columns:
                    old_df[col] = ""
                if col not in new_df.columns:
                    new_df[col] = ""

            old_df = old_df[all_cols]
            new_df = new_df[all_cols]

            combined = pd.concat([old_df, new_df], ignore_index=True)
        except Exception:
            combined = new_df.copy()
    else:
        combined = new_df.copy()

    path.parent.mkdir(parents=True, exist_ok=True)
    combined.to_parquet(path, index=False)
    return len(new_df)

def _ensure_parquet_has_data_source(path: Path) -> dict:
    if not path.exists():
        return {
            "path": str(path),
            "updated": False,
            "rows": 0,
            "synthetic_tagged_rows": 0,
        }

    df = pd.read_parquet(path)
    if df.empty:
        if DATA_SOURCE_COLUMN not in df.columns:
            df[DATA_SOURCE_COLUMN] = DATA_SOURCE_SYNTHETIC
            df.to_parquet(path, index=False)
        return {
            "path": str(path),
            "updated": True,
            "rows": 0,
            "synthetic_tagged_rows": 0,
        }

    updated = False

    if DATA_SOURCE_COLUMN not in df.columns:
        df[DATA_SOURCE_COLUMN] = DATA_SOURCE_SYNTHETIC
        updated = True
    else:
        missing_mask = df[DATA_SOURCE_COLUMN].isna() | (df[DATA_SOURCE_COLUMN].astype(str).str.strip() == "")
        if missing_mask.any():
            df.loc[missing_mask, DATA_SOURCE_COLUMN] = DATA_SOURCE_SYNTHETIC
            updated = True

    if updated:
        df.to_parquet(path, index=False)

    synthetic_count = 0
    if DATA_SOURCE_COLUMN in df.columns:
        synthetic_count = int((df[DATA_SOURCE_COLUMN].astype(str).str.strip().str.lower() == DATA_SOURCE_SYNTHETIC).sum())

    return {
        "path": str(path),
        "updated": updated,
        "rows": int(len(df)),
        "synthetic_tagged_rows": synthetic_count,
    }


def _append_inventory_to_training_datasets(inventory: dict) -> dict:
    server_rows: list[dict] = []
    workstation_rows: list[dict] = []

    for asset in _all_assets(inventory):
        if not _is_valid_asset_for_submit(asset):
            continue

        row = _flatten_asset_for_training(asset)
        hostname = str(asset.get("hostname", "")).strip().upper()

        if _is_server_hostname(hostname):
            server_rows.append(row)
        elif _is_workstation_hostname(hostname):
            workstation_rows.append(row)

    server_source_update = _ensure_parquet_has_data_source(_server_dataset_path())
    workstation_source_update = _ensure_parquet_has_data_source(_workstation_dataset_path())

    server_added = _append_records_to_parquet(_server_dataset_path(), server_rows)
    workstation_added = _append_records_to_parquet(_workstation_dataset_path(), workstation_rows)

    print("SERVER ROWS ADDED =", server_added)
    print("WORKSTATION ROWS ADDED =", workstation_added)

    return {
        "server_rows_added": server_added,
        "workstation_rows_added": workstation_added,
        "total_rows_added": server_added + workstation_added,
        "server_data_source_update": server_source_update,
        "workstation_data_source_update": workstation_source_update,
    }


def _append_inventory_to_training_datasets(inventory: dict) -> dict:
    server_rows: list[dict] = []
    workstation_rows: list[dict] = []

    for asset in _all_assets(inventory):
        if not _is_valid_asset_for_submit(asset):
            continue

        row = _flatten_asset_for_training(asset)
        hostname = str(asset.get("hostname", "")).strip().upper()

        if _is_server_hostname(hostname):
            server_rows.append(row)
        elif _is_workstation_hostname(hostname):
            workstation_rows.append(row)

    server_added = _append_records_to_parquet(_server_dataset_path(), server_rows)
    workstation_added = _append_records_to_parquet(_workstation_dataset_path(), workstation_rows)


    print("SERVER ROWS ADDED =", server_added)
    print("WORKSTATION ROWS ADDED =", workstation_added)

    return {
        "server_rows_added": server_added,
        "workstation_rows_added": workstation_added,
        "total_rows_added": server_added + workstation_added,
    }

def _get_asset_detail(asset: dict) -> dict:
    detail = asset.get("detail")
    if not isinstance(detail, dict):
        detail = _blank_detail()
        asset["detail"] = detail
    return detail


def _parse_possible_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(x).strip() for x in value if str(x).strip()]

    if value is None:
        return []

    text = str(value).strip()
    if not text:
        return []

    if text.startswith("[") and text.endswith("]"):
        try:
            parsed = ast.literal_eval(text)
            if isinstance(parsed, list):
                return [str(x).strip() for x in parsed if str(x).strip()]
        except Exception:
            pass

    parts = re.split(r"[|,;/]+", text)
    return [p.strip() for p in parts if p.strip()]


def _normalize_text_token(value: Any) -> str:
    text = str(value or "").strip().lower()
    return re.sub(r"[^a-z0-9]+", " ", text).strip()


def _tokenize_text(value: Any) -> set[str]:
    text = _normalize_text_token(value)
    if not text:
        return set()
    return {t for t in text.split() if t}


def _normalize_confidence_to_score(value: Any) -> float:
    if value is None:
        return 0.0

    if isinstance(value, (int, float)):
        num = float(value)
        if num > 1:
            return max(0.0, min(1.0, num / 100.0))
        return max(0.0, min(1.0, num))

    text = str(value).strip().lower()
    if not text:
        return 0.0

    mapping = {
        "very high": 0.95,
        "high": 0.85,
        "medium": 0.65,
        "low": 0.40,
        "manual": 1.00,
        "model": 0.75,
    }
    if text in mapping:
        return mapping[text]

    try:
        num = float(text)
        if num > 1:
            return max(0.0, min(1.0, num / 100.0))
        return max(0.0, min(1.0, num))
    except Exception:
        pass

    match = re.search(r"(\d+(?:\.\d+)?)", text)
    if match:
        num = float(match.group(1))
        if num > 1:
            return max(0.0, min(1.0, num / 100.0))
        return max(0.0, min(1.0, num))

    return 0.0


def _score_to_confidence_label(score: float) -> str:
    if score >= 0.90:
        return "Very High"
    if score >= 0.75:
        return "High"
    if score >= 0.55:
        return "Medium"
    if score > 0:
        return "Low"
    return ""


def _first_existing_path(candidates: list[Path]) -> Path | None:
    for p in candidates:
        if p.exists():
            return p
    return None


def _workstation_kb_path() -> Path | None:
    return _find_first_matching_file(
        _search_roots_for_kb(),
        [
            "workstation_role_detection_indicators.csv",
            "workstation_role_knowledge_base.csv",
            "workstation_roles_knowledge_base.csv",
            "windows_workstation_roles.csv",
            "*workstation*role*detection*.csv",
            "*workstation*role*.csv",
        ],
    )
    
def _windows_software_kb_path() -> Path | None:
    return _find_first_matching_file(
        _search_roots_for_kb(),
        [
            "windows_software-categorized.csv",
            "*windows*software*.csv",
            "*software*categorized*.csv",
        ],
    )

def _load_csv_or_empty(path: Path | None) -> pd.DataFrame:
    if not path:
        return pd.DataFrame()
    try:
        return pd.read_csv(path)
    except Exception:
        return pd.DataFrame()


def _installed_software_tokens(asset: dict) -> set[str]:
    detail = _get_asset_detail(asset)
    technical = detail.get("technical_indicators", {}) or {}
    installed_software = technical.get("installed_software", [])
    installed_roles = technical.get("installed_roles", [])
    running_services = technical.get("running_services", [])

    tokens: set[str] = set()
    for item in _safe_list(installed_software) + _safe_list(installed_roles) + _safe_list(running_services):
        tokens |= _tokenize_text(item)
    return tokens


def _installed_software_texts(asset: dict) -> list[str]:
    detail = _get_asset_detail(asset)
    technical = detail.get("technical_indicators", {}) or {}
    texts = []
    for item in _safe_list(technical.get("installed_software", [])):
        s = str(item).strip()
        if s:
            texts.append(s)
    return texts


def _is_workstation_asset(asset: dict) -> bool:
    hostname = str(asset.get("hostname", "")).upper()
    if hostname.startswith("WS-"):
        return True

    detail = _get_asset_detail(asset)
    device_profile = detail.get("device_profile", {}) or {}
    os_type = str(device_profile.get("os_type", "")).lower()
    os_version = str(device_profile.get("os_version", "")).lower()
    role = str(asset.get("role", "")).lower()

    if "server" in role:
        return False
    if "server" in os_type or "server" in os_version:
        return False
    return True

def _is_server_asset(asset: dict) -> bool:
    hostname = str(asset.get("hostname", "")).upper()
    if hostname.startswith("SRV-"):
        return True

    detail = _get_asset_detail(asset)
    device_profile = detail.get("device_profile", {}) or {}
    os_type = str(device_profile.get("os_type", "")).lower()
    os_version = str(device_profile.get("os_version", "")).lower()
    role = str(asset.get("role", "")).lower()

    if "server" in role:
        return True
    if "server" in os_type or "server" in os_version:
        return True

    return False
    
def _candidate_role_columns(df: pd.DataFrame) -> list[str]:
    preferred = [
        "role",
        "workstation_role",
        "server_role",
        "category",
        "software_category",
        "mapped_role",
        "predicted_role",
    ]
    return [c for c in preferred if c in df.columns]


def _choose_best_role_column(df: pd.DataFrame) -> str | None:
    cols = _candidate_role_columns(df)
    return cols[0] if cols else None


def _choose_indicator_column(df: pd.DataFrame) -> str | None:
    candidates = [
        "software_indicators",
        "indicators",
        "software",
        "installed_software",
        "keywords",
        "keyword",
        "applications",
    ]
    for col in candidates:
        if col in df.columns:
            return col
    return None

def _sorted_roles_list(values: set[str]) -> list[str]:
    return sorted([str(v).strip() for v in values if str(v).strip()], key=lambda x: x.lower())

def _indicator_detect_role_from_workstation_kb(asset: dict, kb_df: pd.DataFrame) -> tuple[list[str], float]:
    if kb_df.empty:
        return [], 0.0

    role_col = _choose_best_role_column(kb_df)
    indicator_col = _choose_indicator_column(kb_df)

    if not role_col or not indicator_col:
        return [], 0.0

    asset_tokens = _installed_software_tokens(asset)
    if not asset_tokens:
        return [], 0.0

    scored_roles: list[tuple[str, float]] = []

    for _, row in kb_df.iterrows():
        role_name = str(row.get(role_col, "")).strip()
        if not role_name:
            continue

        indicator_values = _parse_possible_list(row.get(indicator_col))
        row_tokens: set[str] = set()
        for item in indicator_values:
            row_tokens |= _tokenize_text(item)

        if not row_tokens:
            continue

        overlap = asset_tokens & row_tokens
        if not overlap:
            continue

        score = len(overlap) / max(1, len(row_tokens))
        scored_roles.append((role_name, score))

    if not scored_roles:
        return [], 0.0

    scored_roles.sort(key=lambda x: x[1], reverse=True)
    top_role, top_score = scored_roles[0]

    additional_roles = [role for role, score in scored_roles[1:3] if score >= max(0.35, top_score * 0.7)]
    roles = [top_role] + [r for r in additional_roles if r != top_role]

    return roles, top_score

def _server_roles_kb_path() -> Path | None:
    return _find_first_matching_file(
        _search_roots_for_kb(),
        [
            "nist_cia_server_roles_dataset.csv",
            "*server*role*.csv",
            "*server*roles*.csv",
            "*nist*server*.csv",
        ],
    )

def _workstation_roles_kb_path() -> Path | None:
    return _find_first_matching_file(
        _search_roots_for_kb(),
        [
            "workstation_role_detection_indicators.csv",
            "workstation_role_knowledge_base.csv",
            "workstation_roles_knowledge_base.csv",
            "windows_workstation_roles.csv",
            "*workstation*role*detection*.csv",
            "*workstation*role*.csv",
            "*windows*workstation*.csv",
        ],
    )

def _load_allowed_roles_from_csv(path: Path | None) -> set[str]:

    df = _load_csv_or_empty(path)

    if df.empty:
        return set()

    role_columns = [
        "role",
        "server_role",
        "workstation_role",
        "role_name",
        "name",
        "category",
        "software_category",
        "mapped_role",
        "detected_role",
    ]

    for col in role_columns:
        if col in df.columns:
            values = {
                str(v).strip()
                for v in df[col].dropna().tolist()
                if str(v).strip()
            }
            return values

    for col in df.columns:
        col_lower = str(col).strip().lower()
        if "role" in col_lower or "category" in col_lower:
            values = {
                str(v).strip()
                for v in df[col].dropna().tolist()
                if str(v).strip()
            }
            if values:
                return values

    return set()  
    
SERVER_ROLE_ALIAS_MAP = {
    "Domain Controller": [
        "Domain Controller",
        "Active Directory Domain Services",
        "AD DS",
        "Identity Infrastructure",
        "Directory Services",
        "Authentication Server",
        "Kerberos Server",
    ],
    "DNS Server": [
        "DNS Server",
        "Authoritative DNS Server",
        "Recursive DNS Server",
        "Name Resolution Server",
        "Internal DNS Server",
    ],
    "DHCP Server": [
        "DHCP Server",
        "IP Address Management Server",
        "Dynamic Host Configuration Server",
    ],
    "File Server": [
        "File Server",
        "SMB File Server",
        "Network Attached Storage",
        "NAS Server",
        "Storage Server",
    ],
    "Web Server": [
        "Web Server",
        "Web Hosting Server",
        "HTTP Server",
        "HTTPS Server",
        "Application Server",
        "Public Website Server",
        "Intranet Web Server",
        "Reverse Proxy Server",
    ],
    "Database Server": [
        "Database Server",
        "SQL Server",
        "MySQL Server",
        "PostgreSQL Server",
        "Oracle Database Server",
        "Relational Database Server",
    ],
    "Mail Server": [
        "Mail Server",
        "Email Server",
        "Exchange Server",
        "SMTP Server",
        "Messaging Server",
    ],
    "VPN Server": [
        "VPN Server",
        "Remote Access Server",
        "IPsec Gateway",
        "OpenVPN Server",
        "WireGuard Server",
    ],
    "Firewall": [
        "Firewall",
        "Firewall Server",
        "Security Gateway",
        "Perimeter Firewall",
        "Web Application Firewall",
    ],
}


def _best_allowed_role_match(role: str, allowed_roles: set[str]) -> str:
    if not role or not allowed_roles:
        return ""

    role = str(role).strip()
    role_key = _normalize_key(role)

    # 1. exact match
    if role in allowed_roles:
        return role

    # 2. normalized exact match
    for allowed in allowed_roles:
        if _normalize_key(allowed) == role_key:
            return allowed

    # 3. alias map lookup
    alias_candidates = SERVER_ROLE_ALIAS_MAP.get(role, [])
    alias_keys = {_normalize_key(x) for x in alias_candidates if str(x).strip()}

    for allowed in allowed_roles:
        allowed_key = _normalize_key(allowed)
        if allowed_key in alias_keys:
            return allowed

    # 4. contains/substring similarity
    for allowed in allowed_roles:
        allowed_key = _normalize_key(allowed)
        if role_key in allowed_key or allowed_key in role_key:
            return allowed

    # 5. token overlap fallback
    role_tokens = set(_normalize_text_token(role).split())
    best_match = ""
    best_score = 0

    for allowed in allowed_roles:
        allowed_tokens = set(_normalize_text_token(allowed).split())
        if not allowed_tokens:
            continue

        overlap = role_tokens & allowed_tokens
        score = len(overlap)

        if score > best_score:
            best_score = score
            best_match = allowed

    if best_score > 0:
        return best_match

    return ""


def _restrict_role_to_allowed(role: str, allowed_roles: set[str]) -> str:
    role = str(role or "").strip()
    if not role or not allowed_roles:
        return ""

    return _best_allowed_role_match(role, allowed_roles)
    
def _get_indicator_role_candidates(asset: dict) -> list[str]:
    detail = _get_asset_detail(asset)
    indicator = detail.get("indicator_based_role_detection", {}) or {}
    detected_roles = indicator.get("detected_roles", [])

    if isinstance(detected_roles, list):
        cleaned = [str(x).strip() for x in detected_roles if str(x).strip()]
        return cleaned

    if isinstance(detected_roles, str) and detected_roles.strip():
        return [detected_roles.strip()]

    return []


def _indicator_detect_role_from_server_signals(asset: dict, allowed_roles: set[str]) -> tuple[list[str], float]:
    detail = _get_asset_detail(asset)
    technical = detail.get("technical_indicators", {}) or {}

    open_ports = set()
    for p in _safe_list(technical.get("open_ports", [])):
        try:
            open_ports.add(int(p))
        except Exception:
            pass

    running_services = " | ".join(str(x).lower() for x in _safe_list(technical.get("running_services", [])))
    installed_roles = " | ".join(str(x).lower() for x in _safe_list(technical.get("installed_roles", [])))
    installed_software = " | ".join(str(x).lower() for x in _safe_list(technical.get("installed_software", [])))

    matched_roles = []

    def has_text(*terms: str) -> bool:
        haystack = f"{running_services} | {installed_roles} | {installed_software}"
        return any(term.lower() in haystack for term in terms)

    # Domain Controller
    if (
        88 in open_ports
        and (
            has_text(
                "active directory",
                "active directory domain services",
                "ad ds",
                "kerberos"
            )
            or 389 in open_ports
            or 445 in open_ports
        )
    ):
        matched_roles.append("Domain Controller")

    # DNS Server
    if 53 in open_ports or has_text("dns", "dns server"):
        matched_roles.append("DNS Server")

    # DHCP Server
    if {67, 68}.intersection(open_ports) or has_text("dhcp", "dhcp server"):
        matched_roles.append("DHCP Server")

    # File Server
    if 445 in open_ports or has_text("file services", "file server", "smb"):
        matched_roles.append("File Server")

    # Web Server
    if {80, 443}.intersection(open_ports) or has_text("iis", "apache", "nginx", "web server", "http", "https"):
        matched_roles.append("Web Server")

    # Database Server
    if {1433, 1521, 3306, 5432}.intersection(open_ports) or has_text(
        "sql server", "mysql", "postgres", "oracle database", "database"
    ):
        matched_roles.append("Database Server")

    # Mail Server
    if {25, 110, 143, 465, 587, 993, 995}.intersection(open_ports) or has_text(
        "exchange", "smtp", "imap", "pop3", "mail server"
    ):
        matched_roles.append("Mail Server")

    # VPN Server
    if {500, 1701, 1723, 4500, 1194}.intersection(open_ports) or has_text(
        "vpn", "openvpn", "ipsec", "wireguard", "remote access"
    ):
        matched_roles.append("VPN Server")

    # Firewall
    if has_text("firewall", "windows defender firewall", "palo alto", "fortigate", "checkpoint"):
        matched_roles.append("Firewall")

    cleaned = []
    seen = set()
    for role in matched_roles:
        restricted = _restrict_role_to_allowed(role, allowed_roles)
        if restricted and restricted not in seen:
            seen.add(restricted)
            cleaned.append(restricted)

    if not cleaned:
        return [], 0.0

    # If Domain Controller is present, force it to the front.
    # This prevents DNS from winning just because DC also runs DNS.
    if "Domain Controller" in cleaned:
        cleaned = ["Domain Controller"] + [r for r in cleaned if r != "Domain Controller"]
        if "DNS Server" in cleaned:
            return cleaned, 0.95
        return cleaned, 0.92

    if len(cleaned) >= 2:
        return cleaned, 0.90

    return cleaned, 0.85   

def _choose_indicator_role(
    asset: dict,
    workstation_kb_df: pd.DataFrame | None = None,
    server_allowed_roles: set[str] | None = None,
    workstation_allowed_roles: set[str] | None = None,
) -> tuple[str, float, list[str]]:
    server_allowed_roles = server_allowed_roles or set()
    workstation_allowed_roles = workstation_allowed_roles or set()

    is_server = _is_server_asset(asset)
    allowed_roles = server_allowed_roles if is_server else workstation_allowed_roles

    existing_roles = _get_indicator_role_candidates(asset)
    cleaned_existing = []

    for r in existing_roles:
        rr = _restrict_role_to_allowed(r, allowed_roles)
        if rr:
            cleaned_existing.append(rr)

    if cleaned_existing:
        detail = _get_asset_detail(asset)
        existing_conf = detail.get("indicator_based_role_detection", {}).get("confidence", "")
        return cleaned_existing[0], _normalize_confidence_to_score(existing_conf), cleaned_existing

    if is_server:
        server_roles, server_score = _indicator_detect_role_from_server_signals(asset, server_allowed_roles)
        if server_roles:
            return server_roles[0], server_score, server_roles

    if workstation_kb_df is not None and not workstation_kb_df.empty and not is_server:
        kb_roles, kb_score = _indicator_detect_role_from_workstation_kb(asset, workstation_kb_df)
        kb_roles = [_restrict_role_to_allowed(r, workstation_allowed_roles) for r in kb_roles]
        kb_roles = [r for r in kb_roles if r]
        if kb_roles:
            return kb_roles[0], kb_score, kb_roles

    return "", 0.0, []

def _choose_os(asset: dict) -> str:
    detail = _get_asset_detail(asset)
    device_profile = detail.get("device_profile", {}) or {}

    os_version = str(device_profile.get("os_version", "")).strip()
    os_type = str(device_profile.get("os_type", "")).strip()
    current_os = str(asset.get("operating_system", "")).strip()

    if os_version:
        return os_version
    if os_type:
        return os_type
    if current_os:
        return current_os
    return "Unknown"


def _choose_cia(asset: dict) -> str:
    detail = _get_asset_detail(asset)
    business = detail.get("business_context", {}) or {}
    current_cia = asset.get("cia_rating", {}) or {}

    business_criticality = _normalize_cia(str(business.get("criticality", "")).strip())
    if business_criticality:
        return business_criticality

    current_value = _normalize_cia(str(current_cia.get("criticality", "")).strip())
    if current_value:
        return current_value

    role_text = str(asset.get("role", "")).lower()
    if any(x in role_text for x in ["domain controller", "firewall", "dns", "dhcp", "database"]):
        return "Critical"
    if any(x in role_text for x in ["file server", "application", "mail", "web"]):
        return "High"
    if role_text and role_text != "unassigned":
        return "Medium"

    return "Unscanned"


def _build_workstation_feature_row_from_flat_row(row: dict) -> dict:
    cleaned = {}

    for col in WORKSTATION_FEATURE_COLUMNS:
        value = row.get(col, "")

        if isinstance(value, list):
            value = ", ".join(str(v) for v in value)
        elif isinstance(value, dict):
            value = json.dumps(value, sort_keys=True)
        elif value is None:
            value = ""

        cleaned[col] = value

    return cleaned


def _build_workstation_training_dataframe_for_model(
    df: pd.DataFrame,
    target_col: str,
) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame()

    rows: list[dict] = []

    for _, row in df.iterrows():
        role_name = str(row.get(target_col, "")).strip()
        if not role_name or role_name.lower() == "unassigned":
            continue

        raw_row = {col: row.get(col, "") for col in df.columns}
        feature_row = _build_workstation_feature_row_from_flat_row(raw_row)
        feature_row["role"] = role_name
        rows.append(feature_row)

    if not rows:
        return pd.DataFrame()

    return pd.DataFrame(rows)


def _predict_role_for_asset(asset: dict, model) -> tuple[str, float]:
    row = _flatten_asset_for_training(asset)
    row.pop("role", None)

    feature_row = _build_workstation_feature_row_from_flat_row(row)

    try:
        expected_cols = list(model.named_steps["preprocessor"].feature_names_in_)
    except Exception:
        expected_cols = list(WORKSTATION_FEATURE_COLUMNS)

    aligned_row = {}
    for col in expected_cols:
        aligned_row[col] = feature_row.get(col, "")

    df = pd.DataFrame([aligned_row], columns=expected_cols)
    df = df.fillna("")

    pred = model.predict(df)[0]
    predicted_role = str(pred).strip()

    confidence = 0.75
    if hasattr(model, "predict_proba"):
        try:
            probs = model.predict_proba(df)[0]
            confidence = float(max(probs))
        except Exception:
            pass

    return predicted_role, confidence

def _choose_column_by_patterns(df: pd.DataFrame, patterns: list[str]) -> str | None:
    lowered = {c.lower(): c for c in df.columns}
    for pattern in patterns:
        for lc, original in lowered.items():
            if pattern in lc:
                return original
    return None


def _rag_detect_role_from_windows_software(asset: dict, kb_df: pd.DataFrame) -> tuple[str, float]:
    if kb_df.empty:
        return "", 0.0

    asset_software = _installed_software_texts(asset)
    asset_tokens = _installed_software_tokens(asset)
    if not asset_software and not asset_tokens:
        return "", 0.0

    software_col = _choose_column_by_patterns(
        kb_df,
        ["software", "application", "program", "product", "name"]
    )
    role_col = _choose_column_by_patterns(
        kb_df,
        ["role", "category", "software_category", "mapped_role"]
    )

    if not software_col or not role_col:
        return "", 0.0

    role_scores: dict[str, float] = {}

    for _, row in kb_df.iterrows():
        software_name = str(row.get(software_col, "")).strip()
        role_name = str(row.get(role_col, "")).strip()

        if not software_name or not role_name:
            continue

        row_tokens = _tokenize_text(software_name)
        if not row_tokens:
            continue

        overlap = asset_tokens & row_tokens
        if not overlap:
            continue

        coverage = len(overlap) / max(1, len(row_tokens))
        exact_bonus = 0.0

        software_name_norm = _normalize_text_token(software_name)
        for installed in asset_software:
            installed_norm = _normalize_text_token(installed)
            if installed_norm and (
                installed_norm in software_name_norm or software_name_norm in installed_norm
            ):
                exact_bonus = 0.25
                break

        score = min(1.0, coverage + exact_bonus)
        role_scores[role_name] = role_scores.get(role_name, 0.0) + score

    if not role_scores:
        return "", 0.0

    ranked = sorted(role_scores.items(), key=lambda x: x[1], reverse=True)
    best_role, best_raw_score = ranked[0]

    normalized_score = min(1.0, best_raw_score / max(1.0, len(asset_software) if asset_software else 1.0))
    if normalized_score <= 0:
        normalized_score = min(0.90, best_raw_score)

    return best_role, normalized_score


def _choose_winning_role(
    indicator_role: str,
    indicator_score: float,
    ml_role: str,
    ml_score: float,
    rag_role: str,
    rag_score: float,
) -> tuple[str, str]:
    candidates = []
    if indicator_role and indicator_score >= 0.80:
        return indicator_role, "indicator"
        
    if indicator_role and indicator_role.lower() != "unassigned":
        candidates.append(("indicator", indicator_role, indicator_score))
    if ml_role and ml_role.lower() != "unassigned":
        candidates.append(("ml", ml_role, ml_score))
    if rag_role and rag_role.lower() != "unassigned":
        candidates.append(("rag", rag_role, rag_score))

    if not candidates:
        return "Unassigned", ""

    candidates.sort(key=lambda x: (x[2], x[0] == "indicator", x[0] == "rag"), reverse=True)
    best_method, best_role, best_score = candidates[0]

    if best_method == "ml" and best_score < 0.55 and indicator_role and indicator_score >= best_score:
        return indicator_role, "indicator"

    if best_method == "rag" and best_score < 0.50 and indicator_role and indicator_score >= best_score:
        return indicator_role, "indicator"

    return best_role, best_method


def _apply_assignroles_updates(inventory: dict) -> dict:
    server_model = None
    workstation_model = None
    server_model_loaded = False
    workstation_model_loaded = False
    model_message = "No trained ML role models found. Using indicator-based role detection only."

    server_kb_path = _server_roles_kb_path()
    workstation_roles_kb_path = _workstation_roles_kb_path()
    workstation_indicator_kb_path = _workstation_kb_path()
    windows_software_kb_path = _windows_software_kb_path()

    workstation_kb_df = _load_csv_or_empty(workstation_indicator_kb_path)
    windows_software_df = _load_csv_or_empty(windows_software_kb_path)

    server_allowed_roles = _load_allowed_roles_from_csv(server_kb_path)
    workstation_allowed_roles = _load_allowed_roles_from_csv(workstation_roles_kb_path)

    server_model_path = _server_role_model_path()
    workstation_model_path = _workstation_role_model_path()

    server_model_error = ""
    workstation_model_error = ""

    if server_model_path.exists():
        try:
            server_model = joblib.load(server_model_path)
            server_model_loaded = True
        except Exception as e:
            server_model_error = str(e)

    if workstation_model_path.exists():
        try:
            workstation_model = joblib.load(workstation_model_path)
            workstation_model_loaded = True
        except Exception as e:
            workstation_model_error = str(e)

    if server_model_loaded and workstation_model_loaded:
        model_message = "Server and workstation ML role models loaded successfully."
    elif server_model_loaded:
        model_message = "Server ML role model loaded successfully. Workstation ML role model not available."
    elif workstation_model_loaded:
        model_message = "Workstation ML role model loaded successfully. Server ML role model not available."
    else:
        errors = []
        if server_model_error:
            errors.append(f"server model load failed: {server_model_error}")
        if workstation_model_error:
            errors.append(f"workstation model load failed: {workstation_model_error}")
        if errors:
            model_message = " ; ".join(errors)


    assets_processed = 0
    indicator_roles_applied = 0
    ml_roles_applied = 0
    rag_roles_applied = 0
    selected_roles_applied = 0
    os_updated = 0
    cia_updated = 0
    status_updated = 0

    for asset in _all_assets(inventory):
        assets_processed += 1
        detail = _get_asset_detail(asset)
        hostname = asset.get("hostname")

        os_value = _choose_os(asset)
        cia_value = _choose_cia(asset)

        asset["operating_system"] = os_value
        asset["cia_rating"] = {"criticality": cia_value}
        asset["status"] = "Active"

        os_updated += 1
        cia_updated += 1
        status_updated += 1

        is_server = _is_server_asset(asset)
        allowed_roles = server_allowed_roles if is_server else workstation_allowed_roles

        indicator_role, indicator_score, indicator_roles = _choose_indicator_role(
            asset,
            workstation_kb_df=workstation_kb_df,
            server_allowed_roles=server_allowed_roles,
            workstation_allowed_roles=workstation_allowed_roles,
        )

        indicator_block = detail.setdefault("indicator_based_role_detection", {})
        indicator_block["detected_roles"] = indicator_roles
        indicator_block["confidence"] = (
            _score_to_confidence_label(indicator_score)
            or indicator_block.get("confidence", "")
        )

        if indicator_role and indicator_role.lower() != "unassigned":
            indicator_roles_applied += 1

        asset["role"] = indicator_role if indicator_role else ""

        ml_role = ""
        ml_score = 0.0
        ml_block = detail.setdefault("ml_role_prediction", {})
        ml_block["predicted_roles"] = []
        ml_block["confidence"] = ""
        ml_block.pop("error", None)

        asset_model = None
        asset_model_name = ""

        if is_server and server_model_loaded:
            asset_model = server_model
            asset_model_name = "server_model"
        elif (not is_server) and workstation_model_loaded:
            asset_model = workstation_model
            asset_model_name = "workstation_model"


        if asset_model is not None:
            try:
                if is_server:
                    completeness_ratio = _server_feature_completeness_ratio(asset)
                    ml_block["feature_completeness_ratio"] = round(completeness_ratio, 4)

                    if completeness_ratio >= 0.60:
                        ml_role_raw, ml_score = _predict_server_role_for_asset(asset, asset_model)
                    else:
                        ml_role_raw = ""
                        ml_score = 0.0
                        ml_block["predicted_roles"] = []
                        ml_block["confidence"] = ""
                        ml_block["error"] = (
                            "Server ML skipped because server feature completeness is below 0.60."
                        )
                        ml_role = ""
                else:
                    ml_role_raw, ml_score = _predict_role_for_asset(asset, asset_model)

                if not is_server or ml_score >= 0.60:
                    ml_role = _restrict_role_to_allowed(ml_role_raw, allowed_roles)

                    if ml_role:
                        ml_block["predicted_roles"] = [ml_role]
                        ml_block["confidence"] = str(round(ml_score, 4))
                        ml_block.pop("error", None)
                        ml_roles_applied += 1
                    else:
                        if ml_role_raw:
                            ml_block["predicted_roles"] = [ml_role_raw]
                            ml_block["confidence"] = str(round(ml_score, 4))
                            ml_block["error"] = (
                                f"Predicted role '{ml_role_raw}' is not in allowed knowledge-base roles"
                            )
                        ml_role = ""
                        ml_score = 0.0
                else:
                    ml_block["predicted_roles"] = [ml_role_raw] if ml_role_raw else []
                    ml_block["confidence"] = str(round(ml_score, 4)) if ml_role_raw else ""
                    ml_block["error"] = "Server ML confidence is below the minimum threshold of 0.60."
                    ml_role = ""
                    ml_score = 0.0

            except Exception as e:
                ml_block["predicted_roles"] = []
                ml_block["confidence"] = ""
                ml_block["error"] = str(e)
                ml_role = ""
                ml_score = 0.0
        else:
            ml_block["predicted_roles"] = []
            ml_block["confidence"] = ""
            if is_server and not server_model_loaded:
                ml_block["error"] = "Server ML role model is not available."
            elif (not is_server) and not workstation_model_loaded:
                ml_block["error"] = "Workstation ML role model is not available."

        rag_role = ""
        rag_score = 0.0
        rag_block = detail.setdefault("rag_based_role_detection", {})

        try:
            rag_role_raw, rag_score = _rag_detect_role_from_chroma(asset)
            rag_role = _restrict_role_to_allowed(rag_role_raw, allowed_roles)

            if rag_role:
                rag_block["detected_role"] = rag_role
                rag_block["confidence"] = _score_to_confidence_label(rag_score)
                rag_block.pop("error", None)
                rag_roles_applied += 1
            else:
                rag_block["detected_role"] = ""
                rag_block["confidence"] = ""
                if rag_role_raw:
                    rag_block["error"] = (
                        f"RAG role '{rag_role_raw}' is not in allowed knowledge-base roles"
                    )
                else:
                    rag_block.pop("error", None)
                rag_role = ""
                rag_score = 0.0
        except Exception as e:
            rag_block["detected_role"] = ""
            rag_block["confidence"] = ""
            rag_block["error"] = str(e)
            rag_role = ""
            rag_score = 0.0

        selected_role, selected_method = _choose_winning_role(
            indicator_role=indicator_role,
            indicator_score=indicator_score,
            ml_role=ml_role,
            ml_score=ml_score,
            rag_role=rag_role,
            rag_score=rag_score,
        )

        if selected_role in {"Server", "Workstation"}:
            selected_role = ""
            selected_method = ""

        selected_role = _restrict_role_to_allowed(selected_role, allowed_roles)

        selected_block = detail.setdefault("selected_role", {})
        selected_block["role"] = selected_role
        selected_block["method"] = selected_method if selected_role else ""

        asset["role"] = selected_role if selected_role else "Unassigned"
        asset["status"] = "Active"

        if selected_role and selected_role.lower() != "unassigned":
            selected_roles_applied += 1

    kb_files_used = {
        "server_roles_kb": str(server_kb_path) if server_kb_path else "",
        "workstation_roles_kb": str(workstation_roles_kb_path) if workstation_roles_kb_path else "",
        "workstation_indicator_kb": str(workstation_indicator_kb_path) if workstation_indicator_kb_path else "",
        "windows_software_kb": str(windows_software_kb_path) if windows_software_kb_path else "",
        "chroma_db": str(_chroma_db_path()),
    }

    return {
        "assets_processed": assets_processed,
        "indicator_roles_applied": indicator_roles_applied,
        "ml_roles_applied": ml_roles_applied,
        "rag_roles_applied": rag_roles_applied,
        "selected_roles_applied": selected_roles_applied,
        "os_updated": os_updated,
        "cia_updated": cia_updated,
        "status_updated": status_updated,
        "ml_message": model_message,
        "allowed_server_roles_count": len(server_allowed_roles),
        "allowed_workstation_roles_count": len(workstation_allowed_roles),
        "server_model_loaded": server_model_loaded,
        "workstation_model_loaded": workstation_model_loaded,
        "kb_files_used": kb_files_used
    }

@router.post("/explore")
def explore_network(payload: dict):
    year = int(payload.get("year", 2026))
    network_input = (payload.get("network_mask") or "").strip()

    if not network_input:
        return {
            "success": False,
            "message": "Please provide a network address."
        }

    try:
        docker_ready, docker_message = _ensure_docker_lab_running()
        if not docker_ready:
            return {
                "success": False,
                "message": docker_message
            }

        discovered_subnets = _extract_lab_subnets_from_docker_compose()
        if not discovered_subnets:
            return {
                "success": False,
                "message": "No subnets were found in data/docker_lab/docker-compose.yml."
            }

        targets_file = _write_targets_json_for_vm_hosts(
            year=year,
            discovered_subnets=discovered_subnets,
            username=r"CORP\Administrator",
            password="!MT123456",
        )

        matched = _network_matches_lab(network_input, discovered_subnets)
        if not matched:
            return {
                "success": False,
                "message": "Network not found in docker lab architecture."
            }
        inventory = _load_inventory_or_blank(year)
        inventory["network_mask"] = network_input
        _save_json(_asset_file(year), inventory)
        _sync_assets_cia_status(year, inventory)

        _store_discovered_subnets_session(year, discovered_subnets)

        return {
            "success": True,
            "message": _build_docker_explore_message(discovered_subnets),
            "subnets": [
                {
                    "id": subnet["id"],
                    "label": subnet["label"],
                    "hosts": subnet.get("hosts", []),
                    "host_count": subnet["host_count"]
                }
                for subnet in discovered_subnets
            ]
        }

    except ValueError as e:
        return {
            "success": False,
            "message": str(e)
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Backend error while exploring docker lab: {e}"
        }
        
@router.post("/assess")
def assess_subnet(payload: dict):
    year = int(payload.get("year", 2026))
    subnet_id = (payload.get("subnet_id") or "").strip()

    if not subnet_id:
        return {"success": False, "message": "Please provide a subnet id."}

    inventory = _load_inventory_or_blank(year)
    if _inventory_is_read_only(inventory):
        return {
            "success": False,
            "message": "Asset inventory has already been submitted and is now read-only.",
            "inventory": inventory
        }

    asset_file = _asset_file(year)
    selected = _get_discovered_subnet_from_payload_or_session(year, payload, subnet_id)

    if not selected:
        return {
            "success": False,
            "message": "Selected subnet not found in the current /explore session. Please run /explore again."
        }

    details_index = _index_asset_details_by_hostname(year)

    subnet_name = str(selected.get("id", "") or "").strip()
    subnet_label = str(selected.get("label", "") or "").strip()
    hosts = list(selected.get("hosts", []) or [])

    assets = []

    for idx, host in enumerate(hosts, start=1):
        hostname = _service_name_to_hostname(str(host.get("service", "") or "").strip())
        default_role = (
            "Server" if _is_server_hostname(hostname)
            else "Workstation" if _is_workstation_hostname(hostname)
            else "Unassigned"
        )
        ip_address = str(host.get("ip_address", "") or "").strip()
        operating_system = "Unknown"

        detail = _lookup_asset_detail(host, hostname, details_index)

        target_host = _get_matching_target_host(hostname, ip_address)
        if target_host:
            try:
                scanned_record = _assess_target_host_with_scanner(hostname, ip_address, target_host)

                print(f"[DEBUG] scanned_record for {hostname}: {json.dumps(scanned_record, indent=2, default=str)}")

                detail = _merge_scanner_detail(detail, scanned_record)

                print(
                    f"[DEBUG] merged os_version for {hostname}: "
                    f"{detail.get('device_profile', {}).get('os_version', '')}"
                )
            except Exception as e:
                print(f"[ASSESS][SCAN FAILED] {hostname} {ip_address}: {e}")
                traceback.print_exc()
        else:
            print(f"[WARN] No target host match for {hostname} ({ip_address})")

        detail_os_version = str(detail.get("device_profile", {}).get("os_version", "") or "").strip()
        detail_os_type = str(detail.get("device_profile", {}).get("os_type", "") or "").strip()

        if detail_os_version:
            final_os = _normalize_os_name(detail_os_version)
        elif detail_os_type:
            final_os = _normalize_os_name(detail_os_type)
        else:
            final_os = operating_system

        assets.append({
            "hostname": hostname,
            "role": default_role,
            "operating_system": final_os,
            "location": {
                "name": subnet_label,
                "ip_address": ip_address
            },
            "cia_rating": {
                "criticality": "Unscanned"
            },
            "status": "Unknown",
            "detail": detail
        })

    subnet_record = {
        "id": subnet_name,
        "subnet_mask": subnet_label,
        "location": {
            "name": subnet_label,
            "ip_range": subnet_label
        },
        "assets": assets
    }

    inventory_subnets = inventory.get("subnets", [])
    if not isinstance(inventory_subnets, list):
        inventory_subnets = []

    replaced = False
    for i, existing in enumerate(inventory_subnets):
        if (existing.get("id") or "") == subnet_name:
            inventory_subnets[i] = subnet_record
            replaced = True
            break

    if not replaced:
        inventory_subnets.append(subnet_record)

    inventory["subnets"] = inventory_subnets
    _save_json(asset_file, inventory)

    _sync_assets_cia_status(year, inventory)

    return {
        "success": True,
        "message": f"Subnet {subnet_name} assessed successfully.",
        "inventory": inventory,
        "subnet_id": subnet_name,
        "replaced": replaced,
        "host_count": len(assets)
    }


@router.post("/setstatus")
def set_host_status(payload: dict):
    year = int(payload.get("year", 2026))
    hostname = (payload.get("hostname") or "").strip()
    status = _normalize_status(payload.get("status") or "")

    if not hostname:
        return {"success": False, "message": "Please provide a hostname."}

    if not status:
        return {"success": False, "message": "Invalid status. Allowed values: Active, Not Active, Unknown."}

    inventory = _load_inventory_or_blank(year)
    if _inventory_is_read_only(inventory):
        return {
            "success": False,
            "message": "Asset inventory has already been submitted and is now read-only.",
            "inventory": inventory
        }

    _, asset = _find_asset_by_hostname(inventory, hostname)

    if not asset:
        return {
            "success": False,
            "message": f"Hostname '{hostname}' not found.",
            "inventory": inventory
        }

    asset["status"] = status
    _save_json(_asset_file(year), inventory)
    _sync_assets_cia_status(year, inventory)
    
    return {
        "success": True,
        "message": f"Host {hostname} status updated to {status}.",
        "inventory": inventory,
        "hostname": hostname,
        "status": status
    }


@router.post("/editrole")
def edit_role(payload: EditRoleRequest):
    year = int(payload.year or 2026)
    hostname = (payload.hostname or "").strip()
    new_role = (payload.role or "").strip()

    if not hostname:
        return {"success": False, "message": "Please provide a hostname."}

    if not new_role:
        return {"success": False, "message": "Please provide a role."}

    inventory = _load_inventory_or_blank(year)
    if _inventory_is_read_only(inventory):
        return {
            "success": False,
            "message": "Asset inventory has already been submitted and is now read-only.",
            "inventory": inventory
        }

    _, asset = _find_asset_by_hostname(inventory, hostname)

    if not asset:
        return {
            "success": False,
            "message": f"Hostname '{hostname}' not found.",
            "inventory": inventory
        }

    old_role = _asset_selected_role(asset) or str(asset.get("role") or "").strip()

    asset["role"] = new_role
    detail = asset.setdefault("detail", _blank_detail())

    indicator_block = detail.setdefault("indicator_based_role_detection", {})
    indicator_block["detected_roles"] = [new_role]
    indicator_block["confidence"] = "Manual"

    selected_block = detail.setdefault("selected_role", {})
    selected_block["role"] = new_role
    selected_block["method"] = "manual"

    _save_json(_asset_file(year), inventory)
    _sync_assets_cia_status(year, inventory)
    if old_role != new_role:
        safe_increment_manual_correction_counter(year, "role")
    
    return {
        "success": True,
        "message": f"Role for host {hostname} updated to {new_role}.",
        "inventory": inventory,
        "hostname": hostname,
        "role": new_role
    }


@router.post("/delete")
def delete_host(payload: dict):
    year = int(payload.get("year", 2026))
    hostname = (payload.get("hostname") or "").strip()

    if not hostname:
        return {"success": False, "message": "Please provide a hostname."}

    inventory = _load_inventory_or_blank(year)
    if _inventory_is_read_only(inventory):
        return {
            "success": False,
            "message": "Asset inventory has already been submitted and is now read-only.",
            "inventory": inventory
        }

    target_key = _normalize_hostname(hostname)
    found = False

    for subnet in inventory.get("subnets", []):
        assets = subnet.get("assets", [])
        if not isinstance(assets, list):
            continue

        new_assets = []
        removed_here = False

        for asset in assets:
            current_hostname = _normalize_hostname(asset.get("hostname") or "")
            if current_hostname == target_key and not removed_here:
                removed_here = True
                found = True
                continue
            new_assets.append(asset)

        if removed_here:
            subnet["assets"] = new_assets
            break

    if not found:
        return {
            "success": False,
            "message": f"Hostname '{hostname}' not found.",
            "inventory": inventory
        }

    _save_json(_asset_file(year), inventory)
    _sync_assets_cia_status(year, inventory)

    return {
        "success": True,
        "message": f"Host {hostname} deleted successfully.",
        "inventory": inventory,
        "hostname": hostname
    }


@router.post("/assignrole")
@router.post("/assignroles")
def assign_roles(payload: dict):
    year = int(payload.get("year", 2026))
    inventory = _load_inventory_or_blank(year)
    server_kb = _server_roles_kb_path()
    workstation_kb = _workstation_roles_kb_path()
    
    if not server_kb and not workstation_kb:
        return {
            "success": False,
            "message": (
                "No knowledge-base CSV files were found for server/workstation roles. "
                "Please place the CSV files under data/knowledge_base, data/ml, "
                "or app/rag/knowledge_base."
            ),
            "server_kb_path": str(server_kb) if server_kb else "",
            "workstation_kb_path": str(workstation_kb) if workstation_kb else "",
            "inventory": inventory,
        }
    
    if _inventory_is_read_only(inventory):
        return {
            "success": False,
            "message": "Asset inventory has already been submitted and is now read-only.",
            "inventory": inventory
        }

    total_assets = len(_all_assets(inventory))
    if total_assets == 0:
        return {
            "success": False,
            "message": "Asset inventory is empty. Please run /assess first.",
            "inventory": inventory
        }

    kb_message = "Knowledge base check completed."
    kb_status = "not_run"
    rows_embedded = 0

    try:
        from app.rag.build_knowledge_base import rebuild_if_needed

        result = rebuild_if_needed()
        kb_message = result.get("message", kb_message)
        kb_status = result.get("kb_status", "up_to_date")
        rows_embedded = result.get("rows_embedded", 0)
    except FileNotFoundError as e:
        kb_message = str(e)
        kb_status = "error"
    except Exception as e:
        kb_message = f"assignroles knowledge base step failed: {e}"
        kb_status = "error"

    try:
        update_result = _apply_assignroles_updates(inventory)
    except Exception as e:
        tb = traceback.format_exc()
        return {
            "success": False,
            "message": f"Backend error while assigning roles: {e}",
            "traceback": tb,
            "kb_status": kb_status,
            "kb_message": kb_message,
            "rows_embedded": rows_embedded,
            "inventory": inventory
        }
    _save_json(_asset_file(year), inventory)
    _sync_assets_cia_status(year, inventory)
    role_prediction_events = _build_role_prediction_telemetry_events(
        inventory,
        source_endpoint="/api/assets/assignroles",
    )
    _safe_append_aiml_kpi_events(year, "role_prediction_events", role_prediction_events)
    safe_increment_role_prediction_quality_counters(year, role_prediction_events)
    
    final_message = (
    "Indicator-based detection, ML role prediction, "
    "RAG-based role detection, and selected-role comparison "
    "applied to inventory."
    )

    if kb_status == "error":
        final_message = (
            f"Knowledge base rebuild failed, but role assignment still ran. "
        f"{final_message}"
        )
    else:
        final_message = (
            f"Knowledge base check completed. {final_message}"
        )

    return {
        "success": True,
        "message": final_message,
        "kb_status": kb_status,
        "kb_message": kb_message,
        "rows_embedded": rows_embedded,
        "aiml_kpi_events_appended": len(role_prediction_events),
        "inventory": inventory,
        **update_result
    }

@router.post("/submit")
def submit_inventory(payload: SubmitRequest):
    year = int(payload.year or 2026)
    inventory = _load_inventory_or_blank(year)

    assets = _all_assets(inventory)
    if not assets:
        return {
            "success": False,
            "message": "Asset inventory is empty. Nothing to submit.",
            "inventory": inventory,
        }

    counts = _count_hosts_by_status(inventory)
    unknown_count = counts["unknown_count"]
    inactive_count = counts["inactive_count"]

    # Step 1: ask for confirmation first
    if not payload.confirm:
        if unknown_count > 0 or inactive_count > 0:
            return {
                "success": False,
                "requires_confirmation": True,
                "message": (
                    f"There are {unknown_count} Unknown host(s) and "
                    f"{inactive_count} Inactive host(s).\n\n"
                    "They will be removed and will no longer exist in future operations.\n\n"
                    "Do you want to continue?"
                ),
                "unknown_count": unknown_count,
                "inactive_count": inactive_count,
                "inventory": inventory,
            }

    # Step 2: confirmed cleanup
    removed_unknown = 0
    removed_inactive = 0

    for subnet in inventory.get("subnets", []):
        subnet_assets = subnet.get("assets", [])
        if not isinstance(subnet_assets, list):
            subnet["assets"] = []
            continue

        kept_assets = []

        for asset in subnet_assets:
            status = _normalize_status(asset.get("status") or "")

            if status == "Unknown":
                removed_unknown += 1
                continue

            if status == "Not Active":
                removed_inactive += 1
                continue

            kept_assets.append(asset)

        subnet["assets"] = kept_assets

    _save_json(_asset_file(year), inventory)
    _sync_assets_cia_status(year, inventory)

    remaining_assets = _all_assets(inventory)

    if not remaining_assets:
        return {
            "success": True,
            "message": (
                f"Removed {removed_unknown} Unknown host(s) and "
                f"{removed_inactive} Inactive host(s).\n\n"
                "No remaining records were available to add to the training datasets."
            ),
            "removed_unknown": removed_unknown,
            "removed_inactive": removed_inactive,
            "rows_added": {
                "server_rows_added": 0,
                "workstation_rows_added": 0,
                "total_rows_added": 0,
            },
            "inventory": inventory,
        }

    append_result = _append_inventory_to_training_datasets(inventory)

    train_result = None
    train_error = ""
    
    try:
        print("[submit] starting automatic retrain...")
        train_result = train_role_prediction_model(TrainModelRequest(year=year))
        print("[submit] automatic retrain completed successfully.")
    except Exception as e:
        train_error = f"{type(e).__name__}: {e}"
        print("[submit] automatic retrain failed:")
        traceback.print_exc()
        
    status = _load_status(year)
    sections = status.get("sections", {})
    
    # After successful submit
    sections.setdefault("scope_context", {})["status"] = "In Progress"
    sections.setdefault("assets_cia", {})["status"] = "In Progress"
    
    if sections.get("threats_vulns", {}).get("status") == "Blocked":
        sections["threats_vulns"]["status"] = "Not Started"
    
    status["sections"] = sections
    status["year"] = year
    status["updated_at"] = datetime.utcnow().isoformat() + "Z"
    
    _atomic_write_json(_system_status_file(year), status)
        
    return {
        "success": True,
        "message": (
            f"Removed {removed_unknown} Unknown host(s) and "
            f"{removed_inactive} Inactive host(s).\n\n"
            f"Added {append_result.get('server_rows_added', 0)} record(s) to the server training dataset.\n"
            f"Added {append_result.get('workstation_rows_added', 0)} record(s) to the workstation training dataset.\n\n"
            + (
                "Model retraining completed successfully."
                if not train_error
                else f"Dataset updated, but model retraining failed: {train_error}"
            )
        ),
        "removed_unknown": removed_unknown,
        "removed_inactive": removed_inactive,
        "rows_added": append_result,
        "train_result": train_result,
        "train_error": train_error,
        "inventory": inventory,
    }
    
@router.post("/reset")
def reset_inventory(payload: dict):
    year = int(payload.get("year", 2026))
    confirm = bool(payload.get("confirm", False))

    if not confirm:
        return {
            "success": False,
            "message": "Reset cancelled. Confirmation is required before reset."
        }

    blank_doc = _blank_inventory(year)
    _save_json(_asset_file(year), blank_doc)
    _sync_assets_cia_status(year, blank_doc)
    
    return {
        "success": True,
        "message": "Asset inventory has been reset successfully.",
        "inventory": blank_doc
    }


@router.get("/help")
def assets_help():
    return {
        "success": True,
        "section": "Asset Inventory & CIA",
        "message": (
            "This section performs network exploration, subnet assessment, "
            "host inventory creation, role assignment, host status tracking, "
            "and CIA-oriented asset preparation for later ISO 27001 risk analysis."
        )
    }


@router.get("/commands")
def assets_commands():
    return {
        "success": True,
        "commands": [
            "/explore",
            "/assess",
            "/setstatus",
            "/assignroles",
            "/editrole",
            "/delete",
            "/submit",
            "/reset",
            "/commands",
            "/help"
        ]
    }


@router.post("/train")
def train_role_prediction_model(payload: TrainModelRequest):
    year = int(payload.year or 2026)
    ml_dir = _ml_dir()
    model_dir = ml_dir / "models"
    model_dir.mkdir(parents=True, exist_ok=True)

    results = {}
    # SERVER MODEL
    if _server_dataset_path().exists():
        server_source_df = pd.read_parquet(_server_dataset_path())
        if not server_source_df.empty:
            server_train_df = _build_server_training_dataframe_for_model(server_source_df)

            if not server_train_df.empty:
                server_train_df, server_preprocess_stats = _remove_duplicate_training_records(
                    server_train_df,
                    target_col="role",
                    dataset_name="server",
                )
                print("SERVER DF SHAPE BEFORE:", server_train_df.shape)

                if not server_train_df.empty:
                    server_model, server_features, server_class_counts = _train_server_role_pipeline(server_train_df)
                    joblib.dump(server_model, _server_role_model_path())

                    results["server_model_path"] = str(_server_role_model_path())
                    results["server_training_rows"] = int(len(server_train_df))
                    results["server_feature_count"] = int(len(server_features))
                    results["server_class_counts"] = server_class_counts
                    results["server_preprocessing"] = server_preprocess_stats

    # WORKSTATION MODEL
    if _workstation_dataset_path().exists():
        workstation_df = pd.read_parquet(_workstation_dataset_path())
        if not workstation_df.empty:
            target_col = _find_target_column(workstation_df)
            workstation_df = _normalize_training_dataframe(workstation_df, target_col)

            workstation_train_df = _build_workstation_training_dataframe_for_model(
                workstation_df,
                target_col=target_col,
            )

            workstation_train_df, workstation_preprocess_stats = _remove_duplicate_training_records(
                workstation_train_df,
                target_col="role",
                dataset_name="workstation",
            )

            print("WORKSTATION DF SHAPE AFTER:", workstation_train_df.shape)

            if not workstation_train_df.empty:
                X_ws = workstation_train_df.drop(columns=["role"]).copy()
                y_ws = workstation_train_df["role"].astype(str).copy()

                empty_cols = [c for c in X_ws.columns if X_ws[c].dropna().empty]
                if empty_cols:
                    X_ws = X_ws.drop(columns=empty_cols)

                workstation_model = _build_training_pipeline(X_ws)
                workstation_model.fit(X_ws, y_ws)
                joblib.dump(workstation_model, _workstation_role_model_path())

                results["workstation_model_path"] = str(_workstation_role_model_path())
                results["workstation_training_rows"] = int(len(workstation_train_df))
                results["workstation_feature_count"] = int(len(X_ws.columns))
                results["workstation_features_used"] = list(X_ws.columns)
                results["workstation_preprocessing"] = workstation_preprocess_stats    
                
                if not results:
                    raise HTTPException(status_code=400, detail="No valid training datasets found")

                response = {
                    "success": True,
                    "message": "Server and workstation ML role prediction models are ready to use.",
                    **results
                }
                _safe_append_aiml_kpi_event(year or 2026, "role_model_training_runs", {
                    "run_id": f"role_train_{datetime.now().astimezone().strftime('%Y-%m-%d_%H-%M-%S')}",
                    "model_type": "role_prediction",
                    "server_training_rows": results.get("server_training_rows"),
                    "server_feature_count": results.get("server_feature_count"),
                    "server_class_counts": results.get("server_class_counts"),
                    "server_model_path": results.get("server_model_path"),
                    "workstation_training_rows": results.get("workstation_training_rows"),
                    "workstation_feature_count": results.get("workstation_feature_count"),
                    "workstation_features_used": results.get("workstation_features_used"),
                    "workstation_model_path": results.get("workstation_model_path"),
                    "source_endpoint": "/api/assets/train",
                    "notes": [
                        "Role model training telemetry does not include accuracy/F1 unless the training route computes it.",
                        "Role accuracy and F1 can still be computed from role_prediction_events after /assignroles runs.",
                    ],
                })
                return response
@router.get("/inventory")
def get_asset_inventory(year: int):
    asset_file = _asset_file(year)

    if not asset_file.exists():
        return _blank_inventory(year)

    try:
        return _load_json(asset_file)
    except Exception:
        return _blank_inventory(year)


@router.post("/inventory/new")
def create_asset_inventory(
    year: int = Query(...),
    force: bool = Query(False)
):
    asset_file = _asset_file(year)

    if asset_file.exists() and not force:
        try:
            return _load_json(asset_file)
        except Exception:
            pass

    blank_doc = _blank_inventory(year)
    _save_json(asset_file, blank_doc)
    _sync_assets_cia_status(year, blank_doc)
    
    return blank_doc

@router.get("/role-options")
def get_role_options():
    server_kb = _server_roles_kb_path()
    workstation_kb = _workstation_roles_kb_path()

    server_roles = _sorted_roles_list(_load_allowed_roles_from_csv(server_kb))
    workstation_roles = _sorted_roles_list(_load_allowed_roles_from_csv(workstation_kb))

    return {
        "success": True,
        "server_roles": server_roles,
        "workstation_roles": workstation_roles,
        "server_kb_path": str(server_kb) if server_kb else "",
        "workstation_kb_path": str(workstation_kb) if workstation_kb else "",
    }

@router.post("/datasets/mark-synthetic")
def mark_existing_datasets_as_synthetic():
    server_result = _ensure_parquet_has_data_source(_server_dataset_path())
    workstation_result = _ensure_parquet_has_data_source(_workstation_dataset_path())

    return {
        "success": True,
        "message": "Existing parquet datasets were checked and missing data_source values were marked as synthetic.",
        "server_dataset": server_result,
        "workstation_dataset": workstation_result,
    }
