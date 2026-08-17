import json
from pathlib import Path
from datetime import datetime, timedelta
from copy import deepcopy
import subprocess



BASE_DIR = Path(__file__).resolve().parents[2]

TARGET_FILE = BASE_DIR / "lab-scanner" / "config" / "targets.json"
CENTRAL_FILE = BASE_DIR / "data" / "work" / "2026" / "UserBehaviorActivity.json"
ASSET_INVENTORY_FILE = BASE_DIR / "data" / "work" / "2026" / "AssetInventory.json"
ASSET_DETAILS_FILE = BASE_DIR / "data" / "work" / "2026" / "AssetDetails.json"

REMOTE_RELATIVE_PATH = r"C$\ProgramData\BehaviorAgent\UserBehaviorActivity.json"


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def load_json_file(path: Path, default):
    if not path.exists():
        print(f"[DEBUG] File not found: {path}")
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception as exc:
        print(f"[DEBUG] Failed to load JSON from {path}: {exc}")
        return default


def load_json_unc(path_str: str, default):
    try:
        with open(path_str, "r", encoding="utf-8-sig") as f:
            return json.load(f)
    except Exception as exc:
        print(f"[DEBUG] Failed to load JSON from {path_str}: {exc}")
        return default


def save_json_file(path: Path, obj) -> None:
    ensure_parent(path)
    path.write_text(json.dumps(obj, indent=2), encoding="utf-8")


def normalize_records(doc):
    if not isinstance(doc, dict):
        return []
    records = doc.get("records", [])
    if isinstance(records, dict):
        records = [records]
    if not isinstance(records, list):
        return []
    return records


def record_key(record: dict) -> str:
    return f"{str(record.get('hostname', '')).strip().upper()}::{record.get('date', '')}"


def apply_retention(records: list, days: int = 30) -> list:
    cutoff = datetime.now().date() - timedelta(days=days)
    kept = []

    for r in records:
        try:
            d = datetime.strptime(r["date"], "%Y-%m-%d").date()
            if d >= cutoff:
                kept.append(r)
        except Exception:
            # Skip malformed records
            continue

    kept.sort(key=lambda x: (str(x.get("hostname", "")).upper(), x.get("date", "")))
    return kept


def build_unc_from_ip(ip_address: str) -> str:
    return f"\\\\{ip_address}\\{REMOTE_RELATIVE_PATH}"


def _escape_ps_single_quoted(value: str) -> str:
    return str(value).replace("'", "''")


def _test_host_reachable(ip_address: str) -> bool:
    command = (
        f"try {{ "
        f"if (Test-NetConnection -ComputerName '{_escape_ps_single_quoted(ip_address)}' -Port 445 -InformationLevel Quiet) "
        f"{{ exit 0 }} else {{ exit 1 }} "
        f"}} catch {{ exit 1 }}"
    )
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except Exception:
        return False

    return result.returncode == 0


def _read_remote_behavior_with_credentials(ip_address: str, username: str, password: str) -> tuple[list, str]:
    escaped_ip = _escape_ps_single_quoted(ip_address)
    escaped_user = _escape_ps_single_quoted(username)
    escaped_password = _escape_ps_single_quoted(password)

    command = f"""
$sec = ConvertTo-SecureString '{escaped_password}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('{escaped_user}', $sec)
$driveName = 'UAB' + [System.Guid]::NewGuid().ToString('N').Substring(0, 8)
$root = '\\\\{escaped_ip}\\C$'
$path = $null

try {{
    New-PSDrive -Name $driveName -PSProvider FileSystem -Root $root -Credential $cred -ErrorAction Stop | Out-Null
    $path = '{{0}}:' -f $driveName
    $path = Join-Path $path 'ProgramData\\BehaviorAgent\\UserBehaviorActivity.json'

    if (-not (Test-Path -LiteralPath $path)) {{
        Write-Output '__ERROR__:Behavior activity file not found on remote host.'
        exit 3
    }}

    Get-Content -LiteralPath $path -Raw -Encoding UTF8
    exit 0
}} catch {{
    Write-Output ('__ERROR__:' + $_.Exception.Message)
    exit 2
}} finally {{
    if (Get-PSDrive -Name $driveName -ErrorAction SilentlyContinue) {{
        Remove-PSDrive -Name $driveName -Force -ErrorAction SilentlyContinue
    }}
}}
""".strip()

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except Exception as exc:
        return [], str(exc)

    stdout = (result.stdout or "").strip()
    stderr = (result.stderr or "").strip()

    if stdout.startswith("__ERROR__:"):
        return [], stdout.replace("__ERROR__:", "", 1).strip()

    if result.returncode == 0 and stdout:
        try:
            doc = json.loads(stdout)
            return normalize_records(doc), ""
        except Exception as exc:
            return [], f"Failed to parse remote behavior JSON: {exc}"

    error_text = stderr or stdout or f"PowerShell exited with code {result.returncode}"
    return [], error_text


def read_remote_behavior(ip_address: str, username: str, password: str) -> tuple[list, str, bool]:
    unc = build_unc_from_ip(ip_address)
    print(f"[DEBUG] Reading: {unc}")

    records, error = _read_remote_behavior_with_credentials(ip_address, username, password)
    reachable = _test_host_reachable(ip_address)

    if error:
        print(f"[DEBUG] Remote behavior read failed for {ip_address}: {error}")

    print(f"[DEBUG] Records found at {ip_address}: {len(records)}")
    return records, error, reachable


def load_targets() -> list:
    doc = load_json_file(TARGET_FILE, {"hosts": []})
    hosts = doc.get("hosts", [])
    if not isinstance(hosts, list):
        return []
    return hosts


def iter_assetdetails_hosts(doc: dict):
    """
    Flattens AssetDetails.json structure:
    networks -> subnets -> hosts
    """
    if not isinstance(doc, dict):
        return

    for network in doc.get("networks", []):
        if not isinstance(network, dict):
            continue
        for subnet in network.get("subnets", []):
            if not isinstance(subnet, dict):
                continue
            for host in subnet.get("hosts", []):
                if isinstance(host, dict):
                    yield host


def build_assetdetails_user_behavior_map() -> dict:
    """
    Returns:
        {
            "WS-01": {
                "date": "...",
                "user": "...",
                "dailyBehaviorSummary": {...},
                "observations": [...]
            },
            ...
        }
    """
    doc = load_json_file(ASSET_DETAILS_FILE, {})
    result = {}

    for host in iter_assetdetails_hosts(doc):
        hostname = str(host.get("hostname", "")).strip().upper()
        if not hostname:
            continue

        if str(host.get("device_type", "")).strip().lower() != "workstation":
            continue

        user_behavior = host.get("user_behavior", {})
        if isinstance(user_behavior, dict) and user_behavior:
            result[hostname] = deepcopy(user_behavior)

    return result


def extract_workstations_from_assetinventory() -> list:
    doc = load_json_file(ASSET_INVENTORY_FILE, {})
    results = []

    candidates = []

    if isinstance(doc, dict):
        if isinstance(doc.get("assets"), list):
            candidates.extend(doc["assets"])
        if isinstance(doc.get("hosts"), list):
            candidates.extend(doc["hosts"])
        if isinstance(doc.get("records"), list):
            candidates.extend(doc["records"])

        for subnet in doc.get("subnets", []):
            if not isinstance(subnet, dict):
                continue
            for asset in subnet.get("assets", []):
                if isinstance(asset, dict):
                    candidates.append({
                        "hostname": asset.get("hostname", ""),
                        "ip_address": asset.get("location", {}).get("ip_address", ""),
                        "device_type": "Workstation" if str(asset.get("hostname", "")).upper().startswith("WS-") else ""
                    })

    for item in candidates:
        if not isinstance(item, dict):
            continue

        hostname = str(item.get("hostname", "")).strip().upper()
        device_type = str(item.get("device_type", "")).strip()
        ip_address = str(item.get("ip_address", "")).strip()

        if not hostname:
            continue

        is_workstation = (
            device_type.lower() == "workstation"
            or hostname.startswith("WS-")
        )

        if is_workstation:
            results.append({
                "hostname": hostname,
                "ip_address": ip_address,
                "device_type": "Workstation"
            })

    return results


def build_default_behavior_record(hostname: str, ip_address: str, template: dict) -> dict:
    template = deepcopy(template) if isinstance(template, dict) else {}

    return {
        "hostname": hostname.upper(),
        "ip_address": ip_address,

        "date": template.get("date", datetime.now().strftime("%Y-%m-%d")),
        "user": template.get("user", "CORP\\Administrator"),
        "dailyBehaviorSummary": template.get("dailyBehaviorSummary", {
            "accessFrequency": 0,
            "failedLoginAttempts": 0,
            "successfulLoginCount": 0,
            "passwordResets": 0,
            "loginConsistency": 0.0,
            "sessionDuration": 0.0
        }),
        "observations": template.get("observations", [])
    }


def sync_workstations_from_assetdetails(final_records: list, remote_hostnames_with_data: set | None = None) -> tuple[list, list]:
    assetinventory_workstations = extract_workstations_from_assetinventory()
    template_map = build_assetdetails_user_behavior_map()
    remote_hostnames_with_data = {
        str(hostname).strip().upper()
        for hostname in (remote_hostnames_with_data or set())
        if str(hostname).strip()
    }

    workstation_hostnames = {
        str(ws.get("hostname", "")).strip().upper()
        for ws in assetinventory_workstations
        if str(ws.get("hostname", "")).strip()
    }

    synced_records = [
        record for record in final_records
        if (
            str(record.get("hostname", "")).strip().upper() not in workstation_hostnames
            or str(record.get("hostname", "")).strip().upper() in remote_hostnames_with_data
        )
    ]

    synced = []

    for ws in assetinventory_workstations:
        hostname = str(ws.get("hostname", "")).strip().upper()
        ip_address = str(ws.get("ip_address", "")).strip()

        if not hostname or hostname in remote_hostnames_with_data:
            continue

        template = template_map.get(hostname)

        if not template:
            print(f"[DEBUG] No template for {hostname}")
            continue

        synced_records.append(build_default_behavior_record(hostname, ip_address, template))
        synced.append({
            "hostname": hostname,
            "ip_address": ip_address,
            "status": "populated_from_assetdetails"
        })

    return synced_records, synced

def merge_many_hosts(retention_days: int = 30) -> dict:
    all_targets = load_targets()
    targets = [
        h for h in all_targets
        if str(h.get("hostname", "")).strip().upper().startswith("WS-")
    ]
    non_workstation_targets = []

    for host in all_targets:
        hostname = str(host.get("hostname", "")).strip().upper()
        ip_address = str(host.get("ip_address", "")).strip()

        if not hostname or hostname.startswith("WS-"):
            continue

        non_workstation_targets.append({
            "hostname": hostname,
            "ip_address": ip_address,
            "reachable": _test_host_reachable(ip_address) if ip_address else False,
        })

    central_doc = load_json_file(CENTRAL_FILE, {"records": []})
    central_records = normalize_records(central_doc)

    merged = {record_key(r): r for r in central_records}
    results = []
    remote_hostnames_with_data = set()
    template_map = build_assetdetails_user_behavior_map()

    # Step 1: merge remote records from targets.json workstations
    for host in targets:
        hostname = host.get("hostname", "Unknown")
        ip_address = str(host.get("ip_address", "")).strip()
        username = str(host.get("username", "")).strip()
        password = str(host.get("password", "")).strip()

        if not ip_address:
            results.append({
                "hostname": hostname,
                "ip_address": ip_address,
                "status": "error",
                "error": "Missing ip_address in targets.json"
            })
            continue

        remote_records, remote_error, reachable = read_remote_behavior(ip_address, username, password)

        for r in remote_records:
            if not str(r.get("hostname", "")).strip():
                r["hostname"] = str(hostname).strip().upper()

            if not str(r.get("ip_address", "")).strip():
                r["ip_address"] = ip_address

            merged[record_key(r)] = r

        normalized_hostname = str(hostname).strip().upper()
        if remote_records:
            remote_hostnames_with_data.add(normalized_hostname)
            host_status = "ok"
        elif template_map.get(normalized_hostname) and reachable:
            host_status = "populated_from_assetdetails_live_host"
        elif template_map.get(normalized_hostname):
            host_status = "populated_from_assetdetails_unreachable_host"
        else:
            host_status = "no_remote_records" if reachable else "unreachable"

        host_result = {
            "hostname": hostname,
            "ip_address": ip_address,
            "status": host_status,
            "records_merged": len(remote_records),
            "reachable": reachable,
        }
        if remote_error:
            host_result["error"] = remote_error
        results.append(host_result)

    # Step 2: apply retention
    retained_records = apply_retention(list(merged.values()), retention_days)

    # Step 3: populate workstation records from AssetDetails.json when current remote data is unavailable
    final_records, backfilled = sync_workstations_from_assetdetails(
        retained_records.copy(),
        remote_hostnames_with_data,
    )

    # Step 4: final sort and save
    final_records.sort(key=lambda x: (str(x.get("hostname", "")).upper(), x.get("date", "")))

    final_doc = {"records": final_records}
    save_json_file(CENTRAL_FILE, final_doc)

    return {
        "targets_file": str(TARGET_FILE),
        "central_file": str(CENTRAL_FILE),
        "asset_inventory_file": str(ASSET_INVENTORY_FILE),
        "asset_details_file": str(ASSET_DETAILS_FILE),
        "total_records": len(final_records),
        "hosts": results,
        "non_workstation_targets": non_workstation_targets,
        "backfilled_hosts": backfilled,
        "backfilled_count": len(backfilled),
    }

    
if __name__ == "__main__":
    result = merge_many_hosts(retention_days=30)
    print(json.dumps(result, indent=2))
