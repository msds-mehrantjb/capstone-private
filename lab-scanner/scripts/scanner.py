import json
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

import winrm
import traceback

CONFIG = Path(r"C:\Users\mehra\Capstone-main\lab-scanner\config\targets.json")
OUTPUT = Path(r"C:\Users\mehra\Capstone-main\data\work\2026\AssetInventory.json")
NMAP_EXE = r"C:\Program Files (x86)\Nmap\nmap.exe"


def run_nmap_host_discovery(subnet: str) -> str:
    result = subprocess.run(
        [NMAP_EXE, "-sn", subnet],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout


def run_nmap_port_scan(ip: str) -> str:
    # Common ports relevant to your lab profile
    ports = "53,88,135,389,445,464,636,3389"
    result = subprocess.run(
        [NMAP_EXE, "-Pn", "-p", ports, "-sV", ip],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout


def parse_discovered_hosts(nmap_output: str) -> List[str]:
    hosts = []
    for line in nmap_output.splitlines():
        if "Nmap scan report for" in line:
            ip = line.split()[-1].strip()
            hosts.append(ip)
    return hosts


def parse_open_ports(nmap_output: str) -> List[int]:
    open_ports: List[int] = []
    for line in nmap_output.splitlines():
        line = line.strip()
        match = re.match(r"^(\d+)/tcp\s+open", line)
        if match:
            open_ports.append(int(match.group(1)))
    return sorted(open_ports)


def create_session(ip: str, username: str, password: str) -> winrm.Session:
    return winrm.Session(
        f"http://{ip}:5985/wsman",
        auth=(username, password),
        transport="ntlm",
    )


def run_ps(session: winrm.Session, script: str) -> str:
    result = session.run_ps(script)
    if result.status_code != 0:
        return ""
    return result.std_out.decode(errors="ignore").strip()


def parse_software_lines(output: str) -> List[Dict[str, str]]:
    software: List[Dict[str, str]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        parts = line.split("|||", 1)
        name = parts[0].strip()
        version = parts[1].strip() if len(parts) > 1 else ""

        if name:
            software.append({
                "name": name,
                "version": version,
            })
    return software


def normalize_software_name(name: str) -> str:
    low = name.lower().strip()

    if "microsoft office" in low or "office " in low or low == "office":
        return "Microsoft Office"
    if "quickbooks" in low:
        return "QuickBooks Desktop"
    if "adobe acrobat reader" in low or "acrobat reader" in low:
        return "Adobe Acrobat Reader"
    if low in ("browser", "google chrome", "microsoft edge", "mozilla firefox"):
        return "Browser"

    return name.strip()


def parse_version_key(version: str) -> tuple:
    if not version:
        return tuple()

    parts = re.findall(r"\d+", version)
    if not parts:
        return tuple()

    return tuple(int(p) for p in parts)


def keep_latest_software(software_list: List[Dict[str, str]]) -> List[str]:
    latest: Dict[str, Dict[str, str]] = {}

    for item in software_list:
        raw_name = item.get("name", "").strip()
        raw_version = item.get("version", "").strip()

        if not raw_name:
            continue

        normalized_name = normalize_software_name(raw_name)
        current_version_key = parse_version_key(raw_version)

        if normalized_name not in latest:
            latest[normalized_name] = {
                "name": normalized_name,
                "version": raw_version,
            }
            continue

        existing_version_key = parse_version_key(latest[normalized_name]["version"])

        if current_version_key > existing_version_key:
            latest[normalized_name] = {
                "name": normalized_name,
                "version": raw_version,
            }

    return sorted([item["name"] for item in latest.values()])

def parse_lines(output: str) -> List[str]:
    return [line.strip() for line in output.splitlines() if line.strip()]


def get_windows_data(ip: str, username: str, password: str) -> Dict[str, Any]:
    session = create_session(ip, username, password)

    hostname = run_ps(session, "$env:COMPUTERNAME")

    os_caption = run_ps(
        session,
        "(Get-CimInstance Win32_OperatingSystem).Caption"
    )

    domain_name = run_ps(
        session,
        "(Get-CimInstance Win32_ComputerSystem).Domain"
    )

    part_of_domain = run_ps(
        session,
        "(Get-CimInstance Win32_ComputerSystem).PartOfDomain"
    )

    running_services_raw = run_ps(
        session,
        """
        Get-Service |
        Where-Object {$_.Status -eq 'Running'} |
        Select-Object -ExpandProperty DisplayName
        """
    )
    running_services = parse_lines(running_services_raw)

    installed_roles_raw = run_ps(
        session,
        """
        if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
            Get-WindowsFeature |
            Where-Object {$_.InstallState -eq 'Installed'} |
            Select-Object -ExpandProperty DisplayName
        }
        """
    )
    installed_roles = parse_lines(installed_roles_raw)

    installed_software_raw = run_ps(
        session,
        r"""
        $paths = @(
          'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
          'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )

        Get-ItemProperty $paths -ErrorAction SilentlyContinue |
        Where-Object {$_.DisplayName} |
        Select-Object DisplayName, DisplayVersion |
        ForEach-Object {
            $name = if ($_.DisplayName) { $_.DisplayName.Trim() } else { "" }
            $version = if ($_.DisplayVersion) { $_.DisplayVersion.Trim() } else { "" }

            if ($name -ne "") {
                Write-Output "$name|||$version"
            }
        }
        """
    )
    installed_software = parse_software_lines(installed_software_raw)

    return {
        "hostname": hostname,
        "os_caption": os_caption,
        "domain_name": domain_name,
        "is_domain_joined": part_of_domain.lower() == "true",
        "running_services_raw": running_services,
        "installed_roles_raw": installed_roles,
        "installed_software_raw": installed_software,
    }

def infer_device_type(hostname: str, os_caption: str, open_ports: List[int]) -> str:
    hn = hostname.upper()
    osc = os_caption.lower()

    if "server" in osc or hn.startswith("SRV"):
        return "Server"
    if hn.startswith("WS"):
        return "Workstation"
    if 88 in open_ports or 389 in open_ports or 53 in open_ports:
        return "Server"
    return "Workstation"


def infer_role(device_type: str, open_ports: List[int], installed_roles: List[str]) -> str:
    roles_text = " | ".join(installed_roles).lower()

    if (
        device_type == "Server"
        and 53 in open_ports
        and 88 in open_ports
        and 389 in open_ports
        and 445 in open_ports
    ):
        return "Domain Controller"

    if "active directory domain services" in roles_text or "ad ds" in roles_text:
        return "Domain Controller"

    return "User Workstation"


def infer_cia_impact(role: str) -> Dict[str, str]:
    if role == "Domain Controller":
        return {
            "confidentiality": "High",
            "integrity": "High",
            "availability": "High",
        }
    return {
        "confidentiality": "Medium",
        "integrity": "Medium",
        "availability": "Low",
    }


def infer_os_type(os_caption: str) -> str:
    if "server" in os_caption.lower():
        return "Windows Server"
    return "Windows"


def infer_hostname_pattern(hostname: str) -> str:
    if "-" in hostname:
        return hostname.split("-")[0]
    return hostname[:3].upper() if hostname else ""


def normalize_running_services(
    open_ports: List[int],
    raw_services: List[str],
    role: str,
) -> List[str]:
    normalized: List[str] = []

    if role == "Domain Controller":
        if 53 in open_ports:
            normalized.append("DNS Server")
        if 88 in open_ports:
            normalized.append("Kerberos Key Distribution Center")
        if 389 in open_ports or 636 in open_ports:
            normalized.append("LDAP")
        if 445 in open_ports:
            normalized.append("SMB")

        ad_hits = [s for s in raw_services if "active directory" in s.lower()]
        if ad_hits or role == "Domain Controller":
            normalized.insert(0, "Active Directory Domain Services")
    else:
        if 3389 in open_ports:
            normalized.append("Remote Desktop Services")
        if 445 in open_ports:
            normalized.append("SMB")

        spooler = [s for s in raw_services if "print spooler" in s.lower() or s.lower() == "spooler"]
        if spooler:
            normalized.append("Print Spooler")

    # Remove duplicates while preserving order
    deduped = []
    seen = set()
    for item in normalized:
        if item not in seen:
            deduped.append(item)
            seen.add(item)
    return deduped


def parse_software_lines(output: str) -> List[Dict[str, str]]:
    software: List[Dict[str, str]] = []

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        parts = line.split("|||", 1)
        name = parts[0].strip()
        version = parts[1].strip() if len(parts) > 1 else ""

        if name:
            software.append({
                "name": name,
                "version": version,
            })

    return software


def parse_version_key(version: str) -> tuple:
    if not version:
        return tuple()

    nums = re.findall(r"\d+", version)
    return tuple(int(x) for x in nums) if nums else tuple()


def normalize_software_name(name: str) -> str:
    low = name.lower().strip()

    if "quickbooks" in low:
        return "QuickBooks Desktop"

    if "adobe acrobat reader" in low or "acrobat reader" in low:
        return "Adobe Acrobat Reader"

    if (
        "microsoft office" in low
        or low.startswith("office ")
        or low == "office"
    ):
        return "Microsoft Office"

    if low in ("browser", "google chrome", "microsoft edge", "mozilla firefox"):
        return "Browser"

    if "microsoft visual c++" in low:
        arch = ""
        if "x64" in low:
            arch = " (x64)"
        elif "x86" in low:
            arch = " (x86)"
        return f"Microsoft Visual C++{arch}"

    if "vmware tools" in low:
        return "VMware Tools"

    if "microsoft edge webview2" in low:
        return "Microsoft Edge WebView2 Runtime"

    if "microsoft edge update" in low:
        return "Microsoft Edge Update"

    return name.strip()


def keep_latest_software(software_list: List[Dict[str, str]]) -> List[str]:
    latest: Dict[str, Dict[str, str]] = {}

    for item in software_list:
        raw_name = item.get("name", "").strip()
        raw_version = item.get("version", "").strip()

        if not raw_name:
            continue

        normalized_name = normalize_software_name(raw_name)
        current_key = parse_version_key(raw_version)

        if normalized_name not in latest:
            latest[normalized_name] = {
                "name": normalized_name,
                "version": raw_version,
            }
            continue

        existing_key = parse_version_key(latest[normalized_name]["version"])

        if current_key > existing_key:
            latest[normalized_name] = {
                "name": normalized_name,
                "version": raw_version,
            }

    return sorted(item["name"] for item in latest.values())

def normalize_installed_roles(raw_roles: List[str], role: str) -> List[str]:
    roles_out: List[str] = []

    for item in raw_roles:
        low = item.lower()
        if "active directory domain services" in low:
            roles_out.append("AD DS")
        elif low == "dns server" or "dns server" in low:
            roles_out.append("DNS Server")
        elif "active directory certificate services" in low:
            roles_out.append("Active Directory Certificate Services")

    if role != "Domain Controller":
        return []

    # Deduplicate
    deduped = []
    seen = set()
    for item in roles_out:
        if item not in seen:
            deduped.append(item)
            seen.add(item)
    return deduped


def limit_software_list(software: List[Dict[str, str]], max_items: int = 20) -> List[str]:
    latest_only = keep_latest_software(software)
    return latest_only[:max_items]

def build_placeholder_detail_section() -> Dict[str, Any]:
    return {
        "business_context": {
            "department": "",
            "business_function": "",
            "criticality": "",
        },
        "indicator_based_role_detection": {
            "detected_roles": [],
            "confidence": "",
        },
        "ml_role_prediction": {
            "predicted_roles": [],
            "confidence": "",
        },
        "rag_based_role_detection": {
            "detected_role": "",
            "confidence": "",
        },
        "selected_role": {
            "role": "",
            "method": "",
        },
    }


def build_host_record(
    ip: str,
    status: str,
    windows_data: Optional[Dict[str, Any]] = None,
    open_ports: Optional[List[int]] = None,
    fallback_hostname: str = "",
) -> Dict[str, Any]:
    if status != "Active" or not windows_data:
        return {
            "hostname": fallback_hostname,
            "ip_address": ip,
            "device_type": "",
            "status": status,
            "role": "",
            "cia_impact": {
                "confidentiality": "",
                "integrity": "",
                "availability": "",
            },
            "detail": {
                "device_profile": {
                    "os_type": "",
                    "os_version": "",
                    "is_domain_joined": False,
                },
                "technical_indicators": {
                    "open_ports": [],
                    "running_services": [],
                    "installed_roles": [],
                    "installed_software": [],
                },
                **build_placeholder_detail_section(),
            },
        }

    hostname = windows_data["hostname"] or fallback_hostname
    os_caption = windows_data["os_caption"] or ""
    ports = open_ports or []

    device_type = infer_device_type(hostname, os_caption, ports)
    normalized_roles = normalize_installed_roles(windows_data["installed_roles_raw"], "")
    role = infer_role(device_type, ports, normalized_roles)
    cia_impact = infer_cia_impact(role)

    normalized_roles = normalize_installed_roles(windows_data["installed_roles_raw"], role)
    normalized_services = normalize_running_services(
        ports,
        windows_data["running_services_raw"],
        role,
    )

    return {
        "hostname": hostname,
        "ip_address": ip,
        "device_type": device_type,
        "status": status,
        "role": role,
        "cia_impact": cia_impact,
        "detail": {
            "device_profile": {
                "os_type": infer_os_type(os_caption),
                "os_version": os_caption,
                "is_domain_joined": windows_data["is_domain_joined"],
            },
            "technical_indicators": {
                "open_ports": ports,
                "running_services": normalized_services,
                "installed_roles": normalized_roles,
                "installed_software": limit_software_list(windows_data["installed_software_raw"]),
            },
            **build_placeholder_detail_section(),
        },
    }


def main() -> None:
    print("[+] Loading config...")
    with CONFIG.open("r", encoding="utf-8") as f:
        cfg = json.load(f)

    subnet = cfg["subnet"]
    year = cfg.get("year", 2026)
    network_address = cfg.get("network_address", "10.0.0.0")

    print("[+] Discovering live hosts...")
    discovery_output = run_nmap_host_discovery(subnet)
    active_hosts = set(parse_discovered_hosts(discovery_output))

    hosts_output: List[Dict[str, Any]] = []

    for host in cfg["hosts"]:
        ip = host["ip_address"]
        hostname = host["hostname"]
        username = host["username"]
        password = host["password"]

        if ip in active_hosts:
            print(f"[+] Active host found: {ip}")
            port_scan_output = run_nmap_port_scan(ip)
            open_ports = parse_open_ports(port_scan_output)

            try:
                windows_data = get_windows_data(ip, username, password)
                host_record = build_host_record(
                    ip=ip,
                    status="Active",
                    windows_data=windows_data,
                    open_ports=open_ports,
                    fallback_hostname=hostname,
                )
            except Exception as exc:
                print(f"[!] WinRM collection failed for {ip}: {exc}")
                traceback.print_exc()
                host_record = build_host_record(
                    ip=ip,
                    status="Active",
                    windows_data=None,
                    open_ports=[],
                    fallback_hostname=hostname,
                )
        else:
            print(f"[-] Host not active: {ip}")
            host_record = build_host_record(
                ip=ip,
                status="Inactive",
                windows_data=None,
                open_ports=[],
                fallback_hostname=hostname,
            )

        hosts_output.append(host_record)

    final_json = {
        "year": year,
        "networks": [
            {
                "network_address": network_address,
                "subnets": [
                    {
                        "subnet": subnet,
                        "hosts": hosts_output,
                    }
                ],
            }
        ],
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT.open("w", encoding="utf-8") as f:
        json.dump(final_json, f, indent=2)

    print(f"[+] Asset inventory written to: {OUTPUT}")


if __name__ == "__main__":
    main()