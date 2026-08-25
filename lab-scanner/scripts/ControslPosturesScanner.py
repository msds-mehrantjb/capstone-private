import json
import os
import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]

# FIXED PATH (correct folder name: lab-scanner)
TARGET_FILE = BASE_DIR / "lab-scanner" / "config" / "targets.json"

YEAR = os.getenv("CAPSTONE_CONTROLS_YEAR", "2026")
OUTPUT_FILE = Path(
    os.getenv(
        "CAPSTONE_CONTROLS_OUTPUT_FILE",
        str(BASE_DIR / "data" / "work" / YEAR / "VMControlsPostures.json"),
    )
)
PROGRESS_FILE = Path(
    os.getenv(
        "CAPSTONE_CONTROLS_PROGRESS_FILE",
        str(BASE_DIR / "data" / "work" / YEAR / "VMControlsPosturesProgress.json"),
    )
)


def write_progress(status: str, total: int, completed: int, current_host: str = "", message: str = ""):
    PROGRESS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(PROGRESS_FILE, "w", encoding="utf-8") as f:
        json.dump(
            {
                "year": int(YEAR),
                "status": status,
                "total": total,
                "completed": completed,
                "current_host": current_host,
                "message": message,
            },
            f,
            indent=2,
        )

def run_powershell_remote(ip: str, username: str, password: str, ps_script: str):
    command = f"""
$sec = ConvertTo-SecureString '{password}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('{username}', $sec)

try {{
    Invoke-Command -ComputerName '{ip}' -Credential $cred -ScriptBlock {{
        {ps_script}
    }} -ErrorAction Stop
}} catch {{
    Write-Output "ERROR: $($_.Exception.Message)"
}}
"""

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command],
            capture_output=True,
            text=True,
            timeout=20,
        )
    except subprocess.TimeoutExpired:
        print(f"\n--- DEBUG [{ip}] TIMEOUT ---")
        print("PowerShell remote collection timed out.")
        return None

    print(f"\n--- DEBUG [{ip}] STDOUT ---")
    print(result.stdout)
    print(f"--- DEBUG [{ip}] STDERR ---")
    print(result.stderr)

    output = result.stdout.strip()

    if not output or output.startswith("ERROR:"):
        return None

    return output

def detect_role(hostname: str, ip: str, username: str, password: str) -> str:
    ps = r"""
    $role = $null

    try {
        $cs = Get-CimInstance Win32_ComputerSystem
        if ($cs.DomainRole -ge 4) {
            $role = "Domain Controller (Active Directory)"
        }
    } catch {}

    if (-not $role) {
        try {
            if (Get-Service -Name DNS -ErrorAction SilentlyContinue) {
                $role = "DNS Server"
            }
        } catch {}
    }

    if (-not $role) {
        try {
            if (Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin @("ADMIN$", "C$", "IPC$") }) {
                $role = "File Server"
            }
        } catch {}
    }

    if (-not $role) {
        try {
            $appServiceNames = @(
                "W3SVC", "AppHostSvc", "MSSQLSERVER", "Tomcat9", "Tomcat10",
                "Apache2.4", "Nginx", "docker", "docker engine"
            )
            $services = Get-Service -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
            foreach ($svc in $appServiceNames) {
                if ($services -contains $svc) {
                    $role = "Application Server"
                    break
                }
            }
        } catch {}
    }

    if (-not $role) {
        try {
            $os = Get-CimInstance Win32_OperatingSystem
            if ($os.ProductType -eq 1) {
                $role = "Standard Employee Workstation"
            }
        } catch {}
    }

    if (-not $role) {
        $role = "Standard Employee Workstation"
    }

    Write-Output $role
    """
    output = run_powershell_remote(ip, username, password, ps)
    
    if not output:
        return "Unknown"
    
    return output.strip()   


def detect_cia_rating(role: str) -> str:
    critical_roles = {
        "Domain Controller (Active Directory)",
    }

    high_roles = {
        "DNS Server",
        "File Server",
        "Application Server",
    }

    if role in critical_roles:
        return "Critical"
    if role in high_roles:
        return "High"
    return "Medium"


def collect_controls(ip: str, username: str, password: str) -> dict:
    ps = r"""
    $result = [ordered]@{}

    function Test-Exists($value) {
        return ($null -ne $value -and $value -ne "")
    }

    $iam = @()
    $endpoint = @()
    $network = @()
    $logging = @()
    $vuln = @()
    $physical = @()

    try {
        $pwPolicy = net accounts
        if ($pwPolicy) {
            $iam += "Password Policies (complexity, rotation)"
        }
    } catch {}

    try {
        $adService = Get-Service -Name NTDS -ErrorAction SilentlyContinue
        if ($adService) {
            $iam += "Active Directory Domain Services (AD DS)"
        }
    } catch {}

    try {
        $gpoService = Get-Service -Name gpsvc -ErrorAction SilentlyContinue
        if ($gpoService) {
            $iam += "Group Policy Objects (GPO)"
        }
    } catch {}

    try {
        $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
        if ($admins) {
            $iam += "Role-Based Access Control (RBAC)"
        }
    } catch {}

    try {
        $defender = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
        if ($defender) {
            $endpoint += "Antivirus / Anti-malware"
        }
    } catch {}

    try {
        $sb = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
        if ($sb -eq $true) {
            $endpoint += "Secure Boot"
        }
    } catch {}

    try {
        $profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq $true }
        if ($profiles) {
            $network += "Windows Firewall (Host-based)"
        }
    } catch {}

    try {
        $dnsService = Get-Service -Name DNS -ErrorAction SilentlyContinue
        if ($dnsService) {
            $network += "DNS Security (DNS filtering / logging)"
        }
    } catch {}

    try {
        $eventLog = Get-Service -Name EventLog -ErrorAction SilentlyContinue
        if ($eventLog) {
            $logging += "Windows Event Logging"
        }
    } catch {}

    try {
        $wuauserv = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
        if ($wuauserv) {
            $vuln += "Patch Management (WSUS / SCCM)"
        }
    } catch {}

    try {
        $chassis = Get-CimInstance Win32_SystemEnclosure -ErrorAction SilentlyContinue
        if ($chassis) {
            $physical += "Server Room Access Control"
        }
    } catch {}

    if ($iam.Count -gt 0) { $result["Identity & Access Management"] = @($iam | Select-Object -Unique) }
    if ($endpoint.Count -gt 0) { $result["Endpoint Security Controls"] = @($endpoint | Select-Object -Unique) }
    if ($network.Count -gt 0) { $result["Network Security Controls"] = @($network | Select-Object -Unique) }
    if ($logging.Count -gt 0) { $result["Logging, Monitoring & Detection"] = @($logging | Select-Object -Unique) }
    if ($vuln.Count -gt 0) { $result["Vulnerability & Patch Management"] = @($vuln | Select-Object -Unique) }
    if ($physical.Count -gt 0) { $result["Physical & Environmental Controls"] = @($physical | Select-Object -Unique) }

    $result | ConvertTo-Json -Depth 10 -Compress
    """
    output = run_powershell_remote(ip, username, password, ps)
    if not output:
        return {}

    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return {}


def normalize_controls_by_role(role: str, controls: dict) -> dict:
    normalized = {}

    order = [
        "Identity & Access Management",
        "Endpoint Security Controls",
        "Network Security Controls",
        "Logging, Monitoring & Detection",
        "Vulnerability & Patch Management",
        "Physical & Environmental Controls",
    ]

    for key in order:
        if key in controls and isinstance(controls[key], list) and controls[key]:
            normalized[key] = controls[key]

    if role == "Standard Employee Workstation":
        normalized.pop("Physical & Environmental Controls", None)
    
    if role == "Domain Controller (Active Directory)":
        normalized.setdefault("Identity & Access Management", [])
        for item in [
            "Password Policies (complexity, rotation)",
            "Active Directory Domain Services (AD DS)",
            "Group Policy Objects (GPO)",
            "Role-Based Access Control (RBAC)",
        ]:
            if item not in normalized["Identity & Access Management"]:
                normalized["Identity & Access Management"].append(item)

    if role == "DNS Server":
        normalized.setdefault("Network Security Controls", [])
        if "DNS Security (DNS filtering / logging)" not in normalized["Network Security Controls"]:
            normalized["Network Security Controls"].append("DNS Security (DNS filtering / logging)")

    if role in {
        "Domain Controller (Active Directory)",
        "DNS Server",
        "File Server",
        "Application Server",
    }:
        if "Vulnerability & Patch Management" not in normalized:
            normalized["Vulnerability & Patch Management"] = ["Patch Management (WSUS / SCCM)"]
        if "Physical & Environmental Controls" not in normalized:
            normalized["Physical & Environmental Controls"] = ["Server Room Access Control"]

    return normalized


def build_host_entry(host: dict) -> dict:
    hostname = host["hostname"]
    ip = host["ip_address"]
    username = host["username"]
    password = host["password"]

    role = detect_role(hostname, ip, username, password)
    cia_rating = detect_cia_rating(role)
    existing_controls = collect_controls(ip, username, password)
    existing_controls = normalize_controls_by_role(role, existing_controls)

    return {
        "hostname": hostname,
        "ip_address": ip,
        "role": role,
        "CIA rating": cia_rating,
        "existing_controls": existing_controls,
    }


def main():
    if not TARGET_FILE.exists():
        raise FileNotFoundError(f"Target file not found: {TARGET_FILE}")

    with open(TARGET_FILE, "r", encoding="utf-8") as f:
        target_data = json.load(f)

    hosts = target_data.get("hosts", [])
    output_hosts = []
    total_hosts = len(hosts)

    write_progress(
        "Running",
        total_hosts,
        0,
        "",
        f"Running VM controls scanner: 0 of {total_hosts} hosts completed.",
    )

    for index, host in enumerate(hosts, start=1):
        hostname = str(host.get("hostname", "")).strip()
        write_progress(
            "Running",
            total_hosts,
            index - 1,
            hostname,
            f"Scanning {hostname or 'host'} ({index} of {total_hosts}).",
        )
        output_hosts.append(build_host_entry(host))
        write_progress(
            "Running",
            total_hosts,
            index,
            hostname,
            f"Running VM controls scanner: {index} of {total_hosts} hosts completed.",
        )

    output_data = {
        "hosts": output_hosts
    }

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2)

    write_progress(
        "Completed",
        total_hosts,
        total_hosts,
        "",
        f"VM controls scanner completed: {total_hosts} of {total_hosts} hosts completed.",
    )
    print(f"Saved: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
