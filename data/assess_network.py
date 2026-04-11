import subprocess
import json
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parents[2]

OUTPUT_FILE = DATA_DIR / "work" / "2026" / "AssetInventory.json"

SUBNETS = {
    "Subnet_A": {
        "cidr": "10.0.0.0/28",
        "gateway": "10.0.0.1",
        "docker_gateway": "10.0.0.14"
    },
    "Subnet_B": {
        "cidr": "10.0.0.16/28",
        "gateway": "10.0.0.17",
        "docker_gateway": "10.0.0.30"
    }
}

SCANNER_CONTAINER = "ws_01"

HOST_DETAILS = {
    "10.0.0.2": {
        "hostname": "SRV-01",
        "role": "Domain Controller (Active Directory)",
        "operating_system": "Windows Server 2019",
        "criticality": "Critical",
        "subnet": "Subnet_A",
        "location_name": "10.0.0.1",
        "detail": {
            "device_profile": {
                "os_type": "Windows Server",
                "os_version": "Windows Server 2019",
                "is_domain_joined": True,
                "hostname_pattern": "SRV"
            },
            "technical_indicators": {
                "open_ports": [53, 88, 135, 389, 445, 464, 636],
                "running_services": [
                    "Active Directory Domain Services",
                    "DNS Server",
                    "Kerberos Key Distribution Center",
                    "LDAP",
                    "SMB"
                ],
                "installed_roles": [
                    "AD DS",
                    "DNS Server",
                    "Active Directory Certificate Services"
                ],
                "installed_software": [
                    "Group Policy Management",
                    "RSAT",
                    "AD CS Management Tools"
                ]
            },
            "business_context": {
                "department": "IT",
                "business_function": "Identity Infrastructure",
                "criticality": "Critical"
            },
            "indicator_based_role_detection": {
                "detected_roles": [
                    "Domain Controller (Active Directory)",
                    "DNS Server",
                    "File Server"
                ],
                "confidence": "Very High"
            },
            "ml_role_prediction": {
                "predicted_roles": [
                    "Domain Controller (Active Directory)"
                ],
                "confidence": "0.85",
                "feature_completeness_ratio": 1.0
            },
            "rag_based_role_detection": {
                "detected_role": "",
                "confidence": ""
            },
            "selected_role": {
                "role": "Domain Controller (Active Directory)",
                "method": "indicator"
            }
        }
    },
    "10.0.0.3": {
        "hostname": "SRV-02",
        "role": "DNS Server",
        "operating_system": "Windows Server 2019",
        "criticality": "High",
        "subnet": "Subnet_A",
        "location_name": "10.0.0.1",
        "detail": {
            "device_profile": {
                "os_type": "Windows Server",
                "os_version": "Windows Server 2019",
                "is_domain_joined": True,
                "hostname_pattern": "SRV"
            },
            "technical_indicators": {
                "open_ports": [53, 67, 68, 135, 445],
                "running_services": [
                    "DNS Server",
                    "DHCP Server",
                    "RPC Endpoint Mapper",
                    "SMB"
                ],
                "installed_roles": [
                    "DNS Server",
                    "DHCP Server"
                ],
                "installed_software": [
                    "Windows DNS",
                    "DHCP Management Console",
                    "IP Address Management"
                ]
            },
            "business_context": {
                "department": "IT",
                "business_function": "Networking",
                "criticality": "High"
            },
            "indicator_based_role_detection": {
                "detected_roles": [
                    "DNS Server",
                    "DHCP Server",
                    "File Server"
                ],
                "confidence": "Very High"
            },
            "ml_role_prediction": {
                "predicted_roles": [
                    "DHCP Server"
                ],
                "confidence": "0.5067",
                "feature_completeness_ratio": 1.0,
                "error": "Server ML confidence is below the minimum threshold of 0.60."
            },
            "rag_based_role_detection": {
                "detected_role": "",
                "confidence": ""
            },
            "selected_role": {
                "role": "DNS Server",
                "method": "indicator"
            }
        }
    },
    "10.0.0.10": {
        "hostname": "WS-01",
        "role": "Standard Employee Workstation",
        "operating_system": "Windows 11",
        "criticality": "Medium",
        "subnet": "Subnet_A",
        "location_name": "10.0.0.1",
        "detail": {
            "device_profile": {
                "os_type": "Windows",
                "os_version": "Windows 11",
                "is_domain_joined": True,
                "hostname_pattern": "WS"
            },
            "technical_indicators": {
                "open_ports": [3389, 445],
                "running_services": [
                    "Remote Desktop Services",
                    "SMB",
                    "Print Spooler"
                ],
                "installed_roles": [],
                "installed_software": [
                    "Microsoft Office",
                    "QuickBooks Desktop",
                    "Adobe Acrobat Reader",
                    "Browser"
                ]
            },
            "business_context": {
                "department": "Finance",
                "business_function": "End User Computing",
                "criticality": "Medium"
            },
            "indicator_based_role_detection": {
                "detected_roles": [
                    "Standard Employee Workstation",
                    "VDI Client Workstation"
                ],
                "confidence": "Medium"
            },
            "ml_role_prediction": {
                "predicted_roles": [
                    "Standard Employee Workstation"
                ],
                "confidence": "0.84"
            },
            "rag_based_role_detection": {
                "detected_role": "",
                "confidence": ""
            },
            "selected_role": {
                "role": "Standard Employee Workstation",
                "method": "ml"
            }
        }
    },
    "10.0.0.11": {
        "hostname": "WS-02",
        "role": "Standard Employee Workstation",
        "operating_system": "Windows 10",
        "criticality": "Medium",
        "subnet": "Subnet_A",
        "location_name": "10.0.0.1",
        "detail": {
            "device_profile": {
                "os_type": "Windows",
                "os_version": "Windows 10",
                "is_domain_joined": True,
                "hostname_pattern": "WS"
            },
            "technical_indicators": {
                "open_ports": [3389, 135],
                "running_services": [
                    "Remote Desktop Services",
                    "RPC Endpoint Mapper",
                    "Windows Installer"
                ],
                "installed_roles": [],
                "installed_software": [
                    "Workday",
                    "Microsoft Office",
                    "Java Runtime Environment",
                    "Browser"
                ]
            },
            "business_context": {
                "department": "HR",
                "business_function": "End User Computing",
                "criticality": "Medium"
            },
            "indicator_based_role_detection": {
                "detected_roles": [
                    "Standard Employee Workstation",
                    "HR Workstation",
                    "VDI Client Workstation"
                ],
                "confidence": "Medium"
            },
            "ml_role_prediction": {
                "predicted_roles": [
                    "Standard Employee Workstation"
                ],
                "confidence": "0.85"
            },
            "rag_based_role_detection": {
                "detected_role": "",
                "confidence": ""
            },
            "selected_role": {
                "role": "Standard Employee Workstation",
                "method": "ml"
            }
        }
    },
    "10.0.0.12": {
        "hostname": "WS-03",
        "role": "Standard Employee Workstation",
        "operating_system": "Windows 10",
        "criticality": "Medium",
        "subnet": "Subnet_A",
        "location_name": "10.0.0.1",
        "detail": {
            "device_profile": {
                "os_type": "Windows",
                "os_version": "Windows 10",
                "is_domain_joined": True,
                "hostname_pattern": "WS"
            },
            "technical_indicators": {
                "open_ports": [3389, 443],
                "running_services": [
                    "Remote Desktop Services",
                    "Microsoft Teams",
                    "Outlook"
                ],
                "installed_roles": [],
                "installed_software": [
                    "Microsoft Office",
                    "Teams",
                    "Outlook",
                    "OneDrive Sync Client"
                ]
            },
            "business_context": {
                "department": "Operations",
                "business_function": "End User Computing",
                "criticality": "Medium"
            },
            "indicator_based_role_detection": {
                "detected_roles": [
                    "Standard Employee Workstation",
                    "VDI Client Workstation"
                ],
                "confidence": "High"
            },
            "ml_role_prediction": {
                "predicted_roles": [
                    "Standard Employee Workstation"
                ],
                "confidence": "0.84"
            },
            "rag_based_role_detection": {
                "detected_role": "",
                "confidence": ""
            },
            "selected_role": {
                "role": "Standard Employee Workstation",
                "method": "indicator"
            }
        }
    },
    "10.0.0.18": {
        "hostname": "SRV-03",
        "role": "File Server",
        "operating_system": "Windows Server 2016",
        "criticality": "High",
        "subnet": "Subnet_B",
        "location_name": "10.0.0.17",
        "detail": {
            "device_profile": {
                "os_type": "Windows Server",
                "os_version": "Windows Server 2016",
                "is_domain_joined": True,
                "hostname_pattern": "SRV"
            },
            "technical_indicators": {
                "open_ports": [445, 135, 139, 5985],
                "running_services": [
                    "SMB",
                    "File Services",
                    "Distributed File System",
                    "WinRM"
                ],
                "installed_roles": [
                    "File Server",
                    "DFS Namespace",
                    "DFS Replication"
                ],
                "installed_software": [
                    "Windows File Services",
                    "Volume Shadow Copy Service",
                    "File Server Resource Manager"
                ]
            },
            "business_context": {
                "department": "Finance",
                "business_function": "Data Storage",
                "criticality": "High"
            },
            "indicator_based_role_detection": {
                "detected_roles": [
                    "File Server"
                ],
                "confidence": "High"
            },
            "ml_role_prediction": {
                "predicted_roles": [
                    "File Server"
                ],
                "confidence": "0.79",
                "feature_completeness_ratio": 1.0
            },
            "rag_based_role_detection": {
                "detected_role": "",
                "confidence": ""
            },
            "selected_role": {
                "role": "File Server",
                "method": "indicator"
            }
        }
    },
    "10.0.0.19": {
        "hostname": "SRV-04",
        "role": "Application Server",
        "operating_system": "Windows Server 2016",
        "criticality": "High",
        "subnet": "Subnet_B",
        "location_name": "10.0.0.17",
        "detail": {
            "device_profile": {
                "os_type": "Windows Server",
                "os_version": "Windows Server 2016",
                "is_domain_joined": False,
                "hostname_pattern": "SRV"
            },
            "technical_indicators": {
                "open_ports": [80, 443, 135, 5985],
                "running_services": [
                    "IIS",
                    "HTTP",
                    "HTTPS",
                    "Windows Process Activation Service",
                    "WinRM"
                ],
                "installed_roles": [
                    "Web Server (IIS)",
                    "Application Development",
                    "Management Tools"
                ],
                "installed_software": [
                    "Microsoft IIS 10.0",
                    "ASP.NET Core Hosting Bundle",
                    "URL Rewrite Module"
                ]
            },
            "business_context": {
                "department": "Marketing",
                "business_function": "Public Website",
                "criticality": "High"
            },
            "indicator_based_role_detection": {
                "detected_roles": [
                    "Application Server"
                ],
                "confidence": "High"
            },
            "ml_role_prediction": {
                "predicted_roles": [
                    "Application Server"
                ],
                "confidence": "0.8967",
                "feature_completeness_ratio": 1.0
            },
            "rag_based_role_detection": {
                "detected_role": "",
                "confidence": ""
            },
            "selected_role": {
                "role": "Application Server",
                "method": "indicator"
            }
        }
    },
    "10.0.0.26": {
        "hostname": "WS-04",
        "role": "Call Center Workstation",
        "operating_system": "Windows 11",
        "criticality": "Medium",
        "subnet": "Subnet_B",
        "location_name": "10.0.0.17",
        "detail": {
            "device_profile": {
                "os_type": "Windows",
                "os_version": "Windows 11",
                "is_domain_joined": True,
                "hostname_pattern": "WS"
            },
            "technical_indicators": {
                "open_ports": [3389, 5060],
                "running_services": [
                    "Remote Desktop Services",
                    "Softphone Client",
                    "VoIP Helper Service"
                ],
                "installed_roles": [],
                "installed_software": [
                    "CRM Desktop Client",
                    "Softphone",
                    "Call Center Agent",
                    "Browser"
                ]
            },
            "business_context": {
                "department": "Sales",
                "business_function": "End User Computing",
                "criticality": "Medium"
            },
            "indicator_based_role_detection": {
                "detected_roles": [
                    "Call Center Workstation",
                    "VDI Client Workstation"
                ],
                "confidence": "High"
            },
            "ml_role_prediction": {
                "predicted_roles": [
                    "Standard Employee Workstation"
                ],
                "confidence": "0.68"
            },
            "rag_based_role_detection": {
                "detected_role": "",
                "confidence": ""
            },
            "selected_role": {
                "role": "Call Center Workstation",
                "method": "indicator"
            }
        }
    },
    "10.0.0.27": {
        "hostname": "WS-05",
        "role": "Developer Workstation",
        "operating_system": "Windows 10",
        "criticality": "Medium",
        "subnet": "Subnet_B",
        "location_name": "10.0.0.17",
        "detail": {
            "device_profile": {
                "os_type": "Windows",
                "os_version": "Windows 10",
                "is_domain_joined": True,
                "hostname_pattern": "WS"
            },
            "technical_indicators": {
                "open_ports": [3389, 2375, 3000],
                "running_services": [
                    "Remote Desktop Services",
                    "Docker Engine",
                    "Node.js Runtime",
                    "Git Credential Manager"
                ],
                "installed_roles": [],
                "installed_software": [
                    "VS Code",
                    "IntelliJ IDEA",
                    "Git",
                    "Docker Desktop",
                    "Node.js"
                ]
            },
            "business_context": {
                "department": "HR",
                "business_function": "End User Computing",
                "criticality": "Medium"
            },
            "indicator_based_role_detection": {
                "detected_roles": [
                    "Developer Workstation"
                ],
                "confidence": "High"
            },
            "ml_role_prediction": {
                "predicted_roles": [
                    "Developer Workstation"
                ],
                "confidence": "0.64"
            },
            "rag_based_role_detection": {
                "detected_role": "",
                "confidence": ""
            },
            "selected_role": {
                "role": "Developer Workstation",
                "method": "indicator"
            }
        }
    },
    "10.0.0.28": {
        "hostname": "WS-06",
        "role": "Data Scientist Workstation",
        "operating_system": "Windows 11",
        "criticality": "Medium",
        "subnet": "Subnet_B",
        "location_name": "10.0.0.17",
        "detail": {
            "device_profile": {
                "os_type": "Windows",
                "os_version": "Windows 11",
                "is_domain_joined": True,
                "hostname_pattern": "WS"
            },
            "technical_indicators": {
                "open_ports": [3389, 8888, 6006],
                "running_services": [
                    "Remote Desktop Services",
                    "Jupyter Server",
                    "TensorBoard",
                    "Python Service Host"
                ],
                "installed_roles": [],
                "installed_software": [
                    "Python",
                    "R",
                    "JupyterLab",
                    "TensorFlow",
                    "Anaconda"
                ]
            },
            "business_context": {
                "department": "Operations",
                "business_function": "End User Computing",
                "criticality": "Medium"
            },
            "indicator_based_role_detection": {
                "detected_roles": [
                    "Data Scientist Workstation"
                ],
                "confidence": "Very High"
            },
            "ml_role_prediction": {
                "predicted_roles": [
                    "Data Scientist Workstation"
                ],
                "confidence": "0.6833"
            },
            "rag_based_role_detection": {
                "detected_role": "",
                "confidence": ""
            },
            "selected_role": {
                "role": "Data Scientist Workstation",
                "method": "indicator"
            }
        }
    }
}


def run_nmap(subnet: str) -> str:
    print(f"[+] Running nmap on {subnet}")
    result = subprocess.run(
        ["docker", "exec", SCANNER_CONTAINER, "nmap", "-sn", subnet],
        capture_output=True,
        text=True,
        check=False
    )

    if result.stderr.strip():
        print("[!] STDERR:")
        print(result.stderr)

    print("----- RAW NMAP OUTPUT -----")
    print(result.stdout)
    print("---------------------------")
    return result.stdout


def parse_nmap(output: str) -> list[str]:
    hosts = []
    for line in output.splitlines():
        if "Nmap scan report for" in line:
            ip = line.split()[-1].replace("(", "").replace(")", "")
            print(f"[+] Found host: {ip}")
            hosts.append(ip)
    return hosts


def build_asset(ip: str) -> dict | None:
    host = HOST_DETAILS.get(ip)
    if not host:
        print(f"[!] Skipping non-asset IP: {ip}")
        return None

    return {
        "hostname": host["hostname"],
        "role": host["role"],
        "operating_system": host["operating_system"],
        "location": {
            "name": host["location_name"],
            "ip_address": ip
        },
        "cia_rating": {
            "criticality": host["criticality"]
        },
        "status": "Active",
        "detail": host["detail"]
    }


def main():
    result = {
        "meta": {
            "year": 2026,
            "name": "Asset Inventory & CIA",
            "submitted": False,
            "read_only": False
        },
        "network_mask": None,
        "subnets": []
    }

    for subnet_name, subnet_info in SUBNETS.items():
        cidr = subnet_info["cidr"]
        gateway = subnet_info["gateway"]

        output = run_nmap(cidr)
        ips = parse_nmap(output)

        assets = []
        for ip in ips:
            asset = build_asset(ip)
            if asset is not None and HOST_DETAILS[ip]["subnet"] == subnet_name:
                assets.append(asset)

        print(f"[+] Total assets in {subnet_name}: {len(assets)}")

        subnet_entry = {
            "id": subnet_name,
            "subnet_mask": gateway,
            "location": {
                "name": gateway,
                "ip_range": gateway
            },
            "assets": assets
        }

        result["subnets"].append(subnet_entry)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    print(f"[✓] AssetInventory.json generated at: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()