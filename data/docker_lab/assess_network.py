import subprocess
import json
import ipaddress
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parents[2]
OUTPUT_FILE = DATA_DIR / "data" / "work" / "2026" / "DockerAssetInventory.json"

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

HOSTNAMES = {
    "10.0.0.2": "srv_01",
    "10.0.0.3": "srv_02",
    "10.0.0.10": "WS-01",
    "10.0.0.11": "ws_02",
    "10.0.0.12": "ws_03",
    "10.0.0.18": "srv_03",
    "10.0.0.19": "srv_04",
    "10.0.0.26": "ws_04",
    "10.0.0.27": "ws_05",
    "10.0.0.28": "ws_06"
}

VALID_ASSET_IPS = set(HOSTNAMES.keys())


def run_nmap(subnet: str) -> str:
    result = subprocess.run(
        ["docker", "exec", SCANNER_CONTAINER, "nmap", "-sn", subnet],
        capture_output=True,
        text=True,
        check=False
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"Failed to run nmap in container '{SCANNER_CONTAINER}' for subnet {subnet}\n"
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}"
        )

    return result.stdout


def parse_nmap(output: str) -> list[str]:
    hosts = []
    for line in output.splitlines():
        line = line.strip()
        if "Nmap scan report for" not in line:
            continue

        if "(" in line and ")" in line:
            ip = line.split("(")[-1].split(")")[0].strip()
        else:
            ip = line.split()[-1].strip()

        try:
            ipaddress.ip_address(ip)
            hosts.append(ip)
        except ValueError:
            pass

    return hosts


def build_asset(ip: str) -> dict:
    return {
        "hostname": HOSTNAMES.get(ip, ""),
        "ip_address": ip,
        "status": "Active",
        "detail": {}
    }


def main():
    result = {
        "meta": {
            "year": 2026,
            "name": "Asset Inventory & CIA",
            "submitted": False,
            "read_only": False
        },
        "subnets": []
    }

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    for subnet_name, subnet_info in SUBNETS.items():
        cidr = subnet_info["cidr"]
        gateway = subnet_info["gateway"]
        docker_gateway = subnet_info["docker_gateway"]

        output = run_nmap(cidr)
        ips = parse_nmap(output)

        assets = []
        for ip in ips:
            if ip in {gateway, docker_gateway}:
                continue

            if ip not in VALID_ASSET_IPS:
                continue

            assets.append(build_asset(ip))

        assets = sorted(
            assets,
            key=lambda x: ipaddress.ip_address(x["ip_address"])
        )

        subnet_entry = {
            "id": subnet_name,
            "subnet_mask": cidr,
            "location": {
                "name": gateway,
                "ip_range": cidr
            },
            "assets": assets
        }

        result["subnets"].append(subnet_entry)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    print(f"[✓] AssetInventory.json generated at: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()