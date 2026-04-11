import json
import ipaddress
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
MERGED_CONFIG_PATH = BASE_DIR / "merged_lab_config.json"

def load_json(path: Path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def validate_required_top_level_keys(cfg: dict, errors: list):
    required = ["lab_name", "year", "public_gateway_ip", "private_range", "subnets"]
    for key in required:
        if key not in cfg:
            errors.append(f"Missing top-level key: {key}")

def validate_subnet(subnet: dict, errors: list, seen_hostnames: set, seen_ips: dict):
    required_subnet_keys = ["name", "cidr", "gateway_internal", "docker_network_name", "hosts"]
    for key in required_subnet_keys:
        if key not in subnet:
            errors.append(f"Subnet missing key '{key}': {subnet}")
            return

    try:
        network = ipaddress.ip_network(subnet["cidr"], strict=False)
    except ValueError as e:
        errors.append(f"Invalid subnet CIDR '{subnet['cidr']}': {e}")
        return

    try:
        gateway_ip = ipaddress.ip_address(subnet["gateway_internal"])
    except ValueError as e:
        errors.append(f"Invalid gateway IP '{subnet['gateway_internal']}': {e}")
        return

    if gateway_ip not in network:
        errors.append(f"Gateway {gateway_ip} is not inside subnet {subnet['name']} ({network})")

    for host in subnet["hosts"]:
        validate_host(host, subnet["name"], network, errors, seen_hostnames, seen_ips)

def validate_host(host: dict, subnet_name: str, network, errors: list, seen_hostnames: set, seen_ips: dict):
    required_host_keys = [
        "lab_id", "hostname", "ip_address", "nat_type", "device_type", "status",
        "role", "cia_impact", "department", "business_function", "criticality",
        "os_type", "os_version", "is_domain_joined", "hostname_pattern",
        "open_ports", "running_services", "installed_roles", "installed_software",
        "behavior_profile", "published_ports"
    ]

    for key in required_host_keys:
        if key not in host:
            errors.append(f"Host in subnet {subnet_name} missing key '{key}': {host}")
            return

    hostname = host["hostname"]
    if hostname in seen_hostnames:
        errors.append(f"Duplicate hostname found: {hostname}")
    else:
        seen_hostnames.add(hostname)

    ip_str = host["ip_address"]
    try:
        ip_addr = ipaddress.ip_address(ip_str)
    except ValueError as e:
        errors.append(f"Invalid host IP '{ip_str}' for {hostname}: {e}")
        return

    if ip_addr not in network:
        errors.append(f"Host {hostname} IP {ip_addr} is not inside subnet {subnet_name} ({network})")

    if ip_str in seen_ips:
        errors.append(f"Duplicate IP {ip_str} used by {hostname} and {seen_ips[ip_str]}")
    else:
        seen_ips[ip_str] = hostname

    for list_key in ["open_ports", "running_services", "installed_roles", "installed_software", "published_ports"]:
        if not isinstance(host[list_key], list):
            errors.append(f"{hostname}: {list_key} must be a list")

    if not isinstance(host["cia_impact"], dict):
        errors.append(f"{hostname}: cia_impact must be an object/dict")

def main():
    if not MERGED_CONFIG_PATH.exists():
        print(f"ERROR: merged config not found: {MERGED_CONFIG_PATH}")
        raise SystemExit(1)

    cfg = load_json(MERGED_CONFIG_PATH)
    errors = []
    seen_hostnames = set()
    seen_ips = {}

    validate_required_top_level_keys(cfg, errors)

    subnets = cfg.get("subnets", [])
    if not isinstance(subnets, list):
        errors.append("Top-level 'subnets' must be a list")
    else:
        for subnet in subnets:
            validate_subnet(subnet, errors, seen_hostnames, seen_ips)

    if errors:
        print("Validation failed.")
        print("-" * 60)
        for err in errors:
            print(f"[ERROR] {err}")
        print("-" * 60)
        raise SystemExit(1)

    print("Validation passed.")
    print(f"Validated file: {MERGED_CONFIG_PATH}")

if __name__ == "__main__":
    main()
