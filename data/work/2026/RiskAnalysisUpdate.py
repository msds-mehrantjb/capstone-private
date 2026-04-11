import json
from pathlib import Path

INPUT_FILE = Path(r"C:\Users\mehra\Capstone-main\data\work\2026\RiskAnalysis.json")
OUTPUT_FILE = Path(r"C:\Users\mehra\Capstone-main\data\work\2026\RiskAnalysis_updated.json")

SERVER_USER_BEHAVIOR = {}

WORKSTATION_USER_BEHAVIOR = {
    "failedLoginAttempts": 0,
    "accessFrequency": 0.0,
    "loginConsistency": 0.0,
    "passwordResets": 0,
    "sessionDuration": 0.0,
    "behaviorRiskScore": 0.0,
    "likelihood": ""
}


def is_workstation(record: dict) -> bool:
    hostname = str(record.get("hostname", "")).upper()
    role = str(record.get("role", "")).lower()
    return hostname.startswith("WS-") or "workstation" in role


def transform_record(record: dict) -> dict:
    updated = dict(record)

    if "ml_probability" in updated:
        del updated["ml_probability"]

    if is_workstation(updated):
        updated["user_behavior"] = dict(WORKSTATION_USER_BEHAVIOR)
    else:
        updated["user_behavior"] = dict(SERVER_USER_BEHAVIOR)

    return updated


def create_behavior_record(sample_record: dict) -> dict:
    return {
        "hostname": sample_record.get("hostname", "WS-XX"),
        "ip_address": sample_record.get("ip_address", ""),
        "role": "User Workstation",
        "CIA rating": sample_record.get("CIA rating", ""),
        "vulnerability_name": "User Activity Behavior - Vulnerability",
        "severity": "High",
        "cvss_score": 0,
        "exploit_available": False,
        "patch_status": 0,
        "cve": "",
        "open_ports": [],
        "override": 0,
        "likelihood": "",
        "risk": sample_record.get("risk", ""),
        "likelihood_score": 0.0,
        "risk_score": 0.0,
        "exposure": "",
        "user_behavior": dict(WORKSTATION_USER_BEHAVIOR)
    }


def main() -> None:
    if not INPUT_FILE.exists():
        raise FileNotFoundError(f"Input file not found: {INPUT_FILE}")

    with INPUT_FILE.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if "hosts" not in data or not isinstance(data["hosts"], list):
        raise ValueError("Invalid JSON format: expected a top-level 'hosts' list.")

    original_hosts = data["hosts"]

    # Step 1: Transform existing records
    transformed_hosts = [transform_record(record) for record in original_hosts]

    # Step 2: Find unique workstations
    workstation_map = {}
    for record in original_hosts:
        if is_workstation(record):
            hostname = record.get("hostname")
            if hostname not in workstation_map:
                workstation_map[hostname] = record

    # Step 3: Check existing behavior records (avoid duplicates)
    existing_behavior_hosts = {
        r.get("hostname")
        for r in original_hosts
        if r.get("vulnerability_name") == "User Activity Behavior - Vulnerability"
    }

    # Step 4: Add one new record per workstation
    new_records = []
    for hostname, sample_record in workstation_map.items():
        if hostname not in existing_behavior_hosts:
            new_records.append(create_behavior_record(sample_record))

    # Step 5: Combine
    data["hosts"] = transformed_hosts + new_records

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_FILE.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    print("Done.")
    print(f"Input file : {INPUT_FILE}")
    print(f"Output file: {OUTPUT_FILE}")
    print(f"Original records: {len(original_hosts)}")
    print(f"Added behavior records: {len(new_records)}")
    print(f"Final records: {len(data['hosts'])}")


if __name__ == "__main__":
    main()