# Docker Network Lab

Optional Docker Compose lab used to simulate a small enterprise-style network for discovery, asset inventory, and assessment testing inside the ISO 27001 workflow.

## What this lab is used for

This lab gives the project a repeatable, local test environment when real infrastructure is not available or when the workflow needs a safe network to scan and analyze.

Typical usage in the ISO 27001 workflow:

- Asset Inventory & CIA
  The lab provides live hosts on multiple subnets so the application can discover assets, detect active systems, and build inventory data from a realistic network layout.

- Threats & Vulnerabilities
  The lab provides server and workstation targets that can be used for host-based assessment, simulated attack-surface mapping, and validation of vulnerability-discovery logic.

- Existing Controls & Posture
  The simulated hosts can be used to test how the app reads technical indicators, services, and host posture data from live lab systems.

- Risk Analysis
  The discovered assets and their host details can be passed into downstream risk logic to test scoring, prioritization, and workflow progression in a controlled environment.

In short, this lab is the project’s local enterprise-like network sandbox for testing end-to-end audit workflow behavior without requiring an external production network.

## Network architecture

The lab creates a routed two-subnet network with one gateway container connecting both segments.

### Core design

- One custom gateway container
  The `gateway` container acts as the router between both Docker bridge networks.

- Two separate Docker bridge networks
  - `subnet_a_net` → `10.0.0.0/28`
  - `subnet_b_net` → `10.0.0.16/28`

- IP forwarding between subnets
  The gateway container enables `net.ipv4.ip_forward=1` and uses forwarding/NAT rules so hosts on one subnet can reach hosts on the other subnet through the custom gateway.

### Gateway layout

- Gateway interface on Subnet A: `10.0.0.1`
- Gateway interface on Subnet B: `10.0.0.17`

Docker also reserves the bridge-network gateway addresses defined by IPAM:

- Docker gateway for Subnet A: `10.0.0.14`
- Docker gateway for Subnet B: `10.0.0.30`

### Subnet A

Network: `10.0.0.0/28`

Hosts on this subnet:

- `SRV-01` → `10.0.0.2`
- `SRV-02` → `10.0.0.3`
- `WS-01` → `10.0.0.10`
- `WS-02` → `10.0.0.11`
- `WS-03` → `10.0.0.12`

### Subnet B

Network: `10.0.0.16/28`

Hosts on this subnet:

- `SRV-03` → `10.0.0.18`
- `SRV-04` → `10.0.0.19`
- `WS-04` → `10.0.0.26`
- `WS-05` → `10.0.0.27`
- `WS-06` → `10.0.0.28`

### Topology summary

The lab represents a small routed enterprise layout:

- 2 subnets
- 1 router/gateway
- 4 server hosts
- 6 workstation hosts

This structure is useful because it lets the application test:

- same-subnet discovery
- cross-subnet routing
- per-host inventory generation
- server versus workstation handling
- multi-segment assessment logic

## How the lab is used by the project

### Compose topology

- `docker-compose.yml`
  Defines the routed lab topology, host containers, IP addresses, and subnet membership.

### Gateway image

- `gateway.Dockerfile`
- `gateway.init.sh`

These files create the router container and configure forwarding behavior between the two Docker networks.

### Host image

- `host.Dockerfile`
- `host.init.sh`

These files create the simulated endpoint/server containers and configure routing so they can communicate through the custom gateway.

### Assessment helper

- `assess_network.py`

Runs `nmap` from the scanner container `ws_01`, discovers live hosts in both subnets, filters the known lab addresses, and writes the result to:

- `data/work/2026/DockerAssetInventory.json`

This makes the lab directly useful to the Asset Inventory workflow.

### Validation

- `validate_lab.py`

Validates the lab configuration structure, subnets, gateways, host IPs, uniqueness rules, and expected host fields.

### Detailed notes

- `Network-Lab.md`

Contains the longer architecture notes, routing logic, discovery examples, and operational commands for the lab.

## Starting the lab

Start manually with:

```powershell
docker compose up -d --build
```

Stop with:

```powershell
docker compose down
```

Clean unused Docker networks with:

```powershell
docker network prune -f
```

`run-all.bat` starts Docker Desktop / Docker Engine when needed, but it does not automatically start these lab containers.

## Notes

- This lab is optional and local-only unless you intentionally use it for workflow testing.
- The lab is designed to support realistic audit testing, not to replace real production asset data.
- When the lab is running, it provides a predictable network that is especially useful for demo, validation, and troubleshooting scenarios.
