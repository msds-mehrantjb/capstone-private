# Lab Scanner

Windows and network scanning utilities used to discover live assets and collect technical indicators for the ISO 27001 audit workflow.

## Purpose in this app

The `lab-scanner` folder is the bridge between the app and real reachable lab hosts. It is used when the project needs to scan live Windows machines instead of relying only on synthetic datasets, Docker-lab assets, or static fallback records.

In this project, the scanner is especially useful as a proof-of-concept layer because it shows that the workflow can:

- discover live systems on the network
- confirm which hosts are active
- extract technical host details from real Windows machines
- infer roles and CIA impact from live evidence
- collect existing controls and posture information from real hosts

This helps demonstrate that the ISO 27001 workflow is not only using static JSON or simulated examples, but can also consume data from actual VM-based lab machines.

## Live VM proof-of-concept usage

The scanner is designed to work with live Windows VM machines that are reachable over the lab network.

In the current configuration (`lab-scanner/config/targets.json`), the proof-of-concept live targets are:

- `SRV-01` → `10.0.0.2`
- `WS-01` → `10.0.0.10`
- `WS-02` → `10.0.0.11`

These targets are configured with:

- hostname
- IP address
- Windows administrative credentials
- a shared subnet definition (`10.0.0.0/28`)

The scripts use:

- `Nmap`
  For host discovery and TCP port scanning

- `WinRM` / remote PowerShell
  For collecting Windows system, role, software, and control information from live machines

This means the VM machines act as real, reachable audit assets inside the project, allowing the app to prove that inventory and posture data can be gathered from live endpoints rather than only from predefined sample files.

## What information is extracted from the live VMs

### Asset inventory / technical profile extraction

`lab-scanner/scripts/scanner.py` performs:

- subnet host discovery with Nmap
- per-host port scanning
- WinRM-based Windows data collection

The script extracts or derives:

- host active/inactive status
- hostname
- IP address
- operating system caption / version
- OS type (`Windows` or `Windows Server`)
- domain name
- whether the machine is domain joined
- hostname pattern
- open TCP ports
- running services
- installed Windows roles/features
- installed software
- inferred device type (`Server` or `Workstation`)
- inferred business/technical role
- inferred CIA impact

The resulting inventory output is written to:

- `data/work/2026/AssetInventory.json`

### Existing controls and posture extraction

`lab-scanner/scripts/ControslPosturesScanner.py` connects to the same live targets through remote PowerShell and extracts host controls/posture evidence.

The script identifies:

- detected host role
- CIA rating
- Identity & Access Management controls
- Endpoint Security Controls
- Network Security Controls
- Logging, Monitoring & Detection controls
- Vulnerability & Patch Management controls
- Physical & Environmental Controls

Examples of live controls the script looks for include:

- password policy presence
- Active Directory Domain Services
- Group Policy Objects
- role-based access control indicators
- Windows Defender / anti-malware
- Secure Boot
- Windows Firewall
- DNS service/security indicators
- Windows Event Logging
- patch-management service presence
- physical/server-room control placeholders for server-class systems

The resulting posture output is written to:

- `data/work/2026/VMControlsPostures.json`

## How this supports the ISO 27001 workflow

The scanner feeds live-machine evidence into multiple workflow stages:

- Asset Inventory & CIA
  Supplies live host discovery, host identity, OS data, services, software, and role/CIA inference inputs.

- Threats & Vulnerabilities
  Supplies open-port and host-type context that helps explain exposure and attack surface.

- Existing Controls & Posture
  Supplies real host control evidence collected from the Windows VMs.

- Risk Analysis
  Supplies live asset context that can be combined with vulnerabilities and business criticality.

This makes the VM machines important to the app as live audit assets used to validate the end-to-end concept on actual reachable systems.

## Current scanner structure

## Subfolders

- `config/`
  Scan target configuration, including subnet and live host credential definitions.

- `scripts/`
  Nmap / WinRM scanning and control-posture collection scripts.

## Key files

- `config/targets.json`
  Defines the live VM targets, subnet, and credentials used by the scanner.

- `scripts/scanner.py`
  Discovers live hosts and collects asset inventory / technical indicator data.

- `scripts/ControslPosturesScanner.py`
  Connects to live Windows hosts and collects existing controls / posture information.

## Operational notes

- Nmap and WinRM connectivity are required.
- The target VMs must be powered on and reachable from the machine running the app.
- The configured credentials must have enough permission to query Windows system information and controls remotely.
- Scanner output feeds working audit data under `data/work/<year>/`.
