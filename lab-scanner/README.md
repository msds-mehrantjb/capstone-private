# Lab Scanner

Windows/network scanning utilities used to discover assets and collect technical indicators for the audit workflow.

## Subfolders

- `config/` — scan target configuration.
- `scripts/` — Nmap/WinRM scanning and control/posture collection scripts.

Scanner output feeds working audit data under `data/work/<year>/`. Nmap and WinRM connectivity may be required.
