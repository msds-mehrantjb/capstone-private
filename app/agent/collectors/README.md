# Agent Collectors

Environment-specific data collectors used by the agent runtime.

## Current collector

- `dc_collector.py` — Domain Controller collection wrapper.
- `dc_metadata.ps1` — PowerShell metadata collection for Windows/AD systems.

Collectors should return structured data and avoid embedding machine-specific absolute repository paths.
