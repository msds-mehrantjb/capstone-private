# Scanner Scripts

Network and Windows-host collection scripts used by the lab scanner.

- `scanner.py` — host discovery, Nmap port/service collection, WinRM inventory collection, and `AssetInventory.json` generation.
- `ControslPosturesScanner.py` — control/posture-oriented collection logic.

Scripts use repository-relative data/config paths. Nmap and reachable WinRM endpoints are required for applicable scans.
