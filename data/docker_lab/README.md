# Docker Network Lab

Optional Docker Compose lab used to simulate an enterprise-like network for discovery and assessment testing.

## Key files

- `docker-compose.yml` — lab topology/services.
- `gateway.Dockerfile`, `gateway.init.sh` — gateway image/setup.
- `host.Dockerfile`, `host.init.sh` — simulated host image/setup.
- `validate_lab.py` — lab validation.
- `assess_network.py` — Docker-lab assessment helper.
- `Network-Lab.md` — detailed lab notes.

Start manually with:

```powershell
docker compose up -d --build
```

`run-all.bat` starts Docker Desktop/Engine when needed but does not start these containers.
