# Windows Setup and Startup Scripts

Helper batch files for local setup, environment checks, and day-to-day startup of the Capstone app on Windows.

## Recommended launcher

`run-all.bat` is the primary startup script and should be used for normal local execution.

It performs the current full startup flow in this order:

1. Checks for Python 3.11 and the project virtual environment at `venv\`
2. Creates the virtual environment if it is missing
3. Verifies and installs backend dependencies from `requirements.txt` when needed
4. Checks Node.js and npm, and can prompt to install Node.js LTS with `winget`
5. Runs `npm install` in `app\` to synchronize frontend dependencies
6. Verifies Ollama is installed and running
7. Verifies the required Ollama models are available:
   - `qwen3:14b`
   - `nomic-embed-text`
8. Verifies Docker Desktop / Docker Engine is installed and running
9. Stops existing listeners on the Capstone dev ports
10. Starts the backend, verifies the `/health` endpoint, updates `app\.env`, then starts the frontend

## Current runtime ports

The latest scripts use these defaults:

- Preferred backend API port: `8003`
- Fallback backend API port: `8002`
- Frontend Vite port: `5174`
- Ollama service URL: `http://127.0.0.1:11434`

When the backend starts successfully, `run-all.bat` synchronizes:

- `VITE_API_BASE_URL` in `app\.env`

This ensures the frontend points to the correct live backend port.

## Script reference

- `run-all.bat`
  Full startup script for normal use.
  It handles environment checks, dependency installation, Ollama readiness, Docker readiness, backend startup, backend health verification, and frontend startup.

- `run-backend.bat`
  Backend-only launcher.
  Starts FastAPI with:
  - default host: `127.0.0.1`
  - default port: `8003`

  Supported environment variables:
  - `CAPSTONE_API_HOST`
  - `CAPSTONE_API_PORT`
  - `CAPSTONE_ENABLE_RELOAD`

  Notes:
  Reload is disabled by default for Windows startup stability, but can be enabled by setting `CAPSTONE_ENABLE_RELOAD=1`.

- `run-frontend.bat`
  Frontend-only launcher.
  Starts the Vite app on:
  - default port: `5174`

  Supported environment variables:
  - `CAPSTONE_FRONTEND_PORT`
  - `CAPSTONE_API_BASE_URL`
  - `CAPSTONE_API_HOST`
  - `CAPSTONE_API_PORT`

  If `CAPSTONE_API_BASE_URL` is not set, the script builds it from host and port values and passes it to Vite as `VITE_API_BASE_URL`.

- `check-env.bat`
  Quick environment validation script.
  It verifies:
  - the project virtual environment exists
  - Python 3.11 is installed inside that virtual environment
  - `app\.env` exists
  - Node.js is available
  - npm is available

  Use this when you want a simple readiness check without starting the app.

- `list-docker-lab-ips.bat`
  Lists the optional Docker lab containers with their Docker networks and IP addresses.

  Run:

  ```powershell
  scripts\list-docker-lab-ips.bat
  ```

  To also show expected lab containers that are missing or stopped before creation, run:

  ```powershell
  scripts\list-docker-lab-ips.bat -IncludeMissing
  ```

- `setup-project.bat`
  Manual first-time setup helper.
  It:
  - creates the Python 3.11 virtual environment
  - activates it
  - upgrades `pip`
  - installs Python requirements
  - runs `npm install` in `app\`

  This script is simpler than `run-all.bat` and is mainly useful for manual setup scenarios.

## Startup artifacts and logs

`run-all.bat` writes startup logs to:

- `backend_stdout.log`
- `backend_stderr.log`
- `frontend_stdout.log`
- `frontend_stderr.log`

These files are useful when the backend does not become healthy or the frontend does not start correctly.

## Docker note

`run-all.bat` starts Docker Desktop / Docker Engine when needed, but it does **not** automatically create or start the containers under:

- `data/docker_lab/`

Those Docker lab containers must still be started manually with Docker Compose when you want to use the simulated lab network.

## Recommended usage

For normal development and local app startup, run:

```powershell
scripts\run-all.bat
```

Use the other scripts only when you want a narrower action such as backend-only startup, frontend-only startup, or a standalone environment check.
