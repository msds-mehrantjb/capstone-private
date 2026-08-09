# Windows Setup and Startup Scripts

Helper batch files for local development and runtime.

## Recommended launcher

`run-all.bat` performs the full preflight and startup flow: Python 3.11/venv, backend dependencies, PyPI/DNS checks, Node/npm, `npm install`, Ollama/service/models, Docker Engine, port cleanup, backend health verification, and Vite startup.

## Other scripts

- `run-backend.bat` — backend-only launcher.
- `run-frontend.bat` — frontend-only launcher.
- `setup-project.bat` — manual/legacy first-time setup helper.
- `check-env.bat` — environment validation.

For normal use, run `run-all.bat` from the repository root.
