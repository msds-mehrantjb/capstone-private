# ISO 27001 Audit Readiness Platform

AI-assisted ISO 27001 audit readiness platform for managing scope, assets, risks, controls, monitoring, evidence, AI/ML metrics, and final compliance deliverables.

The application provides an end-to-end ISO/IEC 27001:2022 audit workflow with a React/Vite frontend, FastAPI backend, local RAG pipelines, local LLM inference through Ollama, and persistent JSON/CSV working data.

## Dashboard Preview

![ISO 27001 Audit Readiness Dashboard](docs/images/iso27001-dashboard.jpg)

## Audit Lifecycle

The platform supports the following workflow:

1. Scope & Context
2. Asset Inventory & CIA
3. Threats & Vulnerabilities
4. Existing Controls & Posture
5. Risk Analysis
6. Risk Evaluation / Treatment
7. Annex A & SoA
8. Action Plan / Implementation
9. Monitoring & Improvement
10. Final Deliverables

It also includes an **AI/ML Performance Dashboard** for model, RAG, LLM, dataset, and trust/reliability metrics.

## Key Capabilities

- ISO 27001 audit lifecycle tracking and readiness dashboard
- Asset inventory, CIA classification, and infrastructure assessment
- Threat and vulnerability analysis
- Existing-control and security-posture review
- Risk analysis and treatment workflows
- Annex A applicability and Statement of Applicability support
- Action-plan implementation tracking
- Monitoring, improvement, and evidence management
- Final audit deliverables and PDF export
- Local AI assistant with command-driven workflow support
- RAG-backed recommendations using a local vector database
- Local Ollama-based LLM inference
- AI/ML performance and dataset provenance dashboard
- Optional Docker Compose simulated network lab

## Architecture

```text
React + Vite Frontend (app/src)
        |
        v
FastAPI Backend (app/api, app/main.py)
        |
        +-- ISO 27001 workflow routes
        +-- Local JSON/CSV data management
        +-- RAG / Chroma integration
        +-- Ollama generation and embeddings
        +-- ML training / KPI telemetry
        |
        v
Repository Data Store
  - data/work
  - data/knowledge_base
  - data/ml
  - data/models
  - app/chroma_db (runtime-generated local vector store)
```

## Technology Stack

- **Frontend:** React 19, TypeScript, Vite 7, Tailwind CSS
- **Backend:** FastAPI, Uvicorn, Python 3.11
- **ML / Data:** pandas, scikit-learn, joblib, pyarrow
- **Vector Store:** ChromaDB
- **RAG / Agent Tooling:** LangGraph, LangChain Community
- **Local LLM Runtime:** Ollama
- **Storage:** JSON, CSV, and local repository files
- **Lab / Scanning:** Docker Desktop / Docker Compose, Nmap, WinRM

## Repository Layout

```text
capstone-private/
├── .github/                     # GitHub automation and workflow configuration
├── app/
│   ├── main.py                 # FastAPI entry point
│   ├── api/                    # Backend routes and workflow generators
│   ├── agent/                  # Agent-related backend code
│   ├── behavior/               # User behavior collection / aggregation
│   ├── rag/                    # Retrieval, embeddings, Chroma integration
│   ├── chroma_db/              # Runtime-generated local Chroma storage; not application source
│   ├── src/                    # React frontend source
│   ├── package.json            # Frontend dependencies and scripts
│   └── .env                    # Local runtime configuration; created if missing
├── data/
│   ├── work/                   # Year-based working JSON and evidence files
│   ├── docs/                   # Supporting project and design documents
│   ├── knowledge_base/         # Reference knowledge sources
│   ├── ml/                     # ML datasets, scripts, and model artifacts
│   ├── models/                 # Persisted embedding/model artifacts
│   ├── raw/                    # Raw/sample input data
│   └── docker_lab/             # Optional simulated network lab containers
├── docs/
│   └── images/                 # README / documentation images
├── scripts/
│   ├── run-all.bat             # Recommended Windows startup launcher
│   ├── run-backend.bat         # Backend-only launcher
│   ├── run-frontend.bat        # Frontend-only launcher
│   └── setup-project.bat       # Manual/legacy setup helper
├── lab-scanner/                # Local network scanning utilities
├── requirements.txt            # Python dependencies
├── AGENTS.md                   # Repository-specific guidance
└── README.md
```

## Folder Documentation

Every tracked project folder and subfolder contains its own `README.md` describing that directory's purpose, important files, dependencies, and any generated-data cautions.

Useful starting points:

- [`app/README.md`](app/README.md) — application overview
- [`app/api/README.md`](app/api/README.md) — FastAPI route layer
- [`app/api/sections/README.md`](app/api/sections/README.md) — Final Deliverables section builders
- [`app/agent/README.md`](app/agent/README.md) — agent runtime and collection flow
- [`app/behavior/Agent/README.md`](app/behavior/Agent/README.md) — behavior collection and aggregation
- [`app/rag/README.md`](app/rag/README.md) — RAG and Chroma integration
- [`app/src/README.md`](app/src/README.md) — React frontend source
- [`app/src/pages/README.md`](app/src/pages/README.md) — workflow page components
- [`data/README.md`](data/README.md) — data hierarchy
- [`data/knowledge_base/README.md`](data/knowledge_base/README.md) — reference datasets
- [`data/ml/README.md`](data/ml/README.md) — ML datasets/training utilities
- [`data/work/README.md`](data/work/README.md) — year-based working audit state
- [`data/docker_lab/README.md`](data/docker_lab/README.md) — Docker network lab
- [`lab-scanner/README.md`](lab-scanner/README.md) — scanner workflow
- [`scripts/README.md`](scripts/README.md) — startup/setup helper scripts
- [`docs/README.md`](docs/README.md) — documentation assets

Generated or runtime-oriented folders also contain README files that explain when their contents should **not** be manually edited.

## Windows Requirements

The recommended `scripts\run-all.bat` launcher expects:

- **Windows 10/11**
- **Git** for cloning and updating the repository
- **Python 3.11** or the Python launcher with Python 3.11 available
- **Node.js + npm**
- **Ollama** available in `PATH`
- **Docker Desktop / Docker CLI**
- **Internet/DNS access** for first-time Python, npm, and Ollama model downloads

Additional lab/scanning workflows may require:

- **Nmap**
- **WinRM-enabled Windows lab hosts**

### What the startup script installs or configures automatically

`run-all.bat` is the authoritative startup workflow and performs these checks in order:

1. Verifies Python 3.11.
2. Creates `venv\` if it does not exist.
3. Checks backend Python imports and installs `requirements.txt` when dependencies are missing.
4. Checks DNS and HTTPS access to PyPI before attempting a Python dependency install.
5. Creates `app\.env` with local defaults if it is missing.
6. Verifies Node.js and npm.
7. If Node.js is missing and `winget` is available, offers to install the current Node.js LTS release.
8. Runs `npm install --no-audit --no-fund` to synchronize frontend dependencies.
9. Verifies Ollama is installed and starts `ollama serve` when Ollama is not responding.
10. Verifies the required Ollama models and downloads missing models automatically.
11. Verifies Docker CLI/Engine and starts Docker Desktop when the engine is not responding.
12. Stops existing development servers listening on ports `8002` and `5174`.
13. Performs a backend import preflight.
14. Starts FastAPI on port `8002`.
15. Waits for `/health` to succeed.
16. Starts Vite on port `5174` with `VITE_API_BASE_URL=http://127.0.0.1:8002`.

The script **does not install Python, Ollama, or Docker Desktop automatically**. It reports what is missing and stops. Node.js is the exception: when `winget` is available, the launcher can offer to install Node.js LTS.

## Ollama

The application currently expects these local models:

```text
qwen3:14b
nomic-embed-text
```

The startup script checks both models and automatically runs `ollama pull` if either is missing.

You can also install or verify them manually:

```powershell
ollama pull qwen3:14b
ollama pull nomic-embed-text
ollama list
```

Ollama should respond locally at:

```text
http://127.0.0.1:11434
```

## Environment Configuration

The launcher creates `app\.env` if it does not already exist. Its local defaults are equivalent to:

```env
OLLAMA_URL=http://127.0.0.1:11434/api/generate
OLLAMA_MODEL=qwen3:14b
OLLAMA_EMBED_URL=http://127.0.0.1:11434/api/embeddings
OLLAMA_EMBED_MODEL=nomic-embed-text
VITE_API_BASE_URL=http://127.0.0.1:8002
```

If `app\.env` already exists but does not contain `VITE_API_BASE_URL`, the launcher appends the backend URL automatically.

Do not commit secrets or machine-specific credentials to `app\.env`.

## Quick Start

Clone the repository, open PowerShell or Command Prompt in the repository root, and run:

```powershell
.\scripts\run-all.bat
```

For a normal first run, **you do not need to run `setup-project.bat` first**. `run-all.bat` creates the virtual environment and synchronizes backend/frontend dependencies as needed.

The first run can take several minutes because Python packages, npm packages, or Ollama models may need to be downloaded.

### Application URLs

After startup succeeds:

- **Frontend:** `http://localhost:5174`
- **Backend:** `http://127.0.0.1:8002`
- **FastAPI Docs:** `http://127.0.0.1:8002/docs`
- **Backend Health:** `http://127.0.0.1:8002/health`
- **Ollama:** `http://127.0.0.1:11434`

The launcher opens separate **Capstone Backend** and **Capstone Frontend** terminal windows and waits for the backend health check before starting the frontend.

## Start Components Separately

For troubleshooting or development, the existing helper scripts can start components separately.

Backend:

```powershell
.\scripts\run-backend.bat
```

Frontend:

```powershell
.\scripts\run-frontend.bat
```

When starting the frontend separately, make sure `app\.env` already contains:

```env
VITE_API_BASE_URL=http://127.0.0.1:8002
```

Also start the backend first if the frontend workflow needs API access. The standalone frontend helper does not perform the full dependency, Ollama, Docker, or backend-health preflight performed by `run-all.bat`.

For the fully validated environment, prefer `run-all.bat`.

## Docker Desktop and Docker Lab

The current `run-all.bat` launcher **requires the Docker CLI and a running Docker Engine**. If Docker Desktop is installed but the engine is stopped, the launcher attempts to start Docker Desktop and waits for the engine to become ready.

This Docker requirement is part of the current startup preflight. However, the simulated lab containers themselves remain optional.

The launcher **does not automatically run** `docker compose up` for the lab.

The optional lab is located under:

```text
data/docker_lab/
```

Start it manually when needed:

```powershell
cd data\docker_lab
docker compose up -d --build
```

Stop the lab with:

```powershell
docker compose down
```

## Working Data

Most audit workflow state is stored under:

```text
data/work/<year>/
```

Common files include:

- `SystemStatus.json`
- `AssetInventory.json`
- `AssetVulnerabilitiesThreats.json`
- `RiskAnalysis.json`
- `RiskEvaluationTreatment.json`
- `AnnexA_SoA.json`
- `ActionPlanImplementation.json`
- `MonitoringImprovement.json`
- `ActionImplementationGuides.json`
- `MonitoringImplementationGuides.json`
- `AIMLKPIInputs.json`
- `AIMLDashboard.json`

Supporting knowledge and model artifacts are stored under:

- `data/knowledge_base/`
- `data/ml/`
- `data/models/`
- `app/chroma_db/` when local Chroma persistence is created at runtime

Do not manually edit generated Chroma/HNSW index internals unless you are intentionally rebuilding or repairing the local vector store.

## Network / Scanner Notes

The lab scanner uses repository-relative paths for its configuration and generated asset inventory, so the repository can be moved without relying on an old hard-coded workspace path.

Scanner-related functionality can additionally depend on:

- Nmap
- WinRM connectivity and credentials
- The configured lab/network targets

Docker lab startup and scanner execution are separate from launching the main web application.

## Frontend Production Build

```powershell
cd app
npm run build
```

The production frontend is written to:

```text
app/dist/
```

## Troubleshooting

### `pip` cannot reach PyPI / `getaddrinfo failed`

The launcher checks DNS resolution for `pypi.org`, flushes the Windows DNS cache once, and retries. If DNS still fails, it stops instead of waiting through long pip retries.

Useful PowerShell diagnostics:

```powershell
Resolve-DnsName pypi.org
nslookup pypi.org
Test-NetConnection pypi.org -Port 443
```

Also check VPN, proxy, firewall, DNS filtering, or outbound HTTPS restrictions.

### `npm` is not recognized

Run the launcher again. If Node.js is missing and `winget` is available, it will offer to install Node.js LTS. After a new Node installation, you may need to close the terminal and open a new one so the updated `PATH` is visible.

### Ollama is installed but not responding

Try:

```powershell
ollama list
ollama serve
```

The launcher uses `ollama list` as its primary readiness check and also checks the local API.

### Docker Engine is not responding

Open Docker Desktop and wait until the engine is running, then execute:

```powershell
.\scripts\run-all.bat
```

### Backend does not become healthy

Check the **Capstone Backend** terminal window. You can also run the import preflight manually:

```powershell
.\venv\Scripts\python.exe -c "from app.main import app"
```

Then verify:

```text
http://127.0.0.1:8002/health
```

## Verification Checklist

After startup, verify:

1. Ollama responds at `127.0.0.1:11434`.
2. `qwen3:14b` and `nomic-embed-text` are installed.
3. Docker Engine is running.
4. FastAPI health succeeds at `http://127.0.0.1:8002/health`.
5. FastAPI documentation opens at `http://127.0.0.1:8002/docs`.
6. The Vite frontend loads at `http://localhost:5174`.
7. Required `data/` directories are available.
8. Runtime Chroma storage is created when RAG workflows require it.
9. Workflow pages can read and write the current audit state.

## Notes

- The platform is local-first and file-driven.
- Several workflow stages depend on data produced by earlier lifecycle stages.
- Ollama is required for local AI/RAG-assisted functionality.
- The current full startup launcher requires Docker Desktop/Engine, but Docker lab containers are only started when explicitly requested.
- Runtime/generated data should not be treated as application source code.
- Folder-level README files are the preferred place for detailed subsystem-specific notes.
- `run-all.bat` is the recommended source of truth for local Windows startup behavior.
