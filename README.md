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
- Optional Docker-based simulated network lab

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
  - app/chroma_db
```

## Technology Stack

- **Frontend:** React 19, TypeScript, Vite 7, Tailwind CSS
- **Backend:** FastAPI, Uvicorn, Python 3.11
- **ML / Data:** pandas, scikit-learn, joblib, pyarrow
- **Vector Store:** ChromaDB
- **RAG / Agent Tooling:** LangGraph, LangChain Community
- **Local LLM Runtime:** Ollama
- **Storage:** JSON, CSV, and local repository files
- **Optional Lab:** Docker Desktop / Docker Compose, Nmap, WinRM

## Repository Layout

```text
capstone-private/
├── app/
│   ├── main.py                 # FastAPI entry point
│   ├── api/                    # Backend routes and workflow generators
│   ├── agent/                  # Agent-related backend code
│   ├── behavior/               # User behavior collection / aggregation
│   ├── rag/                    # Retrieval, embeddings, Chroma integration
│   ├── chroma_db/              # Local Chroma vector database
│   ├── src/                    # React frontend source
│   ├── package.json            # Frontend dependencies and scripts
│   └── .env                    # Local runtime configuration
├── data/
│   ├── work/                   # Year-based working JSON files
│   ├── docs/                   # Supporting documents
│   ├── knowledge_base/         # Reference knowledge sources
│   ├── ml/                     # ML support files and caches
│   ├── models/                 # Persisted model artifacts
│   ├── raw/                    # Raw source data
│   └── docker_lab/             # Optional simulated network lab
├── docs/
│   └── images/                 # README / documentation images
├── scripts/                    # Setup and startup scripts
├── lab-scanner/                # Local network scanning utilities
├── requirements.txt            # Python dependencies
├── AGENTS.md                   # Repository-specific guidance
└── README.md
```

## Requirements

For the main application:

- Windows 10/11 development environment
- Python **3.11**
- Node.js + npm
- Ollama
- Git

Optional features additionally use:

- Docker Desktop / Docker Compose
- Nmap
- WinRM-enabled Windows lab hosts

## Ollama Models

The application currently expects:

```text
qwen3:14b
nomic-embed-text
```

Install them with:

```powershell
ollama pull qwen3:14b
ollama pull nomic-embed-text
ollama list
```

Ollama should be available locally at:

```text
http://127.0.0.1:11434
```

## First-Time Setup

From the repository root:

```powershell
cd C:\Users\mehra\capstone-private
.\scripts\setup-project.bat
```

The setup process creates the Python 3.11 virtual environment, installs Python dependencies, and installs frontend packages.

Python dependencies are defined in [`requirements.txt`](requirements.txt), and frontend dependencies are defined in [`app/package.json`](app/package.json).

## Running the Application

The recommended launcher is:

```powershell
cd C:\Users\mehra\capstone-private
.\scripts\run-all.bat
```

The startup script performs preflight checks for the local environment and starts the required application services.

### Application URLs

- **Frontend:** `http://localhost:5174`
- **Backend:** `http://127.0.0.1:8002`
- **FastAPI Docs:** `http://127.0.0.1:8002/docs`
- **Backend Health:** `http://127.0.0.1:8002/health`
- **Ollama:** `http://127.0.0.1:11434`

### Start Services Separately

Backend:

```powershell
.\scripts\run-backend.bat
```

Frontend:

```powershell
.\scripts\run-frontend.bat
```

## Docker Lab

Docker is **not required just to open the main application**. It is used for the optional simulated enterprise-network lab under:

```text
data/docker_lab/
```

Start the lab separately when required:

```powershell
cd data\docker_lab
docker compose up -d --build
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
- `app/chroma_db/`

## Frontend Production Build

```powershell
cd app
npm run build
```

The production frontend is written to:

```text
app/dist/
```

## Verification Checklist

After startup, verify:

1. Ollama responds locally.
2. `qwen3:14b` and `nomic-embed-text` are installed.
3. FastAPI health returns successfully at `/health`.
4. FastAPI documentation opens at `/docs`.
5. The Vite frontend loads on port `5174`.
6. Required `data/` and `app/chroma_db/` directories are available.
7. Workflow pages can read and write the current audit state.

## Notes

- The platform is intentionally local-first and file-driven.
- Several workflow stages depend on data produced by earlier lifecycle stages.
- Ollama is required for local AI/RAG-assisted functionality.
- Docker is optional and is only needed for the simulated lab workflow.
