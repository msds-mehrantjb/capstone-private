# Capstone

Agent-based ISO 27001 audit and risk assessment for Windows-based environments, using a local FastAPI backend, a React/Vite frontend, local retrieval pipelines, and local LLM inference.

This repository supports an end-to-end audit workflow that starts with scope definition and continues through:

- Asset Inventory & CIA
- Threats & Vulnerabilities
- Existing Controls & Postures
- Risk Analysis
- Risk Evaluation / Treatment
- Annex A & SoA
- Action Plan / Implementation
- Monitoring & Improvement
- Final Deliverables
- AI/ML Dashboard

The project is designed to run locally and store working data as JSON/CSV files under the repository so the audit state remains persistent across sessions.

---

## Current Architecture

```text
React + Vite Frontend (app/src)
        |
        v
FastAPI Backend (app/api, app/main.py)
        |
        +-- Audit workflow routes
        +-- Local JSON/CSV data management
        +-- RAG / Chroma integration
        +-- Local Ollama-based generation
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

---

## Main Technology Stack

- Frontend: React 19 + Vite 7 + TypeScript
- Backend: FastAPI + Uvicorn
- ML/Data: pandas, scikit-learn, joblib, pyarrow
- Local vector store: ChromaDB
- Orchestration / agent tooling: LangGraph, LangChain Community
- Local LLM runtime: Ollama
- Data storage: JSON, CSV, local files in `data/`

---

## Repository Layout

```text
Capstone-main/
├── app/
│   ├── main.py                 # FastAPI entry point
│   ├── api/                    # Backend routes and section generators
│   ├── agent/                  # Agent-related backend code
│   ├── behavior/               # User behavior collection + aggregation utilities
│   ├── rag/                    # Retrieval, embeddings, Chroma integration
│   ├── chroma_db/              # Local Chroma vector database
│   ├── src/                    # React frontend source
│   ├── package.json            # Frontend scripts and dependencies
│   └── .env                    # Local secrets / configuration
├── data/
│   ├── work/                   # Year-based working JSON files
│   ├── docs/                   # Supporting documents
│   ├── knowledge_base/         # Reference CSVs and supporting knowledge files
│   ├── ml/                     # Embedding caches and ML support files
│   ├── models/                 # Persisted model artifacts
│   ├── raw/                    # Raw source data
│   └── docker_lab/             # Local lab-related files
├── scripts/                    # Helper scripts / batch files
├── lab-scanner/                # Local lab scanning utilities
├── venv/                       # Project virtual environment
├── requirements.txt            # Python dependencies
├── AGENTS.md                   # Repo-specific coding/runtime guidance
└── README.md
```

---

## Environment Requirements

- Windows-oriented local development environment
- Python 3.11
- Project virtual environment at `venv/`
- Node/npm for the frontend
- Ollama running locally for generation/embedding features

Important:

- Use the repository virtual environment, not Conda/base Python
- Frontend environment values live in `app/.env`

---

## Python Dependencies

Python dependencies are listed in [requirements.txt](/C:/Users/mehra/Capstone-main/requirements.txt).

Core packages currently include:

- `fastapi`
- `uvicorn[standard]`
- `python-dotenv`
- `pydantic`
- `requests`
- `numpy`
- `pandas`
- `pyarrow`
- `scikit-learn`
- `joblib`
- `chromadb`
- `sentence-transformers`
- `langgraph`
- `langchain-community`
- `ollama`
- `python-multipart`
- `pyyaml`
- `python-nmap`

Frontend dependencies are defined in [app/package.json](/C:/Users/mehra/Capstone-main/app/package.json).

---

## Setup

### 1. Activate the project virtual environment

```powershell
.\venv\Scripts\Activate.ps1
```

### 2. Install backend dependencies if needed

```powershell
.\venv\Scripts\python.exe -m pip install -r requirements.txt
```

### 3. Install frontend dependencies if needed

```powershell
cd app
npm install
cd ..
```

### 4. Make sure Ollama is available locally

The backend routes that use generation or embeddings expect a local Ollama service. By default, the code uses:

- `http://localhost:11434/api/generate`
- `http://localhost:11434/api/embeddings`

If your setup differs, update `app/.env` accordingly.

---

## Running the Project

### Backend

Run from the repository root:

```powershell
.\venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

Then open:

- [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

### Frontend

Run from the `app` folder:

```powershell
cd app
npm run dev
```

Then open the Vite URL shown in the terminal, typically:

- [http://127.0.0.1:5173](http://127.0.0.1:5173)

---

## Data Model Notes

This project stores most workflow state as local JSON files under:

- `data/work/<year>/`

Common files in the yearly work folder include:

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

Supporting sources are stored in:

- `data/knowledge_base/`
- `data/ml/`
- `data/models/`

---

## Behavior Data Collection

User behavior monitoring support lives under:

- [app/behavior](/C:/Users/mehra/Capstone-main/app/behavior)

This includes:

- workstation behavior agent artifacts
- aggregation logic for `UserBehaviorActivity.json`
- supporting documentation for the behavior agent

The central aggregation path feeds Risk Analysis and AI/ML telemetry workflows.

---

## Frontend Build

To produce a production frontend build:

```powershell
cd app
npm run build
```

Output is written to:

- `app/dist/`

---

## Verification Checklist

After startup, verify:

1. Backend responds at `/docs`
2. Frontend Vite app loads
3. Required local data folders exist:
   - `data/work`
   - `data/knowledge_base`
   - `data/ml`
   - `data/models`
   - `app/chroma_db`
4. Ollama is available if you are using:
   - recommendation flows
   - evidence auto-fill
   - guide generation
   - AI/ML snapshot generation
   - RAG-backed commands

---

## Notes

- The project is intentionally file-driven: many workflow pages read and write local JSON directly through the backend routes.
- Some pages depend on earlier workflow stages being completed enough to create downstream JSON files.
- Docker lab actions are local-only unless you intentionally extend them.
