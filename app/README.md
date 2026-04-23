# `app`

This folder contains the application code for the Capstone project.

It includes:

- the React + TypeScript frontend
- the FastAPI backend entrypoint used from the repo root
- API routes for each ISO 27001 workflow page
- local RAG and AI/ML support code
- behavior collection and aggregation utilities

## Main parts

- `src/`  
  Frontend application code. The page components live in `src/pages`.

- `api/`  
  Backend route modules for the dashboard, workflow pages, AI/ML dashboard, Final Deliverables, and helper APIs.

- `api/sections/`  
  Final Deliverables section builders used to generate tab content and export-ready output.

- `rag/`  
  Local retrieval helpers and Chroma client logic used by recommendation and grounding flows.

- `behavior/`  
  User behavior collection and aggregation logic, including the workstation behavior agent scripts and the central aggregation script.

- `agent/`  
  Supporting collectors and agent-side utilities used by the environment discovery workflow.

- `chroma_db/`  
  Local Chroma vector database storage used by RAG-backed features.

- `main.py`  
  Frontend-side app module file in this folder layout. The backend server is started from the repo root with `app.main:app`.

## Frontend development

Run from this folder:

```powershell
npm install
npm run dev
```

Build the frontend:

```powershell
npm run build
```

## Backend development

Do not start the backend from this folder directly.

Start it from the repository root with the project virtual environment:

```powershell
venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

## What this app implements

The frontend and backend together support the full ISO 27001 workflow used in this project, including:

- Scope & Context
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

## Notes

- `dist/` is generated frontend build output.
- `node_modules/` is local dependency installation output.
- `__pycache__/` and `.ipynb_checkpoints/` are generated caches and not part of the application design.
- Most application state is not stored in this folder. Working audit data lives under `data/work/2026`.
