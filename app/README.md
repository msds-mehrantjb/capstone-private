# `app`

Main application package containing the FastAPI backend, React/Vite frontend, local agent code, RAG helpers, and behavior-processing utilities.

## Key areas

- `main.py` — FastAPI application entry point (`app.main:app`).
- `api/` — workflow and dashboard API routes.
- `agent/` — agent orchestration and environment collectors.
- `behavior/` — workstation behavior collection and aggregation.
- `rag/` — local retrieval/Chroma helpers.
- `src/` — React + TypeScript frontend.

## Runtime

Prefer running the full application from the repository root with:

```powershell
.\scripts\run-all.bat
```

The launcher starts FastAPI on port `8002` and Vite on port `5174` after prerequisite checks.
