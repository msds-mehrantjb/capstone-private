# Capstone project guidance

## Project root
The project root is `Capstone-main`.

## Runtime layout
- Backend runs from the project root:
  - `python -m uvicorn app.main:app --reload`
- Frontend runs from the `app` subfolder:
  - `cd app && npm run dev`

## Environment requirements
- Always use Python 3.11
- Always activate the repo virtual environment at `venv/`
- Do not use Conda/base Python for project tasks
- Frontend uses Node/npm from `app/package.json`
- Secrets are stored in `app/.env`

## Important folders
- Backend code: `app/`
- Frontend code: `app/src`
- API routes: `app/api`
- Agent code: `app/agent`
- RAG code: `app/rag`
- Data: `data/`
- Vector DB: `chroma_iso27002/`

## Constraints
- Do not rename or move project data files unless explicitly requested
- Treat Docker lab steps as local-only unless explicitly requested
- Preserve current import structure unless explicitly requested to refactor

## Verification steps
- Backend: open `/docs` after startup
- Frontend: verify the Vite app loads after `npm run dev`