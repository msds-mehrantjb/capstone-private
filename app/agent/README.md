# Agent Runtime

Agent-side orchestration used for system/environment discovery and event-driven collection.

## Files and subfolders

- `graph.py` — agent workflow/graph definition.
- `runtime.py` — runtime coordination.
- `events.py` — event definitions/handling.
- `core/` — core runner logic.
- `collectors/` — environment-specific collectors.
- `utils/` — shared execution helpers.

This code is separate from the page-specific FastAPI route logic under `app/api/`.
