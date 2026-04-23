# `app/api`

This folder contains the FastAPI route modules for the Capstone application.

It is the backend API layer that connects the frontend pages to:

- working JSON data in `data/work/2026`
- local RAG and Chroma retrieval flows
- local AI/ML telemetry and dashboard snapshot logic
- Final Deliverables section generation
- supporting environment and system-status services

## Structure

- `routes_dashboard.py`  
  ISO 27001 dashboard metrics, readiness logic, and start-new-audit reset flow.

- `routes_scope.py` and `routes_scope_agent.py`  
  Scope & Context loading, versioning, and assistant command behavior.

- `routes_assets_inventory.py`  
  Asset Inventory & CIA APIs, exploration flow, role assignment, CIA handling, and ML role model integration.

- `routes_threat_vulnerabilities.py`  
  Threat and vulnerability assessment APIs.

- `routes_controls_postures.py`  
  Existing Controls & Postures APIs.

- `routes_risk_analysis.py`  
  Risk analysis APIs, user behavior analysis, model training, and behavior collection command support.

- `routes_risk_evaluation_treatment.py`  
  Evaluation and treatment APIs, treatment persistence, and downstream file rebuild logic.

- `routes_annex_a_soa.py`  
  Annex A and Statement of Applicability APIs, recommendation flows, and control-add logic.

- `routes_action_plan_implementation.py`  
  Action plan generation, evidence flows, evidence-all logic, and implementation guide creation.

- `routes_monitoring_improvement.py`  
  Monitoring and improvement actions, recommendations, evidence flows, and monitoring guide creation.

- `routes_final_deliverables.py`  
  Final Deliverables API and export support.

- `routes_aiml_dashboard.py`  
  AI/ML dashboard snapshot generation, KPI computation, and KPI fallback logic.

- `routes_rag.py`  
  Retrieval-related helper endpoints used by RAG-backed features.

- `routes_system_status.py`  
  System status helper APIs.

- `routes_events.py`  
  Event-oriented helper APIs.

- `routes_health.py`  
  Health-check endpoint(s).

- `routes_agent.py`  
  Agent/helper routes used by supporting backend workflows.

- `aiml_kpi_telemetry.py`  
  Shared helpers for recording and normalizing AI/ML KPI telemetry.

- `sections/`  
  Final Deliverables section renderers used by the deliverables backend.

## How this folder is used

Each major frontend page in `app/src/pages` typically has a matching backend route module here.

Most route modules:

- load a working file from `data/work/2026`
- validate or normalize the data
- update JSON state
- return a response that keeps the frontend table, assistant panel, and dashboard in sync

Some route modules also:

- call local LLM/RAG helpers
- rebuild downstream workflow files
- generate evidence-linked guides
- update AI/ML KPI telemetry

## Notes

- These files are tightly connected to the current JSON structures in `data/work/2026`.
- Many submit/reset/rebuild flows update more than one file, so changes here should be made carefully.
- Final Deliverables text generation and guide/PDF behavior rely on this folder together with `api/sections`.
