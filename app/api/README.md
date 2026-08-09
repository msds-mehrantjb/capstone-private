# FastAPI Routes

Backend API layer for the ISO 27001 audit workflow.

## Responsibilities

Route modules expose endpoints for:

- Scope & Context
- Asset Inventory & CIA
- Threats & Vulnerabilities
- Existing Controls & Posture
- Risk Analysis
- Risk Evaluation / Treatment
- Annex A & SoA
- Action Plan / Implementation
- Monitoring & Improvement
- Final Deliverables
- Dashboard and AI/ML Dashboard
- RAG, health, system status, and agent support

`aiml_kpi_telemetry.py` supports AI/ML KPI collection. `sections/` contains Final Deliverables section builders.

The application registers these routers from `app/main.py`.
