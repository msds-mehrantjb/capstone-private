# Frontend Pages

Page-level React components for the ISO 27001 audit workflow and supporting dashboards.

## Workflow pages

- `ScopeContext.tsx`
  Step 1 of the workflow. Defines the audit scope and context, including organizational boundaries, technical and geographic boundaries, exclusions, and stakeholders. This page establishes what the ISMS assessment covers before any asset, risk, or control work begins.

- `AssetInventoryCIA.tsx`
  Step 2 of the workflow. Builds the in-scope asset inventory, identifies host roles, and assigns CIA ratings so the audit can distinguish which systems are most important to confidentiality, integrity, and availability.

- `ThreatVulnerabilities.tsx`
  Step 3 of the workflow. Maps in-scope assets to vulnerabilities, exploit exposure, and likely threat scenarios. This is where the audit turns the inventory into an attack-surface view for formal risk assessment.

- `ControlsPostures.tsx`
  Step 4 of the workflow. Records the safeguards that already exist for each in-scope asset, including technical, operational, and configuration-based protections. This page helps the workflow measure residual risk based on the real environment instead of raw exposure alone.

- `RiskAnalysis.tsx`
  Step 5 of the workflow. Calculates and prioritizes risk by combining asset criticality, vulnerability severity, threat exposure, and supporting user-behavior or ML-driven signals. This page provides the structured risk-scoring layer required before treatment decisions are made.

- `RiskEvaluationTreatment.tsx`
  Step 6 of the workflow. Converts analyzed risk into management decisions by determining whether each risk should be accepted, monitored, or treated, and records the selected treatment direction for each finding.

- `AnnexASoA.tsx`
  Step 7 of the workflow. Builds the Annex A and Statement of Applicability view by translating evaluated risks into selected ISO 27001 / ISO 27002 controls, recording why each control is needed, and tracking implementation status.

- `ActionPlanImplementation.tsx`
  Step 8 of the workflow. Turns selected Annex A controls into operational work by tracking treatment actions, implementation status, host-level evidence, and the practical tasks required to put chosen controls into effect.

- `MonitoringImprovement.tsx`
  Step 9 of the workflow. Verifies whether implemented controls continue operating effectively over time by tracking monitoring actions, evidence, follow-up, and continual-improvement activities required by the ISMS lifecycle.

- `FinalDeliverables.tsx`
  Step 10 of the workflow. Consolidates the completed audit outputs into exportable final deliverables, including the Executive Summary, Asset Inventory, Risk Register, Risk Treatment Plan, Annex A & SoA, Action Plan / Implementation, and Monitoring & Improvement sections.

## Dashboards

- `Dashboard.tsx`
  Executive workflow overview page. Summarizes audit readiness, evidence coverage, high-risk conditions, SoA status, and the completion state of each ISO 27001 workflow step.

- `AIMLDashboard.tsx`
  AI/ML oversight page. Displays model performance, RAG and LLM activity, data provenance, confidence indicators, and human-in-the-loop metrics that support the workflow's ML-assisted asset, behavior, and risk features.

Pages communicate with the FastAPI backend through `VITE_API_BASE_URL`.
