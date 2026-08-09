# Frontend Pages

Page-level React components for the audit lifecycle and dashboards.

## Workflow pages

- `ScopeContext.tsx`
- `AssetInventoryCIA.tsx`
- `ThreatVulnerabilities.tsx`
- `ControlsPostures.tsx`
- `RiskAnalysis.tsx`
- `RiskEvaluationTreatment.tsx`
- `AnnexASoA.tsx`
- `ActionPlanImplementation.tsx`
- `MonitoringImprovement.tsx`
- `FinalDeliverables.tsx`

## Dashboards

- `Dashboard.tsx` — audit readiness overview.
- `AIMLDashboard.tsx` — model/RAG/LLM/data quality metrics.

Pages communicate with the FastAPI backend through `VITE_API_BASE_URL`.
