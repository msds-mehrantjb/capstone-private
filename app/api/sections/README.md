# Final Deliverables Section Builders

Section-generation modules used by the Final Deliverables backend. Each builder transforms working audit data into a preview-ready and export-ready report section.

## Current builders

- `executive_summary.py`
  Builds the management-facing summary of the audit, including scope details, overall posture, major findings, risk distribution, and key recommendations.

- `asset_inventory.py`
  Builds the asset inventory section, including in-scope hosts, roles, operating systems, CIA ratings, business context, subnet grouping, and ML-assisted role-detection results.

- `risk_register.py`
  Builds the consolidated risk register and supporting risk-analysis view, including vulnerabilities, exploitability, likelihood, impact, risk values, and the model-driven risk methodology.

- `risk_treatment_plan.py`
  Builds the risk treatment plan section, showing how identified risks are handled through mitigation, monitoring, acceptance, or other treatment decisions.

- `annex_a_soa.py`
  Builds the Annex A / Statement of Applicability section, mapping selected ISO/IEC 27001 controls to the identified risks, implementation status, and control justifications.

- `action_plan_implementation.py`
  Builds the Action Plan / Implementation section, including control-level treatment actions, host-level evidence, responsibilities, resources, implementation status, and artifact tracking.
  This section also supports a downloadable guide document for each evidence item, providing step-by-step instructions for creating the implementation artifact/evidence.

- `monitoring_improvement.py`
  Builds the Monitoring & Improvement section, including monitoring actions, follow-up evidence, ownership, resources, implementation status, and continual-improvement tracking.
  This section also supports a downloadable guide document for each evidence item, providing step-by-step instructions for creating the monitoring artifact/evidence.

These modules are used to generate the Final Deliverables report sections shown in the app and exported in the final report package.
