# Knowledge Base

Reference datasets used by the ISO 27001 workflow, RAG pipeline, and ML-assisted audit features. These files are treated as curated knowledge sources rather than working audit output.

## Reference datasets in this folder

- `iso27002_controls_2022.csv`
  Master reference of ISO/IEC 27002:2022 controls, including control identifiers, titles, status labels, and purpose statements.
  Usage in the ISO 27001 workflow:
  Used mainly in the Annex A & SoA, Action Plan / Implementation, and Monitoring & Improvement stages to retrieve control knowledge, justify selected controls, and support RAG-based treatment or monitoring recommendations.

- `vulnerability_name_to_controls.json`
  Reference mapping between vulnerability/CVE-oriented findings and related ISO control IDs.
  Usage in the ISO 27001 workflow:
  Helps connect technical findings from Threats & Vulnerabilities and Risk Analysis to relevant control candidates before they appear in Annex A & SoA or downstream implementation planning.

- `matched_controls_vs_risks.json`
  Stored matching output that summarizes how risk records were compared against control references.
  Usage in the ISO 27001 workflow:
  Supports traceability between evaluated risks and control selection logic, mainly for Annex A & SoA and for validating whether risk-driven control matching is working as expected.

- `matched_controls_vs_vulnerability_names.json`
  Stored matching output that summarizes how vulnerability names were compared against control references.
  Usage in the ISO 27001 workflow:
  Supports traceability from named vulnerabilities to candidate controls, helping explain how technical findings can be translated into control recommendations during the Annex A and treatment-planning steps.

- `nist_cia_server_roles_dataset.csv`
  Server-role reference dataset that maps common infrastructure roles to expected confidentiality, integrity, and availability levels.
  Usage in the ISO 27001 workflow:
  Used during Asset Inventory & CIA to infer CIA ratings for server assets based on their detected or assigned role, which then feeds Threats & Vulnerabilities, Risk Analysis, and Risk Evaluation / Treatment.

- `workstation_cia_dataset.csv`
  Workstation-role reference dataset that maps workstation types to expected confidentiality, integrity, and availability levels.
  Usage in the ISO 27001 workflow:
  Used during Asset Inventory & CIA to assign CIA ratings to workstation assets, providing the business-impact context required for later threat scoring and risk prioritization.

- `workstation_role_detection_indicators.csv`
  Workstation role-detection reference dataset containing role descriptions, typical departments, software indicators, AD-group indicators, job-title indicators, and privilege levels.
  Usage in the ISO 27001 workflow:
  Used in Asset Inventory & CIA to infer workstation roles from observed attributes, software, and identity clues before CIA assignment and later risk analysis are performed.

- `windows_software-categorized.csv`
  Categorized Windows software reference dataset that groups installed packages into application categories.
  Usage in the ISO 27001 workflow:
  Used in Asset Inventory & CIA and the RAG preparation pipeline to interpret installed software patterns, improve workstation role inference, and enrich contextual evidence about how an endpoint is used.

- `columns for servers.txt`
  Helper reference file documenting expected server and workstation feature columns such as hostname, OS family, virtualization, open ports, running services, and similar inventory fields.
  Usage in the ISO 27001 workflow:
  Used as a schema/reference aid for asset-feature preparation, especially when normalizing source data for Asset Inventory & CIA and related ML-assisted role or CIA inference logic.

## Workflow relationship

Taken together, these datasets support the workflow in this order:

- Scope & Context
  Indirect support only. The knowledge-base files do not define audit scope, but they provide reference knowledge used after the scope is approved.

- Asset Inventory & CIA
  Primary use of `nist_cia_server_roles_dataset.csv`, `workstation_cia_dataset.csv`, `workstation_role_detection_indicators.csv`, `windows_software-categorized.csv`, and `columns for servers.txt`.

- Threats & Vulnerabilities / Risk Analysis
  Uses the CIA and role outcomes produced from the reference datasets above, while vulnerability-to-control mapping files help prepare later treatment and control-selection steps.

- Risk Evaluation / Treatment
  Uses the upstream asset, threat, and risk outputs and begins relying more directly on the vulnerability/control mapping references.

- Annex A & SoA
  Primary use of `iso27002_controls_2022.csv`, `vulnerability_name_to_controls.json`, `matched_controls_vs_risks.json`, and `matched_controls_vs_vulnerability_names.json` to justify and select controls.

- Action Plan / Implementation
  Uses `iso27002_controls_2022.csv` as the control knowledge source for RAG-assisted treatment guidance and implementation-focused recommendations.

- Monitoring & Improvement
  Uses `iso27002_controls_2022.csv` as the control knowledge source for RAG-assisted monitoring guidance and continual-improvement recommendations.

## Notes

- Treat these files as reference knowledge, not as working audit records.
- When a dataset changes, rebuild or refresh any dependent embeddings, hashes, or indexes used by `app/rag/` and related backend routes.
