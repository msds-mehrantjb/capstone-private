# Knowledge Base Folder

This folder contains the reference datasets and mapping files used by the Capstone application to support:

- ISO 27001 / ISO 27002 control selection
- CIA classification
- workstation role detection
- vulnerability-to-control recommendation
- RAG-assisted reasoning and justification flows

These files are treated as supporting knowledge sources, not as year-specific working data.  
Year-specific workflow state is stored separately under `data/work/<year>/`.

---

## Purpose of This Folder

The files in this folder help the application answer questions such as:

- Which ISO 27002 controls are relevant to a risk or vulnerability?
- What CIA rating should be associated with a server or workstation role?
- Which workstation role best matches observed software and technical indicators?
- Which controls should be recommended in Annex A & SoA or monitoring flows?

In practice, these files are used by backend routes in:

- `app/api/`
- `app/rag/`
- `app/behavior/` indirectly through downstream workflow logic

---

## Files in This Folder

### `iso27002_controls_2022.csv`

Primary ISO 27002 control catalog used by the project.

Current columns:

- `Section`
- `Control`
- `Title`
- `Status`
- `Purpose`

Typical use:

- RAG retrieval for ISO 27002 controls
- Annex A & SoA recommendations
- Action Plan / Implementation evidence and guide generation
- Monitoring / Improvement recommendations and guide generation
- control lookups by control ID

---

### `vulnerability_name_to_controls.json`

Reference mapping from vulnerability names or vulnerability contexts to ISO control recommendations.

Typical use:

- fallback or supporting logic when the system wants to recommend controls based on known vulnerability patterns
- improving consistency of control selection when exact CVE-to-control mapping is limited

---

### `matched_controls_vs_risks.json`

Structured mapping between ISO controls and risk-oriented context.

Typical use:

- control recommendation support
- matching controls to risk scenarios during Annex A & SoA reasoning

This file is a compact helper map rather than a full control catalog.

---

### `matched_controls_vs_vulnerability_names.json`

Structured mapping between ISO controls and vulnerability names.

Typical use:

- vulnerability-driven control recommendation
- support for recommendation flows when the system already knows the vulnerability label but not a richer context

---

### `nist_cia_server_roles_dataset.csv`

Reference dataset for server-role CIA classification.

Current columns:

- `Server Role`
- `Confidentiality`
- `Integrity`
- `Availability`

Typical use:

- CIA rating support for server assets
- backend classification logic for infrastructure roles such as:
  - Domain Controller
  - LDAP Server
  - File Server
  - Web/Application Server

---

### `workstation_cia_dataset.csv`

Reference dataset for workstation-role CIA classification.

Current columns:

- `Workstation Role`
- `Confidentiality`
- `Integrity`
- `Availability`

Typical use:

- CIA rating support for workstation assets
- role-based impact estimation in downstream risk analysis

---

### `workstation_role_detection_indicators.csv`

Role-detection indicator dataset for workstation classification.

Current columns include:

- `role`
- `description`
- `typical_departments`
- `software_indicators`
- `ad_group_indicators`
- `job_title_indicators`
- `privilege_level`

Typical use:

- indicator-based workstation role detection in Asset Inventory & CIA
- comparison against ML-based role prediction
- support for selecting the final role shown in the asset table

---

### `windows_software-categorized.csv`

Large categorized software catalog for Windows applications.

Current columns begin with:

- `package_name`
- `version`
- `application_type`
- `Category`

Typical use:

- software normalization and categorization
- helping infer workstation role or business purpose
- supporting asset context enrichment

Because this file is relatively large, it should be updated carefully and kept in a consistent CSV structure.

---

### `columns for servers.txt`

Plain-text helper file that appears to document or list server-related fields/columns used in supporting data preparation.

Typical use:

- manual reference during dataset preparation
- internal documentation for server-related data extraction or normalization

This file is not a primary runtime source like the CSV/JSON datasets above, but it is useful as a support note.

---

## How the App Uses This Folder

At a high level:

1. Asset-related pages use CIA and role datasets to classify systems.
2. Risk and Annex pages use control-mapping files and ISO control data to recommend relevant controls.
3. Action Plan / Implementation and Monitoring / Improvement pages use ISO control retrieval to generate:
   - evidence descriptions
   - recommended actions
   - technical guides

The most central files for active runtime behavior are usually:

- `iso27002_controls_2022.csv`
- `nist_cia_server_roles_dataset.csv`
- `workstation_cia_dataset.csv`
- `workstation_role_detection_indicators.csv`
- `vulnerability_name_to_controls.json`

---

## Maintenance Notes

- Keep filenames stable unless the application code is updated at the same time.
- Preserve CSV headers when editing existing datasets.
- Prefer updating data values over changing structure, unless the backend is also updated.
- If a file is moved or renamed, route code and helper functions in `app/api/` and `app/rag/` must be checked.
- These files are shared references, so changes can affect multiple pages at once.

---

## Related Folders

- `data/work/`  
  Year-based workflow data and generated JSON files

- `data/ml/`  
  ML helper files such as local embedding caches

- `data/models/`  
  Saved model artifacts

- `app/chroma_db/`  
  Local Chroma vector database used by retrieval features
