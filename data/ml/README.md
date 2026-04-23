# ML Folder

This folder stores machine-learning support assets, intermediate datasets, embedding caches, helper scripts, and local research artifacts used by the Capstone project.

It is not the same as the year-based workflow state in `data/work/`, and it is not the same as the final persisted model-artifact location in `data/models/`.

Think of this folder as the project’s **ML working area**.

---

## Purpose of This Folder

The files in this folder support tasks such as:

- workstation and server role model training
- user behavior model preparation
- local ISO 27002 embedding cache reuse
- vulnerability and exploit reference preparation
- format conversion for training datasets

This folder mixes:

- runtime-support artifacts
- training datasets
- one-off helper scripts
- local research/reference files

So changes here can affect ML-assisted pages and RAG-assisted recommendation flows.

---

## Important Runtime File

### `iso27002_local_embeddings.pkl`

This is the local embedding cache for the ISO 27002 control catalog.

Typical use:

- Annex A & SoA recommendation flows
- Action Plan / Implementation guide generation
- Monitoring / Improvement recommendation and guide generation

Relevant backend routes reference this file from `data/ml/`, including:

- `routes_action_plan_implementation.py`
- `routes_monitoring_improvement.py`

This file is performance-important because it avoids rebuilding ISO embeddings repeatedly.

---

## Training Datasets

### `server_role_training_dataset.csv`
### `server_role_training_dataset.parquet`
### `server_role_training_dataset2.csv`
### `server_role_training_dataset - Copy.csv`

These files support server role classification model training.

Typical use:

- server role ML training
- structured input for role prediction logic in the asset inventory workflow

Notes:

- `.parquet` is the optimized runtime/training format
- duplicate and copy files appear to be retained as working variants or backups

---

### `workstation_role_training_dataset.csv`
### `workstation_role_training_dataset.parquet`
### `workstation_role_training_dataset - Copy.csv`

These files support workstation role classification model training.

Typical use:

- workstation role ML training
- feature preparation for role-prediction logic in Asset Inventory & CIA

---

### `user_behavior_training_dataset.parquet`

Prepared dataset for the user behavior model.

Typical use:

- Risk Analysis behavior-model training
- downstream AI/ML KPI support for behavior model accuracy and related metrics

---

### `user_activity_data_orig.json`

Raw or intermediate user activity source data used during behavior model preparation.

Typical use:

- training-data derivation
- behavior-feature preparation

This is closer to a source/intermediate artifact than a final workflow file.

---

## Helper Scripts

### `convert_csv_to_parquet.py`

Utility script for converting training datasets from CSV to Parquet.

Typical use:

- preparing optimized datasets for ML workflows
- reducing repeated CSV processing overhead

---

### `extract_user_activity.py`

Helper script related to extracting user activity features or reshaping behavior data for training.

Typical use:

- behavior model dataset preparation
- transforming raw activity input into model-friendly structure

---

### `User_behavior_training_model.py`

Model-training script for the user behavior classifier/regressor used in Risk Analysis and AI/ML telemetry flows.

Typical use:

- training or retraining the behavior model
- exporting model artifacts to the expected model storage location

---

## Vulnerability / Exploit Reference Files

### `files_exploits.csv`

Large supporting dataset of exploit-related or vulnerability-related reference data.

Typical use:

- local research support
- data preparation for vulnerability-context enrichment

Because this file is large, changes should be made carefully and only when needed.

---

### `known_exploited_vulnerabilities.json`

Local copy of known exploited vulnerability reference data.

Typical use:

- vulnerability prioritization support
- threat-context enrichment
- helping distinguish more urgent weaknesses during analysis

---

### `nvdcve-2.0-modified.json`

Local NVD CVE dataset snapshot or derived working copy.

Typical use:

- offline or semi-offline vulnerability reference lookups
- support for CVE-related enrichment pipelines

This is a reference/support file, not the primary audit workflow state.

---

## Local Notes / Documentation

### `ControlsPostures.md`

Local markdown notes related to controls/posture work.

Typical use:

- internal reference during dataset or logic development
- support notes rather than a core runtime dependency

---

## Sensitive / Local-Only File

### `nvd API key.txt`

This appears to store a local NVD API key.

Important:

- treat this as sensitive local configuration
- do not expose it in documentation, reports, or shared screenshots
- prefer moving secrets into environment variables when practical

---

## Subfolder

### `models/`

This nested folder appears to be an internal ML support subfolder under `data/ml`.

It is distinct from the top-level repository folder:

- `data/models/`

In the current project structure:

- `data/ml/` is the working area for ML preparation and support artifacts
- `data/models/` is the clearer long-term location for persisted model artifacts

If both folders continue to exist, keep their roles separated to avoid confusion.

---

## How the App Uses This Folder

At a high level:

1. Asset Inventory ML flows rely on role-training datasets and related prepared files.
2. Risk Analysis ML flows rely on user behavior training data and model support files.
3. Annex A, Action Plan, and Monitoring routes reuse `iso27002_local_embeddings.pkl` for fast local retrieval.
4. Some vulnerability-support datasets help enrich local reasoning or preprocessing pipelines.

---

## Maintenance Notes

- Keep `iso27002_local_embeddings.pkl` stable unless you are intentionally rebuilding the ISO embedding cache.
- Prefer updating training datasets in place only if the consuming scripts and routes still expect the same columns.
- Treat duplicate `Copy` files as manual working backups unless you intentionally remove or consolidate them.
- Large reference files should be updated carefully because they can affect performance and storage.
- Sensitive files such as API keys should not be treated as general project documentation artifacts.

---

## Related Folders

- `data/models/`  
  Persisted model artifacts used by the application

- `data/knowledge_base/`  
  Static knowledge sources such as ISO controls and CIA/role lookup datasets

- `data/work/`  
  Year-based audit workflow outputs and active JSON state

- `app/chroma_db/`  
  Local Chroma vector database used by retrieval flows
