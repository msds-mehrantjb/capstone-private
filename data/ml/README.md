# Machine Learning Data and Utilities

Datasets, preprocessing utilities, vulnerability-intelligence files, embedding artifacts, and trained model outputs used by the application.

## ML datasets in this folder

### Role-prediction datasets

- `server_role_training_dataset.csv`
  Primary CSV training dataset for server role prediction.
  Usage:
  Used in the Asset Inventory & CIA workflow to train the server-side role-classification model that predicts roles such as Domain Controller, DNS Server, File Server, and related infrastructure roles from technical and business features.
  Model used:
  `RandomForestClassifier`

- `server_role_training_dataset.parquet`
  Parquet version of the main server role training dataset.
  Usage:
  Used as the optimized training input recorded in model metadata and kept for faster ML retraining and reproducibility.
  Model used:
  `RandomForestClassifier`

- `server_role_training_dataset2.csv`
  Alternate server role training dataset with workstation/server-style inventory features such as CPU, memory, virtualization, ports, services, and CIA labels.
  Usage:
  Kept as an additional training or experimentation dataset for server-role modeling and feature-engineering work. It is useful when testing alternate server-role model inputs outside the primary runtime pipeline.
  Model used:
  `RandomForestClassifier` when used for role-model experimentation

- `server_role_dataset.csv`
  Labeled server-role source dataset.
  Usage:
  Serves as a curated source/reference corpus for server role modeling and dataset maintenance. It supports preparation and review of role-labeled server examples used by the Asset Inventory & CIA ML workflow.
  Model used:
  Supports the server role `RandomForestClassifier` training pipeline

- `workstation_role_training_dataset.csv`
  Primary CSV training dataset for workstation role prediction.
  Usage:
  Used in the Asset Inventory & CIA workflow to train the workstation role-classification model for roles such as Developer Workstation, Finance Workstation, HR Workstation, Executive Workstation, and similar endpoint roles.
  Model used:
  `RandomForestClassifier`

- `workstation_role_training_dataset.parquet`
  Parquet version of the workstation role training dataset.
  Usage:
  Used as an optimized training input for reproducible workstation model training and metadata tracking.
  Model used:
  `RandomForestClassifier`

- `workstation_role_dataset.csv`
  Labeled workstation-role source dataset.
  Usage:
  Serves as a curated source/reference corpus for workstation role modeling and dataset review. It supports the role-prediction workflow before CIA ratings and downstream risk calculations are applied.
  Model used:
  Supports the workstation role `RandomForestClassifier` training pipeline

### User-behavior / risk datasets

- `user_activity_data_orig.json`
  Raw user activity source data containing behavior metrics such as failed logins, access frequency, consistency signals, and session characteristics.
  Usage:
  Used as the source input for user-behavior dataset preparation. `extract_user_activity.py` converts it into a simplified labeled training dataset for the user behavior risk model used in Risk Analysis.
  Model used:
  Source data for the behavior `RandomForestClassifier`

- `user_behavior_training_dataset.parquet`
  Processed and labeled user-behavior training dataset with the `risk_level` target column.
  Usage:
  Used by the Risk Analysis workflow to train and evaluate the ML-assisted user behavior risk model that contributes to UABV-style scoring and ML probability outputs.
  Model used:
  `RandomForestClassifier`

### Vulnerability-intelligence datasets

- `known_exploited_vulnerabilities.json`
  Reference dataset of known exploited vulnerabilities.
  Usage:
  Used in Threats & Vulnerabilities and Risk Analysis to enrich findings with exploitability context and support prioritization of higher-risk items.
  Model used:
  No predictive ML model directly trained from this file in the current workflow; it is used as reference intelligence.

- `nvdcve-2.0-modified.json`
  Local NVD CVE reference dataset.
  Usage:
  Used in Threats & Vulnerabilities and Risk Analysis to look up vulnerability details, descriptions, and supporting CVE metadata for audit findings.
  Model used:
  No predictive ML model directly trained from this file in the current workflow; it is used as reference intelligence.

- `files_exploits.csv`
  Exploit-reference dataset containing exploit metadata and CVE-linked exploit records.
  Usage:
  Used to enrich threat and vulnerability findings with exploit presence and supporting exploit-source context during the technical risk workflow.
  Model used:
  No predictive ML model directly trained from this file in the current workflow; it is used as reference intelligence.

### Embedding artifact

- `iso27002_local_embeddings.pkl`
  Serialized local embedding cache for ISO 27002 control knowledge.
  Usage:
  Used by Annex A & SoA, Action Plan / Implementation, and Monitoring & Improvement to support local retrieval over control content before LLM reasoning generates recommendations or guidance.
  Model used:
  Local embedding generation in these routes uses `nomic-embed-text` for the ISO 27002 control retrieval flow. This is an embedding model rather than a classifier.

## Training utilities in this folder

- `convert_csv_to_parquet.py`
  Utility that converts the main server and workstation role training CSV files into Parquet format for faster downstream training and reproducibility.

- `extract_user_activity.py`
  Utility that transforms `user_activity_data_orig.json` into `user_behavior_training_dataset.parquet`, including simple rule-based labeling of `risk_level`.

- `User_behavior_training_model.py`
  Standalone training script for the user behavior model. It loads the processed Parquet dataset, imputes numeric values, encodes labels, trains the model, evaluates it, exports feature importance, and saves the trained artifacts to `data/ml/models/`.

## Trained model artifacts used by the app

- `models/server_role_prediction_random_forest.joblib`
  Trained server role model used in Asset Inventory & CIA.
  Model:
  `RandomForestClassifier`

- `models/workstation_role_prediction_random_forest.joblib`
  Trained workstation role model used in Asset Inventory & CIA.
  Model:
  `RandomForestClassifier`

- `models/rf_behavior_model.joblib`
  Trained user behavior model used in Risk Analysis for ML-assisted behavior risk scoring.
  Model:
  `RandomForestClassifier`

- `models/label_encoder.joblib`
  Label encoder used with the behavior model to convert risk labels between text and model classes.

- `models/feature_importance.csv`
  Exported feature-importance output from the behavior model training process, also used by the AI/ML dashboard.

- `models/role_prediction_random_forest.joblib`
  General role-prediction artifact retained for compatibility and model provenance.
  Model:
  `RandomForestClassifier`

- `models/role_prediction_random_forest_metadata.json`
  Metadata for the role-prediction model family, including the stored model name, training row count, feature count, target column, and source training files.

## Workflow summary

These datasets support the ISO 27001 workflow in the following way:

- Asset Inventory & CIA
  Uses the server and workstation role datasets plus the trained Random Forest role models to assign asset roles and support downstream CIA and risk decisions.

- Threats & Vulnerabilities
  Uses vulnerability-intelligence datasets to enrich CVE findings with exploit and threat context.

- Risk Analysis
  Uses the trained behavior Random Forest model and the processed user behavior dataset design to add ML-assisted behavior signals and probabilities into risk scoring.

- Annex A & SoA, Action Plan / Implementation, and Monitoring & Improvement
  Use the local control embedding artifact as retrieval support for control-aware recommendation generation.

## Notes

- Large files in this directory may be expensive to regenerate.
- Keep training inputs, generated Parquet files, and saved model artifacts synchronized.
- Treat vulnerability-intelligence files as reference data unless a future training pipeline explicitly adopts them as model inputs.
