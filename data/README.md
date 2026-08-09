# Data Layer

Project data, reference sources, model artifacts, working audit state, and optional lab assets.

## Subfolders

- `raw/` — baseline/sample input documents.
- `work/` — mutable year-based audit state.
- `knowledge_base/` — ISO/NIST/control mapping reference data.
- `ml/` — training datasets, preprocessing scripts, and ML artifacts.
- `models/` — persisted local embedding artifacts.
- `docs/` — project/design notes and supporting documents.
- `docker_lab/` — optional simulated network lab.

`assess_network.py` provides network-assessment support outside the Docker lab folder.
