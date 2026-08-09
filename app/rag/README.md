# RAG and Chroma Helpers

Local retrieval-augmented generation support used by recommendations and grounded AI workflows.

## Files

- `build_knowledge_base.py` — builds/refreshes local retrieval data.
- `chroma_client.py` — persistent Chroma client setup.
- `ingest.py` — ingestion entry/helper.
- `query.py` — query helper.
- `dataset_hashes.json` — source/hash tracking for dataset refresh decisions.

Knowledge sources primarily live under `data/knowledge_base/`.
