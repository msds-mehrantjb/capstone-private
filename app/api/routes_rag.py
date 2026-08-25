# app/api/routes_rag.py

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.rag.chroma_client import get_chroma_client
from app.rag.ingest import ingest_documents
from app.rag.query import rag_query

from app.api.aiml_kpi_telemetry import safe_increment_rag_counter
from app.api.performance_telemetry import performance_span, safe_embedding_configuration


# IMPORTANT: this name must be `router`
router = APIRouter(prefix="/rag", tags=["RAG"])


class IngestDoc(BaseModel):
    text: str = Field(..., description="Document text to ingest")
    source_id: Optional[str] = Field(None, description="Stable source id (file name, url, host, etc.)")
    metadata: Dict[str, Any] = Field(default_factory=dict)


class IngestRequest(BaseModel):
    collection: str = Field("iso27001", description="Chroma collection name")
    docs: List[IngestDoc]
    embedding_model: str = Field("sentence-transformers/all-MiniLM-L6-v2")
    chunk_size: int = Field(800, ge=200, le=4000)
    overlap: int = Field(120, ge=0, le=1000)


class QueryRequest(BaseModel):
    collection: str = Field("iso27001")
    query: str
    top_k: int = Field(5, ge=1, le=20)
    embedding_model: str = Field("sentence-transformers/all-MiniLM-L6-v2")
    where: Optional[Dict[str, Any]] = None
    year: int = Field(2026, ge=2000, le=2100)


def _rag_result_has_hits(result: Any) -> bool:
    if isinstance(result, list):
        return len(result) > 0
    if not isinstance(result, dict):
        return bool(result)

    for key in ("results", "documents", "ids", "matches"):
        value = result.get(key)
        if not isinstance(value, list):
            continue
        for item in value:
            if isinstance(item, list) and item:
                return True
            if not isinstance(item, list) and item:
                return True
    return False


@router.get("/collections")
async def list_collections():
    client = get_chroma_client()
    cols = client.list_collections()
    return {"collections": [c.name for c in cols]}


@router.post("/ingest")
async def ingest(req: IngestRequest):
    return ingest_documents(
        collection=req.collection,
        docs=[d.model_dump() for d in req.docs],
        embedding_model=req.embedding_model,
        chunk_size=req.chunk_size,
        overlap=req.overlap,
    )


@router.post("/query")
async def query(req: QueryRequest):
    try:
        with performance_span(
            year=req.year,
            operation_id="rag.api_query",
            model_configuration=safe_embedding_configuration(
                model="all-MiniLM-L6-v2",
                provider="SentenceTransformers",
            ),
        ):
            result = rag_query(
                query_text=req.query,
                n_results=req.top_k,
                where=req.where,
            )
    except Exception:
        safe_increment_rag_counter(req.year, success=False)
        raise

    safe_increment_rag_counter(req.year, success=_rag_result_has_hits(result))
    return result
