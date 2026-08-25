from pathlib import Path
import chromadb
from sentence_transformers import SentenceTransformer
from app.api.performance_telemetry import (
    performance_span,
    resolve_telemetry_year,
    safe_embedding_configuration,
)

BASE_DIR = Path(__file__).resolve().parents[2]
CHROMA_DIR = BASE_DIR / "app" / "chroma_db"
COLLECTION_NAME = "iso27001_knowledge"
EMBED_MODEL = "all-MiniLM-L6-v2"


class ChromaKnowledgeClient:
    def __init__(self):
        self.client = chromadb.PersistentClient(path=str(CHROMA_DIR))
        self.embedder = SentenceTransformer(EMBED_MODEL)
        self.collection = self.client.get_collection(COLLECTION_NAME)

    def search(self, text: str, n_results: int = 5, where: dict | None = None):
        with performance_span(
            year=resolve_telemetry_year(),
            operation_id="rag.shared_chroma_query",
            model_configuration=safe_embedding_configuration(
                model=EMBED_MODEL,
                provider="SentenceTransformers",
            ),
        ):
            embedding = self.embedder.encode([text]).tolist()[0]
            return self.collection.query(
                query_embeddings=[embedding],
                n_results=n_results,
                where=where
            )


def get_chroma_client() -> ChromaKnowledgeClient:
    return ChromaKnowledgeClient()
