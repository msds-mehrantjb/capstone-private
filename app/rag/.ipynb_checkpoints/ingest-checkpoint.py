from app.rag.build_knowledge_base import rebuild_if_needed


def ingest_documents(*args, **kwargs):
    return rebuild_if_needed()