from app.rag.chroma_client import get_chroma_client


def rag_query(query_text: str, n_results: int = 5, where: dict | None = None):
    client = get_chroma_client()
    return client.search(text=query_text, n_results=n_results, where=where)