"""
Core RAG infrastructure for VibeSecure AI.

Provides PgVector table management, Gemini embedding generation,
batch upsert, and cosine similarity search. Shared by both ingestion
scripts and the FastAPI endpoints.
"""

import hashlib
import json
import logging
import time

from google import genai
from sqlalchemy import text
from sqlmodel import Session, create_engine

from src.core.config import get_settings

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

EMBEDDING_MODEL = "gemini-embedding-001"
EMBEDDING_DIMENSION = 768
BATCH_SIZE_DEFAULT = 32
MAX_RETRIES = 3
RETRY_DELAY = 2.0


# ── Engine ────────────────────────────────────────────────────────────────────

_engine = None


def get_rag_engine():
    """Lazy singleton engine for RAG operations."""
    global _engine
    if _engine is None:
        settings = get_settings()
        _engine = create_engine(
            settings.database_url,
            pool_pre_ping=True,
            pool_size=5,
            max_overflow=10,
        )
    return _engine


# ── Table setup ───────────────────────────────────────────────────────────────


def ensure_pgvector(engine=None) -> None:
    """Create the pgvector extension and rag_documents table."""
    if engine is None:
        engine = get_rag_engine()
    with engine.begin() as conn:
        conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
        conn.execute(
            text(f"""
            CREATE TABLE IF NOT EXISTS rag_documents (
                id TEXT PRIMARY KEY,
                dataset_name TEXT NOT NULL,
                category TEXT NOT NULL,
                content TEXT NOT NULL,
                embedding vector({EMBEDDING_DIMENSION}),
                metadata JSONB DEFAULT '{{}}'::jsonb,
                created_at TIMESTAMPTZ DEFAULT now(),
                updated_at TIMESTAMPTZ DEFAULT now()
            )
        """)
        )
        conn.execute(
            text("""
            CREATE INDEX IF NOT EXISTS idx_rag_documents_category
            ON rag_documents (category)
        """)
        )
        conn.execute(
            text("""
            CREATE INDEX IF NOT EXISTS idx_rag_documents_dataset
            ON rag_documents (dataset_name)
        """)
        )
        # IVFFlat index for cosine similarity -- needs rows to be effective
        conn.execute(
            text("""
            CREATE INDEX IF NOT EXISTS idx_rag_documents_embedding
            ON rag_documents USING ivfflat (embedding vector_cosine_ops)
            WITH (lists = 100)
        """)
        )
    logger.info("PgVector extension and rag_documents table ensured")


# ── Gemini embedding ─────────────────────────────────────────────────────────

_gemini_client = None


def _get_client() -> genai.Client:
    global _gemini_client
    if _gemini_client is None:
        settings = get_settings()
        if not settings.gemini_api_key:
            raise RuntimeError("GEMINI_API_KEY is required for embedding generation")
        _gemini_client = genai.Client(api_key=settings.gemini_api_key)
    return _gemini_client


def generate_embeddings(
    texts: list[str],
    client: genai.Client | None = None,
) -> list[list[float]]:
    """
    Generate embeddings for a list of texts using Gemini.
    Uses gemini-embedding-001 model. Retries on transient failures.
    """
    if client is None:
        client = _get_client()

    for attempt in range(MAX_RETRIES):
        try:
            result = client.models.embed_content(
                model=EMBEDDING_MODEL,
                contents=texts,
            )
            return [e.values for e in result.embeddings]
        except Exception as e:
            error_str = str(e).lower()
            is_transient = any(
                kw in error_str for kw in ["rate limit", "429", "503", "500", "quota", "overloaded"]
            )
            if is_transient and attempt < MAX_RETRIES - 1:
                wait = RETRY_DELAY * (2**attempt)
                logger.warning(
                    f"Embedding attempt {attempt + 1} failed ({e}), retrying in {wait:.1f}s"
                )
                time.sleep(wait)
                continue
            raise RuntimeError(f"Embedding failed after {MAX_RETRIES} attempts: {e}") from e


# ── Helpers ───────────────────────────────────────────────────────────────────


def content_id(category: str, filename: str, chunk: str) -> str:
    """Deterministic document ID for upsert idempotency."""
    digest = hashlib.sha256(chunk.encode("utf-8")).hexdigest()[:16]
    return f"{category}:{filename}:{digest}"


def chunk_text(text_content: str, max_chars: int = 2000, overlap: int = 200) -> list[str]:
    """Split text into overlapping chunks for embedding."""
    if len(text_content) <= max_chars:
        return [text_content]
    chunks = []
    start = 0
    while start < len(text_content):
        end = start + max_chars
        piece = text_content[start:end]
        if piece.strip():
            chunks.append(piece.strip())
        start = end - overlap
    return chunks


# ── Batch upsert ──────────────────────────────────────────────────────────────


def batch_upsert(
    documents: list[dict],
    batch_size: int = BATCH_SIZE_DEFAULT,
    engine=None,
) -> int:
    """
    Generate embeddings and upsert documents into rag_documents.

    Each document dict must have keys:
        id, dataset_name, category, content, metadata (dict)

    Returns number of documents upserted.
    """
    if engine is None:
        engine = get_rag_engine()
    client = _get_client()
    total = 0

    for i in range(0, len(documents), batch_size):
        batch = documents[i : i + batch_size]
        texts = [d["content"] for d in batch]

        logger.info(f"Embedding batch {i // batch_size + 1} ({len(batch)} docs)...")
        embeddings = generate_embeddings(texts, client=client)

        upsert_sql = text("""
            INSERT INTO rag_documents
                (id, dataset_name, category, content, embedding, metadata, updated_at)
            VALUES
                (:id, :dataset_name, :category, :content, :embedding, :metadata, now())
            ON CONFLICT (id) DO UPDATE SET
                content   = EXCLUDED.content,
                embedding = EXCLUDED.embedding,
                metadata  = EXCLUDED.metadata,
                updated_at = now()
        """)

        with Session(engine) as session:
            for doc, emb in zip(batch, embeddings):
                session.exec(
                    upsert_sql,
                    params={
                        "id": doc["id"],
                        "dataset_name": doc["dataset_name"],
                        "category": doc["category"],
                        "content": doc["content"],
                        "embedding": str(emb),
                        "metadata": json.dumps(doc["metadata"]),
                    },
                )
            session.commit()

        total += len(batch)
        logger.info(f"Upserted {total}/{len(documents)}")

        # Rate limit courtesy
        if i + batch_size < len(documents):
            time.sleep(0.5)

    return total


# ── Similarity search ─────────────────────────────────────────────────────────


def search_similar(
    query: str,
    top_k: int = 5,
    category_filter: str | None = None,
    dataset_filter: str | None = None,
    engine=None,
) -> list[dict]:
    """
    Cosine similarity search against rag_documents.

    Returns list of dicts: id, dataset_name, category, content, metadata, similarity.
    """
    if engine is None:
        engine = get_rag_engine()

    query_emb = generate_embeddings([query])[0]

    where_parts = []
    params: dict = {"embedding": str(query_emb), "top_k": top_k}

    if category_filter:
        where_parts.append("category = :category")
        params["category"] = category_filter
    if dataset_filter:
        where_parts.append("dataset_name = :dataset_name")
        params["dataset_name"] = dataset_filter

    where_sql = (" AND " + " AND ".join(where_parts)) if where_parts else ""

    sql = text(f"""
        SELECT id, dataset_name, category, content, metadata,
               1 - (embedding <=> :embedding::vector) AS similarity
        FROM rag_documents
        WHERE embedding IS NOT NULL{where_sql}
        ORDER BY embedding <=> :embedding::vector
        LIMIT :top_k
    """)

    with Session(engine) as session:
        rows = session.exec(sql, params=params).all()
        return [
            {
                "id": r[0],
                "dataset_name": r[1],
                "category": r[2],
                "content": r[3],
                "metadata": r[4],
                "similarity": float(r[5]),
            }
            for r in rows
        ]


# ── Stats ─────────────────────────────────────────────────────────────────────


def get_rag_stats(engine=None) -> dict:
    """Return document counts grouped by category and dataset."""
    if engine is None:
        engine = get_rag_engine()
    with Session(engine) as session:
        rows = session.exec(
            text("""
            SELECT category, dataset_name, count(*) AS doc_count,
                   count(embedding) AS embedded_count
            FROM rag_documents
            GROUP BY category, dataset_name
            ORDER BY category, dataset_name
        """)
        ).all()
        total = sum(r[2] for r in rows)
        return {
            "total_documents": total,
            "by_dataset": [
                {
                    "category": r[0],
                    "dataset_name": r[1],
                    "documents": r[2],
                    "embedded": r[3],
                }
                for r in rows
            ],
        }
