"""
RAG API endpoints for VibeSecure.

Allows triggering RAG upsert, searching the knowledge base, and checking
ingestion stats -- all via authenticated HTTP endpoints.
"""

import logging
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from src.auth.dependencies import get_current_user
from src.rag.core import (
    batch_upsert,
    ensure_pgvector,
    get_rag_engine,
    get_rag_stats,
    search_similar,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/rag", tags=["rag"])


# ── Request / response schemas ────────────────────────────────────────────────


class RAGSearchRequest(BaseModel):
    query: str
    top_k: int = 5
    category: str | None = None
    dataset: str | None = None


class RAGSearchResult(BaseModel):
    id: str
    dataset_name: str
    category: str
    content: str
    metadata: dict
    similarity: float


class RAGSearchResponse(BaseModel):
    query: str
    results: list[RAGSearchResult]
    count: int


class RAGUpsertRequest(BaseModel):
    categories: list[str] = ["deepfake", "threat_intel", "regulatory"]


class RAGUpsertResponse(BaseModel):
    status: str
    documents_upserted: int
    message: str


class RAGStatsResponse(BaseModel):
    total_documents: int
    by_dataset: list[dict]


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.post("/search", response_model=RAGSearchResponse)
async def rag_search(
    body: RAGSearchRequest,
    user: dict = Depends(get_current_user),
):
    """Similarity search across the RAG knowledge base."""
    try:
        results = search_similar(
            query=body.query,
            top_k=body.top_k,
            category_filter=body.category,
            dataset_filter=body.dataset,
        )
        return RAGSearchResponse(
            query=body.query,
            results=[RAGSearchResult(**r) for r in results],
            count=len(results),
        )
    except Exception as e:
        logger.error(f"RAG search failed: {e}")
        raise HTTPException(status_code=500, detail="RAG search failed")


@router.post("/upsert", response_model=RAGUpsertResponse)
async def rag_upsert(
    body: RAGUpsertRequest,
    user: dict = Depends(get_current_user),
):
    """
    Trigger RAG ingestion from seed data on the server.
    Generates seed files if needed, then embeds and upserts.
    """
    try:
        engine = get_rag_engine()
        ensure_pgvector(engine)
        data_dir = Path("data")
        total = 0

        if "deepfake" in body.categories:
            from scripts.rag_deepfake import _load_from_dir
            from scripts.rag_deepfake import seed as seed_deepfake

            seed_deepfake(data_dir)
            docs = _load_from_dir(data_dir / "deepfake")
            total += batch_upsert(docs, engine=engine)

        if "threat_intel" in body.categories or "regulatory" in body.categories:
            from scripts.rag_threat_regulatory import load_all
            from scripts.rag_threat_regulatory import seed as seed_threat_reg

            seed_threat_reg(data_dir)
            docs = load_all(data_dir)
            total += batch_upsert(docs, engine=engine)

        return RAGUpsertResponse(
            status="ok",
            documents_upserted=total,
            message=f"Upserted {total} documents for categories: {body.categories}",
        )
    except Exception as e:
        logger.error(f"RAG upsert failed: {e}")
        raise HTTPException(status_code=500, detail=f"RAG upsert failed: {e}")


@router.get("/stats", response_model=RAGStatsResponse)
async def rag_stats(
    user: dict = Depends(get_current_user),
):
    """Get document counts grouped by category and dataset."""
    try:
        stats = get_rag_stats()
        return RAGStatsResponse(**stats)
    except Exception as e:
        logger.error(f"RAG stats failed: {e}")
        raise HTTPException(status_code=500, detail="RAG stats failed")


@router.post("/init")
async def rag_init(
    user: dict = Depends(get_current_user),
):
    """Create PgVector extension and table (idempotent)."""
    try:
        ensure_pgvector()
        return {"status": "ok", "message": "rag_documents table ready"}
    except Exception as e:
        logger.error(f"RAG init failed: {e}")
        raise HTTPException(status_code=500, detail=f"RAG init failed: {e}")
