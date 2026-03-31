#!/usr/bin/env python3
"""
RAG Verification & Test Script for VibeSecure AI.

After running the upsert scripts, use this to verify embeddings are stored
correctly and run sample similarity searches across all three categories.

Usage:
    cd backend
    python -m scripts.rag_verify
"""

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.rag.core import get_rag_engine, get_rag_stats, search_similar

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("rag_verify")

# ── Sample queries per category ──────────────────────────────────────────────

SAMPLE_QUERIES = [
    {
        "label": "Deepfake detection techniques",
        "query": "How to detect face swap deepfakes using frequency analysis",
        "category": "deepfake",
    },
    {
        "label": "Deepfake attack scenarios",
        "query": "CEO impersonation deepfake video call fraud",
        "category": "deepfake",
    },
    {
        "label": "MITRE ATLAS threat intelligence",
        "query": "adversarial examples and model poisoning attacks on AI systems",
        "category": "threat_intel",
    },
    {
        "label": "Prompt injection threat",
        "query": "How can prompt injection bypass LLM safety guardrails",
        "category": "threat_intel",
    },
    {
        "label": "GDPR AI compliance",
        "query": "GDPR Article 22 automated decision-making and right to explanation",
        "category": "regulatory",
    },
    {
        "label": "EU AI Act deepfake rules",
        "query": "EU AI Act transparency obligations for deepfake detection systems",
        "category": "regulatory",
    },
    {
        "label": "India DPDP Act",
        "query": "India Digital Personal Data Protection Act consent and children data",
        "category": "regulatory",
    },
    {
        "label": "Cross-category (no filter)",
        "query": "What are the legal and technical risks of AI deepfake systems",
        "category": None,
    },
]


def verify():
    """Run full verification: stats check, embedding presence, sample searches."""
    engine = get_rag_engine()

    # ── 1. Stats ──────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("1. RAG DOCUMENT STATS")
    print("=" * 70)

    stats = get_rag_stats(engine=engine)
    if stats["total_documents"] == 0:
        print("\n  [FAIL] No documents found in rag_documents table!")
        print("  Run the upsert scripts first:")
        print("    python -m scripts.rag_deepfake seed && python -m scripts.rag_deepfake upsert")
        print(
            "    python -m scripts.rag_threat_regulatory seed && python -m scripts.rag_threat_regulatory upsert"
        )
        sys.exit(1)

    print(f"\n  Total documents: {stats['total_documents']}")
    print(f"  {'Category':<20} {'Dataset':<25} {'Docs':>6} {'Embedded':>10}")
    print(f"  {'-' * 20} {'-' * 25} {'-' * 6} {'-' * 10}")
    for row in stats["by_dataset"]:
        print(
            f"  {row['category']:<20} {row['dataset_name']:<25} {row['documents']:>6} {row['embedded']:>10}"
        )

    # Check all docs have embeddings
    total_embedded = sum(r["embedded"] for r in stats["by_dataset"])
    if total_embedded < stats["total_documents"]:
        print(
            f"\n  [WARN] {stats['total_documents'] - total_embedded} documents missing embeddings!"
        )
    else:
        print(f"\n  [OK] All {total_embedded} documents have embeddings")

    # ── 2. Sample searches ────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("2. SAMPLE SIMILARITY SEARCHES")
    print("=" * 70)

    pass_count = 0
    fail_count = 0

    for sq in SAMPLE_QUERIES:
        print(f"\n  --- {sq['label']} ---")
        print(f"  Query: {sq['query']}")
        if sq["category"]:
            print(f"  Filter: category={sq['category']}")

        try:
            results = search_similar(
                query=sq["query"],
                top_k=3,
                category_filter=sq["category"],
                engine=engine,
            )
        except Exception as e:
            print(f"  [FAIL] Search error: {e}")
            fail_count += 1
            continue

        if not results:
            print("  [FAIL] No results returned")
            fail_count += 1
            continue

        print(f"  [OK] {len(results)} results (top similarity: {results[0]['similarity']:.4f})")
        for i, r in enumerate(results, 1):
            snippet = r["content"][:120].replace("\n", " ")
            print(f"    {i}. [{r['dataset_name']}] sim={r['similarity']:.4f}: {snippet}...")
        pass_count += 1

    # ── 3. Summary ────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("3. VERIFICATION SUMMARY")
    print("=" * 70)
    print(f"\n  Documents: {stats['total_documents']}")
    print(f"  Embedded:  {total_embedded}")
    print(f"  Searches:  {pass_count} passed, {fail_count} failed out of {len(SAMPLE_QUERIES)}")

    if fail_count == 0 and total_embedded == stats["total_documents"]:
        print("\n  === ALL CHECKS PASSED ===")
    else:
        print("\n  === SOME CHECKS FAILED ===")
        sys.exit(1)


if __name__ == "__main__":
    verify()
