"""
demo_upsert.py  —  Bootstrap RAG knowledge base from public internet sources.

Fetches publicly accessible plain-text documents for three knowledge domains:
  - deepfake      : detection techniques, GAN theory, media forensics
  - regulatory    : GDPR, CCPA, DPDP Act, EU AI Act
  - threat_intel  : MITRE ATT&CK, adversarial ML, AI security

Each source is fetched via HTTP, chunked, embedded with Gemini, and upserted
into rag_documents (pgvector). Fully idempotent — any dataset whose rows already
exist is silently skipped, so re-running this on every Docker start is safe.

Run automatically by the demo_upsert Docker service on project startup.
Can also be run manually:  python scripts/demo_upsert.py
"""

import hashlib
import json
import logging
import sys
import time
from pathlib import Path
from urllib.parse import quote

import httpx
from sqlalchemy import text

# Allow running from any working directory (locally or inside Docker /app)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.rag.core import batch_upsert, chunk_text, ensure_pgvector, get_rag_engine  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("demo_upsert")

# ── Tuning constants ──────────────────────────────────────────────────────────

MIN_TEXT_LEN = 300  # Skip pages shorter than this (chars)
CHUNK_MAX_CHARS = 1500  # Max chars per embedding chunk
CHUNK_OVERLAP = 150  # Overlap between consecutive chunks
REQUEST_TIMEOUT = 30  # HTTP timeout (seconds)
INTER_SOURCE_DELAY = 1.2  # Seconds to wait between dataset upserts (rate limit courtesy)

# ── Source definitions ────────────────────────────────────────────────────────


def _wiki(title: str) -> str:
    """Build a MediaWiki API URL that returns the full plain-text article extract."""
    safe = quote(title, safe="_")
    return (
        "https://en.wikipedia.org/w/api.php"
        f"?action=query&titles={safe}"
        "&prop=extracts&explaintext=1&exsectionformat=plain&format=json"
    )


# Each entry:  category, dataset (unique name), url, type ("wikipedia" | "raw")
SOURCES: list[dict] = [
    # ─── Deepfake detection & media forensics ──────────────────────────────
    {
        "category": "deepfake",
        "dataset": "wiki_deepfake",
        "url": _wiki("Deepfake"),
        "type": "wikipedia",
        "label": "Deepfake — overview, techniques, detection",
    },
    {
        "category": "deepfake",
        "dataset": "wiki_gan",
        "url": _wiki("Generative adversarial network"),
        "type": "wikipedia",
        "label": "Generative Adversarial Networks (GAN)",
    },
    {
        "category": "deepfake",
        "dataset": "wiki_face_swap",
        "url": _wiki("Face swap"),
        "type": "wikipedia",
        "label": "Face Swap technology",
    },
    {
        "category": "deepfake",
        "dataset": "wiki_digital_image_forensics",
        "url": _wiki("Digital image forensics"),
        "type": "wikipedia",
        "label": "Digital Image Forensics",
    },
    {
        "category": "deepfake",
        "dataset": "wiki_photo_manipulation",
        "url": _wiki("Photo manipulation"),
        "type": "wikipedia",
        "label": "Photo Manipulation techniques",
    },
    {
        "category": "deepfake",
        "dataset": "wiki_video_editing",
        "url": _wiki("Video manipulation"),
        "type": "wikipedia",
        "label": "Video Manipulation",
    },
    {
        "category": "deepfake",
        "dataset": "wiki_voice_cloning",
        "url": _wiki("Voice cloning"),
        "type": "wikipedia",
        "label": "Voice Cloning",
    },
    {
        "category": "deepfake",
        "dataset": "faceforensics_readme",
        "url": "https://raw.githubusercontent.com/ondyari/FaceForensics/master/README.md",
        "type": "raw",
        "label": "FaceForensics++ dataset description",
    },
    {
        "category": "deepfake",
        "dataset": "wiki_image_segmentation_dl",
        "url": _wiki("Convolutional neural network"),
        "type": "wikipedia",
        "label": "Convolutional Neural Networks (CNN) — used in deepfake detection",
    },
    # ─── Privacy & data-protection regulations ─────────────────────────────
    {
        "category": "regulatory",
        "dataset": "wiki_gdpr",
        "url": _wiki("General Data Protection Regulation"),
        "type": "wikipedia",
        "label": "GDPR — General Data Protection Regulation",
    },
    {
        "category": "regulatory",
        "dataset": "wiki_ccpa",
        "url": _wiki("California Consumer Privacy Act"),
        "type": "wikipedia",
        "label": "CCPA — California Consumer Privacy Act",
    },
    {
        "category": "regulatory",
        "dataset": "wiki_eu_ai_act",
        "url": _wiki("Artificial Intelligence Act"),
        "type": "wikipedia",
        "label": "EU AI Act — Artificial Intelligence Act",
    },
    {
        "category": "regulatory",
        "dataset": "wiki_dpdp_act",
        "url": _wiki("Digital Personal Data Protection Act, 2023"),
        "type": "wikipedia",
        "label": "India DPDP Act 2023",
    },
    {
        "category": "regulatory",
        "dataset": "wiki_privacy_law",
        "url": _wiki("Privacy law"),
        "type": "wikipedia",
        "label": "Privacy Law — global overview",
    },
    {
        "category": "regulatory",
        "dataset": "wiki_personal_data",
        "url": _wiki("Personal data"),
        "type": "wikipedia",
        "label": "Personal Data — definition & scope",
    },
    {
        "category": "regulatory",
        "dataset": "wiki_data_breach",
        "url": _wiki("Data breach"),
        "type": "wikipedia",
        "label": "Data Breach — definition & regulatory obligations",
    },
    {
        "category": "regulatory",
        "dataset": "wiki_right_to_be_forgotten",
        "url": _wiki("Right to be forgotten"),
        "type": "wikipedia",
        "label": "Right to be Forgotten (GDPR Art. 17)",
    },
    {
        "category": "regulatory",
        "dataset": "wiki_data_minimisation",
        "url": _wiki("Data minimization"),
        "type": "wikipedia",
        "label": "Data Minimisation (GDPR principle)",
    },
    {
        "category": "regulatory",
        "dataset": "wiki_consent_privacy",
        "url": _wiki("Consent (data protection)"),
        "type": "wikipedia",
        "label": "Consent in data protection law",
    },
    {
        "category": "regulatory",
        "dataset": "nist_rmf_readme",
        "url": "https://raw.githubusercontent.com/usnistgov/AI-RMF-playbook/main/README.md",
        "type": "raw",
        "label": "NIST AI Risk Management Framework playbook",
    },
    # ─── AI threat intelligence ────────────────────────────────────────────
    {
        "category": "threat_intel",
        "dataset": "wiki_mitre_attack",
        "url": _wiki("MITRE ATT&CK"),
        "type": "wikipedia",
        "label": "MITRE ATT&CK framework",
    },
    {
        "category": "threat_intel",
        "dataset": "wiki_adversarial_ml",
        "url": _wiki("Adversarial machine learning"),
        "type": "wikipedia",
        "label": "Adversarial Machine Learning",
    },
    {
        "category": "threat_intel",
        "dataset": "wiki_prompt_injection",
        "url": _wiki("Prompt injection"),
        "type": "wikipedia",
        "label": "Prompt Injection attacks",
    },
    {
        "category": "threat_intel",
        "dataset": "wiki_ai_safety",
        "url": _wiki("AI safety"),
        "type": "wikipedia",
        "label": "AI Safety",
    },
    {
        "category": "threat_intel",
        "dataset": "wiki_model_inversion",
        "url": _wiki("Model inversion attack"),
        "type": "wikipedia",
        "label": "Model Inversion Attack",
    },
    {
        "category": "threat_intel",
        "dataset": "wiki_membership_inference",
        "url": _wiki("Membership inference attack"),
        "type": "wikipedia",
        "label": "Membership Inference Attack",
    },
    {
        "category": "threat_intel",
        "dataset": "wiki_backdoor_ml",
        "url": _wiki("Backdoor attack (machine learning)"),
        "type": "wikipedia",
        "label": "Backdoor Attacks on ML models",
    },
    {
        "category": "threat_intel",
        "dataset": "wiki_supply_chain_attack",
        "url": _wiki("Supply chain attack"),
        "type": "wikipedia",
        "label": "Supply Chain Attacks (AI/ML context)",
    },
]

# ── Fetch helpers ─────────────────────────────────────────────────────────────


def _fetch_raw(url: str, client: httpx.Client) -> str | None:
    """GET a URL and return the response text. Returns None on any error."""
    try:
        response = client.get(url, timeout=REQUEST_TIMEOUT, follow_redirects=True)
        response.raise_for_status()
        return response.text
    except httpx.HTTPStatusError as exc:
        logger.warning(f"HTTP {exc.response.status_code} fetching {url}")
        return None
    except Exception as exc:
        logger.warning(f"Request failed for {url}: {exc}")
        return None


def _fetch_wikipedia(url: str, client: httpx.Client) -> str | None:
    """Fetch and extract plain text from a MediaWiki API response."""
    raw = _fetch_raw(url, client)
    if not raw:
        return None
    try:
        data = json.loads(raw)
        pages = data.get("query", {}).get("pages", {})
        page = next(iter(pages.values()))
        if "missing" in page:
            logger.warning(f"Wikipedia page missing for URL: {url}")
            return None
        return page.get("extract") or ""
    except Exception as exc:
        logger.warning(f"Could not parse Wikipedia JSON ({url}): {exc}")
        return None


def fetch_source(source: dict, client: httpx.Client) -> str | None:
    """Dispatch fetch to the correct handler based on source type."""
    if source.get("type") == "wikipedia":
        return _fetch_wikipedia(source["url"], client)
    return _fetch_raw(source["url"], client)


# ── Database helpers ──────────────────────────────────────────────────────────


def dataset_exists(dataset_name: str, engine) -> bool:
    """Return True if rag_documents already contains rows for this dataset."""
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT COUNT(*) FROM rag_documents WHERE dataset_name = :ds"),
            {"ds": dataset_name},
        ).fetchone()
        return (row[0] if row else 0) > 0


# ── Main ──────────────────────────────────────────────────────────────────────


def run() -> None:
    logger.info("=" * 60)
    logger.info("demo_upsert: bootstrapping RAG knowledge base")
    logger.info("=" * 60)

    engine = get_rag_engine()
    ensure_pgvector(engine)

    headers = {"User-Agent": "VibeSecure-RAG-Bootstrap/1.0 (educational/academic use)"}

    total_upserted = 0
    skipped = 0
    failed = 0

    with httpx.Client(headers=headers) as client:
        for source in SOURCES:
            dataset = source["dataset"]
            category = source["category"]
            label = source.get("label", dataset)

            # Idempotency check: skip if already seeded
            if dataset_exists(dataset, engine):
                logger.info(f"[SKIP]  {dataset}")
                skipped += 1
                continue

            logger.info(f"[FETCH] {label}")
            text_content = fetch_source(source, client)

            if not text_content or len(text_content.strip()) < MIN_TEXT_LEN:
                char_count = len((text_content or "").strip())
                logger.warning(f"[SKIP]  {dataset}: content too short ({char_count} chars)")
                failed += 1
                continue

            chunks = chunk_text(text_content, max_chars=CHUNK_MAX_CHARS, overlap=CHUNK_OVERLAP)
            total_chunks = len(chunks)

            docs = []
            for idx, chunk in enumerate(chunks):
                digest = hashlib.sha256(chunk.encode()).hexdigest()[:16]
                docs.append(
                    {
                        "id": f"{category}:{dataset}:c{idx}:{digest}",
                        "dataset_name": dataset,
                        "category": category,
                        "content": chunk,
                        "metadata": {
                            "label": label,
                            "source_url": source["url"],
                            "source_type": source.get("type", "raw"),
                            "chunk_index": idx,
                            "total_chunks": total_chunks,
                        },
                    }
                )

            logger.info(f"[EMBED] {dataset}: {total_chunks} chunks")
            try:
                n = batch_upsert(docs, engine=engine)
                total_upserted += n
                logger.info(f"[DONE]  {dataset}: {n} chunks upserted")
            except Exception as exc:
                logger.error(f"[FAIL]  {dataset}: {exc}")
                failed += 1
                continue

            time.sleep(INTER_SOURCE_DELAY)

    logger.info("=" * 60)
    logger.info(
        f"demo_upsert finished — "
        f"upserted: {total_upserted} chunks, "
        f"skipped: {skipped} datasets, "
        f"failed: {failed} datasets"
    )
    logger.info("=" * 60)


if __name__ == "__main__":
    run()
