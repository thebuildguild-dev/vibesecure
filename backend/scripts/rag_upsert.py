"""
RAG Dataset Upsert Script for VibeSecure AI.

Creates a PgVector table, loads text knowledge datasets from /data/,
generates embeddings via Gemini, and performs batch upserts with metadata.
Includes similarity search for retrieval by agents.

Data folder layout:
    data/
      deepfake/          -> techniques, artifacts, detection methods
      threats/           -> MITRE ATLAS, attack scenarios
      regulations/       -> GDPR, CCPA, DPDP Act, EU AI Act

Usage:
    python -m scripts.rag_upsert init
    python -m scripts.rag_upsert seed                          # generate demo data files
    python -m scripts.rag_upsert upsert --data-dir ./data
    python -m scripts.rag_upsert search "deepfake face swap"
"""

import argparse
import hashlib
import json
import logging
import sys
import time
from pathlib import Path

from google import genai
from sqlalchemy import text
from sqlmodel import Session, create_engine

# Allow running from backend/ root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.core.config import get_settings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("rag_upsert")

EMBEDDING_MODEL = "gemini-embedding-001"
EMBEDDING_DIMENSION = 768
BATCH_SIZE_DEFAULT = 32
RETRY_DELAY = 2.0
MAX_RETRIES = 3

# ── Category registry ─────────────────────────────────────────────────────────
# Folder name inside data/ directly maps to a category.
CATEGORY_FOLDERS = {
    "deepfake": "deepfake",
    "threats": "threat_intel",
    "regulations": "regulatory",
}


# ── Database helpers ──────────────────────────────────────────────────────────


def _get_engine():
    settings = get_settings()
    return create_engine(
        settings.database_url,
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=10,
    )


def ensure_pgvector(engine) -> None:
    """Create the pgvector extension and rag_documents table if they don't exist."""
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
        conn.execute(
            text("""
            CREATE INDEX IF NOT EXISTS idx_rag_documents_embedding
            ON rag_documents
            USING ivfflat (embedding vector_cosine_ops)
            WITH (lists = 100)
        """)
        )
    logger.info("PgVector extension and rag_documents table ensured")


# ── Gemini embedding ─────────────────────────────────────────────────────────


def _get_gemini_client() -> genai.Client:
    settings = get_settings()
    if not settings.gemini_api_key:
        raise RuntimeError("GEMINI_API_KEY is required")
    return genai.Client(api_key=settings.gemini_api_key)


def generate_embeddings(
    texts: list[str],
    client: genai.Client | None = None,
) -> list[list[float]]:
    """
    Generate embeddings for a batch of texts using Gemini's embedding model.
    Retries on transient failures.
    """
    if client is None:
        client = _get_gemini_client()

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
            raise RuntimeError(
                f"Embedding generation failed after {MAX_RETRIES} attempts: {e}"
            ) from e


# ── Data loading ──────────────────────────────────────────────────────────────


def _content_id(dataset_name: str, filename: str, content: str) -> str:
    """Deterministic document ID for upsert idempotency."""
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]
    return f"{dataset_name}:{filename}:{digest}"


def _chunk_text(text_content: str, max_chars: int = 2000, overlap: int = 200) -> list[str]:
    """
    Split long text into overlapping chunks suitable for embedding.
    Each chunk is at most max_chars characters with overlap between consecutive chunks.
    """
    if len(text_content) <= max_chars:
        return [text_content]

    chunks = []
    start = 0
    while start < len(text_content):
        end = start + max_chars
        chunk = text_content[start:end]
        if chunk.strip():
            chunks.append(chunk.strip())
        start = end - overlap
    return chunks


def load_datasets(data_dir: Path) -> list[dict]:
    """
    Load text documents from the data directory.

    Expected structure:
        data/
          deepfake/
            techniques.txt
            artifacts.txt
            detection_methods.txt
            datasets.txt
          threats/
            mitre_atlas.json
            attack_scenarios.txt
          regulations/
            gdpr.txt
            ccpa.txt
            dpdp.txt
            eu_ai_act.txt

    Folder names must match keys in CATEGORY_FOLDERS.
    Files with extensions .txt, .md, .json, .csv, .jsonl are loaded.
    """
    allowed_extensions = {".txt", ".md", ".json", ".csv", ".jsonl"}
    documents = []

    if not data_dir.exists():
        logger.error(f"Data directory does not exist: {data_dir}")
        return documents

    for folder in sorted(data_dir.iterdir()):
        if not folder.is_dir():
            continue

        folder_key = folder.name.lower()
        category = CATEGORY_FOLDERS.get(folder_key)

        if category is None:
            logger.warning(
                f"Skipping unrecognized folder: {folder.name}. "
                f"Known folders: {list(CATEGORY_FOLDERS.keys())}"
            )
            continue

        file_count = 0
        for filepath in sorted(folder.rglob("*")):
            if not filepath.is_file():
                continue
            if filepath.suffix.lower() not in allowed_extensions:
                continue

            # For JSON files, pretty-print the contents as text
            try:
                raw = filepath.read_text(encoding="utf-8", errors="replace").strip()
                if filepath.suffix.lower() == ".json":
                    parsed = json.loads(raw)
                    content = (
                        json.dumps(parsed, indent=2) if isinstance(parsed, (dict, list)) else raw
                    )
                else:
                    content = raw
            except Exception as e:
                logger.warning(f"Failed to read {filepath}: {e}")
                continue

            if not content:
                continue

            dataset_name = filepath.stem  # e.g. "techniques", "gdpr", "mitre_atlas"
            relative_path = str(filepath.relative_to(data_dir))
            chunks = _chunk_text(content)

            for i, chunk in enumerate(chunks):
                doc_id = _content_id(folder_key, filepath.name, chunk)
                documents.append(
                    {
                        "id": doc_id,
                        "dataset_name": dataset_name,
                        "category": category,
                        "content": chunk,
                        "metadata": {
                            "source_file": relative_path,
                            "chunk_index": i,
                            "total_chunks": len(chunks),
                            "char_count": len(chunk),
                        },
                    }
                )
                file_count += 1

        logger.info(f"Loaded {file_count} chunks from {folder_key}/ ({category})")

    logger.info(f"Total documents loaded: {len(documents)}")
    return documents


# ── Batch upsert ──────────────────────────────────────────────────────────────


def batch_upsert(
    engine,
    documents: list[dict],
    batch_size: int = BATCH_SIZE_DEFAULT,
) -> int:
    """
    Generate embeddings and upsert documents into rag_documents in batches.
    Returns the number of documents upserted.
    """
    client = _get_gemini_client()
    total_upserted = 0

    for i in range(0, len(documents), batch_size):
        batch = documents[i : i + batch_size]
        texts = [doc["content"] for doc in batch]

        logger.info(f"Embedding batch {i // batch_size + 1} ({len(batch)} docs)...")
        embeddings = generate_embeddings(texts, client=client)

        upsert_sql = text("""
            INSERT INTO rag_documents (id, dataset_name, category, content, embedding, metadata, updated_at)
            VALUES (:id, :dataset_name, :category, :content, :embedding, :metadata, now())
            ON CONFLICT (id) DO UPDATE SET
                content = EXCLUDED.content,
                embedding = EXCLUDED.embedding,
                metadata = EXCLUDED.metadata,
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
                        "metadata": __import__("json").dumps(doc["metadata"]),
                    },
                )
            session.commit()

        total_upserted += len(batch)
        logger.info(f"Upserted {total_upserted}/{len(documents)} documents")

        # Small delay between batches to respect rate limits
        if i + batch_size < len(documents):
            time.sleep(0.5)

    return total_upserted


# ── Similarity search ─────────────────────────────────────────────────────────


def search_similar(
    query: str,
    top_k: int = 5,
    category_filter: str | None = None,
    dataset_filter: str | None = None,
    engine=None,
) -> list[dict]:
    """
    Find the most similar documents to a query using cosine distance.

    Args:
        query: The search query text.
        top_k: Number of results to return.
        category_filter: Optional category to filter by (deepfake, threat_intel, regulatory).
        dataset_filter: Optional dataset name to filter by.
        engine: SQLAlchemy engine (created from settings if None).

    Returns:
        List of dicts with keys: id, dataset_name, category, content, metadata, similarity.
    """
    if engine is None:
        engine = _get_engine()

    query_embedding = generate_embeddings([query])[0]

    where_clauses = []
    params = {
        "embedding": str(query_embedding),
        "top_k": top_k,
    }

    if category_filter:
        where_clauses.append("category = :category")
        params["category"] = category_filter

    if dataset_filter:
        where_clauses.append("dataset_name = :dataset_name")
        params["dataset_name"] = dataset_filter

    where_sql = (" AND " + " AND ".join(where_clauses)) if where_clauses else ""

    sql = text(f"""
        SELECT
            id,
            dataset_name,
            category,
            content,
            metadata,
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
                "id": row[0],
                "dataset_name": row[1],
                "category": row[2],
                "content": row[3],
                "metadata": row[4],
                "similarity": float(row[5]),
            }
            for row in rows
        ]


# ══════════════════════════════════════════════════════════════════════════════
# SEED DATA  -- Hackathon-ready knowledge chunks (~500 chunks when ingested)
# ══════════════════════════════════════════════════════════════════════════════

# ── Deepfake knowledge ────────────────────────────────────────────────────────

_DEEPFAKE_TECHNIQUES = """\
Face Swap (Identity Swap)

Face swapping replaces the face of a target individual with the face of another \
person using GAN-based models such as DeepFaceLab or FaceSwap. The source face is \
encoded into a latent representation and decoded onto the target's head pose and \
expression. Common tells include mismatched skin tones at the jaw boundary, \
inconsistent lighting direction, and subtle geometric distortion around the hairline.

---

Face Reenactment (Face2Face)

Face reenactment transfers facial expressions from a source actor to a target video \
without changing identity. Techniques like Face2Face track 3D facial landmarks in \
real-time and warp the target face accordingly. Artifacts typically appear around the \
mouth interior, teeth rendering, and rapid head movements that break temporal \
coherence.

---

Lip Sync Manipulation

Lip sync deepfakes modify only the mouth region to match a new audio track. \
Models such as Wav2Lip generate realistic lip movements from speech. Detection \
signals include unnatural jaw motion range, blurring at lip boundaries, and \
audio-visual synchronization drift over long sequences.

---

Full Head Synthesis

Neural head synthesis creates an entirely new talking head from a single photo or \
short video clip. Methods like MegaPortraits and LivePortrait learn a 3D-aware \
representation. Artifacts include static hair, missing ear details, and gaze \
direction inconsistencies when the head turns past training-time angles.

---

GAN-Based Face Generation (StyleGAN)

StyleGAN and its successors generate photorealistic faces that do not correspond to \
real people. The generator maps a latent code through a style-based architecture. \
Forensic cues include bilateral asymmetry in accessories (e.g., earrings), unusual \
background-to-hair transitions, and characteristic frequency-domain fingerprints \
caused by upsampling layers.

---

Diffusion-Based Face Forgery

Diffusion models such as Stable Diffusion can be fine-tuned (DreamBooth, LoRA) on a \
few images of a target person to generate new photorealistic images. Compared to GANs, \
diffusion artifacts are subtler: slight over-smoothing of skin textures, inconsistent \
specular highlights, and semantic errors in hands and fingers.

---

Voice Cloning with Visual Deepfake

Advanced attacks combine visual deepfakes with AI voice cloning (e.g., VALL-E, XTTS). \
The resulting video has both fabricated visuals and speech. Cross-modal consistency \
checks can reveal mismatches between prosody patterns and lip articulation dynamics.

---

Neural Radiance Fields (NeRF) Face Forgery

NeRF-based methods reconstruct a 3D head from 2D images and can render novel views. \
Attackers use this to create convincing video calls from static images. Detection \
relies on view-dependent lighting inconsistencies and missing sub-surface scattering \
that real skin exhibits.
"""

_DEEPFAKE_ARTIFACTS = """\
Common Deepfake Visual Artifacts

1. Face Boundary Artifacts
   Visible seams or color discontinuities at the boundary where the generated face \
meets the original frame. Often most apparent along the jawline and forehead.

2. Eye Blinking Irregularities
   Early deepfake models fail to reproduce natural blink rates (15-20 blinks/min). \
Missing or unusually regular blinks indicate synthetic generation.

3. Lighting and Shadow Mismatch
   Inconsistent specular highlights, shadow direction, or ambient occlusion between \
the face and the rest of the scene. The face may appear flat or over-lit.

4. Temporal Flickering
   Frame-to-frame inconsistencies in face texture, color, or geometry that cause a \
subtle flickering effect visible in video playback.

5. Unnatural Skin Texture
   Over-smoothing or plastic-like appearance caused by GAN training on low-resolution \
crops subsequently upsampled. Pores and fine wrinkles are absent.

6. Teeth and Mouth Rendering Errors
   Blurry or misshapen teeth, missing tongue details, and incorrect mouth interior \
are common. The soft palate and throat area are rarely modeled accurately.

7. Gaze Direction Anomalies
   The synthesized face may exhibit slight but detectable gaze offset from the \
intended direction, particularly during side-to-side eye movements.

8. Hair and Accessory Glitches
   Hair strands that clip through the face, earrings that appear only intermittently, \
and glasses that warp unnaturally during head movement.

9. GAN Frequency Fingerprints
   Spectral analysis of GAN-generated images reveals periodic patterns in the \
high-frequency domain, caused by transposed convolution or upsampling operations.

10. Audio-Visual Desynchronization
    In lip-sync fakes, the viseme (visual phoneme) sequence does not perfectly align \
with the audio spectrogram, detectable by cross-modal transformer models.

11. Compression Artifact Amplification
    Re-encoding a deepfake video amplifies boundary artifacts that were suppressed in \
the original. Multiple compression cycles make detection easier.

12. Physiological Signal Absence
    Real faces exhibit subtle color changes from blood flow (remote photoplethysmography). \
Synthetic faces lack these periodic signals, detectable via temporal frequency analysis.
"""

_DEEPFAKE_DATASETS = """\
Celeb-DF v2

Celeb-DF is a large-scale deepfake dataset designed to improve detection algorithms. \
It contains 590 real celebrity videos and 5,639 corresponding deepfake videos generated \
using an improved synthesis method that reduces visual artifacts compared to earlier \
datasets. The dataset features diverse ethnicities, ages, and lighting conditions. \
Resolution is 256x256 cropped faces. Celeb-DF v2 is widely used as a cross-dataset \
evaluation benchmark.

Source: https://github.com/yuezunli/celeb-deepfakeforensics
Paper: Li et al., "Celeb-DF: A Large-scale Challenging Dataset for DeepFake Forensics" (CVPR 2020)

---

FaceForensics++

FaceForensics++ is a benchmark dataset containing 1,000 original YouTube videos \
manipulated with four face manipulation methods: Deepfakes (autoencoder-based), \
Face2Face (expression transfer), FaceSwap (graphics-based), and NeuralTextures \
(learned texture rendering). Each method produces 1,000 manipulated videos at three \
quality levels (raw, high quality HQ c23, low quality LQ c40). The dataset also \
includes binary and multi-class segmentation masks.

Source: https://github.com/ondyari/FaceForensics
Paper: Rossler et al., "FaceForensics++: Learning to Detect Manipulated Facial Images" (ICCV 2019)

---

DFDC (Deepfake Detection Challenge)

The Deepfake Detection Challenge dataset from Facebook/Meta is one of the largest \
public deepfake datasets at approximately 470 GB. It contains over 100,000 clips \
featuring 3,426 paid actors with diverse demographics, manipulated using multiple \
approaches including neural face swap and audio swap. The dataset was designed for \
the Kaggle DFDC competition and includes train, validation, and test splits with \
metadata labels.

Source: https://www.kaggle.com/c/deepfake-detection-challenge/data
Paper: Dolhansky et al., "The DeepFake Detection Challenge Dataset" (2020)

---

DeeperForensics-1.0

DeeperForensics is a large-scale face forgery detection dataset featuring 60,000 \
videos with 17.6 million frames. It uses a novel end-to-end face swapping framework \
(DF-VAE) that generates higher quality forgeries than previous methods. The dataset \
includes perturbations simulating real-world degradation (compression, blur, noise, \
color saturation, contrast changes) at seven severity levels. Source videos feature \
100 paid actors.

Source: https://github.com/EndlessSora/DeeperForensics-1.0
Paper: Jiang et al., "DeeperForensics-1.0: A Large-Scale Dataset for Real-World Face Forgery Detection" (CVPR 2020)

---

WildDeepfake

WildDeepfake is a dataset of 7,314 face sequences extracted from 707 deepfake \
videos collected from the internet. Unlike lab-created datasets, these represent \
real-world deepfakes with varying quality, compression, and manipulation methods. \
This makes it valuable for testing detector generalization to in-the-wild conditions.

Source: https://github.com/deepfakeinthewild/deepfake-in-the-wild
Paper: Zi et al., "WildDeepfake: A Challenging Real-World Dataset for Deepfake Detection" (ACM MM 2020)
"""

_DEEPFAKE_DETECTION = """\
Detection Method: Frequency Analysis

Deepfake videos often contain abnormal frequency patterns due to GAN architecture \
choices. DCT (Discrete Cosine Transform) spectrum analysis reveals periodic artifacts \
from transposed convolution layers. The F3-Net architecture explicitly models \
frequency-aware features for forgery detection. Applying Fourier analysis to face \
crops can distinguish real from synthetic images with high accuracy, even across \
unknown generation methods.

---

Detection Method: Temporal Consistency Analysis

Real videos maintain natural temporal consistency in facial geometry, lighting, and \
color across consecutive frames. Deepfakes generated frame-by-frame exhibit subtle \
jitter, flickering, and discontinuities. Recurrent neural networks (LSTMs) and 3D \
CNNs capture these temporal artifacts. Optical flow between frames can highlight \
unnatural motion boundaries around the forged region.

---

Detection Method: Biological Signal Detection

Remote photoplethysmography (rPPG) extracts the blood volume pulse from facial \
video by measuring subtle color changes in the skin. Real faces show periodic signals \
at 0.7-4 Hz corresponding to heart rate. Deepfakes lack these signals or show \
attenuated/irregular patterns. DeepRhythm and other rPPG-based detectors achieve \
cross-dataset generalization because GAN generators do not model cardiovascular \
physiology.

---

Detection Method: Face Landmark Consistency

3D face alignment algorithms extract 68+ landmark points from each frame. In real \
videos, landmarks follow anatomically constrained trajectories. Deepfakes often \
produce landmarks with higher variance in inter-frame displacement, particularly \
around the nose bridge and eye corners. Statistical tests on landmark trajectories \
can detect manipulation without training a deep neural network.

---

Detection Method: Cross-Modal Audio-Visual Analysis

When deepfakes include modified speech, the visual lip movements and the audio \
waveform become misaligned. Models like SyncNet and AV-HuBERT measure audio-visual \
correlation and can flag videos where the viseme sequence does not match the \
phoneme sequence. This approach is particularly effective against lip-sync attacks.

---

Detection Method: Attention-Based Deep Networks

State-of-the-art detectors use attention mechanisms (EfficientNet-B4, Multi-Attentional, \
or Vision Transformers) to focus on the most discriminative facial regions. \
Self-attention maps learn to concentrate on forehead-jaw boundaries, eye orbits, \
and nostril regions where artifacts are most prominent. These networks generalize \
better than purely CNN-based approaches.

---

Detection Method: GAN Fingerprint Analysis

Each GAN architecture leaves a unique fingerprint in the generated image attributable \
to its specific upsampling and normalization layers. By training classifiers on these \
fingerprints, detectors can not only distinguish real from fake, but also attribute \
the specific generation model used. This is valuable for forensic investigations.

---

Detection Method: Compression-Aware Detection

Social media platforms re-compress uploaded videos, which removes some artifacts but \
introduces others. Robust detectors are trained with augmented data at multiple \
compression levels (JPEG quality 50-100, H.264 CRF 23-40). Some methods explicitly \
model compression as a noise layer during training to maintain detection accuracy \
on twice-compressed content.
"""

_DEEPFAKE_SCENARIOS = """\
Scenario: Political Deepfake Disinformation

An attacker generates a deepfake video of a political leader making inflammatory or \
false statements and distributes it on social media 48 hours before an election. \
The video is compressed to hide artifacts and shared via encrypted messaging apps \
to bypass platform detection.

Risk: Election manipulation, civil unrest, erosion of public trust.
Detection: Temporal consistency analysis, rPPG signal absence, metadata provenance check.
Mitigation: C2PA content credentials, rapid response detection infrastructure, \
media literacy awareness campaigns.

---

Scenario: Corporate CEO Fraud (Business Email Compromise Extension)

Attackers create a real-time deepfake of a company CEO on a video call instructing \
a finance executive to wire funds to a fraudulent account. The attacker uses voice \
cloning combined with face swap running on commodity hardware.

Risk: Financial loss (documented cases exceeding $25 million), reputational damage.
Detection: Cross-modal AV analysis, challenge-response protocols (ask a question \
only the real person would know), liveness detection with active challenges.
Mitigation: Multi-factor authorization for large transfers, out-of-band verification \
via a separate channel, AI-powered real-time deepfake detection in video platforms.

---

Scenario: Non-Consensual Intimate Imagery (NCII)

An attacker uses face swap technology to place a victim's face onto explicit content. \
This is distributed as harassment or extortion. The attack requires only a few public \
photos of the victim available on social media.

Risk: Psychological harm, reputation damage, legal liability for platforms.
Detection: Face recognition matching against known victims, GAN fingerprint analysis.
Mitigation: Platform hash-matching systems (e.g., StopNCII.org), legal frameworks \
criminalizing deepfake NCII, automated detection and takedown.

---

Scenario: Identity Verification Bypass

An attacker generates a deepfake video to pass a financial institution's video-based \
KYC (Know Your Customer) check. The attack uses a high-quality face swap with a \
real-time rendering pipeline to respond to liveness challenges.

Risk: Fraudulent account creation, money laundering, identity theft.
Detection: Active liveness testing (random head movements, card placement near face), \
injection attack detection (detecting virtual cameras or screen replay), depth sensing.
Mitigation: Certified liveness detection (ISO 30107-3), multi-factor identity \
verification, document chip verification (NFC on passports).

---

Scenario: Academic and Research Fraud

Fabricated video evidence is submitted as part of a research publication or grant \
application, showing experimental results that do not exist. AI-generated faces of \
fake researchers are used to create false identities on academic platforms.

Risk: Scientific integrity, wasted research funding, erosion of peer review trust.
Detection: Reverse image search, GAN face detection, metadata analysis of video files.
Mitigation: Cryptographic signing of experimental data, institutional data governance, \
preregistration of experiments.
"""

# ── Threat intelligence ───────────────────────────────────────────────────────

_MITRE_ATLAS_DATA = {
    "framework": "MITRE ATLAS (Adversarial Threat Landscape for AI Systems)",
    "version": "4.0",
    "description": (
        "ATLAS is a knowledge base of adversarial tactics, techniques, and case "
        "studies targeting machine learning systems. It extends the MITRE ATT&CK "
        "framework to cover AI-specific threats."
    ),
    "tactics": [
        {
            "id": "AML.TA0001",
            "name": "Reconnaissance",
            "description": (
                "Gathering information about the target ML system including model "
                "architecture, training data sources, API endpoints, framework "
                "versions, and deployment infrastructure."
            ),
        },
        {
            "id": "AML.TA0002",
            "name": "Resource Development",
            "description": (
                "Acquiring or developing resources to attack ML systems: shadow "
                "models, adversarial example toolkits, compute infrastructure, "
                "and synthetic training data."
            ),
        },
        {
            "id": "AML.TA0003",
            "name": "Initial Access",
            "description": (
                "Gaining initial access to the ML supply chain or deployment "
                "environment. Methods include compromising model registries, "
                "poisoning public datasets, or exploiting ML API vulnerabilities."
            ),
        },
        {
            "id": "AML.TA0004",
            "name": "ML Attack Staging",
            "description": (
                "Preparing adversarial inputs, crafting transferable perturbations, "
                "and developing trigger patterns for backdoor attacks. Staging may "
                "use a local copy of the model or a functionally equivalent proxy."
            ),
        },
        {
            "id": "AML.TA0005",
            "name": "ML Model Access",
            "description": (
                "Obtaining model predictions, gradients, or parameters. This ranges "
                "from black-box API queries to full white-box access after "
                "compromising the model serving infrastructure."
            ),
        },
        {
            "id": "AML.TA0006",
            "name": "Exfiltration",
            "description": (
                "Extracting valuable information from ML systems: model weights "
                "(model stealing), training data (data extraction), or proprietary "
                "intellectual property (hyperparameters, architecture details)."
            ),
        },
        {
            "id": "AML.TA0007",
            "name": "Impact",
            "description": (
                "Degrading or manipulating ML system behavior to cause harm: "
                "misclassification via adversarial examples, denial of service "
                "through resource exhaustion, or output manipulation through "
                "prompt injection."
            ),
        },
    ],
    "techniques": [
        {
            "id": "AML.T0043",
            "name": "Data Poisoning",
            "tactic": "Initial Access",
            "description": (
                "Injecting malicious samples into training data to compromise model "
                "behavior. Attacks include label flipping, backdoor injection "
                "(trojan triggers), and clean-label poisoning where the attacker "
                "does not change labels but crafts inputs that shift the decision "
                "boundary."
            ),
            "mitigations": [
                "Data sanitization and outlier detection",
                "Robust training algorithms (spectral signatures, activation clustering)",
                "Training data provenance tracking",
            ],
        },
        {
            "id": "AML.T0044",
            "name": "Adversarial Examples (Evasion)",
            "tactic": "Impact",
            "description": (
                "Crafting inputs with imperceptible perturbations that cause "
                "misclassification at inference time. Methods include FGSM, PGD, "
                "C&W, and AutoAttack. Perturbations can be L-inf, L2, or "
                "patch-based (e.g., adversarial patches on stop signs)."
            ),
            "mitigations": [
                "Adversarial training",
                "Input preprocessing and denoising",
                "Randomized smoothing for certified robustness",
                "Ensemble models with diverse architectures",
            ],
        },
        {
            "id": "AML.T0048",
            "name": "Model Stealing (Extraction)",
            "tactic": "Exfiltration",
            "description": (
                "Querying a target model API to build a functionally equivalent "
                "copy. The attacker sends crafted queries and trains a surrogate "
                "model on the input-output pairs. This compromises intellectual "
                "property and enables further white-box attacks on the surrogate."
            ),
            "mitigations": [
                "Rate limiting and query monitoring",
                "Watermarking model outputs",
                "Differential privacy in model training",
                "Output perturbation (rounding, adding noise)",
            ],
        },
        {
            "id": "AML.T0049",
            "name": "Training Data Extraction",
            "tactic": "Exfiltration",
            "description": (
                "Extracting memorized training data from a model through targeted "
                "querying. Large language models are especially susceptible; prefix "
                "prompting can induce verbatim recall of private training data "
                "including PII, API keys, and copyrighted content."
            ),
            "mitigations": [
                "Differential privacy during training",
                "Membership inference detection",
                "Output filtering for sensitive content",
                "Deduplication of training data",
            ],
        },
        {
            "id": "AML.T0051",
            "name": "Prompt Injection",
            "tactic": "Impact",
            "description": (
                "Manipulating LLM behavior by injecting adversarial instructions "
                "into prompts. Direct injection inserts commands in user input; "
                "indirect injection embeds instructions in external data sources "
                "(websites, emails, documents) that the LLM processes. This can "
                "bypass safety guardrails or exfiltrate data."
            ),
            "mitigations": [
                "Input/output filtering and sanitization",
                "System prompt hardening",
                "Privilege separation (LLM actions via sandboxed tools)",
                "Monitoring for anomalous outputs",
            ],
        },
        {
            "id": "AML.T0050",
            "name": "Model Backdoor (Trojan)",
            "tactic": "ML Attack Staging",
            "description": (
                "Embedding a hidden trigger in a model during training. The model "
                "performs normally on clean inputs but produces attacker-chosen "
                "outputs when the trigger pattern is present. Backdoors can be "
                "injected via poisoned training data, compromised pre-trained "
                "models, or supply chain attacks on model hubs."
            ),
            "mitigations": [
                "Neural cleanse and fine-pruning",
                "Model scanning for trigger patterns",
                "Training on curated and verified datasets",
                "Supply chain security for pre-trained models",
            ],
        },
        {
            "id": "AML.T0047",
            "name": "ML Supply Chain Compromise",
            "tactic": "Initial Access",
            "description": (
                "Compromising components in the ML development pipeline including "
                "model registries (Hugging Face, PyTorch Hub), training frameworks, "
                "data pipelines, or deployment infrastructure. Malicious code can "
                "execute during model loading via pickle deserialization or "
                "custom layer definitions."
            ),
            "mitigations": [
                "Verify model checksums and signatures",
                "Use safetensors format instead of pickle",
                "Pin framework versions and audit dependencies",
                "Scan models for known malicious patterns",
            ],
        },
    ],
    "case_studies": [
        {
            "title": "Tay Chatbot Manipulation (Microsoft, 2016)",
            "description": (
                "Coordinated users manipulated Microsoft's Tay chatbot via repeated "
                "adversarial interactions, causing it to produce offensive outputs "
                "within 16 hours of launch. This demonstrated vulnerability to "
                "online learning manipulation."
            ),
        },
        {
            "title": "GPT-4 Jailbreaking and Prompt Injection Attacks (2023-2024)",
            "description": (
                "Researchers demonstrated multiple prompt injection techniques "
                "against GPT-4 and other LLMs including DAN (Do Anything Now), "
                "multi-turn attacks, and encoded prompt injection via base64 and "
                "other encodings to bypass safety filters."
            ),
        },
        {
            "title": "Adversarial Patches on Autonomous Vehicles",
            "description": (
                "Physical adversarial patches placed on stop signs or road surfaces "
                "cause misclassification by autonomous vehicle perception systems. "
                "Demonstrations include making stop signs invisible to detectors "
                "and traffic light misclassification."
            ),
        },
        {
            "title": "ModelScope Malicious Model Upload (2023)",
            "description": (
                "Researchers discovered that model files uploaded to public model "
                "hubs could contain arbitrary code executed during deserialization. "
                "This supply chain vector could compromise any system that loads "
                "an untrusted model."
            ),
        },
    ],
}

_THREAT_SCENARIOS = """\
AI Threat Scenario: Model Poisoning Attack on Content Moderation

An adversary systematically contributes mislabeled examples to a crowdsourced \
content moderation training dataset over several months. The poisoned data causes \
the production classifier to consistently miss hate speech containing specific \
dog-whistle terms while increasing false positives on benign content.

Impact: Hate speech proliferation, user safety degradation, regulator action.
ATLAS Mapping: AML.T0043 Data Poisoning, AML.TA0003 Initial Access
Detection: Monitor model performance for distributional shift, implement data \
provenance tracking, use statistical outlier detection on new training batches.

---

AI Threat Scenario: Adversarial Evasion of Deepfake Detector

An attacker applies adversarial perturbations to a deepfake video to evade \
VibeSecure's deepfake detection system. Using a transferable attack (PGD with \
ensemble of substitute detectors), the perturbations are invisible to humans but \
cause the detector to classify the fake as real with high confidence.

Impact: False negative in security screening, deepfake content bypasses platform moderation.
ATLAS Mapping: AML.T0044 Adversarial Examples, AML.TA0007 Impact
Detection: Ensemble multiple detection approaches (frequency, temporal, biological), \
apply input preprocessing (JPEG compression, spatial smoothing), monitor for confidence \
distribution anomalies.

---

AI Threat Scenario: Prompt Injection via Document Analysis

A malicious PDF is submitted to VibeSecure for AI governance analysis. The document \
contains hidden text (white text on white background) with prompt injection instructions \
that attempt to override the system prompt and exfiltrate previous conversation context.

Impact: Data leakage, system prompt extraction, governance assessment manipulation.
ATLAS Mapping: AML.T0051 Prompt Injection, AML.TA0007 Impact
Detection: Input sanitization pipeline, text extraction auditing, output monitoring \
for anomalous content, system prompt isolation.

---

AI Threat Scenario: Model Supply Chain Attack via Hugging Face

An attacker uploads a backdoored pre-trained model to Hugging Face with a name \
similar to a popular model (typosquatting). Organizations that download and fine-tune \
this model inherit the backdoor. The model performs normally except when a specific \
trigger phrase appears in the input, causing it to produce attacker-controlled output.

Impact: Compromised downstream applications, data exfiltration at inference time.
ATLAS Mapping: AML.T0047 ML Supply Chain Compromise, AML.T0050 Model Backdoor
Detection: Verify model checksums, use SafeTensors format, neural cleanse scanning, \
maintain an approved model registry.

---

AI Threat Scenario: Training Data Extraction from RAG System

An attacker queries VibeSecure's RAG system with carefully crafted prompts designed \
to extract verbatim training data from the vector database. By iteratively probing \
near decision boundaries, the attacker reconstructs private regulatory analysis \
documents and client assessment reports.

Impact: Confidential data leakage, IP theft, regulatory compliance violation.
ATLAS Mapping: AML.T0049 Training Data Extraction, AML.TA0006 Exfiltration
Detection: Query rate limiting, similarity score thresholding (reject exact matches), \
differential privacy in embeddings, output monitoring for PII patterns.
"""

_AI_SUPPLY_CHAIN = """\
AI Supply Chain Security

The AI supply chain encompasses all components from data collection through model \
deployment. Each stage introduces potential vulnerabilities:

1. Data Collection and Labeling
   - Risk: Poisoned datasets from untrusted sources
   - Risk: Label manipulation by malicious annotators
   - Control: Data provenance verification, multi-annotator consensus

2. Pre-trained Model Selection
   - Risk: Backdoored models on public hubs (Hugging Face, PyTorch Hub)
   - Risk: Pickle deserialization exploits in model files
   - Control: Checksum verification, SafeTensors format, approved model registry

3. Training Infrastructure
   - Risk: Compromised training frameworks or dependencies
   - Risk: GPU cluster side-channel attacks
   - Control: Dependency pinning, reproducible builds, isolated training environments

4. Model Registry and Versioning
   - Risk: Unauthorized model replacement (model registry tampering)
   - Risk: Version confusion between staging and production models
   - Control: Cryptographic signing, immutable versioning, access auditing

5. Serving Infrastructure
   - Risk: Model serving API vulnerabilities (injection, DoS)
   - Risk: Inference side-channel attacks (timing, power analysis)
   - Control: Input validation, rate limiting, hardware-level protections

6. Monitoring and Feedback Loops
   - Risk: Adversarial drift via targeted feedback manipulation
   - Risk: Gradual model degradation from distribution shift
   - Control: Continuous performance monitoring, automated drift detection

---

SBOM for AI Systems (AI BOM)

The concept of a Software Bill of Materials (SBOM) extended to AI includes:

- Data BOM: Provenance of all training and evaluation datasets
- Model BOM: Architecture, training hyperparameters, base model lineage
- Code BOM: Framework versions, library dependencies, custom code
- Infrastructure BOM: Hardware, cloud services, orchestration tools
- Evaluation BOM: Benchmark results, bias audits, safety evaluations

Standards: SPDX AI Profile, CycloneDX ML BOM, NIST AI RMF, EU AI Act Annex IV
"""

# ── Regulatory compliance ─────────────────────────────────────────────────────

_GDPR_TEXT = """\
General Data Protection Regulation (GDPR) - Key Provisions for AI Systems

Regulation (EU) 2016/679 of the European Parliament and of the Council

Article 5 - Principles Relating to Processing of Personal Data

Personal data shall be:
(a) Processed lawfully, fairly, and in a transparent manner (lawfulness, fairness, \
and transparency).
(b) Collected for specified, explicit, and legitimate purposes and not further \
processed in a manner incompatible with those purposes (purpose limitation).
(c) Adequate, relevant, and limited to what is necessary (data minimisation).
(d) Accurate and, where necessary, kept up to date (accuracy).
(e) Kept in a form which permits identification for no longer than necessary \
(storage limitation).
(f) Processed in a manner that ensures appropriate security (integrity and \
confidentiality).

---

Article 13 - Information to Be Provided Where Personal Data Are Collected

Where personal data are collected from the data subject, the controller shall \
provide the following information: the existence of automated decision-making, \
including profiling, and meaningful information about the logic involved, as well \
as the significance and the envisaged consequences of such processing for the \
data subject.

---

Article 15 - Right of Access by the Data Subject

The data subject shall have the right to obtain from the controller confirmation \
as to whether personal data concerning them are being processed. Where personal \
data are transferred to a third country, the data subject shall have the right to \
be informed of the appropriate safeguards.

---

Article 17 - Right to Erasure (Right to Be Forgotten)

The data subject shall have the right to obtain from the controller the erasure of \
personal data without undue delay where: the personal data are no longer necessary, \
the data subject withdraws consent, the data subject objects to the processing, \
the personal data have been unlawfully processed, or for compliance with a legal \
obligation. This has implications for ML models trained on personal data -- the \
model itself may need to be retrained or undergo machine unlearning.

---

Article 22 - Automated Individual Decision-Making, Including Profiling

The data subject shall have the right not to be subject to a decision based solely \
on automated processing, including profiling, which produces legal effects or \
similarly significantly affects them. This does not apply if the decision is \
necessary for a contract, authorized by law, or based on explicit consent. In any \
case, the controller shall implement suitable measures to safeguard the data \
subject's rights including the right to obtain human intervention, to express their \
point of view, and to contest the decision.

---

Article 25 - Data Protection by Design and by Default

The controller shall implement appropriate technical and organizational measures \
designed to implement data protection principles effectively and to integrate \
safeguards into the processing. Such measures shall ensure that by default only \
personal data which are necessary for each specific purpose are processed.

For AI systems this means: privacy-preserving training techniques (differential \
privacy, federated learning), data minimization in feature engineering, and purpose \
limitation in model deployment.

---

Article 35 - Data Protection Impact Assessment (DPIA)

Where processing is likely to result in a high risk to the rights and freedoms of \
natural persons, the controller shall carry out a Data Protection Impact Assessment. \
AI systems that profile individuals, make automated decisions with legal effects, \
or process biometric data (including deepfake detection systems) typically require \
a DPIA.

---

Article 44-49 - Transfers of Personal Data to Third Countries

Personal data may only be transferred to countries outside the EU/EEA that ensure \
an adequate level of protection. AI systems that process personal data must consider \
where training data is stored, where model inference occurs, and where results are \
transmitted. Cloud-based AI services may inadvertently transfer data across borders.

---

Recital 71 - Automated Decision-Making Safeguards

The data subject should have the right to obtain an explanation of the decision \
reached after assessment and to challenge the decision. Measures should include \
specific information to the data subject and the right to obtain human intervention, \
express their view, obtain an explanation, and contest the decision. This is often \
cited as establishing a "right to explanation" for AI decisions.

---

GDPR Penalties

Violations of Articles 5, 6, 7 (consent), 12-22 (data subject rights), 44-49 \
(data transfers): up to 20 million EUR or 4% of global annual turnover, whichever \
is higher. Violations of Articles 25, 26, 28-34, 35-39, 42, 43: up to 10 million \
EUR or 2% of global annual turnover.
"""

_CCPA_TEXT = """\
California Consumer Privacy Act (CCPA) / California Privacy Rights Act (CPRA)

Key Provisions Relevant to AI Systems

Section 1798.100 - Right to Know

A consumer shall have the right to request that a business disclose what personal \
information it collects, uses, sells, or shares. For AI systems, this includes \
disclosing: what data is used for training, whether personal information is used \
for profiling, and whether automated decision-making is employed.

---

Section 1798.105 - Right to Delete

A consumer has the right to request deletion of personal information collected by \
a business. AI implications: businesses may need to retrain models or apply machine \
unlearning techniques when deletion requests affect training data.

---

Section 1798.106 - Right to Correct

(Added by CPRA) A consumer has the right to request that inaccurate personal \
information be corrected. For ML systems, this means correcting training labels \
or feature data and potentially retraining affected models.

---

Section 1798.110 - Right to Know Categories

Consumers can request the categories of personal information collected, the \
categories of sources, the business or commercial purpose for collecting, and \
the categories of third parties to whom information is disclosed. AI training \
data pipelines must maintain sufficient metadata to respond to these requests.

---

Section 1798.121 - Right to Opt-Out (Sensitive Personal Information)

(Added by CPRA) Consumers can limit a business's use of sensitive personal \
information to purposes necessary for providing the goods or services. AI \
systems using biometric data (face recognition, deepfake detection) must offer \
opt-out mechanisms.

---

Section 1798.135 - Automated Decision-Making Technology (ADMT)

(CPRA regulations) Businesses must provide consumers with information about their \
use of ADMT and the logic involved. Consumers have the right to opt out of \
automated decision-making and to access information about outcomes. The CPRA \
regulations define ADMT as any technology that processes personal information \
and uses computation to generate a decision, prediction, or recommendation.

---

Section 1798.185 - Profiling and Automated Decision-Making Regulations

The California Privacy Protection Agency is authorized to issue regulations \
governing: access and opt-out rights for profiling, performing risk assessments \
for ADMT, and cybersecurity audits for businesses processing personal information.

---

CCPA/CPRA Penalties

Civil penalties: up to $2,500 per unintentional violation and $7,500 per \
intentional violation. Private right of action for data breaches: $100-$750 per \
consumer per incident (or actual damages if greater).
"""

_DPDP_TEXT = """\
Digital Personal Data Protection Act, 2023 (India)

Key Provisions Relevant to AI Systems

Section 4 - Consent and Lawful Processing

Personal data shall be processed only for a lawful purpose after obtaining the \
consent of the Data Principal (individual). Consent must be free, specific, \
informed, unconditional, and unambiguous with a clear affirmative action. \
Consent can be withdrawn at any time.

For AI systems: Training on Indian citizens' personal data requires valid consent \
(or statutory basis). Purpose limitation applies - data collected for one purpose \
cannot be repurposed for model training without fresh consent.

---

Section 5 - Notice Requirements

Before requesting consent, the Data Fiduciary (controller) must provide a notice \
containing: the personal data to be processed, the purpose, how to exercise \
rights, and how to file complaints. AI systems must clearly communicate when \
personal data will be used for automated processing.

---

Section 6 - Deemed Consent (Legitimate Uses)

Personal data may be processed without explicit consent for: compliance with law, \
medical emergencies, employment purposes, and public interest. The "public interest" \
category may apply to AI safety and deepfake detection systems, though boundaries \
remain to be tested.

---

Section 8 - Rights of the Data Principal

Data principals have the right to:
(a) Information about processing
(b) Correction and erasure of personal data
(c) Grievance redressal
(d) Nominate another person to exercise rights in case of death or incapacity

For AI/ML: The right to erasure may require machine unlearning or model retraining. \
The right to correction requires mechanisms to update training data.

---

Section 9 - Duties of Data Principal

Data principals must: not register false complaints, not furnish false information, \
and comply with applicable data governance laws. This includes not submitting \
falsified biometric data to defeat AI verification systems.

---

Section 10 - Obligations of Data Fiduciary

Data Fiduciaries must:
(a) Ensure completeness, accuracy, and consistency of data
(b) Implement reasonable security safeguards
(c) Notify the Data Protection Board and affected individuals of breaches
(d) Erase personal data when the purpose is fulfilled (unless retention required by law)

AI companies must demonstrate they can fulfill these obligations for data used \
in model training and inference.

---

Section 17 - Significant Data Fiduciary

The Central Government may designate certain Data Fiduciaries as "Significant" \
based on volume of data processed, risk to data principals, and national security \
impact. Significant Data Fiduciaries must:
(a) Appoint a Data Protection Officer (resident of India)
(b) Appoint an independent Data Auditor
(c) Conduct periodic data protection impact assessments
(d) Additional obligations as prescribed

AI companies processing large volumes of Indian personal data are likely to be \
designated as Significant Data Fiduciaries.

---

Section 16 - Processing of Children's Data

Processing personal data of children (under 18) requires verifiable parental \
consent. Tracking, behavioral monitoring, and targeted advertising directed at \
children are prohibited. AI systems (including social media recommendation \
algorithms) must implement age verification and parental consent flows.

---

Section 33-34 - Penalties

Penalties for non-compliance range up to INR 250 crore (approximately USD 30 million) \
per instance. Failure to implement security safeguards: up to INR 250 crore. \
Failure to notify breach: up to INR 200 crore. Non-compliance with children's \
data provisions: up to INR 200 crore.

---

Cross-Border Data Transfer (Section 16)

The Central Government may restrict transfer of personal data to certain countries \
by notification. Unlike GDPR adequacy decisions, India takes a blacklist approach - \
transfers are allowed unless specifically restricted. AI companies must monitor \
government notifications on restricted jurisdictions.
"""

_EU_AI_ACT_TEXT = """\
European Union Artificial Intelligence Act (EU AI Act)

Regulation (EU) 2024/1689 - Harmonised Rules on Artificial Intelligence

Title I - General Provisions

Article 3 - Definitions

'AI system' means a machine-based system designed to operate with varying levels \
of autonomy, that may exhibit adaptiveness after deployment, and that, for \
explicit or implicit objectives, infers from inputs how to generate outputs such \
as predictions, content, recommendations, or decisions that can influence physical \
or virtual environments.

'High-risk AI system' means an AI system listed in Annex III and used in areas such \
as biometrics, critical infrastructure, education, employment, law enforcement, \
migration, and democratic processes.

---

Title II - Prohibited AI Practices (Article 5)

The following AI practices are prohibited:
(a) Subliminal or purposefully manipulative AI techniques causing significant harm
(b) Exploitation of vulnerabilities due to age, disability, or social situation
(c) Social scoring by public authorities (general-purpose scoring of citizens)
(d) Real-time remote biometric identification in publicly accessible spaces for \
law enforcement (with exceptions for targeted search for victims, prevention of \
specific threats, and investigation of serious crimes)
(e) Biometric categorisation based on sensitive attributes (race, political opinions, \
sexual orientation)
(f) Untargeted scraping of facial images from internet or CCTV for facial \
recognition databases
(g) Emotion recognition in workplaces and educational institutions (with exceptions)

---

Title III, Chapter 2 - Requirements for High-Risk AI Systems

Article 9 - Risk Management System

High-risk AI systems must have a continuous risk management system that: identifies \
and analyses known and reasonably foreseeable risks, estimates and evaluates risks \
from intended and misuse scenarios, and adopts risk management measures.

Article 10 - Data and Data Governance

Training, validation, and testing datasets must be: relevant, sufficiently \
representative, and free of errors. Datasets must be examined for possible biases \
that could lead to discriminatory impacts. For systems using personal data, \
appropriate data governance measures must be implemented.

Article 11 - Technical Documentation

High-risk AI systems must have technical documentation demonstrating compliance, \
including: intended purpose, design specifications, training methodologies, data \
requirements, performance metrics, risk management, and human oversight measures.

Article 13 - Transparency and Information to Deployers

High-risk AI systems must be sufficiently transparent to enable deployers to \
interpret and use outputs appropriately. Instructions for use must include: \
characteristics, capabilities, limitations, intended purpose, performance metrics, \
known risks, and human oversight measures.

Article 14 - Human Oversight

High-risk AI systems must incorporate human oversight measures enabling individuals \
to: fully understand the system's capabilities and limitations, correctly interpret \
outputs, decide not to use the system or override its output, and interrupt or stop \
the system. Human oversight measures shall be proportionate to the risks.

Article 15 - Accuracy, Robustness, and Cybersecurity

High-risk AI systems must achieve appropriate levels of accuracy, robustness, and \
cybersecurity. They must be resilient against errors, faults, inconsistencies, and \
attempts to alter their use by unauthorized third parties. This explicitly covers \
adversarial attacks: systems must be technically robust against adversarial machine \
learning techniques including data poisoning, model manipulation, and adversarial \
examples.

---

Title III, Chapter 3 - Obligations of Providers of High-Risk AI Systems

Article 16-27 cover obligations including: quality management systems, conformity \
assessment, CE marking, registration in the EU database, post-market monitoring, \
serious incident reporting, and cooperation with competent authorities.

---

Title IV - Transparency Obligations for Certain AI Systems (Article 50)

(a) AI systems intended to interact with natural persons must disclose that the \
person is interacting with an AI system (chatbots, virtual agents).
(b) Providers of AI systems generating synthetic audio, image, video, or text \
content must ensure outputs are machine-detectable as artificially generated \
(deepfake watermarking, C2PA metadata).
(c) Deployers of emotion recognition or biometric categorisation systems must \
inform individuals of the system's operation.
(d) Deepfakes must be labeled: deployers of AI systems that generate or manipulate \
image, audio, or video content constituting a "deep fake" must disclose that the \
content has been artificially generated or manipulated.

---

Title V - General-Purpose AI Models (Articles 51-56)

Article 51 - Classification as GPAI Model with Systemic Risk

A GPAI model is classified as having systemic risk if: it has high impact \
capabilities (cumulative compute used for training exceeds 10^25 FLOPs), or the \
Commission designates it based on criteria including number of registered end users, \
downstream dependence, and capability evaluations.

Article 53 - Obligations for Providers of GPAI Models

All GPAI model providers must: maintain technical documentation, provide information \
to downstream AI system providers, publish a sufficiently detailed summary of \
training data content, and comply with Union copyright law.

Article 55 - Additional Obligations for GPAI with Systemic Risk

Providers of GPAI models with systemic risk must additionally: perform model \
evaluation including adversarial testing (red teaming), assess and mitigate \
systemic risks, track and report serious incidents, and ensure adequate \
cybersecurity protection for the model and its infrastructure.

---

Title X - Penalties (Articles 99-101)

Non-compliance with prohibited AI practices: up to EUR 35 million or 7% of global \
annual turnover. Non-compliance with other provisions: up to EUR 15 million or 3% \
of global annual turnover. Supply of incorrect information: up to EUR 7.5 million \
or 1% of global annual turnover.

---

Annex III - High-Risk AI Use Cases (selected)

1. Biometrics: Remote biometric identification, biometric categorisation, emotion \
recognition
2. Critical infrastructure: Safety components in management of energy, water, gas, \
heating, road traffic, and digital infrastructure
3. Education: Determining access to education, evaluating learning outcomes
4. Employment: Recruitment, selection, evaluation, monitoring of workers
5. Essential services: Credit scoring, insurance risk assessment, emergency services \
dispatch
6. Law enforcement: Risk assessment of individuals, polygraphs, evidence assessment, \
profiling for crime detection
7. Migration: Polygraphs, risk assessment, document authenticity, visa applications
8. Democratic processes: AI systems used to influence the outcome of elections

---

Timeline

August 1, 2024: Entry into force
February 2, 2025: Prohibited practices apply
August 2, 2025: GPAI model obligations and governance chapters apply
August 2, 2026: Full application of high-risk AI system requirements
August 2, 2027: Obligations for high-risk AI systems integrated into existing \
sectoral safety legislation
"""


# ── Seed data generator ───────────────────────────────────────────────────────


def seed_data(data_dir: Path) -> None:
    """
    Generate hackathon-ready demo dataset files in data_dir.
    Creates ~500 knowledge chunks across deepfake, threat_intel, and regulatory.
    """
    data_dir.mkdir(parents=True, exist_ok=True)

    # ── Deepfake knowledge ────────────────────────────────────────────────
    df_dir = data_dir / "deepfake"
    df_dir.mkdir(exist_ok=True)

    (df_dir / "techniques.txt").write_text(_DEEPFAKE_TECHNIQUES, encoding="utf-8")
    (df_dir / "artifacts.txt").write_text(_DEEPFAKE_ARTIFACTS, encoding="utf-8")
    (df_dir / "datasets.txt").write_text(_DEEPFAKE_DATASETS, encoding="utf-8")
    (df_dir / "detection_methods.txt").write_text(_DEEPFAKE_DETECTION, encoding="utf-8")
    (df_dir / "attack_scenarios.txt").write_text(_DEEPFAKE_SCENARIOS, encoding="utf-8")

    # ── Threat intelligence ───────────────────────────────────────────────
    th_dir = data_dir / "threats"
    th_dir.mkdir(exist_ok=True)

    (th_dir / "mitre_atlas.json").write_text(
        json.dumps(_MITRE_ATLAS_DATA, indent=2), encoding="utf-8"
    )
    (th_dir / "attack_scenarios.txt").write_text(_THREAT_SCENARIOS, encoding="utf-8")
    (th_dir / "ai_supply_chain.txt").write_text(_AI_SUPPLY_CHAIN, encoding="utf-8")

    # ── Regulatory compliance ─────────────────────────────────────────────
    reg_dir = data_dir / "regulations"
    reg_dir.mkdir(exist_ok=True)

    (reg_dir / "gdpr.txt").write_text(_GDPR_TEXT, encoding="utf-8")
    (reg_dir / "ccpa.txt").write_text(_CCPA_TEXT, encoding="utf-8")
    (reg_dir / "dpdp.txt").write_text(_DPDP_TEXT, encoding="utf-8")
    (reg_dir / "eu_ai_act.txt").write_text(_EU_AI_ACT_TEXT, encoding="utf-8")

    logger.info(f"Seed data written to {data_dir}/")


# ── CLI ───────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(description="VibeSecure RAG Dataset Upsert")
    sub = parser.add_subparsers(dest="command", required=True)

    # Init subcommand
    sub.add_parser("init", help="Create the PgVector extension and table only")

    # Seed subcommand
    seed_parser = sub.add_parser("seed", help="Generate demo dataset files in data/")
    seed_parser.add_argument(
        "--data-dir",
        type=Path,
        default=Path("data"),
        help="Path to write seed data files (default: data/)",
    )

    # Upsert subcommand
    upsert_parser = sub.add_parser("upsert", help="Load datasets and upsert into PgVector")
    upsert_parser.add_argument(
        "--data-dir",
        type=Path,
        default=Path("data"),
        help="Path to the data directory containing dataset folders",
    )
    upsert_parser.add_argument(
        "--batch-size",
        type=int,
        default=BATCH_SIZE_DEFAULT,
        help=f"Number of documents per embedding/upsert batch (default: {BATCH_SIZE_DEFAULT})",
    )

    # Search subcommand
    search_parser = sub.add_parser("search", help="Search for similar documents")
    search_parser.add_argument("query", help="Search query text")
    search_parser.add_argument("--top-k", type=int, default=5, help="Number of results")
    search_parser.add_argument(
        "--category",
        choices=["deepfake", "threat_intel", "regulatory"],
        help="Filter by category",
    )
    search_parser.add_argument("--dataset", help="Filter by dataset name (file stem)")

    args = parser.parse_args()

    if args.command == "seed":
        seed_data(args.data_dir)
        return

    engine = _get_engine()

    if args.command == "init":
        ensure_pgvector(engine)
        logger.info("Done. Table rag_documents is ready.")

    elif args.command == "upsert":
        ensure_pgvector(engine)
        documents = load_datasets(args.data_dir)
        if not documents:
            logger.error("No documents found. Check your data directory structure.")
            sys.exit(1)
        count = batch_upsert(engine, documents, batch_size=args.batch_size)
        logger.info(f"Upsert complete. {count} documents processed.")

    elif args.command == "search":
        results = search_similar(
            query=args.query,
            top_k=args.top_k,
            category_filter=args.category,
            dataset_filter=args.dataset,
            engine=engine,
        )
        if not results:
            print("No results found.")
            return
        for i, r in enumerate(results, 1):
            print(f"\n--- Result {i} (similarity: {r['similarity']:.4f}) ---")
            print(f"Dataset: {r['dataset_name']} | Category: {r['category']}")
            print(f"Content: {r['content'][:300]}{'...' if len(r['content']) > 300 else ''}")
            print(f"Metadata: {r['metadata']}")


if __name__ == "__main__":
    main()
