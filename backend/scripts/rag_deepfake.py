#!/usr/bin/env python3
"""
Deepfake RAG Ingestion Script for VibeSecure AI.

Seeds curated deepfake knowledge (techniques, artifacts, detection methods,
dataset descriptions, attack scenarios) and upserts into PgVector.

Usage:
    cd backend
    python -m scripts.rag_deepfake seed                     # write data/ files
    python -m scripts.rag_deepfake upsert                   # embed + upsert
    python -m scripts.rag_deepfake upsert --data-dir ./data/deepfake
    python -m scripts.rag_deepfake search "face swap detection"
"""

import argparse
import json
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.rag.core import (
    batch_upsert,
    chunk_text,
    content_id,
    ensure_pgvector,
    get_rag_engine,
    search_similar,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("rag_deepfake")

CATEGORY = "deepfake"

# ══════════════════════════════════════════════════════════════════════════════
# Seed data -- curated deepfake knowledge for hackathon demo
# ══════════════════════════════════════════════════════════════════════════════

SEED_FILES = {
    "techniques.txt": """\
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
mouth interior, teeth rendering, and rapid head movements that break temporal coherence.

---

Lip Sync Manipulation

Lip sync deepfakes modify only the mouth region to match a new audio track. Models \
such as Wav2Lip generate realistic lip movements from speech. Detection signals include \
unnatural jaw motion range, blurring at lip boundaries, and audio-visual \
synchronization drift over long sequences.

---

Full Head Synthesis

Neural head synthesis creates an entirely new talking head from a single photo or \
short video clip. Methods like MegaPortraits and LivePortrait learn a 3D-aware \
representation. Artifacts include static hair, missing ear details, and gaze direction \
inconsistencies when the head turns past training-time angles.

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
""",
    "artifacts.txt": """\
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
""",
    "datasets.txt": """\
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
the Kaggle DFDC competition and includes train, validation, and test splits.

Source: https://www.kaggle.com/c/deepfake-detection-challenge/data
Paper: Dolhansky et al., "The DeepFake Detection Challenge Dataset" (2020)

---

DeeperForensics-1.0

DeeperForensics is a large-scale face forgery detection dataset featuring 60,000 \
videos with 17.6 million frames. It uses a novel end-to-end face swapping framework \
(DF-VAE) that generates higher quality forgeries than previous methods. The dataset \
includes perturbations simulating real-world degradation (compression, blur, noise, \
color saturation, contrast changes) at seven severity levels.

Source: https://github.com/EndlessSora/DeeperForensics-1.0
Paper: Jiang et al., "DeeperForensics-1.0" (CVPR 2020)

---

WildDeepfake

WildDeepfake is a dataset of 7,314 face sequences extracted from 707 deepfake \
videos collected from the internet. Unlike lab-created datasets, these represent \
real-world deepfakes with varying quality, compression, and manipulation methods. \
Valuable for testing detector generalization to in-the-wild conditions.

Source: https://github.com/deepfakeinthewild/deepfake-in-the-wild
Paper: Zi et al., "WildDeepfake" (ACM MM 2020)
""",
    "detection_methods.txt": """\
Detection Method: Frequency Analysis

Deepfake videos often contain abnormal frequency patterns due to GAN architecture \
choices. DCT (Discrete Cosine Transform) spectrum analysis reveals periodic artifacts \
from transposed convolution layers. The F3-Net architecture explicitly models \
frequency-aware features for forgery detection.

---

Detection Method: Temporal Consistency Analysis

Real videos maintain natural temporal consistency in facial geometry, lighting, and \
color across consecutive frames. Deepfakes generated frame-by-frame exhibit subtle \
jitter, flickering, and discontinuities. Recurrent neural networks (LSTMs) and 3D \
CNNs capture these temporal artifacts.

---

Detection Method: Biological Signal Detection (rPPG)

Remote photoplethysmography (rPPG) extracts the blood volume pulse from facial \
video by measuring subtle color changes in the skin. Real faces show periodic signals \
at 0.7-4 Hz corresponding to heart rate. Deepfakes lack these signals or show \
attenuated/irregular patterns.

---

Detection Method: Face Landmark Consistency

3D face alignment algorithms extract 68+ landmark points from each frame. In real \
videos, landmarks follow anatomically constrained trajectories. Deepfakes often \
produce landmarks with higher variance in inter-frame displacement.

---

Detection Method: Cross-Modal Audio-Visual Analysis

When deepfakes include modified speech, the visual lip movements and the audio \
waveform become misaligned. Models like SyncNet and AV-HuBERT measure audio-visual \
correlation and can flag videos where the viseme sequence does not match the phoneme sequence.

---

Detection Method: Attention-Based Deep Networks

State-of-the-art detectors use attention mechanisms (EfficientNet-B4, Vision \
Transformers) to focus on the most discriminative facial regions. Self-attention \
maps learn to concentrate on forehead-jaw boundaries, eye orbits, and nostril regions.

---

Detection Method: GAN Fingerprint Analysis

Each GAN architecture leaves a unique fingerprint in the generated image attributable \
to its specific upsampling and normalization layers. By training classifiers on these \
fingerprints, detectors can attribute the specific generation model used.

---

Detection Method: Compression-Aware Detection

Social media platforms re-compress uploaded videos, which removes some artifacts but \
introduces others. Robust detectors are trained with augmented data at multiple \
compression levels (JPEG quality 50-100, H.264 CRF 23-40).
""",
    "attack_scenarios.txt": """\
Scenario: Political Deepfake Disinformation

An attacker generates a deepfake video of a political leader making inflammatory or \
false statements and distributes it on social media 48 hours before an election.

Risk: Election manipulation, civil unrest, erosion of public trust.
Detection: Temporal consistency analysis, rPPG signal absence, metadata provenance check.
Mitigation: C2PA content credentials, rapid response detection infrastructure.

---

Scenario: Corporate CEO Fraud (BEC Extension)

Attackers create a real-time deepfake of a company CEO on a video call instructing \
a finance executive to wire funds to a fraudulent account. The attacker uses voice \
cloning combined with face swap running on commodity hardware.

Risk: Financial loss (documented cases exceeding $25 million), reputational damage.
Detection: Cross-modal AV analysis, challenge-response protocols, liveness detection.
Mitigation: Multi-factor authorization for large transfers, out-of-band verification.

---

Scenario: Non-Consensual Intimate Imagery (NCII)

An attacker uses face swap technology to place a victim's face onto explicit content. \
Distributed as harassment or extortion. Requires only a few public photos.

Risk: Psychological harm, reputation damage, legal liability for platforms.
Detection: Face recognition matching against known victims, GAN fingerprint analysis.
Mitigation: Platform hash-matching (StopNCII.org), legal frameworks.

---

Scenario: Identity Verification Bypass (KYC Fraud)

An attacker generates a deepfake video to pass a financial institution's video-based \
KYC check. Uses high-quality face swap with real-time rendering to respond to liveness challenges.

Risk: Fraudulent account creation, money laundering, identity theft.
Detection: Active liveness testing, injection attack detection, depth sensing.
Mitigation: Certified liveness (ISO 30107-3), multi-factor identity verification.

---

Scenario: Academic and Research Fraud

Fabricated video evidence submitted as part of a research publication. AI-generated \
faces of fake researchers used to create false identities on academic platforms.

Risk: Scientific integrity, wasted research funding.
Detection: Reverse image search, GAN face detection, metadata analysis.
Mitigation: Cryptographic signing of experimental data, preregistration.
""",
}


# ── Load / prepare documents ─────────────────────────────────────────────────


def _load_from_dir(data_dir: Path) -> list[dict]:
    """Load .txt/.md/.json files from a deepfake data directory."""
    allowed = {".txt", ".md", ".json"}
    docs = []
    if not data_dir.exists():
        logger.error(f"Directory not found: {data_dir}")
        return docs

    for fp in sorted(data_dir.rglob("*")):
        if not fp.is_file() or fp.suffix.lower() not in allowed:
            continue
        try:
            raw = fp.read_text(encoding="utf-8", errors="replace").strip()
            if fp.suffix == ".json":
                parsed = json.loads(raw)
                content = json.dumps(parsed, indent=2) if isinstance(parsed, (dict, list)) else raw
            else:
                content = raw
        except Exception as e:
            logger.warning(f"Skip {fp}: {e}")
            continue
        if not content:
            continue

        dataset_name = fp.stem
        chunks = chunk_text(content)
        for i, c in enumerate(chunks):
            docs.append(
                {
                    "id": content_id(CATEGORY, fp.name, c),
                    "dataset_name": dataset_name,
                    "category": CATEGORY,
                    "content": c,
                    "metadata": {
                        "source_file": fp.name,
                        "dataset": dataset_name,
                        "type": "deepfake",
                        "chunk_index": i,
                        "total_chunks": len(chunks),
                    },
                }
            )
    logger.info(f"Loaded {len(docs)} deepfake chunks")
    return docs


# ── Seed ──────────────────────────────────────────────────────────────────────


def seed(data_dir: Path) -> Path:
    """Write seed text files into data_dir/deepfake/."""
    out = data_dir / "deepfake"
    out.mkdir(parents=True, exist_ok=True)
    for name, content in SEED_FILES.items():
        (out / name).write_text(content, encoding="utf-8")
    logger.info(f"Seed data written to {out}")
    return out


# ── CLI ───────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(description="VibeSecure Deepfake RAG Ingestion")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("seed", help="Generate seed dataset files into data/deepfake/")

    up = sub.add_parser("upsert", help="Embed and upsert deepfake data")
    up.add_argument("--data-dir", type=Path, default=Path("data/deepfake"))
    up.add_argument("--batch-size", type=int, default=32)

    sp = sub.add_parser("search", help="Similarity search in deepfake data")
    sp.add_argument("query")
    sp.add_argument("--top-k", type=int, default=5)

    args = parser.parse_args()
    engine = get_rag_engine()

    if args.command == "seed":
        seed(Path("data"))

    elif args.command == "upsert":
        ensure_pgvector(engine)
        docs = _load_from_dir(args.data_dir)
        if not docs:
            logger.error("No documents found.")
            sys.exit(1)
        n = batch_upsert(docs, batch_size=args.batch_size, engine=engine)
        logger.info(f"Done. {n} deepfake documents upserted.")

    elif args.command == "search":
        results = search_similar(
            args.query,
            top_k=args.top_k,
            category_filter=CATEGORY,
            engine=engine,
        )
        if not results:
            print("No results.")
            return
        for i, r in enumerate(results, 1):
            print(f"\n--- #{i} (similarity: {r['similarity']:.4f}) ---")
            print(f"Dataset: {r['dataset_name']}")
            print(f"{r['content'][:300]}{'...' if len(r['content']) > 300 else ''}")


if __name__ == "__main__":
    main()
