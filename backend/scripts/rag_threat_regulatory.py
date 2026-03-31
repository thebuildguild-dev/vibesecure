#!/usr/bin/env python3
"""
Threat Intelligence + Regulatory Compliance RAG Ingestion for VibeSecure AI.

Seeds MITRE ATLAS knowledge, AI attack scenarios, and full regulatory text
(GDPR, CCPA, DPDP Act, EU AI Act) then upserts into PgVector.

Usage:
    cd backend
    python -m scripts.rag_threat_regulatory seed
    python -m scripts.rag_threat_regulatory upsert
    python -m scripts.rag_threat_regulatory search "prompt injection attack" --category threat_intel
    python -m scripts.rag_threat_regulatory search "GDPR automated decision" --category regulatory
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
logger = logging.getLogger("rag_threat_reg")


# ══════════════════════════════════════════════════════════════════════════════
# THREAT INTELLIGENCE seed data
# ══════════════════════════════════════════════════════════════════════════════

_MITRE_ATLAS = {
    "framework": "MITRE ATLAS (Adversarial Threat Landscape for AI Systems)",
    "version": "4.0",
    "description": (
        "ATLAS is a knowledge base of adversarial tactics, techniques, and case "
        "studies targeting machine learning systems. Extends MITRE ATT&CK to AI."
    ),
    "tactics": [
        {
            "id": "AML.TA0001",
            "name": "Reconnaissance",
            "description": "Gathering info about target ML system: architecture, training data, API endpoints, framework versions.",
        },
        {
            "id": "AML.TA0002",
            "name": "Resource Development",
            "description": "Acquiring resources to attack ML systems: shadow models, adversarial toolkits, compute, synthetic data.",
        },
        {
            "id": "AML.TA0003",
            "name": "Initial Access",
            "description": "Gaining initial access to ML supply chain or deployment: compromising registries, poisoning datasets, API vulns.",
        },
        {
            "id": "AML.TA0004",
            "name": "ML Attack Staging",
            "description": "Preparing adversarial inputs, crafting transferable perturbations, developing trigger patterns for backdoors.",
        },
        {
            "id": "AML.TA0005",
            "name": "ML Model Access",
            "description": "Obtaining model predictions, gradients, or parameters -- from black-box API to full white-box access.",
        },
        {
            "id": "AML.TA0006",
            "name": "Exfiltration",
            "description": "Extracting model weights (stealing), training data (extraction), or proprietary IP from ML systems.",
        },
        {
            "id": "AML.TA0007",
            "name": "Impact",
            "description": "Degrading/manipulating ML behavior: misclassification, DoS via resource exhaustion, prompt injection.",
        },
    ],
    "techniques": [
        {
            "id": "AML.T0043",
            "name": "Data Poisoning",
            "tactic": "Initial Access",
            "description": "Injecting malicious samples into training data. Includes label flipping, backdoor injection, clean-label poisoning.",
            "mitigations": [
                "Data sanitization",
                "Robust training (spectral signatures)",
                "Provenance tracking",
            ],
        },
        {
            "id": "AML.T0044",
            "name": "Adversarial Examples (Evasion)",
            "tactic": "Impact",
            "description": "Crafting inputs with imperceptible perturbations causing misclassification. Methods: FGSM, PGD, C&W, AutoAttack.",
            "mitigations": [
                "Adversarial training",
                "Input denoising",
                "Randomized smoothing",
                "Ensemble models",
            ],
        },
        {
            "id": "AML.T0048",
            "name": "Model Stealing (Extraction)",
            "tactic": "Exfiltration",
            "description": "Querying target model API to build a functionally equivalent copy. Compromises IP and enables white-box attacks.",
            "mitigations": [
                "Rate limiting",
                "Watermarking outputs",
                "Differential privacy",
                "Output perturbation",
            ],
        },
        {
            "id": "AML.T0049",
            "name": "Training Data Extraction",
            "tactic": "Exfiltration",
            "description": "Extracting memorized training data from models. LLMs susceptible to prefix prompting for verbatim recall of PII.",
            "mitigations": [
                "Differential privacy",
                "Membership inference detection",
                "Output filtering",
                "Deduplication",
            ],
        },
        {
            "id": "AML.T0051",
            "name": "Prompt Injection",
            "tactic": "Impact",
            "description": "Manipulating LLM behavior via adversarial instructions. Direct and indirect injection to bypass safety or exfiltrate data.",
            "mitigations": [
                "Input/output filtering",
                "System prompt hardening",
                "Privilege separation",
                "Anomaly monitoring",
            ],
        },
        {
            "id": "AML.T0050",
            "name": "Model Backdoor (Trojan)",
            "tactic": "ML Attack Staging",
            "description": "Embedding hidden triggers so model behaves normally on clean inputs but produces attacker-chosen outputs on trigger.",
            "mitigations": [
                "Neural cleanse",
                "Fine-pruning",
                "Curated datasets",
                "Supply chain security",
            ],
        },
        {
            "id": "AML.T0047",
            "name": "ML Supply Chain Compromise",
            "tactic": "Initial Access",
            "description": "Compromising model registries (HuggingFace), frameworks, data pipelines. Pickle deserialization exploits.",
            "mitigations": [
                "Verify checksums",
                "SafeTensors format",
                "Pin dependencies",
                "Model scanning",
            ],
        },
    ],
    "case_studies": [
        {
            "title": "Tay Chatbot Manipulation (Microsoft, 2016)",
            "description": "Coordinated users manipulated Tay via adversarial interactions, producing offensive outputs within 16 hours.",
        },
        {
            "title": "GPT-4 Jailbreaking (2023-2024)",
            "description": "Multiple prompt injection techniques: DAN, multi-turn attacks, encoded prompts to bypass safety filters.",
        },
        {
            "title": "Adversarial Patches on Autonomous Vehicles",
            "description": "Physical patches on stop signs cause misclassification by autonomous vehicle perception systems.",
        },
        {
            "title": "ModelScope Malicious Model Upload (2023)",
            "description": "Model files on public hubs containing arbitrary code executed during deserialization.",
        },
    ],
}

THREAT_SEED_FILES = {
    "mitre_atlas.json": json.dumps(_MITRE_ATLAS, indent=2),
    "attack_scenarios.txt": """\
AI Threat Scenario: Model Poisoning on Content Moderation

Adversary contributes mislabeled examples to crowdsourced content moderation training \
data over months. Poisoned data causes the classifier to miss hate speech with specific \
dog-whistle terms while increasing false positives on benign content.

Impact: Hate speech proliferation, user safety degradation.
ATLAS: AML.T0043 Data Poisoning
Detection: Monitor for distributional shift, data provenance, outlier detection on batches.

---

AI Threat Scenario: Adversarial Evasion of Deepfake Detector

Attacker applies adversarial perturbations to deepfake video to evade detection. Uses \
transferable PGD attack with ensemble of substitute detectors. Perturbations invisible \
to humans but cause detector to classify fake as real.

Impact: False negatives in security screening, content moderation bypass.
ATLAS: AML.T0044 Adversarial Examples
Detection: Ensemble detectors (frequency + temporal + biological), input preprocessing.

---

AI Threat Scenario: Prompt Injection via Document Analysis

Malicious PDF submitted for governance analysis contains hidden text (white on white) \
with instructions to override system prompt and exfiltrate conversation context.

Impact: Data leakage, system prompt extraction, assessment manipulation.
ATLAS: AML.T0051 Prompt Injection
Detection: Input sanitization, text extraction audit, output monitoring.

---

AI Threat Scenario: Model Supply Chain Attack via Hugging Face

Attacker uploads backdoored model with name similar to popular model (typosquatting). \
Organizations that download inherit the backdoor. Model performs normally except for \
specific trigger phrase producing attacker-controlled output.

Impact: Compromised downstream applications, data exfiltration.
ATLAS: AML.T0047 Supply Chain + AML.T0050 Backdoor
Detection: Verify checksums, SafeTensors, neural cleanse scanning.

---

AI Threat Scenario: Training Data Extraction from RAG

Attacker queries RAG with crafted prompts to extract verbatim training data. \
Iteratively probes near decision boundaries to reconstruct private documents.

Impact: Confidential data leakage, IP theft, compliance violation.
ATLAS: AML.T0049 Training Data Extraction
Detection: Rate limiting, similarity thresholding, DP embeddings, PII monitoring.
""",
    "ai_supply_chain.txt": """\
AI Supply Chain Security

The AI supply chain encompasses data collection through model deployment. \
Each stage introduces vulnerabilities:

1. Data Collection - Poisoned datasets, label manipulation
   Control: Data provenance, multi-annotator consensus

2. Pre-trained Models - Backdoored models on public hubs, pickle exploits
   Control: Checksum verification, SafeTensors format, approved registry

3. Training Infrastructure - Compromised frameworks, side-channel attacks
   Control: Dependency pinning, reproducible builds, isolated environments

4. Model Registry - Unauthorized replacement, version confusion
   Control: Cryptographic signing, immutable versioning, access auditing

5. Serving Infrastructure - API injection, DoS, inference side-channels
   Control: Input validation, rate limiting, hardware protections

6. Monitoring - Adversarial drift, distribution shift
   Control: Continuous monitoring, automated drift detection

---

SBOM for AI (AI Bill of Materials)

Extends Software BOM to include:
- Data BOM: Provenance of training/evaluation datasets
- Model BOM: Architecture, hyperparameters, base model lineage
- Code BOM: Framework versions, dependencies, custom code
- Infrastructure BOM: Hardware, cloud services, orchestration
- Evaluation BOM: Benchmarks, bias audits, safety evaluations

Standards: SPDX AI Profile, CycloneDX ML BOM, NIST AI RMF, EU AI Act Annex IV
""",
}

# ══════════════════════════════════════════════════════════════════════════════
# REGULATORY COMPLIANCE seed data
# ══════════════════════════════════════════════════════════════════════════════

REGULATORY_SEED_FILES = {
    "gdpr.txt": """\
General Data Protection Regulation (GDPR) - Key Provisions for AI

Regulation (EU) 2016/679

Article 5 - Principles
Personal data shall be processed lawfully, fairly, and transparently. \
Collected for specified, explicit purposes. Adequate, relevant, and limited \
to what is necessary. Accurate and kept up to date. Stored no longer than necessary. \
Processed with appropriate security.

Article 13 - Information on Collection
Controller must disclose existence of automated decision-making including profiling, \
meaningful information about the logic involved, and significance and consequences.

Article 15 - Right of Access
Data subject can obtain confirmation of processing and information about safeguards.

Article 17 - Right to Erasure
Data subject can request erasure when data is no longer necessary, consent withdrawn, \
or data unlawfully processed. ML models may need retraining or machine unlearning.

Article 22 - Automated Decision-Making
Data subject has the right not to be subject to decisions based solely on automated \
processing that produce legal effects. Suitable safeguards include human intervention, \
right to express a point of view, and to contest the decision.

Article 25 - Data Protection by Design
Implement appropriate measures to integrate safeguards into processing. For AI: \
differential privacy, federated learning, data minimization, purpose limitation.

Article 35 - DPIA
High-risk processing requires Data Protection Impact Assessment. AI systems profiling \
individuals, making automated decisions with legal effects, or processing biometrics \
typically require DPIA.

Articles 44-49 - Cross-Border Transfers
Personal data only to countries ensuring adequate protection. AI must consider where \
training data is stored, inference occurs, and results are transmitted.

Recital 71 - Right to Explanation
Data subject should have right to obtain explanation of decision reached after \
assessment and to challenge the decision.

Penalties: Up to EUR 20 million or 4% global annual turnover.
""",
    "ccpa.txt": """\
California Consumer Privacy Act (CCPA) / CPRA

Section 1798.100 - Right to Know
Consumer can request disclosure of what personal information is collected, used, sold.

Section 1798.105 - Right to Delete
Consumer can request deletion. AI may need retraining or machine unlearning.

Section 1798.106 - Right to Correct (CPRA)
Consumer can request correction. ML systems must update training data.

Section 1798.121 - Opt-Out of Sensitive PI (CPRA)
Consumers can limit use of sensitive PI. Biometric AI must offer opt-out.

Section 1798.135 - Automated Decision-Making (ADMT)
Consumers must be informed about ADMT, its logic, and have right to opt out. \
ADMT: any technology processing PI to generate decisions, predictions, recommendations.

Section 1798.185 - Profiling Regulations
CPPA authorized to issue regulations on access/opt-out for profiling, risk \
assessments for ADMT, and cybersecurity audits.

Penalties: $2,500/unintentional violation, $7,500/intentional. Private action \
for breaches: $100-$750 per consumer per incident.
""",
    "dpdp.txt": """\
Digital Personal Data Protection Act, 2023 (India)

Section 4 - Consent
Personal data processed only for lawful purpose with consent that is free, specific, \
informed, unconditional. Consent can be withdrawn. AI training on Indian citizens' \
data requires valid consent or statutory basis.

Section 5 - Notice
Data Fiduciary must provide notice of: data collected, purpose, how to exercise rights, \
how to file complaints. AI must communicate when data used for automated processing.

Section 6 - Deemed Consent (Legitimate Uses)
Processing allowed without consent for: compliance with law, medical emergencies, \
employment, public interest. May apply to AI safety and deepfake detection.

Section 8 - Rights of Data Principal
Information about processing, correction and erasure, grievance redressal, \
nomination of representative. Erasure may require machine unlearning.

Section 10 - Obligations of Data Fiduciary
Ensure accuracy and consistency, implement security safeguards, notify breaches, \
erase data when purpose fulfilled.

Section 16 - Children's Data
Under 18 requires verifiable parental consent. Tracking, behavioral monitoring, \
targeted advertising prohibited. AI must implement age verification.

Section 17 - Significant Data Fiduciary
Designated based on volume and risk. Must appoint DPO (resident of India), \
independent auditor, periodic impact assessments.

Cross-Border Transfer: Allowed unless specifically restricted by government notification.

Penalties: Up to INR 250 crore (~USD 30 million) per instance.
""",
    "eu_ai_act.txt": """\
European Union AI Act - Regulation (EU) 2024/1689

Article 3 - Definitions
AI system: machine-based system operating with varying autonomy, that may adapt \
after deployment, and infers from inputs to generate outputs influencing environments.

Article 5 - Prohibited Practices
(a) Subliminal/manipulative AI causing harm
(b) Exploitation of vulnerabilities (age, disability)
(c) Social scoring by public authorities
(d) Real-time remote biometric ID in public spaces (with exceptions)
(e) Biometric categorisation by sensitive attributes
(f) Untargeted scraping of facial images for recognition DBs
(g) Emotion recognition in workplaces/education (with exceptions)

Article 9 - Risk Management (High-Risk)
Continuous risk management: identify, analyse, estimate, evaluate, mitigate risks.

Article 10 - Data Governance (High-Risk)
Training data must be relevant, representative, free of errors. Examined for biases.

Article 13 - Transparency (High-Risk)
Sufficiently transparent for deployers to interpret and use outputs appropriately.

Article 14 - Human Oversight (High-Risk)
Enable humans to: understand capabilities/limitations, interpret outputs, override, \
interrupt or stop the system. Proportionate to risks.

Article 15 - Accuracy, Robustness, Cybersecurity
Must be resilient against adversarial ML: data poisoning, model manipulation, \
adversarial examples.

Article 50 - Transparency for Certain AI
(a) Chatbots must disclose AI nature
(b) Synthetic content must be machine-detectable (watermarking, C2PA)
(c) Emotion recognition must inform individuals
(d) Deepfakes must be labeled as generated/manipulated

Articles 51-56 - General-Purpose AI (GPAI)
Systemic risk if training compute exceeds 10^25 FLOPs. Providers must: maintain docs, \
publish training data summary, comply with copyright. Systemic risk models: adversarial \
testing, mitigate risks, report incidents, ensure cybersecurity.

Penalties: Up to EUR 35 million or 7% global turnover for prohibited practices.
Up to EUR 15 million or 3% for other provisions.

Timeline:
Feb 2025: Prohibited practices apply
Aug 2025: GPAI obligations apply
Aug 2026: Full high-risk requirements
Aug 2027: Sectoral safety legislation obligations
""",
}


# ── Load / prepare documents ─────────────────────────────────────────────────


def _load_category(data_dir: Path, folder: str, category: str) -> list[dict]:
    """Load text/JSON files from a single category folder."""
    allowed = {".txt", ".md", ".json"}
    docs = []
    cat_dir = data_dir / folder
    if not cat_dir.exists():
        logger.warning(f"Directory not found: {cat_dir}")
        return docs

    for fp in sorted(cat_dir.rglob("*")):
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
                    "id": content_id(category, fp.name, c),
                    "dataset_name": dataset_name,
                    "category": category,
                    "content": c,
                    "metadata": {
                        "source_file": fp.name,
                        "dataset": dataset_name,
                        "type": category,
                        "chunk_index": i,
                        "total_chunks": len(chunks),
                    },
                }
            )
    logger.info(f"Loaded {len(docs)} {category} chunks from {folder}/")
    return docs


def load_all(data_dir: Path) -> list[dict]:
    """Load both threat_intel and regulatory documents."""
    docs = _load_category(data_dir, "threats", "threat_intel")
    docs += _load_category(data_dir, "regulations", "regulatory")
    logger.info(f"Total threat+regulatory: {len(docs)} chunks")
    return docs


# ── Seed ──────────────────────────────────────────────────────────────────────


def seed(data_dir: Path) -> None:
    """Write seed files for threats/ and regulations/."""
    th = data_dir / "threats"
    th.mkdir(parents=True, exist_ok=True)
    for name, content in THREAT_SEED_FILES.items():
        (th / name).write_text(content, encoding="utf-8")

    reg = data_dir / "regulations"
    reg.mkdir(parents=True, exist_ok=True)
    for name, content in REGULATORY_SEED_FILES.items():
        (reg / name).write_text(content, encoding="utf-8")

    logger.info(f"Seed data written to {data_dir}/threats/ and {data_dir}/regulations/")


# ── CLI ───────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(description="VibeSecure Threat+Regulatory RAG Ingestion")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("seed", help="Generate seed dataset files")

    up = sub.add_parser("upsert", help="Embed and upsert threat + regulatory data")
    up.add_argument("--data-dir", type=Path, default=Path("data"))
    up.add_argument("--batch-size", type=int, default=32)

    sp = sub.add_parser("search", help="Similarity search")
    sp.add_argument("query")
    sp.add_argument("--top-k", type=int, default=5)
    sp.add_argument("--category", choices=["threat_intel", "regulatory"])

    args = parser.parse_args()
    engine = get_rag_engine()

    if args.command == "seed":
        seed(Path("data"))

    elif args.command == "upsert":
        ensure_pgvector(engine)
        docs = load_all(args.data_dir)
        if not docs:
            logger.error("No documents found.")
            sys.exit(1)
        n = batch_upsert(docs, batch_size=args.batch_size, engine=engine)
        logger.info(f"Done. {n} threat+regulatory documents upserted.")

    elif args.command == "search":
        results = search_similar(
            args.query,
            top_k=args.top_k,
            category_filter=args.category,
            engine=engine,
        )
        if not results:
            print("No results.")
            return
        for i, r in enumerate(results, 1):
            print(f"\n--- #{i} (similarity: {r['similarity']:.4f}) ---")
            print(f"Dataset: {r['dataset_name']} | Category: {r['category']}")
            print(f"{r['content'][:300]}{'...' if len(r['content']) > 300 else ''}")


if __name__ == "__main__":
    main()
