"""
Ensemble Voter Agent - combines all deepfake detection results.
Performs majority vote + confidence scoring + RAG knowledge base lookup.
"""

import json
import logging

from app.agents.base_agent import BaseAgent
from app.graphs.state import AgentState

logger = logging.getLogger(__name__)

# Reference datasets for RAG similarity matching
REFERENCE_DATASETS = [
    "Celeb-DF v2",
    "FaceForensics++",
    "DFDC (Deepfake Detection Challenge)",
    "DeeperForensics-1.0",
]


class EnsembleVoterAgent(BaseAgent):
    name = "ensemble_voter"
    description = (
        "Combines all deepfake detection results with majority vote and confidence scoring"
    )
    is_brain = True

    def process(self, state: AgentState) -> dict:
        results = state.get("results", {})

        triage_result = results.get("deepfake_triage", {})
        forensic_result = results.get("forensic_artifact", {})
        keyframe_result = results.get("keyframe_extractor", {})

        # Gather all votes
        votes = []

        # Triage vote
        triage_verdict = triage_result.get("triage_verdict", "inconclusive")
        triage_confidence = triage_result.get("confidence", 0)
        if triage_verdict in ("likely_real", "likely_fake", "suspicious"):
            votes.append(
                {
                    "source": "triage",
                    "verdict": triage_verdict,
                    "confidence": triage_confidence,
                }
            )

        # Forensic vote (based on authenticity score)
        forensic_score = forensic_result.get("overall_authenticity_score", 50)
        artifact_types = forensic_result.get("artifact_types_found", [])
        anomaly_count = len(forensic_result.get("anomalies_detected", []))

        if forensic_result.get("status") == "success":
            if forensic_score >= 75:
                forensic_verdict = "likely_real"
            elif forensic_score <= 35:
                forensic_verdict = "likely_fake"
            else:
                forensic_verdict = "suspicious"

            votes.append(
                {
                    "source": "forensic",
                    "verdict": forensic_verdict,
                    "confidence": min(100, int(abs(forensic_score - 50) * 2)),
                }
            )

        # Audio vote if available
        audio_result = forensic_result.get("audio_analysis", {})
        audio_risk = audio_result.get("audio_risk_level")
        if audio_risk:
            audio_verdict = {
                "low": "likely_real",
                "medium": "suspicious",
                "high": "likely_fake",
            }.get(audio_risk, "inconclusive")
            votes.append(
                {
                    "source": "audio",
                    "verdict": audio_verdict,
                    "confidence": 60,
                }
            )

        # Ensemble decision
        verdict_counts = {"likely_real": 0, "likely_fake": 0, "suspicious": 0}
        total_confidence = 0
        for vote in votes:
            v = vote["verdict"]
            if v in verdict_counts:
                verdict_counts[v] += 1
                total_confidence += vote["confidence"]

        if not votes:
            final_verdict = "inconclusive"
            final_confidence = 0
        else:
            avg_confidence = total_confidence / len(votes)
            # Majority vote
            max_votes = max(verdict_counts.values())
            winners = [k for k, v in verdict_counts.items() if v == max_votes]

            if len(winners) == 1:
                final_verdict = winners[0]
            else:
                # Tie-breaking: prefer "suspicious" for safety
                final_verdict = "suspicious" if "suspicious" in winners else winners[0]

            # Adjust confidence based on agreement
            agreement_ratio = max_votes / len(votes)
            final_confidence = int(avg_confidence * agreement_ratio)

        # RAG knowledge base similarity check
        prompt = f"""You are a deepfake detection expert with knowledge of major deepfake datasets and techniques.

Given these analysis results:
- Triage verdict: {triage_result.get("triage_verdict", "N/A")} (confidence: {triage_result.get("confidence", "N/A")}%)
- Forensic authenticity score: {forensic_score}
- Artifact types found: {artifact_types}
- Anomaly count: {anomaly_count}
- Ensemble verdict: {final_verdict}

Compare against known patterns from these reference datasets:
{json.dumps(REFERENCE_DATASETS)}

Return JSON:
{{
    "dataset_matches": [
        {{
            "dataset": "dataset name",
            "similarity": 0-100,
            "technique": "deepfake technique if matched",
            "notes": "explanation"
        }}
    ],
    "plain_english_explanation": "A clear, non-technical explanation of the findings",
    "heatmap_regions": ["face", "hair_boundary", "background"],
    "generation_technique_guess": "GAN | Diffusion | Face Swap | Lip Sync | None detected"
}}"""

        try:
            rag_result = self.generate_json(
                prompt,
                system_instruction="You are a deepfake forensics expert. Provide clear explanations.",
            )
        except Exception as e:
            logger.error(f"RAG lookup failed: {e}")
            rag_result = {
                "dataset_matches": [],
                "plain_english_explanation": "Analysis complete but reference matching unavailable.",
                "heatmap_regions": [],
                "generation_technique_guess": "Unknown",
            }

        # Convert verdict to real/fake percentage
        if final_verdict == "likely_real":
            real_pct = min(99, 50 + final_confidence // 2)
        elif final_verdict == "likely_fake":
            real_pct = max(1, 50 - final_confidence // 2)
        else:
            real_pct = 50

        return {
            "status": "success",
            "final_verdict": final_verdict,
            "confidence_score": final_confidence,
            "real_percentage": real_pct,
            "fake_percentage": 100 - real_pct,
            "votes": votes,
            "vote_counts": verdict_counts,
            "anomaly_count": anomaly_count,
            "artifact_types": artifact_types,
            "rag_analysis": rag_result,
            "plain_explanation": rag_result.get("plain_english_explanation", ""),
            "heatmap_regions": rag_result.get("heatmap_regions", []),
        }
