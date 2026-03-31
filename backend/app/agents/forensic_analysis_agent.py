"""
Forensic Artifact Agent - detailed frame-by-frame analysis.
Performs deep forensic analysis for facial inconsistencies, lighting mismatches,
temporal anomalies, and audio artifacts.
"""

import logging
import os

from app.agents.base_agent import BaseAgent
from app.graphs.state import AgentState

logger = logging.getLogger(__name__)


class ForensicArtifactAgent(BaseAgent):
    name = "forensic_artifact"
    description = "Detailed frame-by-frame forensic analysis for deepfake detection"
    is_brain = True

    def _analyze_frames(self, frames: list[str], file_type: str) -> dict:
        """Perform detailed forensic analysis on frames."""
        frame_analyses = []

        # Analyze frames in batches
        batch_size = 5
        for i in range(0, len(frames), batch_size):
            batch = frames[i : i + batch_size]
            existing_frames = [f for f in batch if os.path.exists(f)]
            if not existing_frames:
                continue

            prompt = f"""You are a forensic deepfake analyst performing DETAILED frame-by-frame analysis.

Analyze frames {i + 1} to {i + len(existing_frames)} of a {file_type}.
Frame paths: {existing_frames}

For each frame, evaluate these forensic dimensions:
1. FACIAL CONSISTENCY: Symmetry, proportions, skin texture quality, eye alignment
2. LIGHTING ANALYSIS: Shadow direction consistency, specular highlights, color temperature
3. EDGE ARTIFACTS: Blending boundaries, halo effects around face/hair, compression artifacts
4. BACKGROUND COHERENCE: Warping, inconsistent perspective, blurred boundaries
5. TEXTURE ANALYSIS: Repeating patterns, unnaturally smooth skin, pore-level detail
6. TEMPORAL MARKERS: If multiple frames, note any sudden jumps in facial geometry

Return JSON:
{{
    "frame_analyses": [
        {{
            "frame_index": 1,
            "facial_consistency_score": 0-100,
            "lighting_score": 0-100,
            "edge_quality_score": 0-100,
            "background_score": 0-100,
            "texture_score": 0-100,
            "anomalies_detected": ["anomaly description"],
            "artifact_type": "none" | "gan_artifact" | "face_swap" | "lip_sync" | "full_synthetic"
        }}
    ],
    "batch_summary": "Brief summary of this batch"
}}"""

            try:
                batch_result = self.generate_json(
                    prompt,
                    system_instruction="You are a forensic image analyst specializing in deepfake detection. Be thorough and precise.",
                )
                frame_analyses.extend(batch_result.get("frame_analyses", []))
            except Exception as e:
                logger.error(f"Frame batch analysis failed: {e}")
                frame_analyses.append(
                    {
                        "frame_index": i + 1,
                        "error": str(e),
                    }
                )

        return {"frame_analyses": frame_analyses}

    def _analyze_audio(self, audio_path: str) -> dict:
        """Analyze audio track for deepfake artifacts."""
        if not audio_path or not os.path.exists(audio_path):
            return {"status": "no_audio"}

        prompt = """You are an audio forensics specialist. Analyze audio characteristics for deepfake indicators.

Common audio deepfake artifacts include:
1. Unnatural prosody or rhythm in speech
2. Inconsistent background noise patterns
3. Spectral gaps or unusual frequency distributions
4. Phase discontinuities at edit points
5. Lip-sync misalignment indicators

Based on general audio deepfake knowledge, describe what to look for and provide a risk assessment.

Return JSON:
{
    "audio_risk_level": "low" | "medium" | "high",
    "audio_observations": ["observation"],
    "lip_sync_risk": "low" | "medium" | "high",
    "voice_clone_indicators": []
}"""

        try:
            return self.generate_json(
                prompt,
                system_instruction="You are an audio forensics expert.",
            )
        except Exception as e:
            logger.error(f"Audio analysis failed: {e}")
            return {"status": "error", "error": str(e)}

    def process(self, state: AgentState) -> dict:
        keyframe_result = state.get("results", {}).get("keyframe_extractor", {})
        triage_result = state.get("results", {}).get("deepfake_triage", {})

        frames = keyframe_result.get("frames", [])
        audio_path = keyframe_result.get("audio_path")
        file_type = keyframe_result.get("file_type", "unknown")

        # Skip if triage says clearly real and high confidence
        triage_verdict = triage_result.get("triage_verdict", "inconclusive")
        triage_confidence = triage_result.get("confidence", 0)
        if triage_verdict == "likely_real" and triage_confidence > 90:
            return {
                "status": "skipped",
                "reason": "Triage indicates high confidence real media",
                "forensic_needed": False,
            }

        if not frames:
            return {
                "status": "skipped",
                "reason": "No frames available",
            }

        # Perform detailed analysis
        frame_result = self._analyze_frames(frames, file_type)
        audio_result = self._analyze_audio(audio_path) if audio_path else {"status": "no_audio"}

        # Calculate aggregate scores
        analyses = frame_result.get("frame_analyses", [])
        valid_analyses = [a for a in analyses if "error" not in a]

        if valid_analyses:
            avg_scores = {
                "avg_facial_consistency": sum(
                    a.get("facial_consistency_score", 50) for a in valid_analyses
                )
                / len(valid_analyses),
                "avg_lighting": sum(a.get("lighting_score", 50) for a in valid_analyses)
                / len(valid_analyses),
                "avg_edge_quality": sum(a.get("edge_quality_score", 50) for a in valid_analyses)
                / len(valid_analyses),
                "avg_background": sum(a.get("background_score", 50) for a in valid_analyses)
                / len(valid_analyses),
                "avg_texture": sum(a.get("texture_score", 50) for a in valid_analyses)
                / len(valid_analyses),
            }
            overall_authenticity = sum(avg_scores.values()) / len(avg_scores)
        else:
            avg_scores = {}
            overall_authenticity = 50.0

        # Collect all detected anomalies
        all_anomalies = []
        artifact_types = set()
        for a in valid_analyses:
            all_anomalies.extend(a.get("anomalies_detected", []))
            at = a.get("artifact_type", "none")
            if at != "none":
                artifact_types.add(at)

        return {
            "status": "success",
            "frames_analyzed": len(frames),
            "valid_analyses": len(valid_analyses),
            "average_scores": avg_scores,
            "overall_authenticity_score": round(overall_authenticity, 1),
            "anomalies_detected": all_anomalies,
            "artifact_types_found": list(artifact_types),
            "audio_analysis": audio_result,
            "frame_details": frame_result,
        }


forensic_artifact_agent = ForensicArtifactAgent()
