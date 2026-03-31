"""
Forensic Artifact Agent - detailed frame-by-frame analysis.
Performs deep forensic analysis for facial inconsistencies, lighting mismatches,
temporal anomalies, and audio artifacts.
Sends actual image data to Gemini via the multimodal API.
"""

import logging
import os

from google.genai import types as genai_types

from app.agents.base_agent import BaseAgent
from app.graphs.state import AgentState
from app.prompts import forensic_prompt
from app.schemas.agent_outputs import AudioAnalysisResult, ForensicBatchResult

logger = logging.getLogger(__name__)


def _image_part(path: str) -> genai_types.Part:
    """Build a Gemini ``Part`` with inline image data."""
    with open(path, "rb") as f:
        data = f.read()
    return genai_types.Part.from_bytes(data=data, mime_type="image/jpeg")


class ForensicArtifactAgent(BaseAgent):
    name = "forensic_artifact"
    description = "Detailed frame-by-frame forensic analysis for deepfake detection"
    is_brain = True

    def _analyze_frames(self, frames: list[str], file_type: str) -> dict:
        """Perform detailed forensic analysis on frames using multimodal API."""
        frame_analyses = []

        batch_size = 5
        for i in range(0, len(frames), batch_size):
            batch = frames[i : i + batch_size]
            existing_frames = [f for f in batch if os.path.exists(f)]
            if not existing_frames:
                continue

            prompt_text = forensic_prompt.build_frame_prompt(
                batch_start=i + 1,
                batch_count=len(existing_frames),
                file_type=file_type,
            )

            # Build multimodal content: prompt text + image parts
            contents: list = [prompt_text]
            for frame_path in existing_frames:
                contents.append(_image_part(frame_path))

            try:
                result = self.generate_multimodal_validated(
                    contents,
                    response_model=ForensicBatchResult,
                    system_instruction=forensic_prompt.SYSTEM_INSTRUCTION,
                )
                frame_analyses.extend([fa.model_dump() for fa in result.frame_analyses])
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

        prompt = forensic_prompt.build_audio_prompt()

        try:
            result = self.generate_validated(
                prompt,
                response_model=AudioAnalysisResult,
                system_instruction=forensic_prompt.AUDIO_SYSTEM_INSTRUCTION,
            )
            return result.model_dump()
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
