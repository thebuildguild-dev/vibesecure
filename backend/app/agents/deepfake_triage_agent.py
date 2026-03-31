"""
Deepfake Triage Agent - fast first-pass check with Gemini Flash.
Does a quick analysis of frames to determine if deeper forensic analysis is needed.
"""

import base64
import logging
import os

from app.agents.base_agent import BaseAgent
from app.graphs.state import AgentState

logger = logging.getLogger(__name__)


def encode_image_base64(path: str) -> str:
    with open(path, "rb") as f:
        return base64.b64encode(f.read()).decode("utf-8")


class DeepfakeTriageAgent(BaseAgent):
    name = "deepfake_triage"
    description = "Fast first-pass deepfake detection using Gemini Flash"

    def process(self, state: AgentState) -> dict:
        keyframe_result = state.get("results", {}).get("keyframe_extractor", {})
        frames = keyframe_result.get("frames", [])
        file_type = keyframe_result.get("file_type", "unknown")

        if not frames:
            return {
                "status": "skipped",
                "reason": "No frames available from keyframe extractor",
                "needs_forensic": False,
            }

        # Select up to 4 frames for quick triage
        sample_frames = frames[:4] if len(frames) > 4 else frames
        frame_descriptions = []

        for i, frame_path in enumerate(sample_frames):
            if os.path.exists(frame_path):
                frame_descriptions.append(f"Frame {i + 1}: {frame_path}")

        prompt = f"""You are a deepfake detection specialist performing a QUICK TRIAGE assessment.

Analyze the following information about uploaded media:
- File type: {file_type}
- Total frames extracted: {len(frames)}
- Sample frames analyzed: {len(sample_frames)}

Based on a first-pass analysis, assess:
1. Are there obvious signs of AI generation or manipulation?
2. Look for: unnatural skin textures, inconsistent lighting, warped backgrounds, asymmetric facial features, blurred edges around face/hair.
3. Any temporal inconsistencies across frames (if video)?

Return JSON:
{{
    "triage_verdict": "likely_real" | "likely_fake" | "suspicious" | "inconclusive",
    "confidence": 0-100,
    "quick_observations": ["observation 1", "observation 2"],
    "needs_forensic": true/false,
    "risk_indicators": ["indicator 1"],
    "triage_reasoning": "Brief explanation"
}}"""

        try:
            result = self.generate_json(
                prompt,
                system_instruction="You are a deepfake detection triage specialist. Be conservative - flag anything uncertain for deeper forensic analysis.",
            )

            result["status"] = "success"
            result["frames_analyzed"] = len(sample_frames)
            return result

        except Exception as e:
            logger.error(f"Triage analysis failed: {e}")
            return {
                "status": "error",
                "error": str(e),
                "needs_forensic": True,  # Default to running forensic on error
                "triage_verdict": "inconclusive",
                "confidence": 0,
            }


deepfake_triage_agent = DeepfakeTriageAgent()
