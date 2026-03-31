"""
Deepfake Triage Agent - fast first-pass check with Gemini Flash.
Does a quick analysis of frames to determine if deeper forensic analysis is needed.
Sends actual image data to Gemini via the multimodal API.
"""

import base64
import logging
import os

from google.genai import types as genai_types

from app.agents.base_agent import BaseAgent
from app.graphs.state import AgentState
from app.prompts import triage_prompt
from app.schemas.agent_outputs import TriageResult

logger = logging.getLogger(__name__)


def _encode_image_base64(path: str) -> str:
    with open(path, "rb") as f:
        return base64.b64encode(f.read()).decode("utf-8")


def _image_part(path: str) -> genai_types.Part:
    """Build a Gemini ``Part`` with inline image data."""
    data = _encode_image_base64(path)
    return genai_types.Part.from_bytes(
        data=base64.b64decode(data),
        mime_type="image/jpeg",
    )


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
        sample_frames = [f for f in frames[:4] if os.path.exists(f)]

        if not sample_frames:
            return {
                "status": "skipped",
                "reason": "No valid frame files found on disk",
                "needs_forensic": True,
            }

        # Build multimodal content: prompt text + image parts
        prompt_text = triage_prompt.build_prompt(
            file_type=file_type,
            total_frames=len(frames),
            sample_count=len(sample_frames),
        )

        contents: list = [prompt_text]
        for frame_path in sample_frames:
            contents.append(_image_part(frame_path))

        try:
            result = self.generate_multimodal_validated(
                contents,
                response_model=TriageResult,
                system_instruction=triage_prompt.SYSTEM_INSTRUCTION,
            )

            output = result.model_dump()
            output["status"] = "success"
            output["frames_analyzed"] = len(sample_frames)
            return output

        except Exception as e:
            logger.error(f"Triage analysis failed: {e}")
            return {
                "status": "error",
                "error": str(e),
                "needs_forensic": True,
                "triage_verdict": "inconclusive",
                "confidence": 0,
            }
