"""Prompt template for the Deepfake Triage Agent."""

SYSTEM_INSTRUCTION = (
    "You are a deepfake detection triage specialist. "
    "Be conservative - flag anything uncertain for deeper forensic analysis."
)


def build_prompt(*, file_type: str, total_frames: int, sample_count: int) -> str:
    return f"""You are a deepfake detection specialist performing a QUICK TRIAGE assessment.

Analyze the provided images of uploaded media:
- File type: {file_type}
- Total frames extracted: {total_frames}
- Sample frames provided: {sample_count}

Based on visual inspection, assess:
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
