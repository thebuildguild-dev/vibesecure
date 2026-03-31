"""Prompt templates for the Forensic Artifact Agent."""

SYSTEM_INSTRUCTION = (
    "You are a forensic image analyst specializing in deepfake detection. Be thorough and precise."
)

AUDIO_SYSTEM_INSTRUCTION = "You are an audio forensics expert."


def build_frame_prompt(*, batch_start: int, batch_count: int, file_type: str) -> str:
    return f"""You are a forensic deepfake analyst performing DETAILED frame-by-frame analysis.

Analyze frames {batch_start} to {batch_start + batch_count - 1} of a {file_type}.
The frames are provided as images.

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


def build_audio_prompt() -> str:
    return """You are an audio forensics specialist. Analyze audio characteristics for deepfake indicators.

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
