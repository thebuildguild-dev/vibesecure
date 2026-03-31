"""
Keyframe Extractor Agent - CPU-only FFmpeg keyframe extraction.
Picks 8-15 representative frames from video, or processes images directly.
"""

import json
import logging
import os
import subprocess
import tempfile
from pathlib import Path

from src.agents.base_agent import BaseAgent
from src.agents.state import AgentState

logger = logging.getLogger(__name__)

MAX_KEYFRAMES = 15
MIN_KEYFRAMES = 8


class KeyframeExtractorAgent(BaseAgent):
    name = "keyframe_extractor"
    description = "CPU-only FFmpeg keyframe extraction for video/image analysis"

    def _extract_video_keyframes(self, file_path: str, output_dir: str) -> list[str]:
        """Extract keyframes from video using FFmpeg scene detection."""
        frames = []

        # First pass: scene detection to find key moments
        try:
            cmd = [
                "ffmpeg",
                "-i",
                file_path,
                "-vf",
                "select='gt(scene,0.3)',setpts=N/FRAME_RATE/TB",
                "-vsync",
                "vfr",
                "-frames:v",
                str(MAX_KEYFRAMES),
                "-q:v",
                "2",
                os.path.join(output_dir, "scene_%03d.jpg"),
                "-y",
                "-loglevel",
                "warning",
            ]
            subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=True)
            frames = sorted(Path(output_dir).glob("scene_*.jpg"))
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            logger.warning(f"Scene detection failed, falling back to uniform sampling: {e}")

        # Fallback: uniform time-based sampling
        if len(frames) < MIN_KEYFRAMES:
            try:
                # Get video duration
                probe_cmd = [
                    "ffprobe",
                    "-v",
                    "error",
                    "-show_entries",
                    "format=duration",
                    "-of",
                    "json",
                    file_path,
                ]
                result = subprocess.run(probe_cmd, capture_output=True, text=True, timeout=30)
                duration = float(json.loads(result.stdout)["format"]["duration"])

                # Calculate interval for target number of frames
                target_frames = max(MIN_KEYFRAMES, min(MAX_KEYFRAMES, int(duration)))
                interval = duration / target_frames

                cmd = [
                    "ffmpeg",
                    "-i",
                    file_path,
                    "-vf",
                    f"fps=1/{interval:.2f}",
                    "-frames:v",
                    str(target_frames),
                    "-q:v",
                    "2",
                    os.path.join(output_dir, "uniform_%03d.jpg"),
                    "-y",
                    "-loglevel",
                    "warning",
                ]
                subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=True)
                frames = sorted(Path(output_dir).glob("*.jpg"))
            except Exception as e:
                logger.error(f"Uniform sampling also failed: {e}")

        return [str(f) for f in frames[:MAX_KEYFRAMES]]

    def _extract_audio_track(self, file_path: str, output_dir: str) -> str | None:
        """Extract audio track from video for audio artifact analysis."""
        audio_path = os.path.join(output_dir, "audio.wav")
        try:
            cmd = [
                "ffmpeg",
                "-i",
                file_path,
                "-vn",
                "-acodec",
                "pcm_s16le",
                "-ar",
                "16000",
                "-ac",
                "1",
                audio_path,
                "-y",
                "-loglevel",
                "warning",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode == 0 and os.path.exists(audio_path):
                return audio_path
        except Exception as e:
            logger.warning(f"Audio extraction failed (video may have no audio): {e}")
        return None

    def process(self, state: AgentState) -> dict:
        input_data = state.get("input_data", {})
        file_path = input_data.get("file_path", "")
        file_type = input_data.get("file_type", "")

        if not file_path or not os.path.exists(file_path):
            return {
                "status": "error",
                "error": f"File not found: {file_path}",
                "frames": [],
            }

        output_dir = tempfile.mkdtemp(prefix="vibesecure_keyframes_")

        if file_type == "video":
            frames = self._extract_video_keyframes(file_path, output_dir)
            audio_path = self._extract_audio_track(file_path, output_dir)

            return {
                "status": "success",
                "file_type": "video",
                "frames": frames,
                "frame_count": len(frames),
                "audio_path": audio_path,
                "has_audio": audio_path is not None,
                "output_dir": output_dir,
            }

        elif file_type == "image":
            # For images, just copy/reference the original
            return {
                "status": "success",
                "file_type": "image",
                "frames": [file_path],
                "frame_count": 1,
                "audio_path": None,
                "has_audio": False,
                "output_dir": output_dir,
            }

        return {
            "status": "error",
            "error": f"Unsupported file type: {file_type}",
            "frames": [],
        }


keyframe_extractor_agent = KeyframeExtractorAgent()
