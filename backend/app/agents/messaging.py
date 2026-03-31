"""
Redis Streams messaging layer for real-time agent communication.

Each job gets its own stream keyed ``vibesecure:job:{job_id}:events``
with a 24-hour TTL so stale data is automatically cleaned up.
"""

import json
import logging
import threading
import time

import redis

from app.core.config import settings

logger = logging.getLogger(__name__)

_STREAM_TTL_SECONDS = 86_400  # 24 hours

_lock = threading.Lock()
_redis_client: redis.Redis | None = None


def get_redis() -> redis.Redis:
    global _redis_client
    if _redis_client is None:
        with _lock:
            if _redis_client is None:
                _redis_client = redis.from_url(settings.redis_url, decode_responses=True)
    return _redis_client


def _stream_key(job_id: str) -> str:
    return f"vibesecure:job:{job_id}:events"


def publish_event(
    job_id: str,
    agent_name: str,
    event_type: str,
    data: dict | None = None,
) -> str:
    """
    Publish an agent event to the per-job Redis Stream.
    Returns the message ID.
    """
    r = get_redis()
    key = _stream_key(job_id)
    payload = {
        "job_id": job_id,
        "agent": agent_name,
        "event": event_type,
        "timestamp": str(time.time()),
        "data": json.dumps(data or {}),
    }
    try:
        msg_id = r.xadd(key, payload, maxlen=5000)
        # Set / refresh TTL so the stream expires after 24 h
        r.expire(key, _STREAM_TTL_SECONDS)
        logger.debug(f"Published event: {agent_name}/{event_type} for job {job_id}")
        return msg_id
    except redis.RedisError as e:
        logger.error(f"Failed to publish event: {e}")
        return ""


def ensure_consumer_group(job_id: str, group_name: str = "workers") -> None:
    """Create a consumer group on the job stream if it doesn't exist."""
    r = get_redis()
    key = _stream_key(job_id)
    try:
        r.xgroup_create(key, group_name, id="0", mkstream=True)
    except redis.ResponseError as e:
        if "BUSYGROUP" not in str(e):
            raise


def read_events(
    job_id: str,
    last_id: str = "0-0",
    count: int = 100,
) -> list[dict]:
    """
    Read events for a specific job from its dedicated stream.
    """
    r = get_redis()
    key = _stream_key(job_id)
    try:
        raw = r.xrange(key, min=last_id, count=count)
        events = []
        for msg_id, fields in raw:
            fields["id"] = msg_id
            if "data" in fields:
                try:
                    fields["data"] = json.loads(fields["data"])
                except json.JSONDecodeError:
                    pass
            events.append(fields)
        return events
    except redis.RedisError as e:
        logger.error(f"Failed to read events: {e}")
        return []


def publish_agent_start(job_id: str, agent_name: str):
    publish_event(job_id, agent_name, "started")


def publish_agent_complete(job_id: str, agent_name: str, summary: dict | None = None):
    publish_event(job_id, agent_name, "completed", summary)


def publish_agent_error(job_id: str, agent_name: str, error: str):
    publish_event(job_id, agent_name, "error", {"error": error})
