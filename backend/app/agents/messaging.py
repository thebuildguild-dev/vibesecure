"""
Redis Streams messaging layer for real-time agent communication.
"""

import json
import logging
import time

import redis

from app.core.config import settings

logger = logging.getLogger(__name__)

_redis_client: redis.Redis | None = None


def get_redis() -> redis.Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = redis.from_url(settings.redis_url, decode_responses=True)
    return _redis_client


STREAM_KEY = "vibesecure:agent:events"


def publish_event(
    job_id: str,
    agent_name: str,
    event_type: str,
    data: dict | None = None,
) -> str:
    """
    Publish an agent event to Redis Streams.
    Returns the message ID.
    """
    r = get_redis()
    payload = {
        "job_id": job_id,
        "agent": agent_name,
        "event": event_type,
        "timestamp": str(time.time()),
        "data": json.dumps(data or {}),
    }
    try:
        msg_id = r.xadd(STREAM_KEY, payload, maxlen=10000)
        logger.debug(f"Published event: {agent_name}/{event_type} for job {job_id}")
        return msg_id
    except redis.RedisError as e:
        logger.error(f"Failed to publish event: {e}")
        return ""


def read_events(
    job_id: str,
    last_id: str = "0-0",
    count: int = 100,
) -> list[dict]:
    """
    Read events for a specific job from the stream.
    """
    r = get_redis()
    try:
        raw = r.xrange(STREAM_KEY, min=last_id, count=count)
        events = []
        for msg_id, fields in raw:
            if fields.get("job_id") == job_id:
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
