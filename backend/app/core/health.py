"""
Deep health-check endpoint that probes every critical dependency.

Returns fine-grained status for each subsystem so load balancers and
Kubernetes probes can make informed routing decisions.

Endpoints:
  /health          -- Shallow liveness probe (always 200 if the process is up).
  /health/ready    -- Deep readiness probe that verifies DB, Redis, Celery.
  /health/detailed -- Full dependency report including circuit breaker states.
"""

import logging
import time
from datetime import UTC, datetime

import redis
from fastapi import APIRouter
from sqlalchemy import text
from sqlmodel import Session

from app.core.circuit_breaker import get_all_breakers
from app.core.config import settings
from app.core.database import engine

logger = logging.getLogger(__name__)

router = APIRouter(tags=["health"])


def _check_database() -> dict:
    try:
        start = time.perf_counter()
        with Session(engine) as session:
            session.exec(text("SELECT 1"))
        latency_ms = (time.perf_counter() - start) * 1000
        return {"status": "healthy", "latency_ms": round(latency_ms, 1)}
    except Exception as e:
        logger.error("Database health check failed: %s", e)
        return {"status": "unhealthy", "error": str(e)}


def _check_redis() -> dict:
    try:
        start = time.perf_counter()
        r = redis.from_url(settings.redis_url, decode_responses=True, socket_timeout=3)
        r.ping()
        info = r.info("memory")
        latency_ms = (time.perf_counter() - start) * 1000
        return {
            "status": "healthy",
            "latency_ms": round(latency_ms, 1),
            "used_memory_human": info.get("used_memory_human", "unknown"),
        }
    except Exception as e:
        logger.error("Redis health check failed: %s", e)
        return {"status": "unhealthy", "error": str(e)}


def _check_celery() -> dict:
    try:
        from app.worker.celery_app import celery_app

        start = time.perf_counter()
        inspector = celery_app.control.inspect(timeout=3)
        active = inspector.active()
        latency_ms = (time.perf_counter() - start) * 1000

        if active is None:
            return {"status": "degraded", "detail": "No workers responded"}

        worker_count = len(active)
        active_tasks = sum(len(tasks) for tasks in active.values())
        return {
            "status": "healthy",
            "latency_ms": round(latency_ms, 1),
            "workers": worker_count,
            "active_tasks": active_tasks,
        }
    except Exception as e:
        logger.error("Celery health check failed: %s", e)
        return {"status": "unhealthy", "error": str(e)}


def _check_circuit_breakers() -> dict:
    breakers = get_all_breakers()
    statuses = {}
    for b in breakers:
        statuses[b.name] = b.status()
    return statuses


@router.get("/health")
def liveness():
    """Shallow liveness probe -- always returns 200 if the process is running."""
    return {
        "status": "ok",
        "app": "VibeSecure API",
        "version": "3.0.0",
        "timestamp": datetime.now(UTC).isoformat(),
    }


@router.get("/health/ready")
def readiness():
    """Deep readiness probe. Returns 503 if any critical dependency is down."""
    db = _check_database()
    rd = _check_redis()

    checks = {"database": db, "redis": rd}
    all_healthy = all(c["status"] == "healthy" for c in checks.values())

    status_code = 200 if all_healthy else 503
    return {
        "status": "ready" if all_healthy else "not_ready",
        "checks": checks,
        "timestamp": datetime.now(UTC).isoformat(),
    }, status_code


@router.get("/health/detailed")
def detailed_health():
    """Full system health report including Celery workers and circuit breakers."""
    db = _check_database()
    rd = _check_redis()
    cl = _check_celery()
    cb = _check_circuit_breakers()

    checks = {"database": db, "redis": rd, "celery": cl}
    all_healthy = all(c["status"] == "healthy" for c in checks.values())

    return {
        "status": "healthy" if all_healthy else "degraded",
        "checks": checks,
        "circuit_breakers": cb,
        "version": "3.0.0",
        "timestamp": datetime.now(UTC).isoformat(),
    }
