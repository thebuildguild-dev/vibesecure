"""
VibeSecure API -- FastAPI application entry point.

Architecture highlights:
  - API versioning under /api/v1
  - Request correlation ID tracing (X-Request-ID)
  - Prometheus-compatible /metrics endpoint
  - Deep health checks (/health/ready, /health/detailed)
  - Circuit breaker protection for external services
  - Domain event bus for decoupled component communication
  - Structured audit logging to PostgreSQL
  - Webhook notification system
  - Graceful startup / shutdown lifecycle
"""

import logging
from contextlib import asynccontextmanager

import redis
from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.database import engine, init_db
from app.core.health import router as health_router
from app.core.metrics import MetricsMiddleware, metrics
from app.core.middleware import RateLimitMiddleware
from app.core.tracing import RequestTracingMiddleware, setup_logging

# Routers
from app.routers.ai_test import router as governance_router
from app.routers.auth import router as auth_router
from app.routers.consent import router as consent_router
from app.routers.deepfake import router as deepfake_router
from app.routers.digital_asset import router as digital_asset_router
from app.routers.domain import router as domains_router
from app.routers.privacy import router as privacy_router
from app.routers.responsible_ai import router as responsible_ai_router
from app.routers.scan import router as scans_router
from app.routers.threat_intel import router as threat_intel_router
from app.routers.webhooks import router as webhooks_router

logger = logging.getLogger(__name__)


# ── Lifecycle ────────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown hooks for the application."""
    # ── Startup ──
    setup_logging(level=logging.DEBUG if settings.debug else logging.INFO)
    logger.info("Initializing database tables")
    init_db()

    # Verify Redis is reachable
    try:
        r = redis.from_url(settings.redis_url, decode_responses=True, socket_timeout=5)
        r.ping()
        logger.info("Redis connection verified")
    except Exception as e:
        logger.warning("Redis not reachable at startup: %s", e)

    # Import webhook_service to register event bus listeners
    import app.services.webhook_service  # noqa: F401

    # Wire audit logger to the event bus (global listener)
    from app.core.audit import audit
    from app.core.events import DomainEvent, event_bus

    @event_bus.on_all
    async def _audit_all_events(event: DomainEvent) -> None:
        """Persist every domain event as an audit entry."""
        audit.log(
            action=event.event_type,
            actor=event.data.get("user_email", "system"),
            resource_type=event.source or event.event_type.split(".")[0],
            resource_id=event.data.get("job_id", event.data.get("scan_id", "")),
            metadata=event.data,
        )

    logger.info("VibeSecure API v3.0.0 ready")

    yield

    # ── Shutdown ──
    logger.info("Shutting down: disposing database engine")
    engine.dispose()
    logger.info("Shutdown complete")


# ── Application ──────────────────────────────────────────────────

app = FastAPI(
    title="VibeSecure API",
    description="AI-native security governance platform with 11-agent swarm, "
    "circuit breakers, event bus, audit logging, and webhook notifications.",
    version="3.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── Middleware (order matters: outermost first) ──────────────────

# 1. Request tracing -- assigns X-Request-ID, measures response time
app.add_middleware(RequestTracingMiddleware)

# 2. Prometheus metrics collection
app.add_middleware(MetricsMiddleware)

# 3. Rate limiting
app.add_middleware(
    RateLimitMiddleware,
    max_requests=settings.rate_limit_max_requests,
    redis_url=settings.redis_url,
)

# 4. CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=settings.cors_allow_credentials,
    allow_methods=[settings.cors_allow_methods] if settings.cors_allow_methods != "*" else ["*"],
    allow_headers=[settings.cors_allow_headers] if settings.cors_allow_headers != "*" else ["*"],
)

# ── Health / observability (no auth, no prefix) ──────────────────

app.include_router(health_router)


@app.get("/metrics", include_in_schema=False)
def prometheus_metrics():
    """Prometheus-compatible metrics endpoint."""
    return Response(content=metrics.to_prometheus(), media_type="text/plain; charset=utf-8")


# ── API v1 routes ────────────────────────────────────────────────

API_V1 = "/api/v1"

app.include_router(auth_router, prefix=API_V1)
app.include_router(scans_router, prefix=API_V1)
app.include_router(domains_router, prefix=API_V1)
app.include_router(consent_router, prefix=API_V1)
app.include_router(governance_router, prefix=API_V1)
app.include_router(deepfake_router, prefix=API_V1)
app.include_router(threat_intel_router, prefix=API_V1)
app.include_router(responsible_ai_router, prefix=API_V1)
app.include_router(privacy_router, prefix=API_V1)
app.include_router(digital_asset_router, prefix=API_V1)
app.include_router(webhooks_router, prefix=API_V1)

# ── Backward-compatible /api routes (deprecated) ─────────────────

app.include_router(auth_router, prefix="/api", include_in_schema=False)
app.include_router(scans_router, prefix="/api", include_in_schema=False)
app.include_router(domains_router, prefix="/api", include_in_schema=False)
app.include_router(consent_router, prefix="/api", include_in_schema=False)
app.include_router(governance_router, prefix="/api", include_in_schema=False)
app.include_router(deepfake_router, prefix="/api", include_in_schema=False)
app.include_router(threat_intel_router, prefix="/api", include_in_schema=False)
app.include_router(responsible_ai_router, prefix="/api", include_in_schema=False)
app.include_router(privacy_router, prefix="/api", include_in_schema=False)
app.include_router(digital_asset_router, prefix="/api", include_in_schema=False)
app.include_router(webhooks_router, prefix="/api", include_in_schema=False)
