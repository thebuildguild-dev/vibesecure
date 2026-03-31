from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.database import init_db
from app.core.middleware import RateLimitMiddleware
from app.routers.ai_test import router as governance_router
from app.routers.auth import router as auth_router
from app.routers.consent import router as consent_router
from app.routers.domain import router as domains_router
from app.routers.scan import router as scans_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="VibeSecure API",
    description="AI-native governance platform with 11-agent swarm",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    RateLimitMiddleware, max_requests=settings.rate_limit_max_requests, redis_url=settings.redis_url
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=settings.cors_allow_credentials,
    allow_methods=[settings.cors_allow_methods] if settings.cors_allow_methods != "*" else ["*"],
    allow_headers=[settings.cors_allow_headers] if settings.cors_allow_headers != "*" else ["*"],
)

app.include_router(auth_router, prefix="/api")
app.include_router(scans_router, prefix="/api")
app.include_router(domains_router, prefix="/api")
app.include_router(consent_router, prefix="/api")
app.include_router(governance_router, prefix="/api")


@app.get("/health")
def health_check():
    return {"status": "ok", "app": "VibeSecure API", "version": "2.0.0"}
