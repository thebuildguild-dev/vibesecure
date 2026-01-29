from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.core.config import settings
from src.core.database import init_db
from src.core.middleware import RateLimitMiddleware
from src.api import scans_router, auth_router, domains_router, consent_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="VibeSecure API",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(RateLimitMiddleware, max_requests=settings.rate_limit_max_requests, redis_url=settings.redis_url)
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


@app.get("/health")
def health_check():
    return {"status": "ok", "app": "VibeSecure API"}

