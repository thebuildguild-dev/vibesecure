from .auth import router as auth_router
from .scans import router as scans_router
from .domains import router as domains_router
from .consent import router as consent_router

__all__ = ["auth_router", "scans_router", "domains_router", "consent_router"]
