from .ai_test import router as governance_router
from .auth import router as auth_router
from .consent import router as consent_router
from .domain import router as domains_router
from .scan import router as scans_router

__all__ = ["auth_router", "scans_router", "domains_router", "consent_router", "governance_router"]
