"""
Request correlation / tracing middleware.

Every inbound request gets a unique ``X-Request-ID`` header that propagates
through logs, downstream service calls, and response headers so operators
can trace a single user action across the entire system.
"""

import contextvars
import logging
import time
import uuid

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

logger = logging.getLogger(__name__)

# Context variable accessible from anywhere in the call stack.
request_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="")


def get_request_id() -> str:
    """Return the current request's correlation ID (empty string outside a request)."""
    return request_id_ctx.get()


class RequestTracingFilter(logging.Filter):
    """Inject ``request_id`` into every log record automatically."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = get_request_id() or "-"
        return True


class RequestTracingMiddleware(BaseHTTPMiddleware):
    """Assign / propagate a correlation ID for every request.

    * If the caller already supplies ``X-Request-ID``, we reuse it.
    * Otherwise a new UUID4 is generated.
    * The ID is set as a context variable for downstream code and attached to
      the response as ``X-Request-ID``.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        rid = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        token = request_id_ctx.set(rid)

        start = time.perf_counter()
        try:
            response = await call_next(request)
            elapsed_ms = (time.perf_counter() - start) * 1000

            response.headers["X-Request-ID"] = rid
            response.headers["X-Response-Time-Ms"] = f"{elapsed_ms:.1f}"

            logger.info(
                "%s %s %d %.1fms",
                request.method,
                request.url.path,
                response.status_code,
                elapsed_ms,
                extra={"request_id": rid},
            )
            return response
        finally:
            request_id_ctx.reset(token)


def setup_logging(level: int = logging.INFO) -> None:
    """Configure structured logging with request-ID injection."""
    fmt = "%(asctime)s [%(levelname)s] %(name)s [%(request_id)s] %(message)s"

    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(fmt))
    handler.addFilter(RequestTracingFilter())

    root = logging.getLogger()
    root.setLevel(level)
    # Avoid duplicate handlers on reload
    root.handlers = [handler]
