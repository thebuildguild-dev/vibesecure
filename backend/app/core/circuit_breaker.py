"""
Circuit Breaker pattern for external service calls.

Prevents cascading failures by short-circuiting calls to unhealthy
dependencies (Gemini, ZAP, email providers, etc.).

States:
  CLOSED   -- Normal operation, requests pass through.
  OPEN     -- Failures exceeded threshold, requests are rejected immediately.
  HALF_OPEN -- After cooldown, one probe request is allowed to test recovery.
"""

import enum
import logging
import threading
import time
from collections import deque
from collections.abc import Callable
from functools import wraps
from typing import Any

logger = logging.getLogger(__name__)


class CircuitState(str, enum.Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitOpenError(Exception):
    """Raised when a call is rejected because the circuit is open."""

    def __init__(self, name: str, remaining_seconds: float):
        self.name = name
        self.remaining_seconds = remaining_seconds
        super().__init__(f"Circuit '{name}' is OPEN. Retry in {remaining_seconds:.1f}s")


class CircuitBreaker:
    """Thread-safe circuit breaker with sliding-window failure tracking."""

    def __init__(
        self,
        name: str,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
        half_open_max_calls: int = 1,
        window_size: float = 120.0,
        expected_exceptions: tuple[type[Exception], ...] = (Exception,),
    ):
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_max_calls = half_open_max_calls
        self.window_size = window_size
        self.expected_exceptions = expected_exceptions

        self._state = CircuitState.CLOSED
        self._failures: deque[float] = deque()
        self._opened_at: float = 0.0
        self._half_open_calls: int = 0
        self._lock = threading.Lock()

        # Counters for observability
        self.total_calls: int = 0
        self.total_successes: int = 0
        self.total_failures: int = 0
        self.total_rejected: int = 0

    @property
    def state(self) -> CircuitState:
        with self._lock:
            if self._state == CircuitState.OPEN:
                if time.monotonic() - self._opened_at >= self.recovery_timeout:
                    self._state = CircuitState.HALF_OPEN
                    self._half_open_calls = 0
                    logger.info("Circuit '%s' transitioning OPEN -> HALF_OPEN", self.name)
            return self._state

    def _record_success(self) -> None:
        with self._lock:
            self.total_successes += 1
            if self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.CLOSED
                self._failures.clear()
                logger.info("Circuit '%s' recovered: HALF_OPEN -> CLOSED", self.name)

    def _record_failure(self) -> None:
        now = time.monotonic()
        with self._lock:
            self.total_failures += 1
            self._failures.append(now)

            # Evict failures outside the sliding window
            cutoff = now - self.window_size
            while self._failures and self._failures[0] < cutoff:
                self._failures.popleft()

            if self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.OPEN
                self._opened_at = now
                logger.warning("Circuit '%s' probe failed: HALF_OPEN -> OPEN", self.name)
            elif len(self._failures) >= self.failure_threshold:
                self._state = CircuitState.OPEN
                self._opened_at = now
                logger.warning(
                    "Circuit '%s' tripped: CLOSED -> OPEN (%d failures in %.0fs window)",
                    self.name,
                    len(self._failures),
                    self.window_size,
                )

    def _allow_request(self) -> bool:
        current_state = self.state  # property check may transition OPEN->HALF_OPEN
        if current_state == CircuitState.CLOSED:
            return True
        if current_state == CircuitState.HALF_OPEN:
            with self._lock:
                if self._half_open_calls < self.half_open_max_calls:
                    self._half_open_calls += 1
                    return True
            return False
        return False

    def call(self, func: Callable, *args: Any, **kwargs: Any) -> Any:
        """Execute *func* through the circuit breaker."""
        self.total_calls += 1
        if not self._allow_request():
            self.total_rejected += 1
            remaining = self.recovery_timeout - (time.monotonic() - self._opened_at)
            raise CircuitOpenError(self.name, max(0, remaining))

        try:
            result = func(*args, **kwargs)
            self._record_success()
            return result
        except self.expected_exceptions:
            self._record_failure()
            raise

    def status(self) -> dict:
        """Return a snapshot of the breaker's health for monitoring."""
        return {
            "name": self.name,
            "state": self.state.value,
            "total_calls": self.total_calls,
            "total_successes": self.total_successes,
            "total_failures": self.total_failures,
            "total_rejected": self.total_rejected,
            "recent_failures": len(self._failures),
            "failure_threshold": self.failure_threshold,
            "recovery_timeout_s": self.recovery_timeout,
        }


def circuit_breaker(breaker: CircuitBreaker):
    """Decorator that wraps a function with a circuit breaker."""

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            return breaker.call(func, *args, **kwargs)

        wrapper._circuit_breaker = breaker
        return wrapper

    return decorator


# ── Pre-configured breakers for core services ───────────────────

gemini_breaker = CircuitBreaker(
    name="gemini",
    failure_threshold=5,
    recovery_timeout=60,
    window_size=120,
)

zap_breaker = CircuitBreaker(
    name="zap",
    failure_threshold=3,
    recovery_timeout=90,
    window_size=180,
)

email_breaker = CircuitBreaker(
    name="email",
    failure_threshold=4,
    recovery_timeout=120,
    window_size=300,
)


def get_all_breakers() -> list[CircuitBreaker]:
    return [gemini_breaker, zap_breaker, email_breaker]
