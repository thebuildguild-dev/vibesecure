"""
Prometheus-compatible metrics collection.

Tracks request latency histograms, in-flight request gauges, agent execution
durations, circuit breaker state changes, and business-level counters.

Exposes a ``/metrics`` endpoint in Prometheus text format.
"""

import threading
import time
from collections import defaultdict

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware


class _Counter:
    """Thread-safe monotonic counter."""

    __slots__ = ("_value", "_lock")

    def __init__(self) -> None:
        self._value: float = 0
        self._lock = threading.Lock()

    def inc(self, amount: float = 1) -> None:
        with self._lock:
            self._value += amount

    @property
    def value(self) -> float:
        return self._value


class _Gauge:
    """Thread-safe gauge (can go up and down)."""

    __slots__ = ("_value", "_lock")

    def __init__(self) -> None:
        self._value: float = 0
        self._lock = threading.Lock()

    def inc(self, amount: float = 1) -> None:
        with self._lock:
            self._value += amount

    def dec(self, amount: float = 1) -> None:
        with self._lock:
            self._value -= amount

    def set(self, value: float) -> None:
        with self._lock:
            self._value = value

    @property
    def value(self) -> float:
        return self._value


class _Histogram:
    """Simple histogram with fixed buckets."""

    DEFAULT_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, float("inf"))

    def __init__(self, buckets: tuple[float, ...] | None = None) -> None:
        self._buckets = buckets or self.DEFAULT_BUCKETS
        self._counts = [0] * len(self._buckets)
        self._sum: float = 0.0
        self._count: int = 0
        self._lock = threading.Lock()

    def observe(self, value: float) -> None:
        with self._lock:
            self._sum += value
            self._count += 1
            for i, bound in enumerate(self._buckets):
                if value <= bound:
                    self._counts[i] += 1

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "buckets": list(zip(self._buckets, list(self._counts))),
                "sum": self._sum,
                "count": self._count,
            }


class MetricsRegistry:
    """Central metrics store. Singleton pattern through module-level instance."""

    def __init__(self) -> None:
        self._lock = threading.Lock()

        # HTTP metrics
        self.http_requests_total: dict[str, _Counter] = defaultdict(_Counter)
        self.http_request_duration = _Histogram()
        self.http_in_flight = _Gauge()

        # Agent metrics
        self.agent_executions_total: dict[str, _Counter] = defaultdict(_Counter)
        self.agent_errors_total: dict[str, _Counter] = defaultdict(_Counter)
        self.agent_duration = _Histogram(
            buckets=(0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, float("inf"))
        )

        # Governance jobs
        self.jobs_created = _Counter()
        self.jobs_completed = _Counter()
        self.jobs_failed = _Counter()

        # Scans
        self.scans_created = _Counter()
        self.scans_completed = _Counter()

        # Circuit breaker trips
        self.circuit_trips_total: dict[str, _Counter] = defaultdict(_Counter)

    def record_http_request(
        self, method: str, path: str, status_code: int, duration: float
    ) -> None:
        label = f"{method}_{self._bucket_path(path)}_{status_code}"
        self.http_requests_total[label].inc()
        self.http_request_duration.observe(duration)

    def record_agent_execution(self, agent_name: str, duration: float, success: bool) -> None:
        self.agent_executions_total[agent_name].inc()
        self.agent_duration.observe(duration)
        if not success:
            self.agent_errors_total[agent_name].inc()

    def record_circuit_trip(self, breaker_name: str) -> None:
        self.circuit_trips_total[breaker_name].inc()

    @staticmethod
    def _bucket_path(path: str) -> str:
        """Reduce cardinality by collapsing path parameters."""
        parts = path.strip("/").split("/")
        collapsed = []
        for p in parts:
            # Collapse UUIDs and numeric IDs
            if len(p) >= 32 or p.isdigit():
                collapsed.append(":id")
            else:
                collapsed.append(p)
        return "/".join(collapsed) or "root"

    def to_prometheus(self) -> str:
        """Render metrics in Prometheus exposition format."""
        lines: list[str] = []

        # HTTP request totals
        lines.append("# HELP vibesecure_http_requests_total Total HTTP requests")
        lines.append("# TYPE vibesecure_http_requests_total counter")
        for label, counter in sorted(self.http_requests_total.items()):
            lines.append(f'vibesecure_http_requests_total{{label="{label}"}} {counter.value}')

        # HTTP duration histogram
        snap = self.http_request_duration.snapshot()
        lines.append("# HELP vibesecure_http_request_duration_seconds HTTP request duration")
        lines.append("# TYPE vibesecure_http_request_duration_seconds histogram")
        cumulative = 0
        for bound, count in snap["buckets"]:
            cumulative += count
            le = "+Inf" if bound == float("inf") else str(bound)
            lines.append(
                f'vibesecure_http_request_duration_seconds_bucket{{le="{le}"}} {cumulative}'
            )
        lines.append(f"vibesecure_http_request_duration_seconds_sum {snap['sum']}")
        lines.append(f"vibesecure_http_request_duration_seconds_count {snap['count']}")

        # In-flight
        lines.append("# HELP vibesecure_http_in_flight Current in-flight requests")
        lines.append("# TYPE vibesecure_http_in_flight gauge")
        lines.append(f"vibesecure_http_in_flight {self.http_in_flight.value}")

        # Agent metrics
        lines.append("# HELP vibesecure_agent_executions_total Agent execution count")
        lines.append("# TYPE vibesecure_agent_executions_total counter")
        for agent, counter in sorted(self.agent_executions_total.items()):
            lines.append(f'vibesecure_agent_executions_total{{agent="{agent}"}} {counter.value}')

        lines.append("# HELP vibesecure_agent_errors_total Agent error count")
        lines.append("# TYPE vibesecure_agent_errors_total counter")
        for agent, counter in sorted(self.agent_errors_total.items()):
            lines.append(f'vibesecure_agent_errors_total{{agent="{agent}"}} {counter.value}')

        # Jobs
        lines.append("# HELP vibesecure_jobs_created_total Governance jobs created")
        lines.append("# TYPE vibesecure_jobs_created_total counter")
        lines.append(f"vibesecure_jobs_created_total {self.jobs_created.value}")
        lines.append(f"vibesecure_jobs_completed_total {self.jobs_completed.value}")
        lines.append(f"vibesecure_jobs_failed_total {self.jobs_failed.value}")

        # Scans
        lines.append(f"vibesecure_scans_created_total {self.scans_created.value}")
        lines.append(f"vibesecure_scans_completed_total {self.scans_completed.value}")

        # Circuit breaker trips
        lines.append("# HELP vibesecure_circuit_trips_total Circuit breaker trip count")
        lines.append("# TYPE vibesecure_circuit_trips_total counter")
        for name, counter in sorted(self.circuit_trips_total.items()):
            lines.append(f'vibesecure_circuit_trips_total{{breaker="{name}"}} {counter.value}')

        return "\n".join(lines) + "\n"


# Module-level singleton
metrics = MetricsRegistry()


class MetricsMiddleware(BaseHTTPMiddleware):
    """Collect HTTP request metrics for every inbound request."""

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.url.path == "/metrics":
            return await call_next(request)

        metrics.http_in_flight.inc()
        start = time.perf_counter()
        try:
            response = await call_next(request)
            duration = time.perf_counter() - start
            metrics.record_http_request(
                request.method, request.url.path, response.status_code, duration
            )
            return response
        except Exception:
            duration = time.perf_counter() - start
            metrics.record_http_request(request.method, request.url.path, 500, duration)
            raise
        finally:
            metrics.http_in_flight.dec()
