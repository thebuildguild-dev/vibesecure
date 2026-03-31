"""
In-process domain event bus.

Enables decoupled communication between components using a publish/subscribe
pattern. Events are dispatched asynchronously within the same process, allowing
different parts of the system (audit logger, webhook dispatcher, metrics,
notifications) to react to domain events without tight coupling.

Usage:
    from app.core.events import event_bus, DomainEvent

    # Define an event
    class ScanCompleted(DomainEvent):
        event_type = "scan.completed"

    # Subscribe
    @event_bus.on("scan.completed")
    async def handle_scan_completed(event):
        ...

    # Publish
    await event_bus.emit(ScanCompleted(data={...}))
"""

import asyncio
import logging
import time
import uuid
from collections import defaultdict
from collections.abc import Callable, Coroutine
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class DomainEvent:
    """Base class for all domain events."""

    event_type: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    source: str = ""
    correlation_id: str = ""


# Concrete event types


@dataclass
class ScanCreatedEvent(DomainEvent):
    event_type: str = "scan.created"


@dataclass
class ScanCompletedEvent(DomainEvent):
    event_type: str = "scan.completed"


@dataclass
class ScanFailedEvent(DomainEvent):
    event_type: str = "scan.failed"


@dataclass
class GovernanceJobCreatedEvent(DomainEvent):
    event_type: str = "governance.job.created"


@dataclass
class GovernanceJobCompletedEvent(DomainEvent):
    event_type: str = "governance.job.completed"


@dataclass
class GovernanceJobFailedEvent(DomainEvent):
    event_type: str = "governance.job.failed"


@dataclass
class AgentStartedEvent(DomainEvent):
    event_type: str = "agent.started"


@dataclass
class AgentCompletedEvent(DomainEvent):
    event_type: str = "agent.completed"


@dataclass
class AgentFailedEvent(DomainEvent):
    event_type: str = "agent.failed"


@dataclass
class DomainVerifiedEvent(DomainEvent):
    event_type: str = "domain.verified"


@dataclass
class WebhookDeliveryEvent(DomainEvent):
    event_type: str = "webhook.delivery"


@dataclass
class CircuitBreakerTrippedEvent(DomainEvent):
    event_type: str = "circuit_breaker.tripped"


@dataclass
class SecurityAlertEvent(DomainEvent):
    event_type: str = "security.alert"


# Handler type
EventHandler = Callable[[DomainEvent], Coroutine[Any, Any, None]]


class EventBus:
    """Async in-process event bus with wildcard support.

    Handlers are called concurrently for each event. Exceptions in individual
    handlers are logged but do not prevent other handlers from executing.
    """

    def __init__(self) -> None:
        self._handlers: dict[str, list[EventHandler]] = defaultdict(list)
        self._global_handlers: list[EventHandler] = []

    def on(self, event_type: str):
        """Decorator to register a handler for a specific event type."""

        def decorator(fn: EventHandler) -> EventHandler:
            self._handlers[event_type].append(fn)
            return fn

        return decorator

    def on_all(self, fn: EventHandler) -> EventHandler:
        """Register a handler that receives every event (useful for audit logging)."""
        self._global_handlers.append(fn)
        return fn

    def subscribe(self, event_type: str, handler: EventHandler) -> None:
        """Programmatic subscription (non-decorator)."""
        self._handlers[event_type].append(handler)

    def unsubscribe(self, event_type: str, handler: EventHandler) -> None:
        """Remove a handler."""
        self._handlers[event_type] = [h for h in self._handlers[event_type] if h is not handler]

    async def emit(self, event: DomainEvent) -> None:
        """Publish an event to all matching handlers."""
        from app.core.tracing import get_request_id

        if not event.correlation_id:
            event.correlation_id = get_request_id()

        specific = self._handlers.get(event.event_type, [])
        # Wildcard: "scan.*" matches "scan.completed"
        wildcard = []
        for pattern, handlers in self._handlers.items():
            if pattern.endswith(".*"):
                prefix = pattern[:-2]
                if event.event_type.startswith(prefix + ".") and pattern != event.event_type:
                    wildcard.extend(handlers)

        all_handlers = specific + wildcard + self._global_handlers

        if not all_handlers:
            return

        tasks = [self._safe_call(h, event) for h in all_handlers]
        await asyncio.gather(*tasks)

    def emit_sync(self, event: DomainEvent) -> None:
        """Fire-and-forget emit for synchronous contexts (e.g., Celery workers).

        If an event loop is already running, schedules the coroutine.
        Otherwise, creates a new loop to run it.
        """
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self.emit(event))
        except RuntimeError:
            asyncio.run(self.emit(event))

    @staticmethod
    async def _safe_call(handler: EventHandler, event: DomainEvent) -> None:
        try:
            await handler(event)
        except Exception:
            logger.exception(
                "Event handler %s failed for event %s",
                handler.__qualname__,
                event.event_type,
            )


# Module-level singleton
event_bus = EventBus()
