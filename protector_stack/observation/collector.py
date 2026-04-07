"""
Observation Layer: Event Collector
------------------------------------
Central event bus for the PROTECTOR_STACK. All sensors submit events here.
The collector normalizes events, writes them to the audit ledger, and dispatches
them to registered analysis handlers.
"""

from __future__ import annotations

import threading
from datetime import datetime
from typing import Any, Callable, Optional

from protector_stack.observation.normalizer import get_normalizer
from protector_stack.observation.schemas import EventType, ObservedEvent
from protector_stack.utils.logging import get_logger

log = get_logger(__name__)

# Type alias for event handler callback
EventHandler = Callable[[ObservedEvent], None]


class EventCollector:
    """Thread-safe central event bus.

    Usage:
        collector = get_collector()
        collector.register_handler(my_handler)
        collector.submit({"type": "process_spawn", "pid": 1234, "name": "python"})
    """

    def __init__(self) -> None:
        self._handlers: list[EventHandler] = []
        self._lock = threading.Lock()
        self._normalizer = get_normalizer()
        self._event_count = 0
        self._started = datetime.utcnow()

    def register_handler(self, handler: EventHandler) -> None:
        """Register a callback to be called for every normalized event."""
        with self._lock:
            self._handlers.append(handler)
        log.debug(f"Event handler registered: {handler.__qualname__}")

    def unregister_handler(self, handler: EventHandler) -> None:
        """Remove a previously registered handler."""
        with self._lock:
            try:
                self._handlers.remove(handler)
            except ValueError:
                pass

    def submit(
        self,
        raw: dict[str, Any],
        source: str = "unknown",
    ) -> ObservedEvent:
        """Normalize and dispatch a raw event dict.

        Returns the normalized ObservedEvent.
        """
        event = self._normalizer.normalize(raw, source=source)
        self._event_count += 1

        with self._lock:
            handlers = list(self._handlers)

        for handler in handlers:
            try:
                handler(event)
            except Exception as exc:
                log.error(f"Event handler {handler.__qualname__} raised: {exc}")

        return event

    def submit_event(self, event: ObservedEvent) -> None:
        """Dispatch an already-normalized ObservedEvent directly."""
        self._event_count += 1
        with self._lock:
            handlers = list(self._handlers)
        for handler in handlers:
            try:
                handler(event)
            except Exception as exc:
                log.error(f"Event handler {handler.__qualname__} raised: {exc}")

    def stats(self) -> dict:
        return {
            "events_processed": self._event_count,
            "handler_count": len(self._handlers),
            "started_at": self._started.isoformat(),
        }


# ── Module-level singleton ────────────────────────────────────────────────────

_collector: Optional[EventCollector] = None


def get_collector() -> EventCollector:
    global _collector
    if _collector is None:
        _collector = EventCollector()
    return _collector


def reset_collector() -> None:
    global _collector
    _collector = None
