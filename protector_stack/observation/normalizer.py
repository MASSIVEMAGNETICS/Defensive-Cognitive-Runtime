"""
Observation Layer: Event Normalizer
-------------------------------------
Converts raw event data from various sensors into normalized ObservedEvent
objects. All events pass through this normalizer before being stored or analyzed.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from protector_stack.observation.schemas import (
    EventType,
    FileEvent,
    ModelInteractionEvent,
    NetworkEvent,
    ObservedEvent,
    ProcessEvent,
)
from protector_stack.utils.logging import get_logger

log = get_logger(__name__)


class EventNormalizer:
    """Converts raw dicts from sensors into typed ObservedEvent objects."""

    def normalize(self, raw: dict[str, Any], source: str = "unknown") -> ObservedEvent:
        """Normalize a raw event dict into an ObservedEvent."""
        event_type_str = raw.get("type", "unknown")
        try:
            event_type = EventType(event_type_str)
        except ValueError:
            event_type = EventType.UNKNOWN

        actor_id = str(raw.get("actor_id", raw.get("username", raw.get("pid", "unknown"))))
        target = raw.get("target", raw.get("path", raw.get("remote_addr", None)))
        description = raw.get("description", self._auto_description(event_type, raw))
        tags = raw.get("tags", [])
        severity = raw.get("severity", "info")
        risk_hint = float(raw.get("risk_hint", 0.0))
        ts_raw = raw.get("timestamp")
        if isinstance(ts_raw, datetime):
            timestamp = ts_raw
        elif isinstance(ts_raw, str):
            try:
                timestamp = datetime.fromisoformat(ts_raw)
            except ValueError:
                timestamp = datetime.utcnow()
        else:
            timestamp = datetime.utcnow()

        # Sanitize: never store full prompts
        sanitized_raw = dict(raw)
        if "prompt" in sanitized_raw:
            prompt = str(sanitized_raw["prompt"])
            sanitized_raw["prompt"] = prompt[:200] + ("…" if len(prompt) > 200 else "")
        if "response" in sanitized_raw:
            resp = str(sanitized_raw["response"])
            sanitized_raw["response"] = resp[:200] + ("…" if len(resp) > 200 else "")

        event = ObservedEvent(
            event_type=event_type,
            source=source,
            actor_id=actor_id,
            target=str(target) if target is not None else None,
            description=description,
            raw_data=sanitized_raw,
            tags=tags,
            timestamp=timestamp,
            severity=severity,
            risk_hint=risk_hint,
        )
        return event

    @staticmethod
    def _auto_description(event_type: EventType, raw: dict[str, Any]) -> str:
        if event_type == EventType.PROCESS_SPAWN:
            return f"Process spawned: {raw.get('name', '?')} (pid={raw.get('pid', '?')})"
        if event_type == EventType.FILE_CREATED:
            return f"File created: {raw.get('path', '?')}"
        if event_type == EventType.FILE_MODIFIED:
            return f"File modified: {raw.get('path', '?')}"
        if event_type == EventType.FILE_DELETED:
            return f"File deleted: {raw.get('path', '?')}"
        if event_type == EventType.NETWORK_CONNECTION:
            return (
                f"Network connection: {raw.get('local_addr','?')} → "
                f"{raw.get('remote_addr','?')}:{raw.get('remote_port','?')}"
            )
        if event_type == EventType.MODEL_INFERENCE:
            return f"Model inference: {raw.get('model_id','?')}"
        if event_type == EventType.TOOL_INVOCATION:
            return f"Tool invoked: {raw.get('tool_name', '?')}"
        if event_type == EventType.AGENT_ACTION:
            return f"Agent action: {raw.get('action_type', '?')}"
        return f"Event: {event_type.value}"


# Singleton
_normalizer: EventNormalizer | None = None


def get_normalizer() -> EventNormalizer:
    global _normalizer
    if _normalizer is None:
        _normalizer = EventNormalizer()
    return _normalizer
