"""
Containment Layer: Rollback Manager
--------------------------------------
Manages state snapshots and rollback hooks for recoverable actions.

A rollback hook is a registered callable that can undo a specific action.
Snapshots are lightweight state captures (JSON-serializable dicts) stored
to disk so that recovery is possible even after process restart.
"""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

from protector_stack.utils.config import get_config
from protector_stack.utils.logging import get_logger

log = get_logger(__name__)


@dataclass
class Snapshot:
    snapshot_id: str
    label: str
    state: dict[str, Any]
    created_at: datetime = field(default_factory=datetime.utcnow)
    action_id: Optional[str] = None


RollbackHook = Callable[[], bool]  # Returns True if rollback succeeded


class RollbackManager:
    """Manages state snapshots and registered rollback hooks."""

    def __init__(self) -> None:
        cfg = get_config()
        self._snapshot_dir = Path(cfg.data_dir) / "snapshots"
        self._snapshot_dir.mkdir(parents=True, exist_ok=True)
        self._hooks: dict[str, RollbackHook] = {}
        self._snapshots: dict[str, Snapshot] = {}

    def take_snapshot(
        self,
        label: str,
        state: dict[str, Any],
        action_id: Optional[str] = None,
    ) -> Snapshot:
        """Take a named snapshot of the given state dict."""
        snap = Snapshot(
            snapshot_id=str(uuid.uuid4())[:12],
            label=label,
            state=state,
            action_id=action_id,
        )
        self._snapshots[snap.snapshot_id] = snap

        # Persist to disk
        snap_path = self._snapshot_dir / f"{snap.snapshot_id}.json"
        snap_path.write_text(
            json.dumps(
                {
                    "snapshot_id": snap.snapshot_id,
                    "label": label,
                    "state": state,
                    "created_at": snap.created_at.isoformat(),
                    "action_id": action_id,
                },
                indent=2,
                default=str,
            ),
            encoding="utf-8",
        )
        log.info(f"Snapshot taken: {snap.snapshot_id} ({label})")
        return snap

    def register_rollback_hook(self, action_id: str, hook: RollbackHook) -> None:
        """Register a callable that can undo the action with the given action_id."""
        self._hooks[action_id] = hook
        log.debug(f"Rollback hook registered for action {action_id[:8]}…")

    def execute_rollback(self, action_id: str, operator_id: str) -> bool:
        """Execute the registered rollback hook for an action.

        Returns True if rollback succeeded.
        """
        hook = self._hooks.get(action_id)
        if hook is None:
            log.warning(f"No rollback hook registered for action {action_id[:8]}…")
            return False
        try:
            result = hook()
            log.info(
                f"Rollback executed for action {action_id[:8]}… "
                f"by {operator_id}: {'success' if result else 'failed'}"
            )
            return result
        except Exception as exc:
            log.error(f"Rollback hook raised exception for {action_id}: {exc}")
            return False

    def get_snapshot(self, snapshot_id: str) -> Optional[Snapshot]:
        return self._snapshots.get(snapshot_id)

    def list_snapshots(self) -> list[dict]:
        return [
            {
                "snapshot_id": s.snapshot_id,
                "label": s.label,
                "created_at": s.created_at.isoformat(),
                "action_id": s.action_id,
            }
            for s in self._snapshots.values()
        ]

    def load_snapshots_from_disk(self) -> int:
        """Load persisted snapshots from the snapshot directory."""
        loaded = 0
        for path in self._snapshot_dir.glob("*.json"):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                snap = Snapshot(
                    snapshot_id=data["snapshot_id"],
                    label=data["label"],
                    state=data["state"],
                    created_at=datetime.fromisoformat(data["created_at"]),
                    action_id=data.get("action_id"),
                )
                self._snapshots[snap.snapshot_id] = snap
                loaded += 1
            except Exception as exc:
                log.warning(f"Failed to load snapshot {path}: {exc}")
        return loaded


# Singleton
_manager: Optional[RollbackManager] = None


def get_rollback_manager() -> RollbackManager:
    global _manager
    if _manager is None:
        _manager = RollbackManager()
    return _manager
