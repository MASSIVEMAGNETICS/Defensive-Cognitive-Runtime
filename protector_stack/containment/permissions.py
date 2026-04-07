"""
Containment Layer: Permission Manager
---------------------------------------
Tracks and enforces permission revocation for agents and processes.
When an actor's permissions are revoked:
- They are removed from the active permission set
- Policy engine denies all future actions from that actor
- The revocation is logged in the audit ledger
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from protector_stack.utils.logging import get_logger

log = get_logger(__name__)


@dataclass
class PermissionGrant:
    actor_id: str
    scope: str              # e.g. "file:read", "network:outbound", "model:inference"
    granted_at: datetime = field(default_factory=datetime.utcnow)
    granted_by: str = "system"
    expires_at: Optional[datetime] = None
    active: bool = True


@dataclass
class RevocationRecord:
    actor_id: str
    scope: str
    revoked_at: datetime = field(default_factory=datetime.utcnow)
    revoked_by: str = "operator"
    reason: str = ""


class PermissionManager:
    """Manages active permissions and revocations for actors."""

    def __init__(self) -> None:
        self._grants: dict[str, list[PermissionGrant]] = {}
        self._revocations: list[RevocationRecord] = []

    def grant(
        self,
        actor_id: str,
        scope: str,
        granted_by: str = "operator",
        expires_at: Optional[datetime] = None,
    ) -> PermissionGrant:
        """Grant a permission scope to an actor."""
        grant = PermissionGrant(
            actor_id=actor_id,
            scope=scope,
            granted_by=granted_by,
            expires_at=expires_at,
        )
        self._grants.setdefault(actor_id, []).append(grant)
        log.info(f"Permission granted: {actor_id} → {scope} (by {granted_by})")
        return grant

    def revoke(
        self,
        actor_id: str,
        scope: Optional[str],
        revoked_by: str,
        reason: str = "",
    ) -> int:
        """Revoke one or all permission scopes for an actor.

        If scope is None, revokes ALL scopes.
        Returns the number of grants revoked.
        """
        count = 0
        grants = self._grants.get(actor_id, [])
        for grant in grants:
            if grant.active and (scope is None or grant.scope == scope):
                grant.active = False
                count += 1
                self._revocations.append(RevocationRecord(
                    actor_id=actor_id,
                    scope=grant.scope,
                    revoked_by=revoked_by,
                    reason=reason,
                ))
                log.warning(
                    f"Permission REVOKED: {actor_id} → {grant.scope} "
                    f"by {revoked_by}: {reason}"
                )
        return count

    def has_permission(self, actor_id: str, scope: str) -> bool:
        """Return True if actor has an active, non-expired grant for scope."""
        now = datetime.utcnow()
        for grant in self._grants.get(actor_id, []):
            if not grant.active:
                continue
            if grant.scope != scope and not scope.startswith(grant.scope.rstrip("*")):
                continue
            if grant.expires_at and grant.expires_at < now:
                grant.active = False
                continue
            return True
        return False

    def get_active_scopes(self, actor_id: str) -> list[str]:
        """Return all active scope strings for an actor."""
        now = datetime.utcnow()
        scopes = []
        for grant in self._grants.get(actor_id, []):
            if not grant.active:
                continue
            if grant.expires_at and grant.expires_at < now:
                grant.active = False
                continue
            scopes.append(grant.scope)
        return scopes

    def get_revocations(self) -> list[RevocationRecord]:
        return list(self._revocations)


# Singleton
_manager: Optional[PermissionManager] = None


def get_permission_manager() -> PermissionManager:
    global _manager
    if _manager is None:
        _manager = PermissionManager()
    return _manager
