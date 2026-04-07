"""Tests for the Containment layer."""

import pytest

from protector_stack.containment.circuit_breaker import (
    CircuitBreakerRegistry,
    CircuitState,
)
from protector_stack.containment.permissions import PermissionManager
from protector_stack.containment.quarantine import QuarantineManager, QuarantineStatus


# ── Circuit Breaker ───────────────────────────────────────────────────────────

def test_circuit_starts_closed():
    reg = CircuitBreakerRegistry()
    cb = reg.get("test_scope", failure_threshold=3)
    assert cb.state == CircuitState.CLOSED
    assert not cb.is_open()


def test_circuit_opens_after_threshold():
    reg = CircuitBreakerRegistry()
    cb = reg.get("scope_a", failure_threshold=3)
    cb.record_failure("fail 1")
    cb.record_failure("fail 2")
    assert cb.state == CircuitState.CLOSED
    cb.record_failure("fail 3")
    assert cb.state == CircuitState.OPEN
    assert cb.is_open()


def test_circuit_force_reset():
    reg = CircuitBreakerRegistry()
    cb = reg.get("scope_b", failure_threshold=2)
    cb.record_failure("f1")
    cb.record_failure("f2")
    assert cb.state == CircuitState.OPEN
    cb.force_reset("operator-1")
    assert cb.state == CircuitState.CLOSED


def test_circuit_scope_blocked():
    reg = CircuitBreakerRegistry()
    cb = reg.get("scope_c", failure_threshold=1)
    cb.record_failure("fail")
    assert reg.is_scope_blocked("scope_c")
    assert not reg.is_scope_blocked("other_scope")


def test_circuit_registry_status():
    reg = CircuitBreakerRegistry()
    reg.get("s1", failure_threshold=3)
    reg.get("s2", failure_threshold=3)
    status = reg.get_status()
    assert "s1" in status
    assert "s2" in status


# ── Permission Manager ────────────────────────────────────────────────────────

def test_grant_and_check():
    mgr = PermissionManager()
    mgr.grant("agent-1", "file:read")
    assert mgr.has_permission("agent-1", "file:read")
    assert not mgr.has_permission("agent-1", "network:outbound")


def test_revoke_specific_scope():
    mgr = PermissionManager()
    mgr.grant("agent-2", "file:read")
    mgr.grant("agent-2", "network:outbound")
    count = mgr.revoke("agent-2", "file:read", revoked_by="op-1", reason="test")
    assert count == 1
    assert not mgr.has_permission("agent-2", "file:read")
    assert mgr.has_permission("agent-2", "network:outbound")


def test_revoke_all_scopes():
    mgr = PermissionManager()
    mgr.grant("agent-3", "file:read")
    mgr.grant("agent-3", "file:write")
    mgr.grant("agent-3", "network:outbound")
    count = mgr.revoke("agent-3", None, revoked_by="op-1", reason="full revoke")
    assert count == 3
    assert not mgr.has_permission("agent-3", "file:read")
    assert not mgr.has_permission("agent-3", "network:outbound")


def test_get_active_scopes():
    mgr = PermissionManager()
    mgr.grant("agent-4", "scope_x")
    mgr.grant("agent-4", "scope_y")
    scopes = mgr.get_active_scopes("agent-4")
    assert "scope_x" in scopes
    assert "scope_y" in scopes


# ── Quarantine Manager ────────────────────────────────────────────────────────

def test_quarantine_agent():
    mgr = QuarantineManager()
    record = mgr.quarantine_agent("agent-bad-1", reason="test quarantine", operator_id="op-1")
    assert record.status == QuarantineStatus.ACTIVE
    assert record.target_type == "agent"
    assert mgr.is_quarantined("agent-bad-1")


def test_quarantine_release():
    mgr = QuarantineManager()
    record = mgr.quarantine_agent("agent-bad-2", reason="test", operator_id="op-1")
    released = mgr.release(record.quarantine_id, "op-1")
    assert released
    assert not mgr.is_quarantined("agent-bad-2")


def test_quarantine_get_active():
    mgr = QuarantineManager()
    mgr.quarantine_agent("agent-x", reason="x", operator_id="op")
    mgr.quarantine_agent("agent-y", reason="y", operator_id="op")
    active = mgr.get_active()
    ids = {r.target_id for r in active}
    assert "agent-x" in ids
    assert "agent-y" in ids
