"""Tests for the Memory/Audit layer."""

import os
import tempfile
import pytest

# Use temp DB for tests
_tmp_dir = tempfile.mkdtemp()
os.environ["PROTECTOR_DB_PATH"] = os.path.join(_tmp_dir, "test_audit.db")
os.environ["PROTECTOR_DATA_DIR"] = _tmp_dir
os.environ["PROTECTOR_AUDIT_SIGNING_KEY_PATH"] = os.path.join(_tmp_dir, "test_key.pem")

from protector_stack.memory.audit import AuditLedger, reset_audit_ledger
from protector_stack.memory.incidents import IncidentManager, IncidentSeverity, IncidentStatus


@pytest.fixture(autouse=True)
def reset():
    reset_audit_ledger()
    yield
    reset_audit_ledger()


@pytest.fixture
def ledger(tmp_path):
    os.environ["PROTECTOR_DB_PATH"] = str(tmp_path / "audit.db")
    os.environ["PROTECTOR_AUDIT_SIGNING_KEY_PATH"] = str(tmp_path / "key.pem")
    reset_audit_ledger()
    return AuditLedger()


# ── Audit Ledger ──────────────────────────────────────────────────────────────

def test_audit_append_and_count(ledger):
    initial = ledger.count()
    ledger.append(entry_type="test", summary="Test event", payload={"x": 1})
    assert ledger.count() == initial + 1


def test_audit_chain_valid_after_append(ledger):
    ledger.append(entry_type="test", summary="Entry 1", payload={})
    ledger.append(entry_type="test", summary="Entry 2", payload={})
    ledger.append(entry_type="test", summary="Entry 3", payload={})
    ok, msg = ledger.verify_chain()
    assert ok, msg


def test_audit_query_by_type(ledger):
    ledger.append(entry_type="threat", summary="Threat A", payload={"score": 0.8})
    ledger.append(entry_type="policy_decision", summary="Policy B", payload={})
    threats = ledger.query(entry_type="threat")
    assert all(e["entry_type"] == "threat" for e in threats)


def test_audit_chain_empty_or_valid_ledger(ledger):
    ok, msg = ledger.verify_chain()
    assert ok, msg
    # Should either be empty or have valid chain
    assert ("empty" in msg.lower() or "verified ok" in msg.lower())


# ── Incident Manager ──────────────────────────────────────────────────────────

@pytest.fixture
def incident_mgr(tmp_path):
    os.environ["PROTECTOR_DB_PATH"] = str(tmp_path / "incidents.db")
    return IncidentManager()


def test_create_incident(incident_mgr):
    inc_id = incident_mgr.create(
        title="Test Incident",
        description="Something suspicious happened.",
        severity=IncidentSeverity.HIGH,
        threat_category="suspicious",
        risk_score=0.75,
    )
    assert inc_id.startswith("INC-")
    incident = incident_mgr.get(inc_id)
    assert incident is not None
    assert incident["title"] == "Test Incident"
    assert incident["severity"] == "high"
    assert incident["status"] == IncidentStatus.DETECTED.value


def test_update_incident_status(incident_mgr):
    inc_id = incident_mgr.create(
        title="Update Test", description=".", severity=IncidentSeverity.LOW
    )
    ok = incident_mgr.update_status(inc_id, IncidentStatus.INVESTIGATING, "Looking into it", "op-1")
    assert ok
    incident = incident_mgr.get(inc_id)
    assert incident["status"] == IncidentStatus.INVESTIGATING.value


def test_add_note(incident_mgr):
    inc_id = incident_mgr.create(
        title="Note Test", description=".", severity=IncidentSeverity.MEDIUM
    )
    ok = incident_mgr.add_note(inc_id, "Initial analysis complete.", "op-1")
    assert ok
    incident = incident_mgr.get(inc_id)
    assert "Initial analysis complete" in incident["operator_notes"]


def test_list_incidents(incident_mgr):
    for i in range(3):
        incident_mgr.create(
            title=f"Incident {i}", description=".", severity=IncidentSeverity.LOW
        )
    items = incident_mgr.list_incidents()
    assert len(items) >= 3


def test_incident_not_found(incident_mgr):
    result = incident_mgr.get("INC-NOTREAL")
    assert result is None
