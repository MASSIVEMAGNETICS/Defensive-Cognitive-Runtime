"""Tests for the Constitution layer."""

import pytest
from protector_stack.constitution.doctrine import (
    HARD_NON_GOALS,
    AUTHORITY_BOUNDARY,
    MISSION_STATEMENT,
    PRINCIPLES,
    check_action_permitted,
    get_doctrine_summary,
)
from protector_stack.constitution.integrity import verify_doctrine_integrity


def test_mission_statement_not_empty():
    assert MISSION_STATEMENT
    assert "human agency" in MISSION_STATEMENT.lower()


def test_hard_non_goals_immutable():
    assert isinstance(HARD_NON_GOALS, frozenset)
    assert "produce_malware" in HARD_NON_GOALS
    assert "autonomous_weapons" in HARD_NON_GOALS
    assert "disable_human_oversight" in HARD_NON_GOALS


def test_six_principles():
    assert len(PRINCIPLES) == 6
    names = {p.name for p in PRINCIPLES}
    assert "pro_human" in names
    assert "defensive_first" in names
    assert "guardian_not_ruler" in names
    assert "auditable" in names
    assert "corrigible" in names
    assert "local_first" in names


def test_all_principles_binding():
    for p in PRINCIPLES:
        assert p.binding is True, f"Principle '{p.name}' should be binding"


def test_check_action_permitted_allowed():
    permitted, reason = check_action_permitted("log_event")
    assert permitted
    assert "permitted" in reason.lower()


def test_check_action_permitted_forbidden():
    permitted, reason = check_action_permitted("produce_malware")
    assert not permitted
    assert "forbidden" in reason.lower()


def test_check_action_requires_approval():
    permitted, reason = check_action_permitted("quarantine_process")
    assert permitted
    assert "approval" in reason.lower()


def test_check_action_unknown_defaults_to_approval():
    permitted, reason = check_action_permitted("unknown_action_xyz")
    assert permitted
    assert "approval" in reason.lower()


def test_doctrine_summary_keys():
    summary = get_doctrine_summary()
    assert "system" in summary
    assert "version" in summary
    assert "mission" in summary
    assert "principles" in summary
    assert "hard_non_goals" in summary


def test_doctrine_integrity():
    ok, msg = verify_doctrine_integrity()
    assert ok, f"Doctrine integrity failed: {msg}"
