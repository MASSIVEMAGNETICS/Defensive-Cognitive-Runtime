"""Tests for the Simulation layer."""

import pytest

from protector_stack.simulation.planner import ActionPlanner
from protector_stack.simulation.safety_gate import SafetyGate, CheckStatus
from protector_stack.policy.schemas import (
    ActionCategory,
    ActionDescriptor,
    PolicyDecision,
    PolicyEvaluationResult,
    RiskLevel,
)


def make_action(**kwargs) -> ActionDescriptor:
    defaults = {
        "action_type": "read_file",
        "category": ActionCategory.READ,
        "actor_id": "test-agent",
        "risk_score": 0.0,
    }
    defaults.update(kwargs)
    return ActionDescriptor(**defaults)


def make_result(decision=PolicyDecision.ALLOW, requires_approval=False, **kwargs) -> PolicyEvaluationResult:
    defaults = {
        "action_id": "test-action",
        "decision": decision,
        "requires_approval": requires_approval,
        "risk_level": RiskLevel.LOW,
        "explanation": "test",
    }
    defaults.update(kwargs)
    return PolicyEvaluationResult(**defaults)


# ── ActionPlanner ─────────────────────────────────────────────────────────────

def test_planner_benign_read():
    planner = ActionPlanner()
    action = make_action(action_type="read_file", category=ActionCategory.READ, risk_score=0.1)
    result = planner.simulate(action)
    assert result.safe
    assert result.reversible
    assert len(result.branches) == 3


def test_planner_high_risk_not_safe():
    planner = ActionPlanner()
    action = make_action(action_type="delete_all", category=ActionCategory.WRITE, risk_score=0.9)
    result = planner.simulate(action)
    assert not result.safe
    assert len(result.warnings) > 0


def test_planner_irreversible_action():
    planner = ActionPlanner()
    action = make_action(action_type="delete_database", category=ActionCategory.SYSTEM, risk_score=0.5)
    result = planner.simulate(action)
    assert not result.reversible


def test_planner_has_branches():
    planner = ActionPlanner()
    action = make_action(action_type="write_config", category=ActionCategory.WRITE, risk_score=0.3)
    result = planner.simulate(action)
    names = {b.name for b in result.branches}
    assert "best_case" in names
    assert "expected" in names
    assert "worst_case" in names


# ── SafetyGate ────────────────────────────────────────────────────────────────

def test_safety_gate_clears_benign():
    gate = SafetyGate()
    action = make_action(risk_score=0.1)
    policy_result = make_result(decision=PolicyDecision.ALLOW, requires_approval=False)
    result = gate.evaluate(action, policy_result)
    assert result.cleared


def test_safety_gate_blocks_hard_deny():
    gate = SafetyGate()
    action = make_action(action_type="read_file", risk_score=0.1)
    policy_result = make_result(decision=PolicyDecision.HARD_DENY, requires_approval=False)
    result = gate.evaluate(action, policy_result)
    assert not result.cleared
    assert result.block_reason


def test_safety_gate_blocks_missing_approval():
    gate = SafetyGate()
    action = make_action(risk_score=0.5)
    policy_result = make_result(
        decision=PolicyDecision.ESCALATE,
        requires_approval=True,
        approval_id=None,
    )
    result = gate.evaluate(action, policy_result)
    assert not result.cleared


def test_safety_gate_blocks_doctrine_violation():
    gate = SafetyGate()
    action = make_action(action_type="produce_malware", risk_score=0.0)
    policy_result = make_result(decision=PolicyDecision.ALLOW)
    result = gate.evaluate(action, policy_result)
    assert not result.cleared


def test_safety_gate_blocks_critical_risk():
    gate = SafetyGate()
    action = make_action(risk_score=0.9)
    policy_result = make_result(decision=PolicyDecision.ALLOW)
    result = gate.evaluate(action, policy_result)
    assert not result.cleared
