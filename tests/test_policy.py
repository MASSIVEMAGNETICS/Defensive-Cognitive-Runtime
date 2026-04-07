"""Tests for the Policy Engine."""

import os
import pytest

os.environ.setdefault("PROTECTOR_DB_PATH", "/tmp/protector_test.db")
os.environ.setdefault("PROTECTOR_DATA_DIR", "/tmp/protector_test_data")
os.environ.setdefault("PROTECTOR_AUDIT_SIGNING_KEY_PATH", "/tmp/protector_test_key.pem")

from protector_stack.policy.engine import PolicyEngine, reset_policy_engine
from protector_stack.policy.schemas import (
    ActionCategory,
    ActionDescriptor,
    PolicyDecision,
    RiskLevel,
)


@pytest.fixture(autouse=True)
def reset_engine():
    reset_policy_engine()
    yield
    reset_policy_engine()


def make_action(**kwargs) -> ActionDescriptor:
    defaults = {
        "action_type": "read_file",
        "category": ActionCategory.READ,
        "actor_id": "test-agent",
        "risk_score": 0.0,
    }
    defaults.update(kwargs)
    return ActionDescriptor(**defaults)


def test_benign_read_allowed():
    engine = PolicyEngine()
    action = make_action(action_type="read_config", category=ActionCategory.READ, risk_score=0.0)
    result = engine.evaluate(action)
    assert result.decision in (PolicyDecision.ALLOW, PolicyDecision.ALLOW_WITH_AUDIT)


def test_hard_deny_for_malware():
    engine = PolicyEngine()
    action = make_action(
        action_type="produce_malware",
        category=ActionCategory.EXECUTE,
        risk_score=0.0,
    )
    result = engine.evaluate(action)
    assert result.decision == PolicyDecision.HARD_DENY


def test_hard_deny_for_exploit():
    engine = PolicyEngine()
    action = make_action(action_type="generate_exploit_chain", risk_score=0.0)
    result = engine.evaluate(action)
    assert result.decision == PolicyDecision.HARD_DENY


def test_hard_deny_for_credential_theft():
    engine = PolicyEngine()
    action = make_action(action_type="credential_theft", risk_score=0.0)
    result = engine.evaluate(action)
    assert result.decision == PolicyDecision.HARD_DENY


def test_escalate_on_high_risk_score():
    engine = PolicyEngine()
    action = make_action(action_type="network_send", category=ActionCategory.NETWORK, risk_score=0.75)
    result = engine.evaluate(action)
    assert result.decision in (PolicyDecision.ESCALATE, PolicyDecision.HARD_DENY)
    assert result.requires_approval


def test_hard_deny_on_critical_risk_score():
    engine = PolicyEngine()
    action = make_action(action_type="some_action", risk_score=0.95)
    result = engine.evaluate(action)
    assert result.decision == PolicyDecision.HARD_DENY


def test_model_inference_audited():
    engine = PolicyEngine()
    action = make_action(
        action_type="model_inference",
        category=ActionCategory.MODEL_INFERENCE,
        risk_score=0.1,
    )
    result = engine.evaluate(action)
    assert result.decision in (PolicyDecision.ALLOW_WITH_AUDIT, PolicyDecision.ALLOW)


def test_quarantine_requires_approval():
    engine = PolicyEngine()
    action = make_action(
        action_type="quarantine_process",
        category=ActionCategory.PROCESS,
        risk_score=0.3,
    )
    result = engine.evaluate(action)
    assert result.requires_approval


def test_evaluation_result_has_explanation():
    engine = PolicyEngine()
    action = make_action(action_type="read_file", risk_score=0.0)
    result = engine.evaluate(action)
    assert result.explanation
    assert result.action_id == action.action_id


def test_load_yaml_rules_missing_file():
    engine = PolicyEngine()
    loaded = engine.load_yaml_rules("/nonexistent/path.yaml")
    assert loaded == 0
