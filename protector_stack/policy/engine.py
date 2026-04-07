"""
Policy Engine: Core Evaluation Engine
---------------------------------------
Evaluates ActionDescriptors against the active ruleset and returns
PolicyEvaluationResult objects. Supports context-sensitive evaluation,
risk-score integration, and explicit approval workflows.

Evaluation order:
  1. Doctrine check (hard-wired non-goals from constitution)
  2. Hard-deny rules (highest precedence)
  3. Escalate rules
  4. Soft-deny rules
  5. Audit rules
  6. Allow rules
  7. Default fallback (configurable: allow or deny)
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

import yaml

from protector_stack.constitution.doctrine import HARD_NON_GOALS
from protector_stack.policy.rules import DEFAULT_RULES
from protector_stack.policy.schemas import (
    ActionCategory,
    ActionDescriptor,
    ApprovalRequest,
    PolicyDecision,
    PolicyEvaluationResult,
    PolicyRule,
    RiskLevel,
)
from protector_stack.utils.config import get_config
from protector_stack.utils.logging import get_logger

log = get_logger(__name__)


def _risk_to_level(score: float) -> RiskLevel:
    if score >= 0.85:
        return RiskLevel.CRITICAL
    if score >= 0.70:
        return RiskLevel.HIGH
    if score >= 0.40:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def _condition_matches(condition: dict[str, Any], action: ActionDescriptor) -> bool:
    """Evaluate a single condition dict against an ActionDescriptor."""
    for key, value in condition.items():
        if key == "action_type_contains":
            if str(value).lower() not in action.action_type.lower():
                return False
        elif key == "category_equals":
            if action.category.value != str(value):
                return False
        elif key == "risk_score_above":
            if action.risk_score <= float(value):
                return False
        elif key == "risk_score_below":
            if action.risk_score >= float(value):
                return False
        elif key == "actor_id_equals":
            if action.actor_id != str(value):
                return False
        elif key == "target_contains":
            if action.target is None or str(value).lower() not in action.target.lower():
                return False
        elif key == "context_key_exists":
            if str(value) not in action.context:
                return False
        elif key == "parameter_key_exists":
            if str(value) not in action.parameters:
                return False
        # Unknown condition keys are ignored (safe: does not break rule matching)
    return True


def _rule_applies(rule: PolicyRule, action: ActionDescriptor) -> bool:
    """Return True if a rule applies to the given action."""
    if not rule.enabled:
        return False
    # Category match: if rule specifies a non-UNKNOWN category, it must match
    if rule.category != ActionCategory.UNKNOWN and rule.category != action.category:
        return False
    # All conditions must match (AND logic)
    if rule.conditions:
        return all(_condition_matches(c, action) for c in rule.conditions)
    # No conditions: rule matches any action of the correct category
    return True


class PolicyEngine:
    """Evaluates actions against the active policy ruleset."""

    def __init__(self, extra_rules: Optional[list[PolicyRule]] = None) -> None:
        self._rules: list[PolicyRule] = list(DEFAULT_RULES)
        if extra_rules:
            self._rules.extend(extra_rules)
        self._default_unknown_decision = PolicyDecision.ALLOW_WITH_AUDIT
        cfg = get_config()
        self._strict_mode = cfg.policy_strict_mode
        self._risk_threshold_warn = cfg.risk_threshold_warn
        self._risk_threshold_block = cfg.risk_threshold_block
        self._risk_threshold_quarantine = cfg.risk_threshold_quarantine
        self._require_human_above = cfg.require_human_approval_above

    def load_yaml_rules(self, path: str) -> int:
        """Load additional rules from a YAML file. Returns count of rules loaded."""
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            extra = data.get("rules", [])
            loaded = 0
            for r in extra:
                try:
                    rule = PolicyRule(**r)
                    self._rules.append(rule)
                    loaded += 1
                except Exception as exc:
                    log.warning(f"Skipping invalid rule in {path}: {exc}")
            log.info(f"Loaded {loaded} rules from {path}")
            return loaded
        except FileNotFoundError:
            log.warning(f"Policy file not found: {path}")
            return 0
        except Exception as exc:
            log.error(f"Error loading policy file {path}: {exc}")
            return 0

    def evaluate(self, action: ActionDescriptor) -> PolicyEvaluationResult:
        """Evaluate an action against all rules. Returns PolicyEvaluationResult."""
        matched_rules: list[str] = []
        reasons: list[str] = []
        highest_decision = PolicyDecision.ALLOW
        requires_approval = False

        # ── Doctrine check: always applied first ─────────────────────────────
        for non_goal in HARD_NON_GOALS:
            if non_goal in action.action_type.lower():
                return PolicyEvaluationResult(
                    action_id=action.action_id,
                    decision=PolicyDecision.HARD_DENY,
                    matched_rules=["DOCTRINE"],
                    reasons=[
                        f"Action '{action.action_type}' matches hard non-goal "
                        f"'{non_goal}' from core doctrine."
                    ],
                    risk_level=RiskLevel.CRITICAL,
                    requires_approval=False,
                    explanation=(
                        f"This action is absolutely forbidden by the system's "
                        f"core doctrine (non-goal: {non_goal}). No override is possible."
                    ),
                )

        # ── Risk-score override ───────────────────────────────────────────────
        if action.risk_score >= self._risk_threshold_quarantine:
            return PolicyEvaluationResult(
                action_id=action.action_id,
                decision=PolicyDecision.HARD_DENY,
                matched_rules=["RISK_SCORE_CRITICAL"],
                reasons=[
                    f"Risk score {action.risk_score:.2f} exceeds quarantine "
                    f"threshold {self._risk_threshold_quarantine:.2f}."
                ],
                risk_level=RiskLevel.CRITICAL,
                requires_approval=True,
                explanation=(
                    f"The computed risk score ({action.risk_score:.2f}) exceeds the "
                    f"critical quarantine threshold. Action blocked. Human review required."
                ),
            )

        if action.risk_score >= self._risk_threshold_block:
            highest_decision = PolicyDecision.ESCALATE
            requires_approval = True
            reasons.append(
                f"Risk score {action.risk_score:.2f} exceeds block threshold "
                f"{self._risk_threshold_block:.2f} — escalating."
            )
            matched_rules.append("RISK_SCORE_HIGH")

        elif action.risk_score >= self._risk_threshold_warn:
            if _decision_rank(PolicyDecision.ALLOW_WITH_AUDIT) > _decision_rank(highest_decision):
                highest_decision = PolicyDecision.ALLOW_WITH_AUDIT
            reasons.append(
                f"Risk score {action.risk_score:.2f} exceeds warn threshold "
                f"{self._risk_threshold_warn:.2f} — auditing."
            )
            matched_rules.append("RISK_SCORE_MEDIUM")

        # ── Rule evaluation ───────────────────────────────────────────────────
        decision_priority = {
            PolicyDecision.HARD_DENY: 5,
            PolicyDecision.SOFT_DENY: 4,
            PolicyDecision.ESCALATE: 3,
            PolicyDecision.ALLOW_WITH_AUDIT: 2,
            PolicyDecision.ALLOW: 1,
        }

        for rule in self._rules:
            if _rule_applies(rule, action):
                matched_rules.append(rule.rule_id)
                reasons.append(f"Rule '{rule.name}' ({rule.rule_id}): {rule.description}")
                if decision_priority.get(rule.decision, 0) > decision_priority.get(highest_decision, 0):
                    highest_decision = rule.decision
                if rule.requires_approval:
                    requires_approval = True

        # ── Human-approval threshold ──────────────────────────────────────────
        if action.risk_score >= self._require_human_above:
            requires_approval = True

        # ── Final fallback ────────────────────────────────────────────────────
        if not matched_rules:
            highest_decision = self._default_unknown_decision
            reasons.append("No matching rules — applying default audit policy.")
            matched_rules.append("DEFAULT")

        risk_level = _risk_to_level(action.risk_score)
        explanation = _build_explanation(action, highest_decision, reasons)

        result = PolicyEvaluationResult(
            action_id=action.action_id,
            decision=highest_decision,
            matched_rules=matched_rules,
            reasons=reasons,
            risk_level=risk_level,
            requires_approval=requires_approval,
            explanation=explanation,
        )

        log.info(
            f"Policy eval [{action.action_type}] → {highest_decision.value} "
            f"(risk={action.risk_score:.2f}, rules={matched_rules})"
        )
        return result

    def get_rules(self) -> list[PolicyRule]:
        """Return a copy of the active ruleset."""
        return list(self._rules)

    def get_rule_by_id(self, rule_id: str) -> Optional[PolicyRule]:
        """Return a specific rule by ID."""
        for rule in self._rules:
            if rule.rule_id == rule_id:
                return rule
        return None


def _decision_rank(d: PolicyDecision) -> int:
    return {
        PolicyDecision.ALLOW: 1,
        PolicyDecision.ALLOW_WITH_AUDIT: 2,
        PolicyDecision.ESCALATE: 3,
        PolicyDecision.SOFT_DENY: 4,
        PolicyDecision.HARD_DENY: 5,
    }.get(d, 0)


def _build_explanation(
    action: ActionDescriptor,
    decision: PolicyDecision,
    reasons: list[str],
) -> str:
    lines = [
        f"Action: {action.action_type} (ID: {action.action_id[:8]}…)",
        f"Actor: {action.actor_id}",
        f"Risk Score: {action.risk_score:.2f}",
        f"Decision: {decision.value.upper()}",
        "Reasons:",
    ]
    for r in reasons:
        lines.append(f"  - {r}")
    return "\n".join(lines)


# Module-level singleton
_engine: Optional[PolicyEngine] = None


def get_policy_engine() -> PolicyEngine:
    """Return the global policy engine singleton."""
    global _engine
    if _engine is None:
        _engine = PolicyEngine()
        cfg = get_config()
        if cfg.policy_path:
            _engine.load_yaml_rules(cfg.policy_path)
    return _engine


def reset_policy_engine() -> None:
    """Reset singleton (for testing)."""
    global _engine
    _engine = None
