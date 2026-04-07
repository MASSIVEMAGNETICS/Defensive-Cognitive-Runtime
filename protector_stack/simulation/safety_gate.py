"""
Simulation Layer: Safety Gate
-------------------------------
Pre-action safety checklist. Before high-risk actions execute, the safety gate
runs a checklist of conditions that must pass. Failed checks block execution.

The gate is the last line of defense before a containment action is dispatched
to an external system.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from protector_stack.policy.schemas import ActionDescriptor, PolicyDecision, PolicyEvaluationResult
from protector_stack.utils.logging import get_logger

log = get_logger(__name__)


class CheckStatus(str, Enum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"


@dataclass
class SafetyCheck:
    name: str
    status: CheckStatus
    message: str


@dataclass
class SafetyGateResult:
    action_id: str
    cleared: bool  # True if action may proceed
    checks: list[SafetyCheck] = field(default_factory=list)
    block_reason: Optional[str] = None
    warnings: list[str] = field(default_factory=list)


class SafetyGate:
    """Runs a checklist of safety conditions before high-risk actions execute."""

    def evaluate(
        self,
        action: ActionDescriptor,
        policy_result: PolicyEvaluationResult,
        simulation_result: Optional[dict] = None,
    ) -> SafetyGateResult:
        """Run the safety checklist. Returns SafetyGateResult."""
        checks: list[SafetyCheck] = []

        # ── Check 1: Doctrine compliance ─────────────────────────────────────
        from protector_stack.constitution.doctrine import HARD_NON_GOALS
        doctrine_violation = any(ng in action.action_type.lower() for ng in HARD_NON_GOALS)
        checks.append(SafetyCheck(
            name="doctrine_compliance",
            status=CheckStatus.FAIL if doctrine_violation else CheckStatus.PASS,
            message=(
                "Action violates core doctrine non-goals."
                if doctrine_violation else "Doctrine compliance OK."
            ),
        ))

        # ── Check 2: Policy decision ──────────────────────────────────────────
        if policy_result.decision == PolicyDecision.HARD_DENY:
            checks.append(SafetyCheck(
                name="policy_decision",
                status=CheckStatus.FAIL,
                message=f"Policy hard-deny: {policy_result.explanation[:100]}",
            ))
        elif policy_result.decision == PolicyDecision.SOFT_DENY:
            checks.append(SafetyCheck(
                name="policy_decision",
                status=CheckStatus.WARN,
                message=f"Policy soft-deny: {policy_result.explanation[:100]}",
            ))
        else:
            checks.append(SafetyCheck(
                name="policy_decision",
                status=CheckStatus.PASS,
                message=f"Policy decision: {policy_result.decision.value}",
            ))

        # ── Check 3: Human approval (if required) ─────────────────────────────
        if policy_result.requires_approval and policy_result.approval_id is None:
            checks.append(SafetyCheck(
                name="human_approval",
                status=CheckStatus.FAIL,
                message="Human approval required but not yet obtained.",
            ))
        else:
            checks.append(SafetyCheck(
                name="human_approval",
                status=CheckStatus.PASS,
                message=(
                    "Human approval not required."
                    if not policy_result.requires_approval
                    else f"Approval obtained: {policy_result.approval_id}"
                ),
            ))

        # ── Check 4: Risk score ceiling ────────────────────────────────────────
        from protector_stack.utils.config import get_config
        cfg = get_config()
        if action.risk_score >= cfg.risk_threshold_quarantine:
            checks.append(SafetyCheck(
                name="risk_ceiling",
                status=CheckStatus.FAIL,
                message=f"Risk score {action.risk_score:.2f} exceeds quarantine threshold.",
            ))
        elif action.risk_score >= cfg.risk_threshold_block:
            checks.append(SafetyCheck(
                name="risk_ceiling",
                status=CheckStatus.WARN,
                message=f"Risk score {action.risk_score:.2f} is above block threshold.",
            ))
        else:
            checks.append(SafetyCheck(
                name="risk_ceiling",
                status=CheckStatus.PASS,
                message=f"Risk score {action.risk_score:.2f} within acceptable range.",
            ))

        # ── Check 5: Simulation result (if available) ─────────────────────────
        if simulation_result:
            sim_safe = simulation_result.get("safe", True)
            sim_msg = simulation_result.get("summary", "Simulation completed.")
            checks.append(SafetyCheck(
                name="simulation_outcome",
                status=CheckStatus.PASS if sim_safe else CheckStatus.FAIL,
                message=sim_msg[:150],
            ))

        # ── Aggregate ─────────────────────────────────────────────────────────
        failures = [c for c in checks if c.status == CheckStatus.FAIL]
        warnings_list = [c.message for c in checks if c.status == CheckStatus.WARN]
        cleared = len(failures) == 0

        block_reason = None
        if failures:
            block_reason = "; ".join(c.message for c in failures)

        result = SafetyGateResult(
            action_id=action.action_id,
            cleared=cleared,
            checks=checks,
            block_reason=block_reason,
            warnings=warnings_list,
        )

        if not cleared:
            log.warning(
                f"SafetyGate BLOCKED action {action.action_type} "
                f"[{action.action_id[:8]}…]: {block_reason}"
            )
        else:
            if warnings_list:
                log.info(
                    f"SafetyGate CLEARED action {action.action_type} "
                    f"(with warnings: {warnings_list})"
                )
            else:
                log.debug(f"SafetyGate CLEARED action {action.action_type}")

        return result
