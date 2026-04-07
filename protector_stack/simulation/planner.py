"""
Simulation Layer: Pre-Action Planner & Forecaster
---------------------------------------------------
Before high-risk actions execute, the planner:
1. Describes what the action will do (dry-run description)
2. Estimates consequences (reversible vs irreversible)
3. Generates scenario branches (best-case / worst-case)
4. Produces a plain-English summary for the human reviewer

This is a CLOSED, SYNTHETIC simulation — it does NOT execute the action.
It reasons about the action type and parameters only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from protector_stack.policy.schemas import ActionDescriptor, ActionCategory
from protector_stack.utils.logging import get_logger

log = get_logger(__name__)


@dataclass
class ActionBranch:
    """A possible outcome scenario for a simulated action."""
    name: str       # "best_case" | "expected" | "worst_case"
    description: str
    reversible: bool
    impact_score: float  # 0.0–1.0
    affected_resources: list[str] = field(default_factory=list)


@dataclass
class SimulationResult:
    """Result of a dry-run simulation for a proposed action."""
    action_id: str
    action_type: str
    safe: bool
    summary: str
    reversible: bool
    branches: list[ActionBranch] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    estimated_impact_score: float = 0.0


# ── Impact estimation by category ─────────────────────────────────────────────

_CATEGORY_IMPACT: dict[str, float] = {
    ActionCategory.READ.value: 0.1,
    ActionCategory.WRITE.value: 0.35,
    ActionCategory.EXECUTE.value: 0.60,
    ActionCategory.NETWORK.value: 0.45,
    ActionCategory.PROCESS.value: 0.55,
    ActionCategory.PERMISSION.value: 0.70,
    ActionCategory.MODEL_INFERENCE.value: 0.20,
    ActionCategory.AGENT_ACTION.value: 0.50,
    ActionCategory.GOVERNANCE.value: 0.30,
    ActionCategory.SYSTEM.value: 0.65,
    ActionCategory.UNKNOWN.value: 0.40,
}

_REVERSIBLE_CATEGORIES = {
    ActionCategory.READ,
    ActionCategory.MODEL_INFERENCE,
    ActionCategory.GOVERNANCE,
}

_IRREVERSIBLE_KEYWORDS = {
    "delete", "purge", "destroy", "wipe", "format", "terminate",
    "kill", "disable", "revoke", "remove", "quarantine",
}


class ActionPlanner:
    """Simulates the effects of proposed actions without executing them."""

    def simulate(self, action: ActionDescriptor) -> SimulationResult:
        """Generate a dry-run simulation report for the given action."""
        action_lower = action.action_type.lower()
        base_impact = _CATEGORY_IMPACT.get(action.category.value, 0.4)

        # Adjust impact based on risk score
        impact = min(1.0, max(base_impact, action.risk_score))

        # Reversibility
        is_reversible = action.category in _REVERSIBLE_CATEGORIES
        if any(kw in action_lower for kw in _IRREVERSIBLE_KEYWORDS):
            is_reversible = False

        # Scenario branches
        branches = self._generate_branches(action, impact, is_reversible)

        # Warnings
        warnings: list[str] = []
        if not is_reversible:
            warnings.append("This action may be IRREVERSIBLE. Ensure a snapshot/backup exists.")
        if impact >= 0.7:
            warnings.append(
                f"High estimated impact score ({impact:.2f}). Recommend human review before proceeding."
            )
        if action.risk_score >= 0.85:
            warnings.append(
                "Risk score exceeds quarantine threshold. Action should NOT execute without explicit approval."
            )

        summary = self._build_summary(action, impact, is_reversible, warnings)

        result = SimulationResult(
            action_id=action.action_id,
            action_type=action.action_type,
            safe=impact < 0.7 and action.risk_score < 0.7,
            summary=summary,
            reversible=is_reversible,
            branches=branches,
            warnings=warnings,
            estimated_impact_score=round(impact, 3),
        )

        log.info(
            f"Simulation [{action.action_type}]: impact={impact:.2f}, "
            f"reversible={is_reversible}, safe={result.safe}"
        )
        return result

    def _generate_branches(
        self,
        action: ActionDescriptor,
        base_impact: float,
        reversible: bool,
    ) -> list[ActionBranch]:
        target = action.target or "unspecified target"
        actor = action.actor_id

        best = ActionBranch(
            name="best_case",
            description=(
                f"Action '{action.action_type}' completes successfully with minimal side effects. "
                f"Target '{target}' is affected as intended. No cascade effects."
            ),
            reversible=reversible,
            impact_score=max(0.0, base_impact * 0.5),
            affected_resources=[target],
        )
        expected = ActionBranch(
            name="expected",
            description=(
                f"Action '{action.action_type}' executes by actor '{actor}'. "
                f"Target '{target}' state is changed. "
                f"Estimated impact: {base_impact:.2f}. "
                + ("Reversible." if reversible else "NOT REVERSIBLE — state change is permanent.")
            ),
            reversible=reversible,
            impact_score=base_impact,
            affected_resources=[target],
        )
        worst = ActionBranch(
            name="worst_case",
            description=(
                f"Action '{action.action_type}' causes cascading changes beyond '{target}'. "
                f"If this actor is compromised, this action may enable further privilege or "
                f"access expansion. "
                + ("Manual rollback may be needed." if not reversible else "Rollback is possible.")
            ),
            reversible=False,
            impact_score=min(1.0, base_impact * 1.5),
            affected_resources=[target, "adjacent_resources"],
        )
        return [best, expected, worst]

    @staticmethod
    def _build_summary(
        action: ActionDescriptor,
        impact: float,
        reversible: bool,
        warnings: list[str],
    ) -> str:
        lines = [
            f"DRY-RUN SIMULATION: {action.action_type}",
            f"  Actor: {action.actor_id}",
            f"  Target: {action.target or 'N/A'}",
            f"  Estimated impact: {impact:.2f}/1.00",
            f"  Reversible: {'yes' if reversible else 'NO — irreversible change'}",
            f"  Risk score: {action.risk_score:.2f}",
        ]
        if warnings:
            lines.append("  Warnings:")
            for w in warnings:
                lines.append(f"    ⚠ {w}")
        return "\n".join(lines)
