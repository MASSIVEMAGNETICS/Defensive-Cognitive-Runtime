"""
Memory Layer: Decision Provenance
-----------------------------------
Records the full decision provenance chain for every policy decision:
Why was this action allowed/blocked/escalated?
What evidence led to this decision?
Which rules fired?
Who approved or denied?

This layer is the "explainability backbone" of the system.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from protector_stack.memory.audit import get_audit_ledger
from protector_stack.utils.logging import get_logger

log = get_logger(__name__)


@dataclass
class ProvenanceRecord:
    """Full provenance chain for a single decision."""
    provenance_id: str
    action_id: str
    action_type: str
    actor_id: str
    decision: str
    risk_score: float
    matched_rules: list[str]
    threat_signals: list[str]
    simulation_summary: Optional[str]
    human_reviewer: Optional[str]
    approved: Optional[bool]
    explanation: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    context: dict[str, Any] = field(default_factory=dict)


class ProvenanceTracker:
    """Records and retrieves provenance chains."""

    def __init__(self) -> None:
        self._records: list[ProvenanceRecord] = []

    def record(
        self,
        action_id: str,
        action_type: str,
        actor_id: str,
        decision: str,
        risk_score: float,
        matched_rules: list[str],
        threat_signals: list[str],
        explanation: str,
        simulation_summary: Optional[str] = None,
        human_reviewer: Optional[str] = None,
        approved: Optional[bool] = None,
        context: Optional[dict] = None,
    ) -> str:
        """Record a provenance entry. Returns the provenance_id."""
        import uuid
        prov_id = f"PROV-{str(uuid.uuid4())[:8].upper()}"

        prov = ProvenanceRecord(
            provenance_id=prov_id,
            action_id=action_id,
            action_type=action_type,
            actor_id=actor_id,
            decision=decision,
            risk_score=risk_score,
            matched_rules=matched_rules,
            threat_signals=threat_signals,
            simulation_summary=simulation_summary,
            human_reviewer=human_reviewer,
            approved=approved,
            explanation=explanation,
            context=context or {},
        )
        self._records.append(prov)

        # Also persist to audit ledger
        try:
            get_audit_ledger().append(
                entry_type="policy_decision",
                summary=f"Decision: {decision} for {action_type} by {actor_id}",
                payload={
                    "provenance_id": prov_id,
                    "action_id": action_id,
                    "action_type": action_type,
                    "actor_id": actor_id,
                    "decision": decision,
                    "risk_score": risk_score,
                    "matched_rules": matched_rules,
                    "threat_signals": threat_signals,
                    "explanation": explanation,
                },
                actor_id=actor_id,
            )
        except Exception as exc:
            log.error(f"Failed to persist provenance to audit ledger: {exc}")

        return prov_id

    def get_for_action(self, action_id: str) -> Optional[ProvenanceRecord]:
        for rec in reversed(self._records):
            if rec.action_id == action_id:
                return rec
        return None

    def get_recent(self, limit: int = 50) -> list[ProvenanceRecord]:
        return list(reversed(self._records[-limit:]))

    def explain_action(self, action_id: str) -> str:
        """Return a human-readable explanation of why an action was decided."""
        rec = self.get_for_action(action_id)
        if rec is None:
            return f"No provenance record found for action {action_id}."

        lines = [
            f"═══ Decision Provenance: {rec.provenance_id} ═══",
            f"Action:       {rec.action_type} [{rec.action_id[:8]}…]",
            f"Actor:        {rec.actor_id}",
            f"Decision:     {rec.decision.upper()}",
            f"Risk Score:   {rec.risk_score:.2f}",
            f"Timestamp:    {rec.timestamp.isoformat()}",
            "",
            "Rules Matched:",
        ]
        for rule in rec.matched_rules:
            lines.append(f"  ▶ {rule}")
        if rec.threat_signals:
            lines.append("")
            lines.append("Threat Signals:")
            for sig in rec.threat_signals:
                lines.append(f"  ⚠ {sig}")
        if rec.simulation_summary:
            lines.append("")
            lines.append("Simulation:")
            lines.append(f"  {rec.simulation_summary[:200]}")
        if rec.human_reviewer:
            lines.append("")
            lines.append(
                f"Human Review: {rec.human_reviewer} → "
                f"{'APPROVED' if rec.approved else 'DENIED'}"
            )
        lines.append("")
        lines.append("Explanation:")
        lines.append(rec.explanation)
        return "\n".join(lines)


# Singleton
_tracker: Optional[ProvenanceTracker] = None


def get_provenance_tracker() -> ProvenanceTracker:
    global _tracker
    if _tracker is None:
        _tracker = ProvenanceTracker()
    return _tracker
