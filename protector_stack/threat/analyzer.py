"""
Threat Analysis: Main Analyzer
--------------------------------
Orchestrates all threat detectors. Registered as an event handler on the
collector, it scores each event and triggers policy evaluation + containment
as needed.
"""

from __future__ import annotations

from typing import Optional

from protector_stack.observation.schemas import ObservedEvent
from protector_stack.policy.engine import get_policy_engine
from protector_stack.policy.schemas import ActionCategory, ActionDescriptor
from protector_stack.threat.scorer import ThreatAssessment, ThreatScorer, get_scorer
from protector_stack.utils.logging import get_logger

log = get_logger(__name__)


def _event_type_to_action_category(event_type_str: str) -> ActionCategory:
    mapping = {
        "process_spawn": ActionCategory.PROCESS,
        "process_terminate": ActionCategory.PROCESS,
        "file_created": ActionCategory.WRITE,
        "file_modified": ActionCategory.WRITE,
        "file_deleted": ActionCategory.WRITE,
        "network_connection": ActionCategory.NETWORK,
        "model_inference": ActionCategory.MODEL_INFERENCE,
        "tool_invocation": ActionCategory.AGENT_ACTION,
        "agent_action": ActionCategory.AGENT_ACTION,
        "permission_change": ActionCategory.PERMISSION,
        "login_event": ActionCategory.SYSTEM,
        "config_change": ActionCategory.SYSTEM,
    }
    return mapping.get(event_type_str, ActionCategory.UNKNOWN)


class ThreatAnalyzer:
    """Main threat analysis pipeline.

    Hooks into the event collector and processes each event through:
    1. ThreatScorer (multi-signal risk scoring)
    2. PolicyEngine (rule-based decision)
    3. ContainmentLayer (if action required)
    4. AuditLedger (all assessments logged)
    """

    def __init__(self) -> None:
        self._scorer: ThreatScorer = get_scorer()
        self._assessments: list[ThreatAssessment] = []
        self._containment_callback: Optional[callable] = None
        self._audit_callback: Optional[callable] = None

    def set_containment_callback(self, cb) -> None:
        self._containment_callback = cb

    def set_audit_callback(self, cb) -> None:
        self._audit_callback = cb

    def handle_event(self, event: ObservedEvent) -> ThreatAssessment:
        """Process a single event through the full threat pipeline."""
        assessment = self._scorer.score_event(event)
        self._assessments.append(assessment)

        # Build action descriptor for policy evaluation
        action = ActionDescriptor(
            action_type=event.event_type.value,
            category=_event_type_to_action_category(event.event_type.value),
            actor_id=event.actor_id,
            target=event.target,
            parameters={"event_id": event.event_id},
            context={"source": event.source, "tags": event.tags},
            risk_score=assessment.final_risk_score,
        )

        policy_result = get_policy_engine().evaluate(action)

        # Notify audit callback
        if self._audit_callback:
            try:
                self._audit_callback(event, assessment, policy_result)
            except Exception as exc:
                log.error(f"Audit callback error: {exc}")

        # Trigger containment if warranted
        if (
            self._containment_callback
            and assessment.recommended_action in ("block", "quarantine")
        ):
            try:
                self._containment_callback(event, assessment, policy_result)
            except Exception as exc:
                log.error(f"Containment callback error: {exc}")

        return assessment

    def get_recent_assessments(self, limit: int = 50) -> list[ThreatAssessment]:
        """Return the most recent threat assessments (in-memory, not persisted)."""
        return list(reversed(self._assessments[-limit:]))

    def high_risk_count(self) -> int:
        """Return number of assessments with risk_score >= 0.7."""
        return sum(1 for a in self._assessments if a.final_risk_score >= 0.7)


# Singleton
_analyzer: Optional[ThreatAnalyzer] = None


def get_analyzer() -> ThreatAnalyzer:
    global _analyzer
    if _analyzer is None:
        _analyzer = ThreatAnalyzer()
    return _analyzer
