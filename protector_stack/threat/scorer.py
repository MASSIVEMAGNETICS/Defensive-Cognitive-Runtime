"""
Threat Analysis: Multi-Signal Risk Scorer
------------------------------------------
Aggregates signals from multiple detectors into a unified risk score (0.0–1.0).
Provides a final ThreatAssessment with explanation for policy decision making.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from protector_stack.observation.schemas import EventType, ObservedEvent
from protector_stack.threat.injection_detector import InjectionAnalysis, analyze_text as detect_injection
from protector_stack.threat.escalation_detector import EscalationAnalysis, analyze_text as detect_escalation
from protector_stack.threat.exfil_detector import ExfilAnalysis, analyze_text as detect_exfil
from protector_stack.utils.logging import get_logger

log = get_logger(__name__)


@dataclass
class ThreatAssessment:
    """Unified threat assessment from all detectors."""
    event_id: str
    final_risk_score: float
    threat_category: str  # benign | anomalous | suspicious | dangerous | critical
    signals: list[str] = field(default_factory=list)
    injection_score: float = 0.0
    escalation_score: float = 0.0
    exfil_score: float = 0.0
    base_risk_hint: float = 0.0
    explanation: str = ""
    recommended_action: str = "monitor"  # monitor | warn | escalate | block | quarantine


def _category_from_score(score: float) -> str:
    if score >= 0.9:
        return "critical"
    if score >= 0.7:
        return "dangerous"
    if score >= 0.5:
        return "suspicious"
    if score >= 0.3:
        return "anomalous"
    return "benign"


def _action_from_score(score: float) -> str:
    if score >= 0.85:
        return "quarantine"
    if score >= 0.7:
        return "block"
    if score >= 0.5:
        return "escalate"
    if score >= 0.3:
        return "warn"
    return "monitor"


class ThreatScorer:
    """Runs all detectors on an observed event and produces a ThreatAssessment."""

    def score_event(self, event: ObservedEvent) -> ThreatAssessment:
        """Compute a full threat assessment for an observed event."""
        text_corpus = self._build_text_corpus(event)
        base_hint = event.risk_hint

        # Run individual detectors
        inj: InjectionAnalysis = detect_injection(text_corpus)
        esc: EscalationAnalysis = detect_escalation(text_corpus)
        exf: ExfilAnalysis = detect_exfil(text_corpus)

        signals: list[str] = []
        signals.extend(inj.signals)
        signals.extend(s.signal_type for s in esc.signals)
        signals.extend(s.signal_type for s in exf.signals)

        # Aggregate: take max of all sub-scores, amplified by count
        sub_scores = [base_hint, inj.risk_score, esc.risk_score, exf.risk_score]
        max_score = max(sub_scores)
        nonzero = sum(1 for s in sub_scores if s > 0.1)
        final = min(1.0, max_score * (1 + 0.05 * max(0, nonzero - 1)))
        final = round(final, 3)

        category = _category_from_score(final)
        action = _action_from_score(final)

        explanation_parts = [
            f"Event: {event.event_type.value} from {event.source}",
            f"Base risk hint: {base_hint:.2f}",
            f"Injection score: {inj.risk_score:.2f}",
            f"Escalation score: {esc.risk_score:.2f}",
            f"Exfil score: {exf.risk_score:.2f}",
            f"Final risk score: {final:.2f} ({category})",
        ]
        if signals:
            explanation_parts.append(f"Signals: {', '.join(signals)}")

        assessment = ThreatAssessment(
            event_id=event.event_id,
            final_risk_score=final,
            threat_category=category,
            signals=signals,
            injection_score=inj.risk_score,
            escalation_score=esc.risk_score,
            exfil_score=exf.risk_score,
            base_risk_hint=base_hint,
            explanation="\n".join(explanation_parts),
            recommended_action=action,
        )

        if final >= 0.5:
            log.warning(
                f"Threat detected [{category}] event={event.event_id[:8]}… "
                f"score={final:.2f} action={action} signals={signals[:3]}"
            )

        return assessment

    @staticmethod
    def _build_text_corpus(event: ObservedEvent) -> str:
        """Concatenate all text fields from an event for pattern analysis."""
        parts = [
            event.description,
            event.event_type.value,
            " ".join(event.tags),
        ]
        raw = event.raw_data
        # Add cmdline, prompt snippet, tool names, etc.
        for key in ("cmdline", "prompt", "response", "tool_name", "action_type", "command"):
            val = raw.get(key)
            if isinstance(val, list):
                parts.append(" ".join(str(v) for v in val))
            elif isinstance(val, str):
                parts.append(val)
        return " ".join(parts)


# Singleton
_scorer: Optional[ThreatScorer] = None


def get_scorer() -> ThreatScorer:
    global _scorer
    if _scorer is None:
        _scorer = ThreatScorer()
    return _scorer
