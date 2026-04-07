"""
Governance Layer: Explainability Engine
-----------------------------------------
Generates human-readable explanations for:
- Why an action was allowed/blocked/escalated
- What threat signals were detected
- What the simulation predicted
- What the human reviewer decided

These explanations are included in incident reports and alert notifications.
"""

from __future__ import annotations

from typing import Optional

from protector_stack.memory.provenance import get_provenance_tracker
from protector_stack.threat.scorer import ThreatAssessment
from protector_stack.policy.schemas import PolicyEvaluationResult


def explain_threat(assessment: ThreatAssessment) -> str:
    """Generate a plain-English explanation of a threat assessment."""
    lines = [
        f"THREAT ASSESSMENT",
        f"─────────────────────────────────────────",
        f"Event ID:      {assessment.event_id[:8]}…",
        f"Risk Score:    {assessment.final_risk_score:.2f}/1.00",
        f"Category:      {assessment.threat_category.upper()}",
        f"Recommended:   {assessment.recommended_action.upper()}",
        "",
    ]

    if assessment.injection_score > 0:
        lines.append(f"  Prompt Injection Score:    {assessment.injection_score:.2f}")
    if assessment.escalation_score > 0:
        lines.append(f"  Privilege Escalation Score:{assessment.escalation_score:.2f}")
    if assessment.exfil_score > 0:
        lines.append(f"  Exfiltration Score:        {assessment.exfil_score:.2f}")

    if assessment.signals:
        lines.append("")
        lines.append("Detection Signals:")
        for sig in assessment.signals:
            lines.append(f"  ⚠ {sig}")

    lines.append("")
    lines.append("System Explanation:")
    lines.append(assessment.explanation)
    return "\n".join(lines)


def explain_policy_decision(result: PolicyEvaluationResult) -> str:
    """Generate a plain-English explanation of a policy decision."""
    lines = [
        f"POLICY DECISION",
        f"─────────────────────────────────────────",
        f"Action ID:   {result.action_id[:8]}…",
        f"Decision:    {result.decision.value.upper()}",
        f"Risk Level:  {result.risk_level.value.upper()}",
        f"Needs Approval: {'YES' if result.requires_approval else 'no'}",
        "",
        "Matched Rules:",
    ]
    for rule in result.matched_rules:
        lines.append(f"  ▶ {rule}")
    if result.reasons:
        lines.append("")
        lines.append("Reasons:")
        for reason in result.reasons:
            lines.append(f"  • {reason}")
    lines.append("")
    lines.append("Full Explanation:")
    lines.append(result.explanation)
    return "\n".join(lines)


def explain_action_by_id(action_id: str) -> str:
    """Look up the provenance record for an action and return a full explanation."""
    tracker = get_provenance_tracker()
    return tracker.explain_action(action_id)


def generate_incident_report_text(incident: dict) -> str:
    """Generate a plain-English incident report from an incident dict."""
    lines = [
        "═══════════════════════════════════════════════════",
        f"  PROTECTOR_STACK INCIDENT REPORT",
        "═══════════════════════════════════════════════════",
        f"  Incident ID:   {incident.get('incident_id', 'N/A')}",
        f"  Title:         {incident.get('title', 'N/A')}",
        f"  Severity:      {incident.get('severity', 'N/A').upper()}",
        f"  Status:        {incident.get('status', 'N/A').upper()}",
        f"  Category:      {incident.get('threat_category', 'N/A')}",
        f"  Risk Score:    {incident.get('risk_score', 0.0):.2f}",
        f"  Created:       {incident.get('created_at', 'N/A')}",
        f"  Updated:       {incident.get('updated_at', 'N/A')}",
        "",
        "Description:",
        incident.get("description", ""),
        "",
    ]

    notes = incident.get("operator_notes", "").strip()
    if notes:
        lines.append("Operator Notes:")
        lines.append(notes)
        lines.append("")

    source_events = incident.get("source_event_ids", [])
    if source_events:
        lines.append("Source Events:")
        for eid in source_events:
            lines.append(f"  - {eid}")
        lines.append("")

    lines.append("═══════════════════════════════════════════════════")
    return "\n".join(lines)
