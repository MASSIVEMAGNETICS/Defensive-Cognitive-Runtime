"""
Interface Layer: Report Generator
-----------------------------------
Generates structured incident reports in plain text and JSON formats.
Reports can be saved to disk for operator review and audit trails.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from protector_stack.governance.explainer import generate_incident_report_text
from protector_stack.memory.incidents import get_incident_manager
from protector_stack.memory.audit import get_audit_ledger
from protector_stack.utils.config import get_config
from protector_stack.utils.logging import get_logger

log = get_logger(__name__)


def generate_incident_report(incident_id: str, output_path: Optional[str] = None) -> str:
    """Generate a full incident report. Returns the report text.

    If output_path is provided, writes the report to that file.
    """
    mgr = get_incident_manager()
    incident = mgr.get(incident_id)
    if not incident:
        return f"Incident not found: {incident_id}"

    text = generate_incident_report_text(incident)

    if output_path:
        Path(output_path).write_text(text, encoding="utf-8")
        log.info(f"Report written to {output_path}")

    return text


def generate_summary_report(output_path: Optional[str] = None) -> str:
    """Generate a system-wide summary report."""
    cfg = get_config()
    mgr = get_incident_manager()
    ledger = get_audit_ledger()

    all_incidents = mgr.list_incidents(limit=1000)
    total = len(all_incidents)
    open_count = sum(1 for i in all_incidents if i["status"] in ("detected", "investigating"))
    critical_count = sum(1 for i in all_incidents if i["severity"] == "critical")
    resolved_count = sum(1 for i in all_incidents if i["status"] in ("resolved", "false_positive"))
    audit_count = ledger.count()

    lines = [
        "═══════════════════════════════════════════════════",
        "  PROTECTOR_STACK SYSTEM SUMMARY REPORT",
        f"  Generated: {datetime.utcnow().isoformat()} UTC",
        "═══════════════════════════════════════════════════",
        "",
        f"Total Incidents:    {total}",
        f"Open / Active:      {open_count}",
        f"Critical Severity:  {critical_count}",
        f"Resolved:           {resolved_count}",
        f"Audit Log Entries:  {audit_count}",
        "",
        "Recent Incidents:",
    ]

    for inc in all_incidents[:10]:
        lines.append(
            f"  [{inc['severity'].upper():8s}] {inc['incident_id']} — "
            f"{inc['title'][:50]} ({inc['status']})"
        )

    lines.append("")
    lines.append("═══════════════════════════════════════════════════")

    text = "\n".join(lines)

    if output_path:
        Path(output_path).write_text(text, encoding="utf-8")
        log.info(f"Summary report written to {output_path}")

    return text
