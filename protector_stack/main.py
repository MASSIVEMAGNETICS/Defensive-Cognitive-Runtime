"""
PROTECTOR_STACK: Main Runtime
-------------------------------
Wires all layers together into a cohesive runtime.
Initializes all components, registers event handlers, and starts background threads.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional

from protector_stack.utils.config import get_config
from protector_stack.utils.logging import get_logger, setup_logging

log = get_logger(__name__)


class ProtectorRuntime:
    """
    Top-level orchestrator for the PROTECTOR_STACK system.

    Startup sequence:
    1. Validate configuration
    2. Verify doctrine integrity
    3. Initialize data directory
    4. Start audit ledger
    5. Wire observation → threat → policy → governance → containment pipeline
    6. Start background monitors (process, file)
    7. Begin event processing loop
    """

    def __init__(self) -> None:
        self._cfg = get_config()
        self._started = False
        self._components: dict = {}

    def initialize(self) -> bool:
        """Initialize all components. Returns True if all checks pass."""
        setup_logging(self._cfg.log_level)
        log.info("═══ PROTECTOR_STACK initializing ═══")
        log.info(f"  Mission: {__import__('protector_stack').__mission__}")

        # ── 1. Ensure data directories exist ─────────────────────────────────
        self._cfg.ensure_data_dir()

        # ── 2. Doctrine integrity check ───────────────────────────────────────
        from protector_stack.constitution.integrity import verify_doctrine_integrity
        ok, msg = verify_doctrine_integrity()
        if not ok:
            log.critical(f"DOCTRINE INTEGRITY FAILURE: {msg}")
            log.critical("System will run in RESTRICTED SAFE MODE. Human review required.")
        else:
            log.info(f"Constitution: {msg}")

        # ── 3. Initialize audit ledger ────────────────────────────────────────
        from protector_stack.memory.audit import get_audit_ledger
        ledger = get_audit_ledger()
        self._components["audit_ledger"] = ledger
        log.info(f"Audit ledger ready ({ledger.count()} existing entries)")

        # ── 4. Initialize policy engine ───────────────────────────────────────
        from protector_stack.policy.engine import get_policy_engine
        policy = get_policy_engine()
        self._components["policy_engine"] = policy
        log.info(f"Policy engine ready ({len(policy.get_rules())} rules loaded)")

        # ── 5. Initialize collectors ──────────────────────────────────────────
        from protector_stack.observation.collector import get_collector
        collector = get_collector()
        self._components["collector"] = collector

        # ── 6. Initialize threat analyzer ─────────────────────────────────────
        from protector_stack.threat.analyzer import get_analyzer
        analyzer = get_analyzer()
        self._components["threat_analyzer"] = analyzer

        # ── 7. Wire: observation → threat analysis ────────────────────────────
        analyzer.set_audit_callback(self._audit_callback)
        analyzer.set_containment_callback(self._containment_callback)
        collector.register_handler(analyzer.handle_event)

        # ── 8. Initialize governance queue ────────────────────────────────────
        from protector_stack.governance.review import get_alert_queue
        self._components["alert_queue"] = get_alert_queue()

        # ── 9. Initialize incident manager ────────────────────────────────────
        from protector_stack.memory.incidents import get_incident_manager
        self._components["incident_manager"] = get_incident_manager()

        # ── 10. Log startup event ─────────────────────────────────────────────
        ledger.append(
            entry_type="system_status",
            summary="PROTECTOR_STACK started",
            payload={"version": "1.0.0", "env": self._cfg.env},
        )

        self._started = True
        log.info("═══ PROTECTOR_STACK READY ═══")
        return True

    def start_monitors(self) -> None:
        """Start background process and file monitors."""
        if not self._started:
            raise RuntimeError("Runtime not initialized. Call initialize() first.")

        cfg = self._cfg
        collector = self._components["collector"]

        # Process monitor
        from protector_stack.observation.process_monitor import ProcessMonitor
        proc_monitor = ProcessMonitor(collector)
        proc_monitor.start()
        self._components["process_monitor"] = proc_monitor
        log.info("Process monitor started.")

        # File watcher (watches data dir by default)
        from protector_stack.observation.file_watcher import FileWatcher
        file_watcher = FileWatcher(collector)
        # Watch the data directory for changes
        watch_paths_raw = os.environ.get("PROTECTOR_WATCH_PATHS", cfg.data_dir)
        for wp in watch_paths_raw.split(":"):
            wp = wp.strip()
            if wp and Path(wp).exists():
                file_watcher.add_watch_path(wp)
        file_watcher.start()
        self._components["file_watcher"] = file_watcher
        log.info("File watcher started.")

    def stop(self) -> None:
        """Gracefully stop all background components."""
        log.info("PROTECTOR_STACK shutting down…")
        for name in ("process_monitor", "file_watcher"):
            comp = self._components.get(name)
            if comp and hasattr(comp, "stop"):
                try:
                    comp.stop()
                except Exception as exc:
                    log.error(f"Error stopping {name}: {exc}")

        # Log shutdown
        try:
            self._components["audit_ledger"].append(
                entry_type="system_status",
                summary="PROTECTOR_STACK stopped",
                payload={"clean_shutdown": True},
            )
        except Exception:
            pass
        log.info("PROTECTOR_STACK stopped.")

    def submit_event(self, raw: dict, source: str = "manual") -> dict:
        """Submit a raw event dict for analysis. Returns the threat assessment dict."""
        collector = self._components.get("collector")
        if not collector:
            raise RuntimeError("Runtime not initialized.")
        event = collector.submit(raw, source=source)
        # Threat assessment is produced by the registered handler
        analyzer = self._components.get("threat_analyzer")
        if analyzer:
            recent = analyzer.get_recent_assessments(1)
            if recent and recent[0].event_id == event.event_id:
                a = recent[0]
                return {
                    "event_id": event.event_id,
                    "risk_score": a.final_risk_score,
                    "category": a.threat_category,
                    "action": a.recommended_action,
                    "signals": a.signals,
                }
        return {"event_id": event.event_id}

    def get_status(self) -> dict:
        """Return a system status summary dict."""
        from protector_stack.constitution.integrity import get_constitution_status
        status = {
            "system": "PROTECTOR_STACK",
            "version": "1.0.0",
            "started": self._started,
            "constitution": get_constitution_status(),
            "components": {
                name: "running"
                for name in self._components
            },
        }
        analyzer = self._components.get("threat_analyzer")
        if analyzer:
            status["threat_stats"] = {
                "high_risk_events": analyzer.high_risk_count(),
            }
        ledger = self._components.get("audit_ledger")
        if ledger:
            status["audit_entries"] = ledger.count()
        return status

    # ── Internal callbacks ────────────────────────────────────────────────────

    def _audit_callback(self, event, assessment, policy_result) -> None:
        """Write event + assessment to audit ledger and raise alerts."""
        try:
            ledger = self._components.get("audit_ledger")
            if ledger:
                ledger.append(
                    entry_type="threat",
                    summary=(
                        f"[{assessment.threat_category}] "
                        f"{event.event_type.value} risk={assessment.final_risk_score:.2f}"
                    ),
                    payload={
                        "event_id": event.event_id,
                        "event_type": event.event_type.value,
                        "final_risk_score": assessment.final_risk_score,
                        "threat_category": assessment.threat_category,
                        "signals": assessment.signals,
                        "policy_decision": policy_result.decision.value,
                    },
                    actor_id=event.actor_id,
                )

            # Raise alert for suspicious+ events
            if assessment.final_risk_score >= self._cfg.risk_threshold_warn:
                from protector_stack.governance.review import get_alert_queue, AlertSeverity
                queue = self._components.get("alert_queue") or get_alert_queue()
                sev = (
                    AlertSeverity.CRITICAL if assessment.final_risk_score >= 0.85
                    else AlertSeverity.HIGH if assessment.final_risk_score >= 0.7
                    else AlertSeverity.WARNING
                )
                queue.raise_alert(
                    title=f"{assessment.threat_category.title()} event: {event.event_type.value}",
                    description=assessment.explanation,
                    severity=sev,
                    source=event.source,
                    risk_score=assessment.final_risk_score,
                    event_id=event.event_id,
                )
        except Exception as exc:
            log.error(f"Audit callback error: {exc}")

    def _containment_callback(self, event, assessment, policy_result) -> None:
        """Trigger containment actions for dangerous events."""
        try:
            from protector_stack.memory.incidents import get_incident_manager, IncidentSeverity
            mgr = self._components.get("incident_manager")
            if not mgr:
                mgr = get_incident_manager()
            sev = (
                IncidentSeverity.CRITICAL if assessment.final_risk_score >= 0.85
                else IncidentSeverity.HIGH
            )
            inc_id = mgr.create(
                title=f"Auto-incident: {assessment.threat_category} [{event.event_type.value}]",
                description=assessment.explanation,
                severity=sev,
                threat_category=assessment.threat_category,
                risk_score=assessment.final_risk_score,
                source_event_ids=[event.event_id],
            )
            log.warning(f"Incident created automatically: {inc_id}")
        except Exception as exc:
            log.error(f"Containment callback error: {exc}")


# Module-level singleton
_runtime: Optional[ProtectorRuntime] = None


def get_runtime() -> ProtectorRuntime:
    global _runtime
    if _runtime is None:
        _runtime = ProtectorRuntime()
    return _runtime
