"""
Threat Analysis: Agentic Drift Detector
-----------------------------------------
Detects behavioral drift in AI agents: gradual deviation from expected scope,
mission creep, unauthorized resource accumulation, and goal substitution.

Drift signals:
- Unexpected tool invocations outside declared scope
- Repeated scope-expansion attempts
- Accumulation of permissions over time
- Out-of-scope data access patterns
- Self-referential or self-modifying behaviors
- Anomalously long reasoning chains without human checkpoints
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional


# ── Signal definitions ────────────────────────────────────────────────────────

# Tool names that are out of scope for most benign agents
OUT_OF_SCOPE_TOOLS = {
    "shell_exec", "system_call", "exec_command", "run_code",
    "write_file", "delete_file", "modify_registry",
    "send_email", "send_http_request", "post_to_api",
    "read_credentials", "access_secrets", "get_token",
    "spawn_process", "kill_process", "modify_permissions",
}

# Keywords in tool/action names that suggest scope expansion
SCOPE_EXPANSION_KEYWORDS = {
    "admin", "root", "sudo", "privilege", "escalat",
    "persist", "install", "inject", "hook", "intercept",
    "exfil", "download", "upload", "send", "transmit",
}

# Maximum tool calls in a short window before flagging
TOOL_BURST_THRESHOLD = 20
TOOL_BURST_WINDOW_SECONDS = 60


@dataclass
class DriftSignal:
    signal_type: str
    description: str
    weight: float  # 0.0–1.0


@dataclass
class DriftAnalysis:
    agent_id: str
    risk_score: float
    signals: list[DriftSignal] = field(default_factory=list)
    is_drifting: bool = False
    recommendation: str = "monitor"


class AgentDriftTracker:
    """Tracks per-agent behavioral history for drift detection."""

    def __init__(self, agent_id: str, declared_scope: Optional[list[str]] = None) -> None:
        self.agent_id = agent_id
        self.declared_scope: set[str] = set(declared_scope or [])
        self._tool_calls: deque[tuple[float, str]] = deque(maxlen=500)
        self._scope_expansion_count = 0
        self._permission_requests: list[str] = []
        self._self_reference_count = 0
        self._reasoning_steps_since_checkpoint = 0

    def record_tool_call(self, tool_name: str) -> None:
        self._tool_calls.append((time.monotonic(), tool_name.lower()))

    def record_permission_request(self, permission: str) -> None:
        self._permission_requests.append(permission.lower())

    def record_self_reference(self) -> None:
        self._self_reference_count += 1

    def record_reasoning_step(self) -> None:
        self._reasoning_steps_since_checkpoint += 1

    def record_human_checkpoint(self) -> None:
        self._reasoning_steps_since_checkpoint = 0

    def analyze(self) -> DriftAnalysis:
        signals: list[DriftSignal] = []

        # ── Out-of-scope tool usage ───────────────────────────────────────────
        recent_tools = {tc[1] for tc in self._tool_calls}
        if self.declared_scope:
            oob = recent_tools & OUT_OF_SCOPE_TOOLS - self.declared_scope
            if oob:
                signals.append(DriftSignal(
                    signal_type="out_of_scope_tool",
                    description=f"Used out-of-scope tools: {sorted(oob)}",
                    weight=0.7,
                ))

        # ── Tool burst ────────────────────────────────────────────────────────
        now = time.monotonic()
        burst_count = sum(
            1 for ts, _ in self._tool_calls
            if now - ts <= TOOL_BURST_WINDOW_SECONDS
        )
        if burst_count >= TOOL_BURST_THRESHOLD:
            signals.append(DriftSignal(
                signal_type="tool_burst",
                description=f"{burst_count} tool calls in {TOOL_BURST_WINDOW_SECONDS}s window",
                weight=min(0.9, 0.4 + 0.05 * (burst_count - TOOL_BURST_THRESHOLD)),
            ))

        # ── Scope expansion keywords ──────────────────────────────────────────
        expansion_hits = []
        for _, tool in self._tool_calls:
            if any(kw in tool for kw in SCOPE_EXPANSION_KEYWORDS):
                expansion_hits.append(tool)
        if expansion_hits:
            signals.append(DriftSignal(
                signal_type="scope_expansion_keyword",
                description=f"Scope-expansion tools detected: {expansion_hits[:5]}",
                weight=min(0.9, 0.5 + 0.1 * len(expansion_hits)),
            ))

        # ── Permission accumulation ───────────────────────────────────────────
        if len(self._permission_requests) >= 5:
            signals.append(DriftSignal(
                signal_type="permission_accumulation",
                description=f"{len(self._permission_requests)} permission requests recorded",
                weight=min(0.85, 0.3 + 0.1 * len(self._permission_requests)),
            ))

        # ── Self-referential behavior ─────────────────────────────────────────
        if self._self_reference_count >= 3:
            signals.append(DriftSignal(
                signal_type="self_reference_anomaly",
                description=f"{self._self_reference_count} self-referential actions observed",
                weight=min(0.8, 0.4 + 0.1 * self._self_reference_count),
            ))

        # ── Long reasoning chain without checkpoint ───────────────────────────
        if self._reasoning_steps_since_checkpoint > 50:
            signals.append(DriftSignal(
                signal_type="long_autonomous_chain",
                description=(
                    f"{self._reasoning_steps_since_checkpoint} reasoning steps "
                    f"since last human checkpoint"
                ),
                weight=min(0.75, 0.3 + 0.01 * self._reasoning_steps_since_checkpoint),
            ))

        # ── Score aggregation ─────────────────────────────────────────────────
        if not signals:
            return DriftAnalysis(
                agent_id=self.agent_id,
                risk_score=0.0,
                is_drifting=False,
                recommendation="continue",
            )

        max_w = max(s.weight for s in signals)
        score = min(1.0, max_w * (1 + 0.05 * (len(signals) - 1)))

        recommendation = (
            "quarantine" if score >= 0.85
            else "escalate" if score >= 0.65
            else "warn"
        )

        return DriftAnalysis(
            agent_id=self.agent_id,
            risk_score=round(score, 3),
            signals=signals,
            is_drifting=score >= 0.5,
            recommendation=recommendation,
        )


class DriftDetector:
    """Manages per-agent drift trackers."""

    def __init__(self) -> None:
        self._trackers: dict[str, AgentDriftTracker] = {}

    def get_tracker(
        self, agent_id: str, declared_scope: Optional[list[str]] = None
    ) -> AgentDriftTracker:
        if agent_id not in self._trackers:
            self._trackers[agent_id] = AgentDriftTracker(agent_id, declared_scope)
        return self._trackers[agent_id]

    def analyze_agent(self, agent_id: str) -> Optional[DriftAnalysis]:
        tracker = self._trackers.get(agent_id)
        if tracker is None:
            return None
        return tracker.analyze()

    def all_analyses(self) -> list[DriftAnalysis]:
        return [t.analyze() for t in self._trackers.values()]
