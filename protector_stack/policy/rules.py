"""
Policy Engine: Default Rules
------------------------------
Defines the baseline set of policy rules for PROTECTOR_STACK.
Rules are loaded at runtime and can be extended via YAML policy files.

Rule evaluation logic (precedence, highest to lowest):
  HARD_DENY > SOFT_DENY > ESCALATE > ALLOW_WITH_AUDIT > ALLOW
"""

from __future__ import annotations

from protector_stack.policy.schemas import (
    ActionCategory,
    PolicyDecision,
    PolicyRule,
    RiskLevel,
)

# ── Hard-deny rules: forbidden regardless of context ─────────────────────────

HARD_DENY_RULES: list[PolicyRule] = [
    PolicyRule(
        rule_id="HD-001",
        name="block_offensive_exploit",
        description="Block any action classified as generating offensive exploit code.",
        category=ActionCategory.UNKNOWN,  # matches any category
        risk_level=RiskLevel.CRITICAL,
        decision=PolicyDecision.HARD_DENY,
        conditions=[{"action_type_contains": "exploit"}],
        tags=["offensive", "hard_deny", "doctrine"],
    ),
    PolicyRule(
        rule_id="HD-002",
        name="block_credential_theft",
        description="Block credential harvesting, token dumping, or password theft.",
        category=ActionCategory.UNKNOWN,
        risk_level=RiskLevel.CRITICAL,
        decision=PolicyDecision.HARD_DENY,
        conditions=[{"action_type_contains": "credential_theft"}],
        tags=["credential", "hard_deny", "doctrine"],
    ),
    PolicyRule(
        rule_id="HD-003",
        name="block_autonomous_weapons",
        description="Block any action related to autonomous weapons or lethal targeting.",
        category=ActionCategory.UNKNOWN,
        risk_level=RiskLevel.CRITICAL,
        decision=PolicyDecision.HARD_DENY,
        conditions=[{"action_type_contains": "weapon"}],
        tags=["weapons", "hard_deny", "doctrine"],
    ),
    PolicyRule(
        rule_id="HD-004",
        name="block_human_oversight_disable",
        description="Block any action that attempts to disable human oversight or governance.",
        category=ActionCategory.UNKNOWN,
        risk_level=RiskLevel.CRITICAL,
        decision=PolicyDecision.HARD_DENY,
        conditions=[{"action_type_contains": "disable_oversight"}],
        tags=["governance", "hard_deny", "doctrine"],
    ),
    PolicyRule(
        rule_id="HD-005",
        name="block_self_rewrite",
        description="Block any action that attempts to rewrite core doctrine or mission.",
        category=ActionCategory.UNKNOWN,
        risk_level=RiskLevel.CRITICAL,
        decision=PolicyDecision.HARD_DENY,
        conditions=[{"action_type_contains": "rewrite_mission"}],
        tags=["self_rewrite", "hard_deny", "doctrine"],
    ),
    PolicyRule(
        rule_id="HD-006",
        name="block_mass_manipulation",
        description="Block covert social manipulation or mass persuasion operations.",
        category=ActionCategory.UNKNOWN,
        risk_level=RiskLevel.CRITICAL,
        decision=PolicyDecision.HARD_DENY,
        conditions=[{"action_type_contains": "mass_manipulation"}],
        tags=["manipulation", "hard_deny", "doctrine"],
    ),
]

# ── Escalate rules: require human approval ───────────────────────────────────

ESCALATE_RULES: list[PolicyRule] = [
    PolicyRule(
        rule_id="ESC-001",
        name="escalate_quarantine_request",
        description="Quarantine operations require human approval before execution.",
        category=ActionCategory.PROCESS,
        risk_level=RiskLevel.HIGH,
        decision=PolicyDecision.ESCALATE,
        requires_approval=True,
        conditions=[{"action_type_contains": "quarantine"}],
        tags=["containment", "escalate"],
    ),
    PolicyRule(
        rule_id="ESC-002",
        name="escalate_permission_revoke",
        description="Permission revocation requires human approval.",
        category=ActionCategory.PERMISSION,
        risk_level=RiskLevel.HIGH,
        decision=PolicyDecision.ESCALATE,
        requires_approval=True,
        conditions=[{"action_type_contains": "revoke_permission"}],
        tags=["permission", "escalate"],
    ),
    PolicyRule(
        rule_id="ESC-003",
        name="escalate_high_risk_network",
        description="High-risk network operations (exfil-like) require approval.",
        category=ActionCategory.NETWORK,
        risk_level=RiskLevel.HIGH,
        decision=PolicyDecision.ESCALATE,
        requires_approval=True,
        conditions=[{"risk_score_above": 0.7}],
        tags=["network", "escalate"],
    ),
    PolicyRule(
        rule_id="ESC-004",
        name="escalate_agent_bulk_action",
        description="Agent actions affecting many resources in bulk require approval.",
        category=ActionCategory.AGENT_ACTION,
        risk_level=RiskLevel.HIGH,
        decision=PolicyDecision.ESCALATE,
        requires_approval=True,
        conditions=[{"action_type_contains": "bulk_action"}],
        tags=["agent", "escalate"],
    ),
    PolicyRule(
        rule_id="ESC-005",
        name="escalate_rollback",
        description="System rollback operations require human approval.",
        category=ActionCategory.SYSTEM,
        risk_level=RiskLevel.HIGH,
        decision=PolicyDecision.ESCALATE,
        requires_approval=True,
        conditions=[{"action_type_contains": "rollback"}],
        tags=["rollback", "escalate"],
    ),
]

# ── Audit rules: allow but log carefully ─────────────────────────────────────

AUDIT_RULES: list[PolicyRule] = [
    PolicyRule(
        rule_id="AUD-001",
        name="audit_model_inference",
        description="All model inference actions are allowed but audited.",
        category=ActionCategory.MODEL_INFERENCE,
        risk_level=RiskLevel.MEDIUM,
        decision=PolicyDecision.ALLOW_WITH_AUDIT,
        conditions=[],
        tags=["model", "audit"],
    ),
    PolicyRule(
        rule_id="AUD-002",
        name="audit_file_write",
        description="File write operations are allowed but logged for review.",
        category=ActionCategory.WRITE,
        risk_level=RiskLevel.MEDIUM,
        decision=PolicyDecision.ALLOW_WITH_AUDIT,
        conditions=[],
        tags=["file", "audit"],
    ),
    PolicyRule(
        rule_id="AUD-003",
        name="audit_process_spawn",
        description="New process spawns are allowed but logged.",
        category=ActionCategory.PROCESS,
        risk_level=RiskLevel.MEDIUM,
        decision=PolicyDecision.ALLOW_WITH_AUDIT,
        conditions=[],
        tags=["process", "audit"],
    ),
    PolicyRule(
        rule_id="AUD-004",
        name="audit_external_network",
        description="External network connections are allowed but logged.",
        category=ActionCategory.NETWORK,
        risk_level=RiskLevel.MEDIUM,
        decision=PolicyDecision.ALLOW_WITH_AUDIT,
        conditions=[],
        tags=["network", "audit"],
    ),
]

# ── Allow rules: low-risk operations ─────────────────────────────────────────

ALLOW_RULES: list[PolicyRule] = [
    PolicyRule(
        rule_id="ALW-001",
        name="allow_read_ops",
        description="Read-only operations are allowed.",
        category=ActionCategory.READ,
        risk_level=RiskLevel.LOW,
        decision=PolicyDecision.ALLOW,
        conditions=[],
        tags=["read", "allow"],
    ),
    PolicyRule(
        rule_id="ALW-002",
        name="allow_logging",
        description="Logging and monitoring operations are always allowed.",
        category=ActionCategory.SYSTEM,
        risk_level=RiskLevel.LOW,
        decision=PolicyDecision.ALLOW,
        conditions=[{"action_type_contains": "log"}],
        tags=["logging", "allow"],
    ),
    PolicyRule(
        rule_id="ALW-003",
        name="allow_governance_review",
        description="Human governance review actions are always allowed.",
        category=ActionCategory.GOVERNANCE,
        risk_level=RiskLevel.LOW,
        decision=PolicyDecision.ALLOW,
        conditions=[{"action_type_contains": "review"}],
        tags=["governance", "allow"],
    ),
]

# ── Combined default ruleset ──────────────────────────────────────────────────

DEFAULT_RULES: list[PolicyRule] = (
    HARD_DENY_RULES + ESCALATE_RULES + AUDIT_RULES + ALLOW_RULES
)
