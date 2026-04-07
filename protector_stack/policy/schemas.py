"""
Policy Engine: Schemas
-----------------------
Pydantic models for policy rules, action descriptors, and evaluation results.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field
import uuid
from datetime import datetime


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PolicyDecision(str, Enum):
    ALLOW = "allow"
    ALLOW_WITH_AUDIT = "allow_with_audit"
    ESCALATE = "escalate"
    SOFT_DENY = "soft_deny"
    HARD_DENY = "hard_deny"


class ActionCategory(str, Enum):
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    NETWORK = "network"
    PROCESS = "process"
    PERMISSION = "permission"
    MODEL_INFERENCE = "model_inference"
    AGENT_ACTION = "agent_action"
    GOVERNANCE = "governance"
    SYSTEM = "system"
    UNKNOWN = "unknown"


class PolicyRule(BaseModel):
    """A single policy rule."""
    rule_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str
    description: str
    category: ActionCategory
    risk_level: RiskLevel
    decision: PolicyDecision
    conditions: list[dict[str, Any]] = Field(default_factory=list)
    enabled: bool = True
    requires_approval: bool = False
    tags: list[str] = Field(default_factory=list)


class ActionDescriptor(BaseModel):
    """Describes an action to be evaluated by the policy engine."""
    action_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    action_type: str
    category: ActionCategory = ActionCategory.UNKNOWN
    actor_id: str = "unknown"
    target: Optional[str] = None
    parameters: dict[str, Any] = Field(default_factory=dict)
    context: dict[str, Any] = Field(default_factory=dict)
    risk_score: float = 0.0
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class PolicyEvaluationResult(BaseModel):
    """Result of evaluating an action against all policy rules."""
    action_id: str
    decision: PolicyDecision
    matched_rules: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.LOW
    requires_approval: bool = False
    approval_id: Optional[str] = None
    evaluated_at: datetime = Field(default_factory=datetime.utcnow)
    explanation: str = ""


class ApprovalRequest(BaseModel):
    """A pending human approval request."""
    approval_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    action_id: str
    action_descriptor: ActionDescriptor
    evaluation_result: PolicyEvaluationResult
    requested_at: datetime = Field(default_factory=datetime.utcnow)
    reviewed_at: Optional[datetime] = None
    reviewer_id: Optional[str] = None
    approved: Optional[bool] = None
    reviewer_notes: str = ""
    status: str = "pending"  # pending | approved | denied | expired
