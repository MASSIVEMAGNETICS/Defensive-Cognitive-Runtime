"""
Observation Layer: Event Schemas
----------------------------------
Pydantic models for all observed events in the system.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional
from datetime import datetime
import uuid

from pydantic import BaseModel, Field


class EventType(str, Enum):
    PROCESS_SPAWN = "process_spawn"
    PROCESS_TERMINATE = "process_terminate"
    FILE_CREATED = "file_created"
    FILE_MODIFIED = "file_modified"
    FILE_DELETED = "file_deleted"
    NETWORK_CONNECTION = "network_connection"
    MODEL_INFERENCE = "model_inference"
    TOOL_INVOCATION = "tool_invocation"
    AGENT_ACTION = "agent_action"
    PERMISSION_CHANGE = "permission_change"
    LOGIN_EVENT = "login_event"
    CONFIG_CHANGE = "config_change"
    ALERT_RAISED = "alert_raised"
    POLICY_DECISION = "policy_decision"
    CONTAINMENT_ACTION = "containment_action"
    SYSTEM_STATUS = "system_status"
    UNKNOWN = "unknown"


class ObservedEvent(BaseModel):
    """A normalized, typed event from the observation layer."""
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: EventType
    source: str  # Component or sensor that generated the event
    actor_id: str = "unknown"
    target: Optional[str] = None
    description: str = ""
    raw_data: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    severity: str = "info"  # info | warning | alert | critical
    risk_hint: float = 0.0   # 0.0–1.0, filled in by threat analysis


class ProcessEvent(BaseModel):
    """Process spawn/terminate event details."""
    pid: int
    name: str
    cmdline: list[str] = Field(default_factory=list)
    parent_pid: Optional[int] = None
    username: Optional[str] = None
    cwd: Optional[str] = None


class FileEvent(BaseModel):
    """File system change event details."""
    path: str
    event_kind: str  # created | modified | deleted | moved
    size_bytes: Optional[int] = None
    src_path: Optional[str] = None   # for move events


class NetworkEvent(BaseModel):
    """Network connection event details."""
    protocol: str = "tcp"
    local_addr: Optional[str] = None
    local_port: Optional[int] = None
    remote_addr: Optional[str] = None
    remote_port: Optional[int] = None
    direction: str = "outbound"  # inbound | outbound
    pid: Optional[int] = None
    process_name: Optional[str] = None


class ModelInteractionEvent(BaseModel):
    """A model inference or tool interaction event."""
    model_id: str
    prompt_snippet: str = ""  # first 200 chars only — no full content stored
    response_snippet: str = ""
    tool_calls: list[str] = Field(default_factory=list)
    latency_ms: Optional[float] = None
    token_count: Optional[int] = None
