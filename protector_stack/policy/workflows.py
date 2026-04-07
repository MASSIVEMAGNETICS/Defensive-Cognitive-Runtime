"""
Policy Engine: Approval Workflows
-----------------------------------
Manages pending human approval requests for high-risk actions.
Approval state is stored in the local SQLite database.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Column, String, Float, Boolean, DateTime, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from protector_stack.policy.schemas import (
    ActionDescriptor,
    ApprovalRequest,
    PolicyEvaluationResult,
)
from protector_stack.utils.config import get_config
from protector_stack.utils.logging import get_logger

log = get_logger(__name__)


class Base(DeclarativeBase):
    pass


class ApprovalRecord(Base):
    __tablename__ = "approval_requests"

    approval_id = Column(String, primary_key=True)
    action_id = Column(String, nullable=False)
    action_type = Column(String, nullable=False)
    actor_id = Column(String, nullable=False)
    risk_score = Column(Float, nullable=False, default=0.0)
    decision_suggested = Column(String, nullable=False)
    explanation = Column(Text, nullable=False, default="")
    requested_at = Column(DateTime, nullable=False)
    reviewed_at = Column(DateTime, nullable=True)
    reviewer_id = Column(String, nullable=True)
    approved = Column(Boolean, nullable=True)
    reviewer_notes = Column(Text, nullable=False, default="")
    status = Column(String, nullable=False, default="pending")


def _get_engine():
    cfg = get_config()
    import os
    os.makedirs(os.path.dirname(cfg.db_path) if os.path.dirname(cfg.db_path) else ".", exist_ok=True)
    engine = create_engine(f"sqlite:///{cfg.db_path}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    return engine


class ApprovalWorkflow:
    """Manages the lifecycle of human approval requests."""

    def __init__(self) -> None:
        self._engine = _get_engine()
        self._Session = sessionmaker(bind=self._engine)

    def create_request(
        self,
        action: ActionDescriptor,
        evaluation: PolicyEvaluationResult,
    ) -> ApprovalRequest:
        """Create and persist a new approval request."""
        req = ApprovalRequest(
            approval_id=str(uuid.uuid4()),
            action_id=action.action_id,
            action_descriptor=action,
            evaluation_result=evaluation,
            requested_at=datetime.utcnow(),
            status="pending",
        )
        with self._Session() as session:
            record = ApprovalRecord(
                approval_id=req.approval_id,
                action_id=action.action_id,
                action_type=action.action_type,
                actor_id=action.actor_id,
                risk_score=action.risk_score,
                decision_suggested=evaluation.decision.value,
                explanation=evaluation.explanation,
                requested_at=req.requested_at,
                status="pending",
            )
            session.add(record)
            session.commit()
        log.info(f"Approval request created: {req.approval_id[:8]}… for action {action.action_type}")
        return req

    def get_pending(self) -> list[dict]:
        """Return all pending approval requests as dicts."""
        with self._Session() as session:
            records = session.query(ApprovalRecord).filter_by(status="pending").all()
            return [self._record_to_dict(r) for r in records]

    def get_by_id(self, approval_id: str) -> Optional[dict]:
        """Return a specific approval request by ID."""
        with self._Session() as session:
            record = session.get(ApprovalRecord, approval_id)
            return self._record_to_dict(record) if record else None

    def review(
        self,
        approval_id: str,
        approved: bool,
        reviewer_id: str,
        notes: str = "",
    ) -> bool:
        """Record a human review decision. Returns True on success."""
        with self._Session() as session:
            record = session.get(ApprovalRecord, approval_id)
            if not record:
                log.warning(f"Approval request not found: {approval_id}")
                return False
            if record.status != "pending":
                log.warning(f"Approval {approval_id} already reviewed (status={record.status})")
                return False
            record.approved = approved
            record.reviewer_id = reviewer_id
            record.reviewer_notes = notes
            record.reviewed_at = datetime.utcnow()
            record.status = "approved" if approved else "denied"
            session.commit()
        action = "approved" if approved else "denied"
        log.info(f"Approval {approval_id[:8]}… {action} by {reviewer_id}")
        return True

    def expire_old_requests(self, max_age_hours: int = 24) -> int:
        """Mark requests older than max_age_hours as expired. Returns count."""
        cutoff = datetime.utcnow()
        from datetime import timedelta
        cutoff = cutoff - timedelta(hours=max_age_hours)
        with self._Session() as session:
            records = (
                session.query(ApprovalRecord)
                .filter(
                    ApprovalRecord.status == "pending",
                    ApprovalRecord.requested_at < cutoff,
                )
                .all()
            )
            for r in records:
                r.status = "expired"
            session.commit()
            count = len(records)
        if count:
            log.info(f"Expired {count} stale approval requests.")
        return count

    @staticmethod
    def _record_to_dict(r: ApprovalRecord) -> dict:
        return {
            "approval_id": r.approval_id,
            "action_id": r.action_id,
            "action_type": r.action_type,
            "actor_id": r.actor_id,
            "risk_score": r.risk_score,
            "decision_suggested": r.decision_suggested,
            "explanation": r.explanation,
            "requested_at": r.requested_at.isoformat() if r.requested_at else None,
            "reviewed_at": r.reviewed_at.isoformat() if r.reviewed_at else None,
            "reviewer_id": r.reviewer_id,
            "approved": r.approved,
            "reviewer_notes": r.reviewer_notes,
            "status": r.status,
        }


# Singleton
_workflow: Optional[ApprovalWorkflow] = None


def get_approval_workflow() -> ApprovalWorkflow:
    global _workflow
    if _workflow is None:
        _workflow = ApprovalWorkflow()
    return _workflow
