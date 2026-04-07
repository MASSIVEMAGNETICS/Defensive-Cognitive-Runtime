"""
Governance Layer: Alert Review Queue
--------------------------------------
Manages the queue of alerts requiring human review.
Operators can list, acknowledge, and resolve alerts.
All review actions are logged to the audit ledger.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Optional

from sqlalchemy import Column, DateTime, Float, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from protector_stack.memory.audit import get_audit_ledger
from protector_stack.utils.config import get_config
from protector_stack.utils.logging import get_logger

log = get_logger(__name__)


class AlertSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(str, Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"


class _Base(DeclarativeBase):
    pass


class AlertRecord(_Base):
    __tablename__ = "alerts"

    alert_id = Column(String, primary_key=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String, nullable=False)
    status = Column(String, nullable=False, default="open")
    source = Column(String, nullable=False)
    risk_score = Column(Float, nullable=False, default=0.0)
    event_id = Column(String, nullable=True)
    incident_id = Column(String, nullable=True)
    reviewer_id = Column(String, nullable=True)
    review_notes = Column(Text, nullable=False, default="")
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    resolved_at = Column(DateTime, nullable=True)


def _get_engine(db_path: str):
    import os
    dir_ = os.path.dirname(db_path)
    if dir_:
        os.makedirs(dir_, exist_ok=True)
    engine = create_engine(
        f"sqlite:///{db_path}", connect_args={"check_same_thread": False}
    )
    _Base.metadata.create_all(engine)
    return engine


class AlertReviewQueue:
    """Manages the human review queue for security alerts."""

    def __init__(self) -> None:
        cfg = get_config()
        self._engine = _get_engine(cfg.db_path)
        self._Session = sessionmaker(bind=self._engine)

    def raise_alert(
        self,
        title: str,
        description: str,
        severity: AlertSeverity,
        source: str,
        risk_score: float = 0.0,
        event_id: Optional[str] = None,
        incident_id: Optional[str] = None,
    ) -> str:
        """Create a new alert. Returns alert_id."""
        alert_id = f"ALT-{str(uuid.uuid4())[:8].upper()}"
        now = datetime.utcnow()
        with self._Session() as session:
            record = AlertRecord(
                alert_id=alert_id,
                title=title,
                description=description,
                severity=severity.value,
                status=AlertStatus.OPEN.value,
                source=source,
                risk_score=risk_score,
                event_id=event_id,
                incident_id=incident_id,
                created_at=now,
                updated_at=now,
            )
            session.add(record)
            session.commit()

        # Log to audit ledger
        try:
            get_audit_ledger().append(
                entry_type="alert",
                summary=f"Alert raised: {title} [{severity.value}]",
                payload={
                    "alert_id": alert_id,
                    "severity": severity.value,
                    "source": source,
                    "risk_score": risk_score,
                    "event_id": event_id,
                },
            )
        except Exception as exc:
            log.error(f"Failed to log alert to audit ledger: {exc}")

        log.warning(f"Alert raised: {alert_id} [{severity.value}] {title}")
        return alert_id

    def acknowledge(
        self,
        alert_id: str,
        reviewer_id: str,
        notes: str = "",
    ) -> bool:
        """Acknowledge an alert. Returns True on success."""
        with self._Session() as session:
            record = session.get(AlertRecord, alert_id)
            if not record or record.status != AlertStatus.OPEN.value:
                return False
            record.status = AlertStatus.ACKNOWLEDGED.value
            record.reviewer_id = reviewer_id
            record.review_notes = notes
            record.updated_at = datetime.utcnow()
            session.commit()
        log.info(f"Alert {alert_id} acknowledged by {reviewer_id}")
        return True

    def resolve(
        self,
        alert_id: str,
        reviewer_id: str,
        notes: str = "",
    ) -> bool:
        """Resolve an alert. Returns True on success."""
        with self._Session() as session:
            record = session.get(AlertRecord, alert_id)
            if not record:
                return False
            if record.status not in (
                AlertStatus.OPEN.value, AlertStatus.ACKNOWLEDGED.value
            ):
                return False
            record.status = AlertStatus.RESOLVED.value
            record.reviewer_id = reviewer_id
            record.review_notes = (record.review_notes + f"\n{notes}").strip()
            record.updated_at = datetime.utcnow()
            record.resolved_at = datetime.utcnow()
            session.commit()

        try:
            get_audit_ledger().append(
                entry_type="governance",
                summary=f"Alert {alert_id} resolved by {reviewer_id}",
                payload={"alert_id": alert_id, "reviewer_id": reviewer_id, "notes": notes},
                actor_id=reviewer_id,
            )
        except Exception:
            pass
        log.info(f"Alert {alert_id} resolved by {reviewer_id}")
        return True

    def dismiss(self, alert_id: str, reviewer_id: str, reason: str = "") -> bool:
        """Dismiss an alert (false positive or not actionable)."""
        with self._Session() as session:
            record = session.get(AlertRecord, alert_id)
            if not record:
                return False
            record.status = AlertStatus.DISMISSED.value
            record.reviewer_id = reviewer_id
            record.review_notes = reason
            record.updated_at = datetime.utcnow()
            session.commit()
        log.info(f"Alert {alert_id} dismissed by {reviewer_id}: {reason}")
        return True

    def get_open(self, limit: int = 50) -> list[dict]:
        with self._Session() as session:
            records = (
                session.query(AlertRecord)
                .filter(AlertRecord.status == AlertStatus.OPEN.value)
                .order_by(AlertRecord.created_at.desc())
                .limit(limit)
                .all()
            )
            return [self._to_dict(r) for r in records]

    def get_all(self, limit: int = 100) -> list[dict]:
        with self._Session() as session:
            records = (
                session.query(AlertRecord)
                .order_by(AlertRecord.created_at.desc())
                .limit(limit)
                .all()
            )
            return [self._to_dict(r) for r in records]

    def get_by_id(self, alert_id: str) -> Optional[dict]:
        with self._Session() as session:
            record = session.get(AlertRecord, alert_id)
            return self._to_dict(record) if record else None

    @staticmethod
    def _to_dict(r: AlertRecord) -> dict:
        return {
            "alert_id": r.alert_id,
            "title": r.title,
            "description": r.description,
            "severity": r.severity,
            "status": r.status,
            "source": r.source,
            "risk_score": r.risk_score,
            "event_id": r.event_id,
            "incident_id": r.incident_id,
            "reviewer_id": r.reviewer_id,
            "review_notes": r.review_notes,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "resolved_at": r.resolved_at.isoformat() if r.resolved_at else None,
        }


# Singleton
_queue: Optional[AlertReviewQueue] = None


def get_alert_queue() -> AlertReviewQueue:
    global _queue
    if _queue is None:
        _queue = AlertReviewQueue()
    return _queue
