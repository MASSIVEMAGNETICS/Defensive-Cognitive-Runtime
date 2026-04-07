"""
Memory Layer: Incident Manager
---------------------------------
Creates, stores, and manages security incidents (cases).
Each incident tracks a threat event through its full lifecycle:
  detected → investigating → contained → resolved | escalated

Incidents are stored in SQLite and linked to audit ledger entries.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Optional

from sqlalchemy import Column, DateTime, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from protector_stack.utils.config import get_config
from protector_stack.utils.logging import get_logger

log = get_logger(__name__)


class IncidentStatus(str, Enum):
    DETECTED = "detected"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    ESCALATED = "escalated"
    FALSE_POSITIVE = "false_positive"


class IncidentSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class _Base(DeclarativeBase):
    pass


class IncidentRecord(_Base):
    __tablename__ = "incidents"

    incident_id = Column(String, primary_key=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String, nullable=False)
    status = Column(String, nullable=False)
    threat_category = Column(String, nullable=False, default="unknown")
    risk_score = Column(String, nullable=False, default="0.0")
    source_event_ids = Column(Text, nullable=False, default="")
    audit_entry_ids = Column(Text, nullable=False, default="")
    assigned_to = Column(String, nullable=True)
    operator_notes = Column(Text, nullable=False, default="")
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    resolved_at = Column(DateTime, nullable=True)


def _get_engine(db_path: str):
    import os
    dir_ = os.path.dirname(db_path)
    if dir_:
        os.makedirs(dir_, exist_ok=True)
    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    _Base.metadata.create_all(engine)
    return engine


class IncidentManager:
    """Creates and manages security incidents."""

    def __init__(self) -> None:
        cfg = get_config()
        self._engine = _get_engine(cfg.db_path)
        self._Session = sessionmaker(bind=self._engine)

    def create(
        self,
        title: str,
        description: str,
        severity: IncidentSeverity,
        threat_category: str = "unknown",
        risk_score: float = 0.0,
        source_event_ids: Optional[list[str]] = None,
    ) -> str:
        """Create a new incident. Returns incident_id."""
        inc_id = f"INC-{str(uuid.uuid4())[:8].upper()}"
        now = datetime.utcnow()
        with self._Session() as session:
            record = IncidentRecord(
                incident_id=inc_id,
                title=title,
                description=description,
                severity=severity.value,
                status=IncidentStatus.DETECTED.value,
                threat_category=threat_category,
                risk_score=str(risk_score),
                source_event_ids=",".join(source_event_ids or []),
                created_at=now,
                updated_at=now,
            )
            session.add(record)
            session.commit()
        log.warning(f"Incident created: {inc_id} [{severity.value}] {title}")
        return inc_id

    def update_status(
        self,
        incident_id: str,
        status: IncidentStatus,
        notes: str = "",
        operator_id: str = "operator",
    ) -> bool:
        """Update the status of an incident. Returns True on success."""
        with self._Session() as session:
            record = session.get(IncidentRecord, incident_id)
            if not record:
                return False
            record.status = status.value
            record.updated_at = datetime.utcnow()
            if notes:
                record.operator_notes = (record.operator_notes + f"\n[{operator_id}] {notes}").strip()
            if status in (IncidentStatus.RESOLVED, IncidentStatus.FALSE_POSITIVE):
                record.resolved_at = datetime.utcnow()
            session.commit()
        log.info(f"Incident {incident_id} → {status.value}")
        return True

    def add_note(self, incident_id: str, note: str, operator_id: str) -> bool:
        with self._Session() as session:
            record = session.get(IncidentRecord, incident_id)
            if not record:
                return False
            record.operator_notes = (
                record.operator_notes + f"\n[{datetime.utcnow().isoformat()}] [{operator_id}] {note}"
            ).strip()
            record.updated_at = datetime.utcnow()
            session.commit()
        return True

    def get(self, incident_id: str) -> Optional[dict]:
        with self._Session() as session:
            record = session.get(IncidentRecord, incident_id)
            return self._to_dict(record) if record else None

    def list_incidents(
        self,
        status: Optional[IncidentStatus] = None,
        severity: Optional[IncidentSeverity] = None,
        limit: int = 50,
    ) -> list[dict]:
        with self._Session() as session:
            q = session.query(IncidentRecord)
            if status:
                q = q.filter(IncidentRecord.status == status.value)
            if severity:
                q = q.filter(IncidentRecord.severity == severity.value)
            records = q.order_by(IncidentRecord.created_at.desc()).limit(limit).all()
            return [self._to_dict(r) for r in records]

    @staticmethod
    def _to_dict(r: IncidentRecord) -> dict:
        return {
            "incident_id": r.incident_id,
            "title": r.title,
            "description": r.description,
            "severity": r.severity,
            "status": r.status,
            "threat_category": r.threat_category,
            "risk_score": float(r.risk_score),
            "source_event_ids": r.source_event_ids.split(",") if r.source_event_ids else [],
            "operator_notes": r.operator_notes,
            "assigned_to": r.assigned_to,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "updated_at": r.updated_at.isoformat() if r.updated_at else None,
            "resolved_at": r.resolved_at.isoformat() if r.resolved_at else None,
        }


# Singleton
_manager: Optional[IncidentManager] = None


def get_incident_manager() -> IncidentManager:
    global _manager
    if _manager is None:
        _manager = IncidentManager()
    return _manager
