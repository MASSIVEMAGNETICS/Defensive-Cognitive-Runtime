"""
Memory Layer: Audit Ledger
---------------------------
Append-only, tamper-evident audit ledger stored in SQLite.
Each record is HMAC-signed, and records are chain-linked via SHA-256
so that any deletion or modification of a prior record is detectable.

Design principles:
- Append-only (no UPDATE or DELETE in normal operation)
- HMAC-SHA256 per record
- SHA-256 chain linking (each record includes previous_hash)
- Operator can verify the chain at any time
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import Column, DateTime, Integer, String, Text, create_engine, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from protector_stack.utils.config import get_config
from protector_stack.utils.crypto import (
    chain_hash,
    get_or_create_signing_key,
    sign_record,
    verify_record,
)
from protector_stack.utils.logging import get_logger

log = get_logger(__name__)

_GENESIS_HASH = "0" * 64  # Starting hash for the chain


class Base(DeclarativeBase):
    pass


class AuditEntry(Base):
    __tablename__ = "audit_ledger"

    id = Column(Integer, primary_key=True, autoincrement=True)
    entry_id = Column(String, nullable=False, unique=True)
    entry_type = Column(String, nullable=False)   # event | threat | policy | containment | governance
    actor_id = Column(String, nullable=False, default="system")
    summary = Column(Text, nullable=False)
    payload_json = Column(Text, nullable=False)
    timestamp = Column(DateTime, nullable=False)
    previous_hash = Column(String(64), nullable=False)
    record_hash = Column(String(64), nullable=False)  # chain hash
    signature = Column(String(64), nullable=False)    # HMAC-SHA256


def _get_engine(db_path: str):
    import os
    dir_ = os.path.dirname(db_path)
    if dir_:
        os.makedirs(dir_, exist_ok=True)
    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    return engine


class AuditLedger:
    """Append-only tamper-evident audit ledger."""

    def __init__(self) -> None:
        cfg = get_config()
        self._engine = _get_engine(cfg.db_path)
        self._Session = sessionmaker(bind=self._engine)
        self._key = get_or_create_signing_key(cfg.audit_signing_key_path)
        self._chain_enabled = cfg.audit_chain_enabled
        self._last_hash = self._get_tail_hash()

    def _get_tail_hash(self) -> str:
        """Return the most recent record_hash from the ledger, or genesis hash."""
        with self._Session() as session:
            result = session.execute(
                text("SELECT record_hash FROM audit_ledger ORDER BY id DESC LIMIT 1")
            ).fetchone()
            return result[0] if result else _GENESIS_HASH

    def append(
        self,
        entry_type: str,
        summary: str,
        payload: dict[str, Any],
        actor_id: str = "system",
        timestamp: Optional[datetime] = None,
    ) -> str:
        """Append a new entry to the ledger. Returns the entry_id."""
        ts = timestamp or datetime.utcnow()
        entry_id = str(uuid.uuid4())

        record_body = {
            "entry_id": entry_id,
            "entry_type": entry_type,
            "actor_id": actor_id,
            "summary": summary,
            "timestamp": ts.isoformat(),
            "payload": payload,
        }

        sig = sign_record(record_body, self._key)
        prev_hash = self._last_hash
        rec_hash = chain_hash(prev_hash, record_body)

        with self._Session() as session:
            entry = AuditEntry(
                entry_id=entry_id,
                entry_type=entry_type,
                actor_id=actor_id,
                summary=summary,
                payload_json=json.dumps(payload, default=str),
                timestamp=ts,
                previous_hash=prev_hash,
                record_hash=rec_hash,
                signature=sig,
            )
            session.add(entry)
            session.commit()

        self._last_hash = rec_hash
        log.debug(f"Audit entry appended: {entry_id[:8]}… [{entry_type}] {summary[:60]}")
        return entry_id

    def verify_chain(self) -> tuple[bool, str]:
        """Walk the entire ledger and verify chain integrity.

        Returns (ok: bool, message: str).
        """
        with self._Session() as session:
            entries = (
                session.query(AuditEntry).order_by(AuditEntry.id).all()
            )

        if not entries:
            return True, "Ledger is empty — chain OK."

        prev_hash = _GENESIS_HASH
        for entry in entries:
            payload = json.loads(entry.payload_json)
            record_body = {
                "entry_id": entry.entry_id,
                "entry_type": entry.entry_type,
                "actor_id": entry.actor_id,
                "summary": entry.summary,
                "timestamp": entry.timestamp.isoformat(),
                "payload": payload,
            }
            # Verify HMAC signature
            if not verify_record(record_body, entry.signature, self._key):
                return (
                    False,
                    f"SIGNATURE MISMATCH at entry #{entry.id} ({entry.entry_id[:8]}…) — "
                    "ledger may have been tampered with!",
                )
            # Verify chain link
            expected_hash = chain_hash(prev_hash, record_body)
            if expected_hash != entry.record_hash:
                return (
                    False,
                    f"CHAIN BREAK at entry #{entry.id} ({entry.entry_id[:8]}…) — "
                    "a previous record may have been modified or deleted!",
                )
            prev_hash = entry.record_hash

        return True, f"Chain verified OK — {len(entries)} entries checked."

    def query(
        self,
        entry_type: Optional[str] = None,
        actor_id: Optional[str] = None,
        since: Optional[datetime] = None,
        limit: int = 100,
    ) -> list[dict]:
        """Query ledger entries with optional filters."""
        with self._Session() as session:
            q = session.query(AuditEntry)
            if entry_type:
                q = q.filter(AuditEntry.entry_type == entry_type)
            if actor_id:
                q = q.filter(AuditEntry.actor_id == actor_id)
            if since:
                q = q.filter(AuditEntry.timestamp >= since)
            entries = q.order_by(AuditEntry.id.desc()).limit(limit).all()

        return [
            {
                "id": e.id,
                "entry_id": e.entry_id,
                "entry_type": e.entry_type,
                "actor_id": e.actor_id,
                "summary": e.summary,
                "timestamp": e.timestamp.isoformat(),
                "record_hash": e.record_hash[:16] + "…",
            }
            for e in entries
        ]

    def count(self) -> int:
        with self._Session() as session:
            return session.query(AuditEntry).count()


# Singleton
_ledger: Optional[AuditLedger] = None


def get_audit_ledger() -> AuditLedger:
    global _ledger
    if _ledger is None:
        _ledger = AuditLedger()
    return _ledger


def reset_audit_ledger() -> None:
    global _ledger
    _ledger = None
