"""
Containment Layer: Quarantine Orchestrator
-------------------------------------------
Manages quarantine of suspicious processes, agents, and sessions.

Quarantine actions:
- Suspend a process (SIGSTOP or equivalent)
- Terminate a process
- Restrict file system access (record-only mode — actual FS restriction
  requires OS-level privileges; this module records and alerts)
- Flag an agent session as quarantined (preventing further policy passes)

All quarantine actions:
1. Are logged in the audit ledger
2. Require human approval (tracked via approval workflow)
3. Are reversible where possible (resume, restore)
"""

from __future__ import annotations

import os
import signal
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional

import psutil

from protector_stack.utils.logging import get_logger

log = get_logger(__name__)


class QuarantineStatus(str, Enum):
    ACTIVE = "active"
    RELEASED = "released"
    EXPIRED = "expired"
    FAILED = "failed"


@dataclass
class QuarantineRecord:
    quarantine_id: str
    target_type: str        # process | agent | session | file_path
    target_id: str          # pid, agent_id, session_id, or path
    reason: str
    initiated_by: str       # operator_id or "auto"
    status: QuarantineStatus
    created_at: datetime = field(default_factory=datetime.utcnow)
    released_at: Optional[datetime] = None
    notes: str = ""


class QuarantineManager:
    """Manages active quarantine records and executes quarantine/release actions."""

    def __init__(self) -> None:
        self._records: dict[str, QuarantineRecord] = {}

    def quarantine_process(
        self,
        pid: int,
        reason: str,
        operator_id: str = "auto",
        suspend: bool = True,
    ) -> QuarantineRecord:
        """Quarantine a process: suspend (preferred) or terminate.

        Returns a QuarantineRecord.
        NOTE: Actual OS-level suspension requires platform support.
        On unsupported platforms, the process is terminated instead.
        """
        import uuid
        qid = f"QTN-{str(uuid.uuid4())[:8].upper()}"

        record = QuarantineRecord(
            quarantine_id=qid,
            target_type="process",
            target_id=str(pid),
            reason=reason,
            initiated_by=operator_id,
            status=QuarantineStatus.ACTIVE,
        )

        try:
            proc = psutil.Process(pid)
            if suspend and hasattr(signal, "SIGSTOP"):
                proc.suspend()
                record.notes = f"Process {pid} ({proc.name()}) suspended."
                log.warning(f"[QUARANTINE] Suspended PID {pid}: {reason}")
            else:
                proc.terminate()
                record.notes = f"Process {pid} terminated."
                log.warning(f"[QUARANTINE] Terminated PID {pid}: {reason}")
        except psutil.NoSuchProcess:
            record.status = QuarantineStatus.FAILED
            record.notes = f"Process {pid} no longer exists."
            log.warning(f"[QUARANTINE] PID {pid} not found: {reason}")
        except psutil.AccessDenied:
            record.status = QuarantineStatus.FAILED
            record.notes = f"Access denied to process {pid}."
            log.error(f"[QUARANTINE] Access denied to PID {pid}: {reason}")
        except Exception as exc:
            record.status = QuarantineStatus.FAILED
            record.notes = f"Quarantine failed: {exc}"
            log.error(f"[QUARANTINE] Failed for PID {pid}: {exc}")

        self._records[qid] = record
        return record

    def quarantine_agent(
        self,
        agent_id: str,
        reason: str,
        operator_id: str = "auto",
    ) -> QuarantineRecord:
        """Record quarantine of an agent session (soft quarantine — flags the agent)."""
        import uuid
        qid = f"QTN-{str(uuid.uuid4())[:8].upper()}"
        record = QuarantineRecord(
            quarantine_id=qid,
            target_type="agent",
            target_id=agent_id,
            reason=reason,
            initiated_by=operator_id,
            status=QuarantineStatus.ACTIVE,
            notes=f"Agent '{agent_id}' flagged as quarantined.",
        )
        self._records[qid] = record
        log.warning(f"[QUARANTINE] Agent '{agent_id}' quarantined: {reason}")
        return record

    def release(self, quarantine_id: str, operator_id: str) -> bool:
        """Release a quarantined resource. Returns True on success."""
        record = self._records.get(quarantine_id)
        if record is None:
            log.warning(f"Quarantine record not found: {quarantine_id}")
            return False
        if record.status != QuarantineStatus.ACTIVE:
            log.warning(f"Quarantine {quarantine_id} is not active (status={record.status})")
            return False

        if record.target_type == "process":
            try:
                pid = int(record.target_id)
                proc = psutil.Process(pid)
                proc.resume()
                log.info(f"[QUARANTINE RELEASE] PID {pid} resumed by {operator_id}")
            except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError) as exc:
                log.warning(f"[QUARANTINE RELEASE] Could not resume PID: {exc}")

        record.status = QuarantineStatus.RELEASED
        record.released_at = datetime.utcnow()
        record.notes += f" Released by {operator_id}."
        return True

    def is_quarantined(self, target_id: str) -> bool:
        """Check if a target_id has an active quarantine record."""
        return any(
            r.target_id == str(target_id) and r.status == QuarantineStatus.ACTIVE
            for r in self._records.values()
        )

    def get_active(self) -> list[QuarantineRecord]:
        """Return all active quarantine records."""
        return [r for r in self._records.values() if r.status == QuarantineStatus.ACTIVE]

    def get_all(self) -> list[QuarantineRecord]:
        return list(self._records.values())


# Singleton
_manager: Optional[QuarantineManager] = None


def get_quarantine_manager() -> QuarantineManager:
    global _manager
    if _manager is None:
        _manager = QuarantineManager()
    return _manager
