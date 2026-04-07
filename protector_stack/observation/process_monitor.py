"""
Observation Layer: Process Monitor
------------------------------------
Monitors running processes using psutil and emits ObservedEvents for
process spawn/terminate and suspicious process attributes.

Runs in a background thread at configurable intervals.
"""

from __future__ import annotations

import threading
import time
from typing import Optional

import psutil

from protector_stack.observation.collector import EventCollector
from protector_stack.observation.schemas import EventType
from protector_stack.utils.config import get_config
from protector_stack.utils.logging import get_logger

log = get_logger(__name__)

# Names/keywords that warrant elevated scrutiny
SUSPICIOUS_PROCESS_KEYWORDS = {
    "mimikatz", "nc.exe", "netcat", "ncat", "meterpreter", "cobaltstrike",
    "empire", "beacon", "pwdump", "lsass", "procdump", "dumpert",
}


class ProcessMonitor:
    """Background process monitor.

    On each scan interval:
    1. Enumerate all running processes via psutil.
    2. Detect newly spawned processes since last scan.
    3. Detect terminated processes.
    4. Flag processes with suspicious names/cmdline keywords.
    5. Emit ObservedEvent via the collector.
    """

    def __init__(self, collector: EventCollector) -> None:
        self._collector = collector
        self._cfg = get_config()
        self._known_pids: dict[int, dict] = {}
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        """Start the background monitoring thread."""
        self._stop_event.clear()
        # Initial snapshot
        self._known_pids = self._snapshot_processes()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="ProcessMonitor",
            daemon=True,
        )
        self._thread.start()
        log.info("ProcessMonitor started.")

    def stop(self) -> None:
        """Stop the background monitoring thread."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        log.info("ProcessMonitor stopped.")

    def _run_loop(self) -> None:
        interval = self._cfg.scan_interval_seconds
        while not self._stop_event.wait(timeout=interval):
            try:
                self._scan()
            except Exception as exc:
                log.error(f"ProcessMonitor scan error: {exc}")

    def _scan(self) -> None:
        current = self._snapshot_processes()

        # New processes
        for pid, info in current.items():
            if pid not in self._known_pids:
                self._emit_spawn(info)

        # Terminated processes
        for pid in list(self._known_pids.keys()):
            if pid not in current:
                old = self._known_pids[pid]
                self._collector.submit(
                    {
                        "type": EventType.PROCESS_TERMINATE.value,
                        "pid": pid,
                        "name": old.get("name", "?"),
                        "description": f"Process terminated: {old.get('name', '?')} (pid={pid})",
                        "severity": "info",
                    },
                    source="process_monitor",
                )

        self._known_pids = current

    def _emit_spawn(self, info: dict) -> None:
        name = info.get("name", "").lower()
        cmdline = info.get("cmdline", [])
        cmdline_str = " ".join(cmdline).lower()

        suspicious = any(
            kw in name or kw in cmdline_str
            for kw in SUSPICIOUS_PROCESS_KEYWORDS
        )

        self._collector.submit(
            {
                "type": EventType.PROCESS_SPAWN.value,
                "pid": info["pid"],
                "name": info.get("name", "?"),
                "cmdline": cmdline,
                "username": info.get("username"),
                "cwd": info.get("cwd"),
                "description": f"Process spawned: {info.get('name', '?')} (pid={info['pid']})",
                "severity": "warning" if suspicious else "info",
                "risk_hint": 0.6 if suspicious else 0.1,
                "tags": ["suspicious_process"] if suspicious else [],
            },
            source="process_monitor",
        )
        if suspicious:
            log.warning(
                f"SUSPICIOUS process detected: {info.get('name')} "
                f"(pid={info['pid']}, cmdline={cmdline_str[:80]})"
            )

    @staticmethod
    def _snapshot_processes() -> dict[int, dict]:
        """Return dict of {pid: info} for all running processes."""
        procs: dict[int, dict] = {}
        for proc in psutil.process_iter(
            ["pid", "name", "cmdline", "username", "cwd"]
        ):
            try:
                info = proc.info  # type: ignore[attr-defined]
                procs[info["pid"]] = {
                    "pid": info["pid"],
                    "name": info.get("name") or "",
                    "cmdline": info.get("cmdline") or [],
                    "username": info.get("username"),
                    "cwd": info.get("cwd"),
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return procs
