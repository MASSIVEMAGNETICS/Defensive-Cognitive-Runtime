"""
Observation Layer: File Watcher
---------------------------------
Monitors file system paths for suspicious changes using the watchdog library.
Emits file creation/modification/deletion events via the collector.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from watchdog.events import (
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
    FileMovedEvent,
    FileSystemEventHandler,
)
from watchdog.observers import Observer

from protector_stack.observation.collector import EventCollector
from protector_stack.observation.schemas import EventType
from protector_stack.utils.logging import get_logger

log = get_logger(__name__)

# Extensions that warrant elevated scrutiny when created/modified
SUSPICIOUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta",
    ".dll", ".sys", ".scr", ".pif", ".jar",
}

# Path fragments that warrant elevated scrutiny
SUSPICIOUS_PATH_FRAGMENTS = {
    "temp", "tmp", "appdata\\roaming", "startup", "run",
    "system32", "winlogon", "lsass",
}


class _ProtectorFileEventHandler(FileSystemEventHandler):
    def __init__(self, collector: EventCollector, watch_path: str) -> None:
        super().__init__()
        self._collector = collector
        self._watch_path = watch_path

    def on_created(self, event: FileCreatedEvent) -> None:  # type: ignore[override]
        if event.is_directory:
            return
        self._emit(EventType.FILE_CREATED, event.src_path)

    def on_modified(self, event: FileModifiedEvent) -> None:  # type: ignore[override]
        if event.is_directory:
            return
        self._emit(EventType.FILE_MODIFIED, event.src_path)

    def on_deleted(self, event: FileDeletedEvent) -> None:  # type: ignore[override]
        if event.is_directory:
            return
        self._emit(EventType.FILE_DELETED, event.src_path)

    def on_moved(self, event: FileMovedEvent) -> None:  # type: ignore[override]
        if event.is_directory:
            return
        self._emit(EventType.FILE_MODIFIED, event.dest_path, src=event.src_path)

    def _emit(self, etype: EventType, path: str, src: Optional[str] = None) -> None:
        path_lower = path.lower()
        ext = os.path.splitext(path_lower)[1]
        suspicious_ext = ext in SUSPICIOUS_EXTENSIONS
        suspicious_path = any(frag in path_lower for frag in SUSPICIOUS_PATH_FRAGMENTS)
        suspicious = suspicious_ext or suspicious_path

        raw: dict = {
            "type": etype.value,
            "path": path,
            "severity": "warning" if suspicious else "info",
            "risk_hint": 0.5 if suspicious else 0.05,
            "tags": [],
        }
        if suspicious_ext:
            raw["tags"].append("suspicious_extension")
        if suspicious_path:
            raw["tags"].append("suspicious_path")
        if src:
            raw["src_path"] = src

        self._collector.submit(raw, source="file_watcher")
        if suspicious:
            log.warning(f"Suspicious file event: {etype.value} at {path}")


class FileWatcher:
    """Watches one or more filesystem paths for suspicious changes."""

    def __init__(self, collector: EventCollector) -> None:
        self._collector = collector
        self._observer: Optional[Observer] = None
        self._watch_paths: list[str] = []

    def add_watch_path(self, path: str, recursive: bool = True) -> None:
        """Register a path to watch. Must be called before start()."""
        self._watch_paths.append((path, recursive))

    def start(self) -> None:
        """Start the file system observer."""
        if not self._watch_paths:
            log.info("FileWatcher: no paths configured, skipping start.")
            return
        self._observer = Observer()
        for path, recursive in self._watch_paths:
            if not Path(path).exists():
                log.warning(f"FileWatcher: watch path does not exist: {path}")
                continue
            handler = _ProtectorFileEventHandler(self._collector, path)
            self._observer.schedule(handler, path, recursive=recursive)
            log.info(f"FileWatcher: watching {path} (recursive={recursive})")
        self._observer.start()
        log.info("FileWatcher started.")

    def stop(self) -> None:
        """Stop the file system observer."""
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=5)
        log.info("FileWatcher stopped.")
