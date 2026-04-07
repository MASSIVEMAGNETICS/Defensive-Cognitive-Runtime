"""
Utility: Structured Logging
----------------------------
Provides a structured, leveled logger with Rich console output.
All modules import their logger from here for consistent formatting.
"""

from __future__ import annotations

import logging
import sys
from typing import Optional

from rich.console import Console
from rich.logging import RichHandler

_console = Console(stderr=True)
_initialized = False


def setup_logging(level: str = "INFO", log_file: Optional[str] = None) -> None:
    """Configure root logging with Rich handler and optional file handler."""
    global _initialized
    numeric = getattr(logging, level.upper(), logging.INFO)

    handlers: list[logging.Handler] = [
        RichHandler(
            console=_console,
            show_time=True,
            show_path=True,
            rich_tracebacks=True,
            markup=True,
        )
    ]

    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s %(levelname)s [%(name)s] %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%S",
            )
        )
        handlers.append(file_handler)

    logging.basicConfig(
        level=numeric,
        format="%(message)s",
        datefmt="[%X]",
        handlers=handlers,
        force=True,
    )
    _initialized = True


def get_logger(name: str) -> logging.Logger:
    """Return a named logger, initializing with INFO level if not yet done."""
    global _initialized
    if not _initialized:
        setup_logging()
    return logging.getLogger(name)
