"""
Constitution Layer: Integrity Checker
---------------------------------------
Computes and verifies a SHA-256 checksum over the doctrine module source code.
On startup, the runtime verifies this checksum to detect tampering.

The checksum is stored in a separate manifest file so that if someone alters
doctrine.py, the mismatch will be detected.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Optional

from protector_stack.utils.logging import get_logger

log = get_logger(__name__)

_DOCTRINE_FILE = Path(__file__).parent / "doctrine.py"
_MANIFEST_FILE = Path(__file__).parent / "doctrine_checksum.json"


def compute_doctrine_checksum() -> str:
    """Compute SHA-256 of the doctrine.py source file."""
    content = _DOCTRINE_FILE.read_bytes()
    return hashlib.sha256(content).hexdigest()


def write_doctrine_manifest() -> str:
    """Write (or overwrite) the doctrine checksum manifest. Call this during
    initial setup or after an intentional, authorized update to doctrine.py."""
    checksum = compute_doctrine_checksum()
    manifest = {
        "file": "doctrine.py",
        "sha256": checksum,
        "note": (
            "This file records the expected SHA-256 checksum of doctrine.py. "
            "If doctrine.py is modified without updating this manifest, the "
            "system will raise a TamperAlert on startup."
        ),
    }
    _MANIFEST_FILE.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    log.info(f"Doctrine manifest written: {checksum[:16]}…")
    return checksum


def verify_doctrine_integrity() -> tuple[bool, str]:
    """Verify that doctrine.py matches the stored checksum manifest.

    Returns:
        (ok: bool, message: str)
    """
    if not _MANIFEST_FILE.exists():
        # First run: create the manifest automatically
        checksum = write_doctrine_manifest()
        return True, f"Doctrine manifest created on first run. Checksum: {checksum[:16]}…"

    try:
        manifest = json.loads(_MANIFEST_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return False, f"Failed to read doctrine manifest: {exc}"

    expected = manifest.get("sha256", "")
    actual = compute_doctrine_checksum()

    if actual != expected:
        return (
            False,
            f"DOCTRINE INTEGRITY FAILURE: doctrine.py has been modified! "
            f"Expected {expected[:16]}… got {actual[:16]}…  "
            "This may indicate tampering. The system will operate in restricted "
            "safe mode until an operator reviews and re-authorizes the doctrine.",
        )

    return True, f"Doctrine integrity OK ({actual[:16]}…)"


def get_constitution_status() -> dict:
    """Return a status dict for the constitution layer."""
    ok, message = verify_doctrine_integrity()
    return {
        "layer": "constitution",
        "integrity_ok": ok,
        "message": message,
        "doctrine_file": str(_DOCTRINE_FILE),
        "manifest_file": str(_MANIFEST_FILE),
    }
