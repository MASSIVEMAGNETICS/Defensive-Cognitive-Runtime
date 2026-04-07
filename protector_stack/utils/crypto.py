"""
Utility: Cryptographic Helpers
--------------------------------
Provides HMAC-SHA256 audit record signing, chain-link hashing, and key
management for tamper-evident audit ledgers.

No offensive capability. Defensive integrity tooling only.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from pathlib import Path
from typing import Optional


# ── Key Management ────────────────────────────────────────────────────────────

def generate_signing_key(path: str) -> bytes:
    """Generate a 32-byte random signing key and write it to path (hex-encoded).
    Returns the raw key bytes."""
    key = secrets.token_bytes(32)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(key.hex(), encoding="utf-8")
    return key


def load_signing_key(path: str) -> Optional[bytes]:
    """Load a hex-encoded signing key from path. Returns None if missing."""
    try:
        return bytes.fromhex(Path(path).read_text(encoding="utf-8").strip())
    except (FileNotFoundError, ValueError):
        return None


def get_or_create_signing_key(path: str) -> bytes:
    """Load key from path, generating a new one if absent."""
    key = load_signing_key(path)
    if key is None:
        key = generate_signing_key(path)
    return key


# ── Record Hashing ────────────────────────────────────────────────────────────

def sha256_hex(data: bytes) -> str:
    """Return hex-encoded SHA-256 digest of data."""
    return hashlib.sha256(data).hexdigest()


def sign_record(record: dict, key: bytes) -> str:
    """Return HMAC-SHA256 hex signature of the canonical JSON of record."""
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)
    return hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_record(record: dict, signature: str, key: bytes) -> bool:
    """Verify HMAC-SHA256 signature of record. Returns True if valid."""
    expected = sign_record(record, key)
    return hmac.compare_digest(expected, signature)


def chain_hash(previous_hash: str, record: dict) -> str:
    """Compute chain link hash: SHA-256(previous_hash + canonical_record_json).
    This creates a tamper-evident chain: changing any prior record invalidates
    all subsequent hashes."""
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)
    combined = (previous_hash + canonical).encode("utf-8")
    return sha256_hex(combined)


def record_fingerprint(record: dict) -> str:
    """Return a short 8-char fingerprint (first 8 chars of SHA-256) for display."""
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)
    return sha256_hex(canonical.encode("utf-8"))[:8]
