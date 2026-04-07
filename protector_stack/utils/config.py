"""
Utility: Configuration Management
----------------------------------
Loads runtime configuration from environment variables and optional YAML file.
All configuration is validated via Pydantic and available via a singleton.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import yaml
from dotenv import load_dotenv
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

load_dotenv()


class ProtectorConfig(BaseSettings):
    """Central configuration for the Protector Stack runtime."""

    model_config = SettingsConfigDict(env_prefix="PROTECTOR_", extra="ignore")

    # Core
    env: str = "production"
    log_level: str = "INFO"
    db_path: str = "./protector_data/protector.db"
    data_dir: str = "./protector_data"
    config_path: str = "./config/default_config.yaml"

    # Resource limits
    low_resource_mode: bool = False
    max_worker_threads: int = 4
    scan_interval_seconds: int = 30
    deep_scan_interval_seconds: int = 300

    # Policy
    policy_path: str = "./config/default_policy.yaml"
    policy_strict_mode: bool = True
    auto_quarantine_high_risk: bool = True
    risk_threshold_warn: float = 0.4
    risk_threshold_block: float = 0.7
    risk_threshold_quarantine: float = 0.85

    # Audit
    audit_signing_key_path: str = "./protector_data/audit_key.pem"
    audit_chain_enabled: bool = True

    # API
    api_enabled: bool = False
    api_host: str = "127.0.0.1"
    api_port: int = 8741

    # Governance
    require_human_approval_above: float = 0.7
    alert_email: Optional[str] = None
    operator_id: str = "operator-1"

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if v.upper() not in allowed:
            raise ValueError(f"log_level must be one of {allowed}")
        return v.upper()

    @field_validator("env")
    @classmethod
    def validate_env(cls, v: str) -> str:
        allowed = {"development", "staging", "production"}
        if v.lower() not in allowed:
            raise ValueError(f"env must be one of {allowed}")
        return v.lower()

    def ensure_data_dir(self) -> None:
        """Create data directory and subdirectories if they don't exist."""
        base = Path(self.data_dir)
        for sub in ("", "incidents", "snapshots", "quarantine", "reports"):
            (base / sub).mkdir(parents=True, exist_ok=True)


def load_yaml_config(path: str) -> dict:
    """Load a YAML config file and return as dict. Returns empty dict on failure."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}
    except yaml.YAMLError:
        return {}


# Singleton instance
_config: Optional[ProtectorConfig] = None


def get_config() -> ProtectorConfig:
    """Return the global singleton config instance."""
    global _config
    if _config is None:
        _config = ProtectorConfig()
    return _config


def reset_config() -> None:
    """Reset singleton (for testing)."""
    global _config
    _config = None
