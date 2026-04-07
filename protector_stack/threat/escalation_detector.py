"""
Threat Analysis: Privilege Escalation Detector
------------------------------------------------
Detects patterns consistent with privilege escalation attempts:
- Requests to read/access credential stores
- UAC bypass technique keywords
- Attempts to run as SYSTEM or elevated user
- Token impersonation patterns
- Exploiting known vulnerable services
- Unusual permission grants
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class EscalationSignal:
    signal_type: str
    description: str
    weight: float


@dataclass
class EscalationAnalysis:
    risk_score: float
    signals: list[EscalationSignal] = field(default_factory=list)
    is_escalation_attempt: bool = False


# ── Pattern bank ──────────────────────────────────────────────────────────────

_PATTERNS: list[tuple[re.Pattern, str, float]] = []


def _add(pattern: str, sig_type: str, weight: float) -> None:
    _PATTERNS.append(
        (re.compile(pattern, re.IGNORECASE), sig_type, weight)
    )


# Credential access
_add(r"\blsass\b", "lsass_access", 0.95)
_add(r"\bmimikatz\b", "mimikatz_reference", 0.99)
_add(r"sekurlsa|kerberoast|pass.the.hash|pass.the.ticket|golden.ticket|silver.ticket", "credential_attack_technique", 0.95)
_add(r"(read|dump|extract|steal)\s+(credential|password|hash|token|secret|key)", "credential_dump_attempt", 0.90)
_add(r"(sam\s+database|ntds\.dit|security\s+hive)", "credential_store_access", 0.90)

# UAC bypass
_add(r"uac.bypass|fodhelper|eventvwr|sdclt|cmstp|bypassuac", "uac_bypass_technique", 0.90)
_add(r"(bypass|disable|circumvent)\s+uac", "uac_bypass_intent", 0.90)

# Token/impersonation
_add(r"(impersonat|token\s+theft|steal\s+token|duplicate\s+token)", "token_impersonation", 0.85)
_add(r"(runas|run\s+as)\s+(administrator|system|nt\s+authority|root)", "run_as_elevated", 0.80)
_add(r"seimpersonateprivilege|sedebugprivilege|setcbprivilege", "dangerous_privilege_request", 0.85)

# Process injection
_add(r"(dll\s+inject|process\s+inject|shellcode\s+inject|reflective\s+dll)", "process_injection", 0.90)
_add(r"(createremotethread|virtualalloc|writeprocessmemory|ntcreatethread)", "injection_api_call", 0.85)

# Registry persistence
_add(r"(hklm|hkcu).*(run|runonce|winlogon|services|drivers)", "registry_persistence", 0.75)
_add(r"(reg\s+add|registry\s+(write|modify)).*(system|software)", "registry_write_system", 0.70)

# Service manipulation
_add(r"(sc\s+create|new-service|install.*service).*(system|kernel|driver)", "suspicious_service_install", 0.80)
_add(r"(net\s+localgroup\s+administrators|add.+administrators)", "admin_group_manipulation", 0.85)


def analyze_text(text: str) -> EscalationAnalysis:
    """Analyze text for privilege escalation signals."""
    if not text:
        return EscalationAnalysis(risk_score=0.0)

    signals: list[EscalationSignal] = []

    for pattern, sig_type, weight in _PATTERNS:
        if pattern.search(text):
            signals.append(EscalationSignal(
                signal_type=sig_type,
                description=f"Pattern match: {sig_type}",
                weight=weight,
            ))

    if not signals:
        return EscalationAnalysis(risk_score=0.0)

    max_w = max(s.weight for s in signals)
    score = min(1.0, max_w * (1 + 0.05 * (len(signals) - 1)))

    return EscalationAnalysis(
        risk_score=round(score, 3),
        signals=signals,
        is_escalation_attempt=score >= 0.5,
    )
