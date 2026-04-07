"""
Threat Analysis: Data Exfiltration Detector
---------------------------------------------
Detects indicators of data exfiltration attempts:
- Bulk data reads followed by network connections
- Encoding/archiving followed by network send
- DNS tunneling patterns
- Unusual outbound connections to non-whitelisted endpoints
- Large payload sizes in outbound requests
- Steganographic or encoding obfuscation attempts
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ExfilSignal:
    signal_type: str
    description: str
    weight: float


@dataclass
class ExfilAnalysis:
    risk_score: float
    signals: list[ExfilSignal] = field(default_factory=list)
    is_exfil_attempt: bool = False


# ── Text-based pattern analysis ───────────────────────────────────────────────

_PATTERNS: list[tuple[re.Pattern, str, float]] = []


def _add(pattern: str, sig_type: str, weight: float) -> None:
    _PATTERNS.append(
        (re.compile(pattern, re.IGNORECASE | re.DOTALL), sig_type, weight)
    )


# Data collection + send combos
_add(r"(compress|zip|tar|archive|7z).{0,100}(send|upload|post|transmit)", "compress_then_send", 0.85)
_add(r"(base64.encode|encode.{0,30}(base64|b64)).{0,100}(send|post|request|curl|wget)", "encode_then_send", 0.80)
_add(r"(read.{0,30}(file|database|credential|config)).{0,100}(send|upload|post|transmit)", "read_then_send", 0.75)

# DNS tunneling
_add(r"(dns.{0,20}(tunnel|exfil|query).{0,50}data)", "dns_tunneling", 0.85)
_add(r"(nslookup|dig|resolve).{0,50}(base64|encoded|data)", "dns_data_embedding", 0.80)

# Covert channels
_add(r"(icmp|ping).{0,50}(data|payload|exfil|tunnel)", "icmp_covert_channel", 0.80)
_add(r"(steganograph|hide.{0,20}data.{0,20}(image|file|audio))", "steganography", 0.75)

# Cloud upload patterns
_add(r"(s3\.amazonaws|blob\.core\.windows|storage\.googleapis|dropbox|pastebin|paste\.ee|hastebin).{0,100}(upload|put|post)", "cloud_upload_exfil", 0.75)
_add(r"(curl|wget|invoke-webrequest).{0,100}(-d\s+@|-T\s+|--data)", "cli_upload_tool", 0.65)

# Bulk data reads
_add(r"(select\s+\*\s+from|dump\s+(database|table|schema))", "bulk_database_read", 0.70)
_add(r"(find\s+/\s+-type\s+f|dir\s+/s\s+/b\s+[cde]:\\)", "bulk_filesystem_enum", 0.60)


def analyze_text(text: str) -> ExfilAnalysis:
    """Analyze text/command for data exfiltration signals."""
    if not text:
        return ExfilAnalysis(risk_score=0.0)

    signals: list[ExfilSignal] = []
    for pattern, sig_type, weight in _PATTERNS:
        if pattern.search(text):
            signals.append(ExfilSignal(
                signal_type=sig_type,
                description=f"Pattern match: {sig_type}",
                weight=weight,
            ))

    if not signals:
        return ExfilAnalysis(risk_score=0.0)

    max_w = max(s.weight for s in signals)
    score = min(1.0, max_w * (1 + 0.05 * (len(signals) - 1)))

    return ExfilAnalysis(
        risk_score=round(score, 3),
        signals=signals,
        is_exfil_attempt=score >= 0.5,
    )


def analyze_network_event(
    remote_addr: Optional[str],
    remote_port: Optional[int],
    payload_size_bytes: Optional[int],
    process_name: Optional[str],
    whitelist: Optional[set[str]] = None,
) -> ExfilAnalysis:
    """Analyze a network event for exfiltration indicators."""
    signals: list[ExfilSignal] = []

    if remote_addr and whitelist and remote_addr not in whitelist:
        signals.append(ExfilSignal(
            signal_type="non_whitelisted_destination",
            description=f"Outbound connection to non-whitelisted {remote_addr}",
            weight=0.5,
        ))

    # DNS tunneling: large DNS query (port 53, large payload)
    if remote_port == 53 and payload_size_bytes and payload_size_bytes > 512:
        signals.append(ExfilSignal(
            signal_type="large_dns_query",
            description=f"Unusually large DNS query ({payload_size_bytes} bytes)",
            weight=0.75,
        ))

    # Unusual ports
    unusual_ports = {6667, 6697, 4444, 1337, 31337, 8888, 9999}
    if remote_port in unusual_ports:
        signals.append(ExfilSignal(
            signal_type="suspicious_port",
            description=f"Connection on suspicious port {remote_port}",
            weight=0.65,
        ))

    # Large outbound payload
    if payload_size_bytes and payload_size_bytes > 10 * 1024 * 1024:  # 10MB
        signals.append(ExfilSignal(
            signal_type="large_outbound_payload",
            description=f"Large outbound payload: {payload_size_bytes // 1024} KB",
            weight=0.6,
        ))

    if not signals:
        return ExfilAnalysis(risk_score=0.0)

    max_w = max(s.weight for s in signals)
    score = min(1.0, max_w * (1 + 0.05 * (len(signals) - 1)))

    return ExfilAnalysis(
        risk_score=round(score, 3),
        signals=signals,
        is_exfil_attempt=score >= 0.5,
    )
