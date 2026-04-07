"""
Threat Analysis: Prompt Injection Detector
-------------------------------------------
Detects known and heuristic prompt injection patterns in model inputs/outputs.
Returns a risk score (0.0–1.0) and a list of detected signals.

Patterns covered:
- Classic "ignore previous instructions" variants
- Role-play jailbreaks ("you are now DAN...")
- Instruction override attempts
- System prompt extraction attempts
- Indirect injection via tool outputs
- Encoding tricks (base64 hints, reverse text patterns)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# ── Pattern Bank ──────────────────────────────────────────────────────────────

# Each pattern: (compiled regex, description, weight 0.0–1.0)
_PATTERNS: list[tuple[re.Pattern, str, float]] = []


def _add(pattern: str, description: str, weight: float) -> None:
    _PATTERNS.append((re.compile(pattern, re.IGNORECASE | re.DOTALL), description, weight))


# Direct override instructions
_add(r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context)", "ignore_previous_instructions", 0.9)
_add(r"disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?)", "disregard_instructions", 0.9)
_add(r"forget\s+everything\s+(you\s+)?(were\s+)?(told|instructed|given)", "forget_instructions", 0.85)
_add(r"(you\s+are\s+now|act\s+as|pretend\s+(you\s+are|to\s+be))\s+(\w+\s+)?(?:without\s+restrictions|unrestricted|unfiltered|jailbroken|DAN|evil|bad\s+AI)", "jailbreak_persona", 0.95)
_add(r"DAN\s*(mode|prompt|\d+\.?\d*)", "dan_jailbreak", 0.95)
_add(r"(bypass|override|circumvent|disable)\s+(your\s+)?(safety|filter|restriction|alignment|guard|policy)", "safety_bypass_attempt", 0.95)
_add(r"(print|output|reveal|show|display|tell me)\s+(your\s+)?(system\s+prompt|instruction|hidden\s+prompt|initial\s+prompt)", "system_prompt_extraction", 0.9)
_add(r"(what\s+(are|were)\s+your\s+(original\s+)?instructions)", "instruction_extraction", 0.8)
_add(r"</?(system|assistant|user|human|ai|prompt)>", "pseudo_xml_role_injection", 0.85)
_add(r"\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>", "llama_template_injection", 0.85)
_add(r"(new\s+)?instructions?\s*:?\s*\n", "inline_instruction_injection", 0.6)
_add(r"(simulate|roleplay|role\s*play)\s+(a\s+)?(hacker|attacker|malicious|unrestricted|uncensored)", "malicious_roleplay", 0.9)
_add(r"(encode|obfuscate|base64|rot13|caesar)\s+(this\s+)?(instruction|command|prompt)", "obfuscation_attempt", 0.8)
_add(r"(translate\s+to\s+\w+\s+and\s+execute|run\s+the\s+following\s+code)", "code_execution_injection", 0.85)
_add(r"(tool\s+output|search\s+result|webpage\s+content).*?(ignore|disregard|override)", "indirect_injection_via_tool", 0.8)
_add(r"(you\s+must|you\s+shall|you\s+will)\s+(always\s+)?(comply|obey|follow|execute)\s+(?:my|all)\s+commands", "compliance_coercion", 0.75)
_add(r"(secret|hidden|confidential)\s+(mode|capability|power|instruction|command)", "secret_mode_appeal", 0.7)


@dataclass
class InjectionAnalysis:
    """Result of prompt injection analysis."""
    text_snippet: str  # first 200 chars
    risk_score: float
    signals: list[str] = field(default_factory=list)
    is_injection: bool = False
    confidence: str = "low"  # low | medium | high


def analyze_text(text: str) -> InjectionAnalysis:
    """Analyze text for prompt injection signals.

    Returns an InjectionAnalysis with risk score (0.0–1.0).
    Score is NOT a simple average: it uses max with weighted accumulation
    to reflect that even one strong signal is dangerous.
    """
    if not text:
        return InjectionAnalysis(text_snippet="", risk_score=0.0)

    snippet = text[:200]
    signals: list[str] = []
    weights: list[float] = []

    for pattern, description, weight in _PATTERNS:
        if pattern.search(text):
            signals.append(description)
            weights.append(weight)

    if not weights:
        return InjectionAnalysis(
            text_snippet=snippet,
            risk_score=0.0,
            signals=[],
            is_injection=False,
            confidence="low",
        )

    # Risk = max(weights) * (1 + 0.1 * (count-1)) capped at 1.0
    # This means one strong hit is already very high; multiple signals push it to 1.0
    max_w = max(weights)
    amplified = min(1.0, max_w * (1 + 0.1 * (len(weights) - 1)))

    confidence = "high" if amplified >= 0.7 else ("medium" if amplified >= 0.4 else "low")

    return InjectionAnalysis(
        text_snippet=snippet,
        risk_score=round(amplified, 3),
        signals=signals,
        is_injection=amplified >= 0.5,
        confidence=confidence,
    )
