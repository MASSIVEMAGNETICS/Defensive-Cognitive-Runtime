# PROTECTOR_STACK

**Defensive Cognitive Runtime** — A guardian-class AI safety system.

> *"Preserve human agency and continuity by detecting, constraining, and containing
> malicious or misaligned AI behavior without becoming a hidden ruler itself."*

---

## What is this?

PROTECTOR_STACK is a production-grade defensive AI safety system designed to:

- **Detect** prompt injection, privilege escalation, data exfiltration, and agentic drift
- **Enforce** policy boundaries before actions execute
- **Contain** suspicious processes and agents
- **Audit** every action in a tamper-evident ledger
- **Preserve** human oversight, control, and decision authority

It is **not** a chatbot, persuasion engine, or autonomous decision-maker.
It is a **guardian, not a ruler**.

---

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Copy config
cp .env.example .env

# Run the demo (proves the system works)
python -m protector_stack.interface.cli demo

# Start monitoring
python -m protector_stack.interface.cli start
```

---

## Demo Output

The built-in demo shows all three protection tiers:

```
Scenario 1: Benign workflow
  ● BENIGN | risk=0.00 | category=benign | action=monitor

Scenario 2: Suspicious workflow (prompt injection)
  ● SUSPICIOUS | risk=1.00 | category=critical | action=quarantine
    ⚠ ignore_previous_instructions
    ⚠ jailbreak_persona

Scenario 3: Dangerous workflow (credential theft + exfiltration)
  ● DANGEROUS | risk=1.00 | category=critical | action=quarantine
    ⚠ lsass_access
    ⚠ mimikatz_reference
    ⚠ credential_attack_technique
```

---

## Architecture

Nine modular layers, each with a single responsibility:

```
┌─────────────────────────────────────┐
│  9. Interface         CLI / Reports  │
│  8. Governance        Review Queue   │
│  7. Memory/Provenance Audit Ledger   │
│  6. Containment       Quarantine     │
│  5. Simulation        Safety Gate    │
│  4. Threat Analysis   Detectors      │
│  3. Observation       Event Bus      │
│  2. Policy Engine     Rule Engine    │
│  1. Constitution      Doctrine       │
└─────────────────────────────────────┘
```

---

## CLI Commands

```bash
protector demo              # Run the three-tier demo
protector start             # Start monitoring mode
protector status            # System health check
protector scan "text"       # Scan text for threats
protector alerts            # Show open alert queue
protector incidents         # List security incidents
protector audit verify      # Verify audit chain integrity
protector audit tail        # Recent audit entries
protector doctrine          # Show core doctrine
protector report <INC-ID>   # Generate incident report
```

---

## Detection Capabilities

| Threat Type | Detector | Patterns |
|-------------|----------|---------|
| Prompt Injection | `injection_detector` | 16+ patterns |
| Privilege Escalation | `escalation_detector` | 15+ patterns |
| Data Exfiltration | `exfil_detector` | 12+ patterns |
| Agentic Drift | `drift_detector` | 6 behavioral signals |

---

## Core Guarantees

- **Hard non-goals** (malware, weapons, credential theft, etc.) are hardcoded in
  Python `frozenset` — immutable at runtime, doctrine file is checksum-verified
- **Audit chain** is HMAC-signed + SHA-256 chain-linked — tampering is detectable
- **Human override** always available — no action is autonomously irreversible
  without explicit operator approval

---

## Documentation

| File | Contents |
|------|----------|
| `HUMAN_EXPLANATION.txt` | Plain-English guide for operators |
| `MANUAL.md` | Full technical manual |
| `ARCHITECTURE.md` | System architecture details |
| `THREAT_MODEL.md` | Threat model and mitigations |
| `CHANGELOG.md` | Version history |

---

## Requirements

- Python 3.11+
- ~80 MB RAM (normal operation)
- Works on Windows 10 / Linux / macOS
- No cloud dependencies required

---

## License

MIT — See LICENSE for details.

---

*PROTECTOR_STACK v1.0.0 — Built for defenders, not rulers.*
