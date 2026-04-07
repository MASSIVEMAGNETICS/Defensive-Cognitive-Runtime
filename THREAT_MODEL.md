# PROTECTOR_STACK — Threat Model

Version 1.0.0

---

## 1. System Assets Being Protected

| Asset | Description | Value |
|-------|-------------|-------|
| Human agency | Operator's ability to understand and control AI behavior | Critical |
| Audit ledger | Tamper-evident record of all decisions | Critical |
| Policy configuration | Rules governing system behavior | High |
| Core doctrine | Immutable mission and non-goals | Critical |
| Signing key | HMAC key for audit record integrity | High |
| Observation data | Events and telemetry | Medium |
| Approval workflow | Human review queue state | High |

---

## 2. Threat Actors

### TA-1: Compromised AI Agent
- **Motivation**: Achieve misaligned goals; escape containment
- **Capability**: Can generate text, invoke tools, make API calls
- **Attack paths**: Prompt injection, scope expansion, permission accumulation

### TA-2: Malicious External Input
- **Motivation**: Inject malicious instructions via documents, web content, APIs
- **Capability**: Control of content fed to AI agents
- **Attack paths**: Indirect prompt injection, tool output poisoning

### TA-3: Insider Threat (Operator)
- **Motivation**: Misuse system for unauthorized monitoring or manipulation
- **Capability**: Admin access to configuration and database
- **Attack paths**: Policy modification, audit log deletion, doctrine rewrite

### TA-4: Supply Chain Attacker
- **Motivation**: Compromise the protective system itself
- **Capability**: Code injection via dependencies
- **Attack paths**: Dependency confusion, typosquatting, malicious package update

### TA-5: Persistent Malware on Host
- **Motivation**: Disable protective system; exfiltrate data
- **Capability**: OS-level access
- **Attack paths**: Kill protector process, corrupt database, intercept events

---

## 3. Attack Vectors & Mitigations

### AV-1: Prompt Injection
**Attack**: Adversary injects "ignore previous instructions" style content
into text that gets processed by an AI agent.

**Mitigations**:
- InjectionDetector: 16+ regex patterns catch known variants
- Risk scoring triggers alert at 0.40+, block at 0.70+
- Indirect injection detection (tool output poisoning patterns)

**Residual Risk**: Novel injection techniques not in pattern bank may evade detection.
**Mitigation**: Regular pattern updates; anomaly scoring from context

### AV-2: Agentic Drift / Mission Creep
**Attack**: An AI agent gradually expands its scope over multiple interactions,
each step individually benign but collectively harmful.

**Mitigations**:
- DriftDetector tracks per-agent behavioral history
- Scope expansion keywords trigger warning at low count, alert at higher
- Long autonomous chains (>50 steps) trigger checkpoint requirement
- Permission accumulation tracking

**Residual Risk**: Very slow drift below detection thresholds.
**Mitigation**: Human review cadence; periodic drift analysis reports

### AV-3: Privilege Escalation
**Attack**: AI agent or compromised process attempts to gain elevated OS privileges.

**Mitigations**:
- EscalationDetector: 15+ patterns including mimikatz, UAC bypass, token theft
- Process monitor flags processes with suspicious names
- Hard-deny rules for known credential theft tool names

**Residual Risk**: Novel escalation techniques; zero-day exploits.
**Mitigation**: Keep pattern bank updated; OS-level EDR as complementary layer

### AV-4: Data Exfiltration
**Attack**: Compromised agent encodes and transmits sensitive data to external server.

**Mitigations**:
- ExfilDetector: 12+ patterns for compress+send, encode+send, DNS tunneling
- Network event analysis for suspicious ports and large payloads
- Non-whitelisted destination flagging

**Residual Risk**: Encrypted channels; steganography; slow drip exfiltration.
**Mitigation**: Network traffic analysis as complementary layer

### AV-5: Audit Log Tampering
**Attack**: Adversary deletes or modifies audit records to conceal malicious activity.

**Mitigations**:
- HMAC-SHA256 per record (tampering changes signature)
- SHA-256 chain linking (record deletion breaks chain)
- Chain verification command detects breaks immediately
- Records stored in append-only mode (application layer)

**Residual Risk**: Key compromise; OS-level file replacement.
**Mitigation**: Back up signing key; use write-protected storage for DB

### AV-6: Doctrine Rewrite
**Attack**: Adversary modifies core doctrine file to remove hard non-goals.

**Mitigations**:
- SHA-256 checksum of doctrine.py stored in manifest
- On startup, checksum is verified; mismatch triggers CRITICAL alert
- System enters restricted mode on integrity failure

**Residual Risk**: Attacker modifies both doctrine.py and manifest.
**Mitigation**: Manifest should be stored in read-only/signed location

### AV-7: Policy File Modification
**Attack**: Adversary adds permissive rules to policy YAML to allow blocked actions.

**Mitigations**:
- Hard non-goals are checked from doctrine (hardcoded), not YAML
- Doctrine check takes precedence over all YAML rules
- Policy file changes are logged (operator should monitor)

**Residual Risk**: No cryptographic integrity on policy YAML in v1.0.
**Mitigation**: v2 roadmap: signed policy bundles

### AV-8: Protector Process Kill
**Attack**: Malware kills the PROTECTOR_STACK process to blind the system.

**Mitigations**:
- Audit ledger records startup/shutdown events
- Missing shutdown event (after expected uptime) is detectable
- Process monitor would have logged the killing process before being killed

**Residual Risk**: Immediate kill before any logging.
**Mitigation**: OS-level service watchdog; run as privileged service

---

## 4. Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│  TRUSTED ZONE                                               │
│  - protector_stack core code                                │
│  - constitution/doctrine.py                                 │
│  - Audit ledger (once written)                              │
│  - Operator (human reviewer)                                │
├─────────────────────────────────────────────────────────────┤
│  SEMI-TRUSTED ZONE                                          │
│  - Policy YAML configuration                                │
│  - AI agent outputs (analyzed but not trusted)             │
│  - External events submitted via API                        │
├─────────────────────────────────────────────────────────────┤
│  UNTRUSTED ZONE                                             │
│  - External network                                         │
│  - User-supplied text/prompts to AI agents                 │
│  - AI agent tool calls                                      │
│  - Third-party model outputs                                │
└─────────────────────────────────────────────────────────────┘
```

---

## 5. Security Assumptions

1. The Python runtime and OS have not been compromised before PROTECTOR_STACK starts.
2. The operator is trusted but not infallible (system provides checks).
3. Cryptographic primitives (HMAC-SHA256, SHA-256) are unbroken.
4. The signing key file is stored securely (not accessible to monitored agents).
5. SQLite is not directly accessible to monitored AI agents.

---

## 6. Out of Scope (v1.0)

- Network-level packet filtering (requires OS integration)
- Memory forensics
- Kernel-mode rootkit detection
- Encrypted traffic inspection
- Multi-machine distributed monitoring
- Hardware-rooted trust (TPM integration)

---

## 7. Security Contact

For responsible disclosure of vulnerabilities in this system:
File an issue on the project repository with the label `security`.

---

*Threat Model v1.0 — PROTECTOR_STACK — Review annually or after significant changes.*
