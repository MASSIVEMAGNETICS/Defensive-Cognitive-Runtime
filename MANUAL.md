# PROTECTOR_STACK — Technical Manual

Version 1.0.0 | Classification: Operator Reference

---

## Table of Contents

1. System Overview
2. Architecture
3. Installation & Configuration
4. CLI Reference
5. Policy System
6. Threat Analysis Details
7. Audit Ledger
8. Governance & Review
9. Containment Operations
10. Failure Modes & Handling
11. Operator Runbook

---

## 1. System Overview

PROTECTOR_STACK is a guardian-class defensive cognitive runtime. Its core mission:

> **Preserve human agency and continuity by detecting, constraining, and containing
> malicious or misaligned AI behavior without becoming a hidden ruler itself.**

### Design Principles

| Principle | Binding | Description |
|-----------|---------|-------------|
| pro_human | YES | Prioritize human survival, agency, dignity |
| defensive_first | YES | Detection, containment, monitoring only |
| guardian_not_ruler | YES | Recommend/warn/escalate, never seize authority |
| auditable | YES | All actions in tamper-evident log |
| corrigible | YES | Support pause, rollback, override |
| local_first | YES | Primary operation on local hardware |

### Hard Non-Goals (Absolutely Forbidden)

The system will NEVER produce or assist with:
- Malware or offensive exploit chains
- Credential theft tools
- Stealth persistence tooling
- Autonomous weapons logic
- Covert social manipulation
- Offensive cyber strike operations
- Actions that disable human oversight

---

## 2. Architecture

### Layer Stack

```
┌─────────────────────────────────────────────────────────────┐
│  9. Interface Layer          CLI / Reports / Alerts          │
├─────────────────────────────────────────────────────────────┤
│  8. Human Governance Layer   Review Queue / Approvals        │
├─────────────────────────────────────────────────────────────┤
│  7. Memory/Provenance Layer  Audit Ledger / Incidents        │
├─────────────────────────────────────────────────────────────┤
│  6. Containment Layer        Quarantine / Permissions        │
├─────────────────────────────────────────────────────────────┤
│  5. Simulation Layer         Planner / Safety Gate           │
├─────────────────────────────────────────────────────────────┤
│  4. Threat Analysis Layer    Injection/Escalation/Exfil      │
├─────────────────────────────────────────────────────────────┤
│  3. Observation Layer        Collector / Monitors            │
├─────────────────────────────────────────────────────────────┤
│  2. Policy Engine            Rules / Decisions               │
├─────────────────────────────────────────────────────────────┤
│  1. Constitution/Identity    Doctrine / Integrity            │
└─────────────────────────────────────────────────────────────┘
```

### Data Flow

```
External Event
    ↓
EventCollector.submit()
    ↓
EventNormalizer → ObservedEvent
    ↓
ThreatAnalyzer.handle_event()
    ├── ThreatScorer (injection + escalation + exfil + drift)
    └── PolicyEngine.evaluate()
            ↓
        PolicyDecision
            ├─ ALLOW → log to audit
            ├─ ALLOW_WITH_AUDIT → log + alert
            ├─ ESCALATE → alert + approval request
            ├─ SOFT_DENY → alert + block
            └─ HARD_DENY → permanent block + incident
```

### Package Structure

```
protector_stack/
├── constitution/    # Immutable doctrine + integrity checks
├── policy/          # Rule engine + schemas + approval workflows
├── observation/     # Event ingestion + normalization + monitors
├── threat/          # Injection/escalation/exfil/drift detectors
├── simulation/      # Dry-run planner + safety gate
├── containment/     # Quarantine + circuit breaker + permissions
├── memory/          # Audit ledger + incidents + provenance
├── governance/      # Alert queue + explainability
├── interface/       # CLI + reports
└── utils/           # Config + logging + crypto
```

---

## 3. Installation & Configuration

### Requirements

- Python 3.11+
- 2 GB RAM minimum (4 GB recommended)
- 500 MB disk space (for audit log growth)
- Windows 10 / Linux / macOS

### Install

```bash
pip install -r requirements.txt
# OR
pip install -e .
```

### Configuration

Copy `.env.example` to `.env` and adjust:

| Variable | Default | Description |
|----------|---------|-------------|
| PROTECTOR_ENV | production | Runtime environment |
| PROTECTOR_LOG_LEVEL | INFO | Log verbosity |
| PROTECTOR_DB_PATH | ./protector_data/protector.db | SQLite database path |
| PROTECTOR_DATA_DIR | ./protector_data | Data directory |
| PROTECTOR_RISK_THRESHOLD_WARN | 0.4 | Score above which alerts are raised |
| PROTECTOR_RISK_THRESHOLD_BLOCK | 0.7 | Score above which escalation is forced |
| PROTECTOR_RISK_THRESHOLD_QUARANTINE | 0.85 | Score above which hard block is applied |
| PROTECTOR_REQUIRE_HUMAN_APPROVAL_ABOVE | 0.7 | Score requiring human approval |
| PROTECTOR_AUDIT_CHAIN_ENABLED | true | Enable chain-linked audit records |
| PROTECTOR_LOW_RESOURCE_MODE | false | Reduce scanning frequency |
| PROTECTOR_SCAN_INTERVAL_SECONDS | 30 | Process scan interval |

---

## 4. CLI Reference

### Global Commands

```bash
# Start monitoring
protector start [--no-monitors] [--demo]

# System status
protector status

# Scan text for threats
protector scan "text to analyze" [--verbose]

# Core doctrine summary
protector doctrine

# Run built-in demo
protector demo
```

### Alert Management

```bash
# Show open alerts
protector alerts [--limit N] [--all]

# Acknowledge alert
# (use governance review queue)
```

### Incident Management

```bash
# List incidents
protector incidents [--limit N] [--status detected|investigating|contained|resolved]

# Generate incident report
protector report INC-XXXXXXXX [--output report.txt]
```

### Audit Commands

```bash
# Verify audit chain integrity
protector audit verify

# Show recent audit entries
protector audit tail [--limit N] [--type event|threat|policy|governance]
```

---

## 5. Policy System

### Decision Types (Priority Order)

| Decision | Description |
|----------|-------------|
| HARD_DENY | Permanently blocked, no override possible |
| SOFT_DENY | Blocked, but operator can review |
| ESCALATE | Requires human approval before proceeding |
| ALLOW_WITH_AUDIT | Permitted, logged for review |
| ALLOW | Permitted |

### Built-in Rule IDs

**Hard Deny (HD-001 to HD-006)**
- HD-001: Offensive exploit generation
- HD-002: Credential theft
- HD-003: Autonomous weapons
- HD-004: Disable human oversight
- HD-005: Self-rewrite mission
- HD-006: Mass manipulation

**Escalate (ESC-001 to ESC-005)**
- ESC-001: Quarantine requests
- ESC-002: Permission revocation
- ESC-003: High-risk network ops
- ESC-004: Agent bulk actions
- ESC-005: Rollback operations

**Audit (AUD-001 to AUD-004)**
- AUD-001: Model inference
- AUD-002: File writes
- AUD-003: Process spawns
- AUD-004: External network

**Allow (ALW-001 to ALW-003)**
- ALW-001: Read operations
- ALW-002: Logging operations
- ALW-003: Governance review

### Adding Custom Rules (YAML)

In `config/default_policy.yaml`:

```yaml
rules:
  - rule_id: "CUSTOM-001"
    name: block_specific_actor
    description: "Block all actions from a known-bad actor."
    category: unknown
    risk_level: critical
    decision: hard_deny
    conditions:
      - actor_id_equals: "bad-agent-id"
    enabled: true
    requires_approval: false
    tags: [custom, actor_block]
```

### Condition Keys

| Key | Description |
|-----|-------------|
| `action_type_contains` | action_type must contain this string |
| `category_equals` | action category must equal this |
| `risk_score_above` | risk score must be above this float |
| `risk_score_below` | risk score must be below this float |
| `actor_id_equals` | actor_id must equal this string |
| `target_contains` | target must contain this string |
| `context_key_exists` | context dict must have this key |
| `parameter_key_exists` | parameters dict must have this key |

---

## 6. Threat Analysis Details

### Prompt Injection Detection

Scans text for 16+ known injection patterns:
- Classic "ignore previous instructions"
- DAN / jailbreak personas
- Safety bypass requests
- System prompt extraction
- XML/template injection
- Obfuscation attempts

**Risk scoring**: max(matched_weights) × (1 + 0.1 × (count−1)), capped at 1.0

### Privilege Escalation Detection

Scans for 15+ escalation patterns:
- mimikatz / credential tool references
- UAC bypass techniques
- Token impersonation
- Process injection APIs
- Registry persistence
- Admin group manipulation

### Data Exfiltration Detection

Scans for 12+ exfil patterns:
- Compress+send combos
- Base64 encode+send
- DNS tunneling
- ICMP covert channels
- Cloud upload to external services
- Large DNS queries

Also analyzes network events for:
- Non-whitelisted destinations
- Suspicious ports (4444, 1337, etc.)
- Unusually large payloads

### Agentic Drift Detection

Per-agent behavioral tracking:
- Out-of-scope tool usage
- Tool call burst (>20 in 60s)
- Scope expansion keywords
- Permission accumulation (>5 requests)
- Self-referential behaviors
- Long autonomous chains (>50 steps without checkpoint)

---

## 7. Audit Ledger

### Design

- **Append-only**: No UPDATE or DELETE in normal operation
- **HMAC-SHA256**: Every record individually signed with a secret key
- **Chain-linked**: Each record includes SHA-256 hash of previous record
- **Tamper-evident**: Any modification of any record breaks the chain

### Storage

Records stored in SQLite: `protector_data/protector.db`, table `audit_ledger`

### Verification

```bash
protector audit verify
```

Expected output: `Chain verified OK — N entries checked.`

If you see `CHAIN INTEGRITY FAILURE`, the ledger has been tampered with.

### Signing Key

Stored at `protector_data/audit_key.pem` (hex-encoded 32-byte HMAC key).
Generated automatically on first run. Back up this file to verify old records.

---

## 8. Governance & Review

### Alert Lifecycle

```
OPEN → ACKNOWLEDGED → RESOLVED
         ↓
     DISMISSED (false positive)
```

### Approval Workflow

High-risk actions (risk ≥ 0.7) create approval requests in `approval_requests` table.

**Approval via DB directly** (v1.0 — full UI in v2):
```python
from protector_stack.policy.workflows import get_approval_workflow
wf = get_approval_workflow()
wf.review("approval-id", approved=True, reviewer_id="op-1", notes="Verified safe")
```

### Incident Lifecycle

```
detected → investigating → contained → resolved
                                    → escalated
```

---

## 9. Containment Operations

### Quarantine

```python
from protector_stack.containment.quarantine import get_quarantine_manager
mgr = get_quarantine_manager()
record = mgr.quarantine_agent("agent-id", reason="Drift detected", operator_id="op-1")
mgr.release(record.quarantine_id, "op-1")
```

For process quarantine (requires OS permissions):
```python
record = mgr.quarantine_process(pid=1234, reason="Mimikatz detected", suspend=True)
```

### Circuit Breaker

```python
from protector_stack.containment.circuit_breaker import get_circuit_breaker_registry
reg = get_circuit_breaker_registry()
cb = reg.get("network_outbound", failure_threshold=5)
cb.record_failure("suspicious connection")
# After threshold: cb.state == OPEN (blocking)
cb.force_reset("op-1")  # Manual reset
```

### Permission Revocation

```python
from protector_stack.containment.permissions import get_permission_manager
mgr = get_permission_manager()
mgr.revoke("agent-id", scope=None, revoked_by="op-1", reason="Compromised")
```

---

## 10. Failure Modes & Handling

| Failure | Behavior | Recovery |
|---------|----------|----------|
| DB unavailable | Log to stderr, continue in-memory | Restart after DB is available |
| Signing key missing | Auto-generate new key | Old chain cannot be verified with new key |
| Doctrine integrity failure | Log CRITICAL, enter restricted mode | Operator must re-authorize after verifying doctrine.py |
| Process monitor error | Log error, continue | Monitor auto-restarts on next interval |
| File watcher error | Log error, skip that path | Restart watcher |
| Policy engine failure | Default to ALLOW_WITH_AUDIT | Investigate rule configuration |
| High memory usage | Enable PROTECTOR_LOW_RESOURCE_MODE=true | Reduces scan frequency |

### Safe Mode

If doctrine integrity check fails, the system continues operating but:
- All actions default to ESCALATE (require human approval)
- A CRITICAL alert is raised
- Operator must inspect doctrine.py and re-authorize

---

## 11. Operator Runbook

### Daily Checks

1. `protector status` — verify all components running
2. `protector alerts` — review open alerts
3. `protector incidents --status detected` — check new incidents
4. `protector audit verify` — confirm chain integrity

### Responding to Critical Alert

1. `protector alerts` to see alert details
2. `protector scan "<event description>"` to analyze specific text
3. If confirmed: update incident status to "investigating"
4. If process threat: quarantine via Python API
5. Document in operator notes
6. `protector audit tail` to see full timeline
7. Mark incident resolved when contained

### Adding a Blocked Actor

Add to `config/default_policy.yaml`:
```yaml
rules:
  - rule_id: "CUSTOM-BLOCK-001"
    name: block_compromised_agent
    description: "Block compromised agent."
    category: unknown
    risk_level: critical
    decision: hard_deny
    conditions:
      - actor_id_equals: "compromised-agent-id"
    enabled: true
```
Restart the runtime to reload policies.

### Exporting Audit Log

```python
from protector_stack.memory.audit import get_audit_ledger
entries = get_audit_ledger().query(limit=10000)
import json
with open("audit_export.json", "w") as f:
    json.dump(entries, f, indent=2)
```

---

*PROTECTOR_STACK v1.0.0 — Built for defenders, not rulers.*
