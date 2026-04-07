# PROTECTOR_STACK — System Architecture

Version 1.0.0

---

## Overview

PROTECTOR_STACK is a layered, modular defensive cognitive runtime. Each layer has a
single responsibility and communicates only with adjacent layers via well-defined
interfaces. The system is designed so that any single layer can fail without
compromising the integrity of the others.

---

## Layer Architecture

### Layer 1: Constitution / Identity

**Package**: `protector_stack/constitution/`

**Purpose**: Encodes the immutable core doctrine. This is the moral and operational
bedrock of the system. Nothing can override it.

**Components**:
- `doctrine.py`: Hardcoded PRINCIPLES, HARD_NON_GOALS, AUTHORITY_BOUNDARY
- `integrity.py`: SHA-256 checksum of doctrine.py; tamper detection on startup

**Key invariant**: HARD_NON_GOALS are a Python `frozenset` — immutable at runtime.
The only way to change them is to modify the source code, which is detected by
the integrity checker.

---

### Layer 2: Policy Engine

**Package**: `protector_stack/policy/`

**Purpose**: Evaluates proposed actions against a structured ruleset and produces
a policy decision.

**Components**:
- `schemas.py`: Pydantic models (ActionDescriptor, PolicyEvaluationResult, etc.)
- `rules.py`: Default ruleset (HD, ESC, AUD, ALW rule families)
- `engine.py`: PolicyEngine — doctrine check → risk override → rule evaluation
- `workflows.py`: ApprovalWorkflow — human approval request lifecycle

**Decision precedence**: HARD_DENY > SOFT_DENY > ESCALATE > ALLOW_WITH_AUDIT > ALLOW

**Rule matching**: AND logic within a rule (all conditions must match).
Multiple rules: highest-precedence decision wins.

---

### Layer 3: Observation Layer

**Package**: `protector_stack/observation/`

**Purpose**: Ingests events from all sensors, normalizes them into typed
ObservedEvent objects, and dispatches them to registered handlers.

**Components**:
- `schemas.py`: Event type models (ObservedEvent, ProcessEvent, etc.)
- `normalizer.py`: Raw dict → ObservedEvent conversion + sanitization
- `collector.py`: Thread-safe event bus; registers and calls handlers
- `process_monitor.py`: Background psutil-based process scanner
- `file_watcher.py`: watchdog-based file system monitor

**Privacy note**: Prompts are truncated to 200 chars before storage. Full content
is never persisted.

---

### Layer 4: Threat Analysis Layer

**Package**: `protector_stack/threat/`

**Purpose**: Runs all detector modules over each event and produces a unified
ThreatAssessment with a 0.0–1.0 risk score.

**Components**:
- `injection_detector.py`: 16+ regex patterns for prompt injection
- `escalation_detector.py`: 15+ patterns for privilege escalation
- `exfil_detector.py`: 12+ patterns for data exfiltration
- `drift_detector.py`: Per-agent behavioral drift tracking
- `scorer.py`: ThreatScorer — aggregates sub-scores into final assessment
- `analyzer.py`: ThreatAnalyzer — orchestrates pipeline + callbacks

**Scoring formula**: `min(1.0, max_sub_score × (1 + 0.05 × (nonzero_count − 1)))`
One strong hit gives a high score; multiple signals push it toward 1.0.

---

### Layer 5: Simulation / Pre-Action Forecast

**Package**: `protector_stack/simulation/`

**Purpose**: Before high-risk actions execute, simulates consequences and runs
a safety checklist. This layer provides the "think before act" gate.

**Components**:
- `planner.py`: ActionPlanner — dry-run consequence estimation (3 branches)
- `safety_gate.py`: SafetyGate — 5-check safety checklist

**SafetyGate checks** (all must PASS to clear):
1. Doctrine compliance (no hard non-goals)
2. Policy decision (not HARD_DENY or SOFT_DENY)
3. Human approval obtained (if required)
4. Risk score below quarantine threshold
5. Simulation outcome safe (if simulation was run)

---

### Layer 6: Containment Layer

**Package**: `protector_stack/containment/`

**Purpose**: Executes containment actions — quarantine, permission revocation,
circuit breaking, rollback.

**Components**:
- `quarantine.py`: Process suspension/termination; agent soft quarantine
- `permissions.py`: Grant/revoke permission scopes per actor
- `circuit_breaker.py`: CLOSED/OPEN/HALF-OPEN state machine per scope
- `rollback.py`: Snapshot state; execute registered rollback hooks

**Design note**: All containment actions are logged. Process suspension requires
OS permissions and may fail gracefully with a logged warning.

---

### Layer 7: Memory / Provenance Layer

**Package**: `protector_stack/memory/`

**Purpose**: Persists all system state in tamper-evident form. Provides the
"explainability backbone" via provenance chains.

**Components**:
- `audit.py`: AuditLedger — HMAC-signed, SHA-256 chain-linked SQLite records
- `incidents.py`: IncidentManager — security incident lifecycle
- `provenance.py`: ProvenanceTracker — full decision provenance per action

**Audit chain integrity**: Each record contains `previous_hash` (chain link) and
`signature` (HMAC-SHA256). Chain verification walks all records in order.

---

### Layer 8: Human Governance Layer

**Package**: `protector_stack/governance/`

**Purpose**: Provides human-facing review, explainability, and approval interfaces.

**Components**:
- `review.py`: AlertReviewQueue — raise/acknowledge/resolve/dismiss alerts
- `explainer.py`: Plain-English explanations for threats, policy decisions, incidents

---

### Layer 9: Interface Layer

**Package**: `protector_stack/interface/`

**Purpose**: Human-facing CLI and report generation.

**Components**:
- `cli.py`: Typer + Rich CLI with all operator commands
- `reports.py`: Incident and summary report generation

---

## Database Schema

All persistent state in SQLite (`protector_data/protector.db`):

| Table | Purpose |
|-------|---------|
| `audit_ledger` | Tamper-evident event log |
| `approval_requests` | Human approval workflow state |
| `alerts` | Alert review queue |
| `incidents` | Security incident records |

---

## Threading Model

| Thread | Component | Description |
|--------|-----------|-------------|
| Main | CLI / Runtime | Event loop, command processing |
| ProcessMonitor | Background | Scans processes every N seconds |
| FileWatcher | Background | Watchdog observer thread |
| EventCollector | Caller's thread | Synchronous dispatch to handlers |

All handlers are called synchronously in the submitting thread. Long-running
handlers should be wrapped in a thread pool (future enhancement).

---

## Dependency Graph (simplified)

```
interface → governance → memory → utils
interface → containment
interface → policy
interface → threat
governance → memory
threat → policy
threat → observation
policy → constitution
observation → utils
containment → utils
memory → utils
```

No circular imports. Constitution layer has no internal dependencies.

---

## Resource Profile

**Target machine**: Intel Core i5-7200U, 16 GB RAM, Windows 10 Home

| Mode | CPU | RAM | Disk/day |
|------|-----|-----|----------|
| Normal | <2% avg | ~80 MB | ~10 MB |
| High-event | <10% | ~150 MB | ~50 MB |
| Low-resource | <1% | ~50 MB | ~5 MB |

Low-resource mode doubles scan intervals and reduces in-memory retention.

---

## Future Architecture (v2/v3)

See `ROADMAP.md` for planned enhancements including:
- Plugin adapter system for external model hooks
- Signed policy bundles
- Web dashboard (FastAPI + React)
- Multi-agent coordination bus
- Offline-capable model adapter interface
