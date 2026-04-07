# CHANGELOG

All notable changes to PROTECTOR_STACK will be documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.0.0] — 2026-04-07

### Added

- Constitution/Identity layer with immutable doctrine, hard non-goals, and
  SHA-256 checksum integrity verification of doctrine.py
- Policy Engine with 18 built-in rules (HD, ESC, AUD, ALW families)
  and YAML-loadable custom rule support
- Observation layer: EventCollector, EventNormalizer, ProcessMonitor, FileWatcher
- Threat Analysis layer: InjectionDetector (16+ patterns), EscalationDetector
  (15+ patterns), ExfilDetector (12+ patterns), DriftDetector (6 signals),
  ThreatScorer (multi-signal aggregation)
- Simulation layer: ActionPlanner (3-branch dry-run), SafetyGate (5-check checklist)
- Containment layer: QuarantineManager, PermissionManager, CircuitBreakerRegistry,
  RollbackManager
- Memory/Provenance layer: AuditLedger (HMAC-signed, SHA-256 chain-linked),
  IncidentManager, ProvenanceTracker
- Governance layer: AlertReviewQueue, Explainability engine
- Interface layer: Typer+Rich CLI with 12 commands + audit subcommands
- Three-tier demo scenario (benign / suspicious / dangerous)
- Full test suite: 90 tests across 7 test files
- Documentation: README, MANUAL.md, HUMAN_EXPLANATION.txt, ARCHITECTURE.md,
  THREAT_MODEL.md, OPERATOR_MANUAL.md
- Sample config files and incident scenario fixtures

---

## [Upcoming] — v2.0.0

### Planned
- Web dashboard (FastAPI + Jinja2/React)
- Signed policy bundles (Ed25519)
- Plugin adapter system for external model hooks
- Multi-agent coordination bus
- Offline-capable model adapter interface
- Role-based access control for governance layer
- Windows service / systemd unit integration
- Automated drift report scheduler

## [Upcoming] — v3.0.0

### Planned
- Federated multi-instance coordination
- Hardware-rooted trust (TPM integration)
- Behavioral ML model for anomaly detection
- Network traffic analysis integration
- Cross-system threat intelligence sharing (air-gapped mode)
