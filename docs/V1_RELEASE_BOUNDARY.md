# PostgreSQL v1.0 Release Boundary

Status: baseline-frozen
Last updated: 2026-03-26

## Purpose

This document freezes what counts as **done for v1.0** versus what is intentionally deferred to later versions.

## Evidence confirmed for v1.0 baseline

### Validation completed
- Unit test suite passes via `make test`
- Live Docker fixture validation completed via `make test-fixtures`
- Validated fixture outcomes:
  - `pg-hardened` → `PASS 30 / FAIL 3 / WARN 2`
  - `pg-baseline` → `PASS 19 / FAIL 12 / WARN 4`
  - `pg-vulnerable` → `PASS 17 / FAIL 14 / WARN 4`

### Confirmed v1.0 characteristics
- Runtime audit CLI exists and executes successfully
- Docker fixture set demonstrates materially different security postures
- Core outputs exist for terminal, JSON, CSV, SARIF, and evidence-oriented artifacts
- Wiz support exists as an optional integration path, not a required core workflow

## v1.0 Done Boundary

For v1.0, the project is considered complete when all of the following are true:
1. Validation results are recorded in repo docs
2. README/test docs match actual supported workflow and outputs
3. v1.0 scope is explicitly frozen in writing
4. Non-blocking expansion items are moved to a v1.1+ backlog
5. Release/pilot handoff path is written down

## In scope for v1.0
- PostgreSQL audit workflow for Docker, Kubernetes, and direct connection modes already supported by the tool
- Core checks already implemented across auth, SSL/TLS, logging, privileges, configuration posture, and container hardening
- Output artifacts already implemented: terminal, JSON, CSV, SARIF, evidence-bundle style outputs
- Repeatable Docker fixture validation workflow
- Optional Wiz integration documented separately from the core run path

## Explicitly out of scope for v1.0
- Broad managed-service-specific feature parity beyond the currently documented direct-mode behavior
- Deep topology-aware coverage for replication edge cases and advanced deployment nuance
- Broader packaging/distribution polish beyond current documented usage
- Any claim of official CIS endorsement or certification
- Making Wiz a required dependency or core positioning element

## Known non-blocking warnings in validated v1.0 baseline
- The hardened fixture still shows a small number of findings/warnings because the lightweight test environment does not model a fully production-hardened PostgreSQL deployment
- Fixture validation demonstrates repeatable posture differences across hardened, baseline, and vulnerable targets; it does not claim exhaustive production-environment coverage

## Candidate v1.1+ backlog
- Packaging/install polish
- Additional topology-aware checks for replication and more managed-service nuance
- Additional downstream platform integrations and workflow polish
- Broader fixture coverage and environment matrix expansion
- Deeper release engineering / packaging improvements not required for v1.0

## Release / pilot path
- Present v1.0 as a validated community-draft benchmark + runtime audit prototype for pilot users
- Keep positioning conservative: useful, tested, evidence-oriented, but not marketed as formally certified guidance
- Keep Wiz framed as optional for teams that already have it, not a prerequisite for using the tool
- Use pilot feedback to prioritize v1.1 backlog instead of reopening v1.0 scope
