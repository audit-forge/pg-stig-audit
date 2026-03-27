# Pilot Tester Handoff

Hey — I have a PostgreSQL security audit tool ready for pilot testing.

It is called `pg-stig-audit`.

This version should be described as a **validated v1.0 community-draft benchmark + runtime audit prototype** for PostgreSQL in containerized environments.

## What it does

It checks PostgreSQL security posture across:
- SSL/TLS posture
- authentication and access control
- logging and auditing
- privilege and configuration posture
- container runtime hardening

It supports:
- Docker
- Kubernetes
- direct TCP connections

It can produce:
- terminal output
- JSON
- CSV
- SARIF
- evidence bundle output

Optional integrations such as Wiz are supported separately and are not required to use the core audit workflow.

## Validation completed

- unit tests pass
- live Docker fixture validation completed via `make test-fixtures`
- validated fixture outcomes:
  - `pg-hardened` → `PASS 30 / FAIL 3 / WARN 2`
  - `pg-baseline` → `PASS 19 / FAIL 12 / WARN 4`
  - `pg-vulnerable` → `PASS 17 / FAIL 14 / WARN 4`
- v1.0 boundary is frozen in `docs/V1_RELEASE_BOUNDARY.md`

## Important positioning note

This is **not** an officially certified CIS, DISA, or NIST product.
It should be treated as a practical pilot tool for testing, feedback, and early operational use.

## What feedback is most helpful

Please focus feedback on:
- setup clarity
- ease of running the commands
- whether the output is useful
- confusing findings or false positives
- what would make it easier to use in real environments

## Useful docs for testers

- `docs/QUICKSTART.md`
- `docs/BEGINNER_GUIDE.md`
- `docs/RUN_BENCHMARK.md`
- `docs/V1_RELEASE_BOUNDARY.md`
