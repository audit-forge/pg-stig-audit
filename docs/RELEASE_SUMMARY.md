# Release Summary

## pg-stig-audit v1.0 baseline frozen

This release freezes the initial v1.0 boundary for `pg-stig-audit`, a community-built PostgreSQL container security benchmark and runtime audit tool.

## What is included

- PostgreSQL audit CLI for:
  - Docker
  - Kubernetes
  - direct TCP connections
- security checks across:
  - SSL/TLS posture
  - authentication and access control
  - logging and auditing
  - privilege and configuration posture
  - container hardening
- output formats:
  - terminal
  - JSON
  - CSV
  - SARIF
  - evidence bundle output
- optional Wiz support documented separately

## Validation

- unit test suite passed
- live Docker fixture validation completed via `make test-fixtures`
- validated fixture outcomes:
  - `pg-hardened` → `PASS 30 / FAIL 3 / WARN 2`
  - `pg-baseline` → `PASS 19 / FAIL 12 / WARN 4`
  - `pg-vulnerable` → `PASS 17 / FAIL 14 / WARN 4`
- v1.0 scope is frozen in `docs/V1_RELEASE_BOUNDARY.md`

## Positioning

This release should be treated as a **validated community-draft benchmark + runtime audit prototype** suitable for pilot use and early feedback.

It is **not** an official CIS, DISA, or NIST benchmark.

## Recommended docs

- `README.md`
- `docs/QUICKSTART.md`
- `docs/BEGINNER_GUIDE.md`
- `docs/RUN_BENCHMARK.md`
- `docs/V1_RELEASE_BOUNDARY.md`
- `test/README.md`

## Next step

Pilot feedback should drive v1.1 improvements, especially around broader topology coverage, packaging polish, and additional usability refinement.
