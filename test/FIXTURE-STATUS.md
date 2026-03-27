# PostgreSQL Live Fixture Status

Added fixture set for repeatable manual validation:

- `pg-hardened` — stronger PostgreSQL posture intended to pass most checks
- `pg-baseline` — near-default PostgreSQL posture for comparison
- `pg-vulnerable` — intentionally weak posture for negative testing

Primary entrypoints:

- `test/run_tests.sh`
- `test/README.md`
- `docs/RUN_BENCHMARK.md`

Expected use:

1. Run `make test-fixtures`
2. Review outputs under `test/output/`
3. Compare posture differences across hardened, baseline, and vulnerable targets
4. Tear fixtures down automatically at the end of the run

Current observed outcomes from live validation on 2026-03-26:
- `pg-hardened` → `PASS 30 / FAIL 3 / WARN 2`
- `pg-baseline` → `PASS 19 / FAIL 12 / WARN 4`
- `pg-vulnerable` → `PASS 17 / FAIL 14 / WARN 4`

Notes:
- The hardened fixture is intentionally stronger than the others, but it is still a lightweight validation target rather than a claim of perfect production hardening.
- The fixture set is designed to prove repeatability and visible posture differences, not to claim exhaustive production-environment coverage.
- These outcomes were used to freeze the documented v1.0 release boundary in `docs/V1_RELEASE_BOUNDARY.md`.
