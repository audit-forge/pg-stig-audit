# pg-stig-audit fixture workflow

This directory provides a reproducible local validation path for `pg-stig-audit`.

Included fixture targets:
- `pg-hardened` — stronger configuration meant to pass most checks
- `pg-baseline` — near-default PostgreSQL posture for comparison
- `pg-vulnerable` — intentionally weak posture for negative testing

## Quick start

```bash
# Start fixtures
bash test/run_tests.sh
```

The main fixture workflow now uses plain `docker run`, so it does not depend on Docker Compose.

If you still want the Compose file directly, `test/docker-compose.test.yml` remains available as a reference for the same fixture intent.

Then audit a fixture manually:

```bash
python3 audit.py --mode docker --container pg-hardened --json output/hardened.json --csv output/hardened.csv
python3 audit.py --mode docker --container pg-baseline --json output/baseline.json --csv output/baseline.csv
python3 audit.py --mode docker --container pg-vulnerable --json output/vulnerable.json --csv output/vulnerable.csv
```

Bring the fixtures down when finished:

```bash
docker rm -f pg-hardened pg-baseline pg-vulnerable
docker volume rm pg_hardened_data pg_baseline_data pg_vulnerable_data
```

## What to expect

- `pg-hardened` should pass substantially more checks than the other fixtures
- `pg-vulnerable` should fail loudly and demonstrate that the tool is detecting real weaknesses
- `pg-baseline` shows what a more ordinary/default PostgreSQL container looks like

## Exit code behavior

The audit tool can exit non-zero even when it is functioning correctly.
That usually means the target produced findings at or above the selected `--fail-on` threshold.

Examples:
- `--fail-on high` → exits non-zero if HIGH or CRITICAL findings exist
- `--fail-on none` → never fails the process based on findings

This matters for CI: a non-zero exit may mean "the scanner worked and found problems," not "the scanner crashed."
