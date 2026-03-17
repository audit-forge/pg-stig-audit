# Security Hardening Report

## Summary
Final targeted hardening pass completed.

## Changes applied
- Added input validation and safer query construction guards in settings lookups.
- Added URL scheme validation for external API calls.
- Added explicit subprocess safety annotations where list-based args are required.
- Replaced bare `except/pass` in SCC token fallback with debug-aware handling.

## Residual findings rationale
Remaining Bandit findings are low-severity and mostly static-analysis false positives:
- Enum/status literals like `PASS` / `RESOLVED` / `INACTIVE` / `dry-run-token` flagged as hardcoded passwords (not secrets).
- Required subprocess usage for `docker`, `kubectl`, `psql`, and `gcloud` in list-arg mode (no shell invocation).

## Operational recommendation
Treat current residuals as accepted low risk and keep periodic scans in CI.
