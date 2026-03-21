# CVE/KEV Vulnerability Scanning

`pg-stig-audit` integrates live CVE and CISA KEV data alongside its
compliance checks. This document explains how version detection, NVD queries,
KEV lookups, caching, and output work.

---

## Overview

When you run `audit.py` without `--skip-cve`, the tool:

1. Detects the PostgreSQL version running in the target container/pod/host.
2. Queries the NIST NVD API v2 for CVEs matching that version.
3. Downloads the CISA Known Exploited Vulnerabilities (KEV) catalog.
4. Cross-references CVE IDs against KEV.
5. Produces a `CheckResult` (check ID `PG-VER-001`) that appears in all
   output formats (terminal report, JSON, SARIF, CSV, evidence bundle).

---

## How Version Detection Works

The scanner calls `runner.query_with_cols("SELECT version();", ["version"])`.
It parses the major.minor version from the PostgreSQL version string using a
regex match against `PostgreSQL {major}.{minor}`.

Example version string: `PostgreSQL 16.2 on x86_64-pc-linux-gnu, compiled by gcc ...`
Parsed version: `16.2`

This works identically across all three runner modes:

| Mode | Mechanism |
|---|---|
| `docker` | `docker exec <container> psql -U postgres -c 'SELECT version();'` |
| `kubectl` | `kubectl exec <pod> -- psql -U postgres -c 'SELECT version();'` |
| `direct` | TCP connection to host:port via psql |

If version detection fails (e.g. connection refused, psql not found),
the CVE check is skipped with a console warning.

---

## NVD API Usage and Rate Limits

**Endpoint:** `https://services.nvd.nist.gov/rest/json/cves/2.0`

**Query parameter:** `keywordSearch=postgresql+{version}` with `resultsPerPage=100`.

**Filter:** Only CVEs whose English description contains the word "postgresql"
are kept, reducing false positives from unrelated packages.

**Extracted fields per CVE:**
- CVE ID (e.g. `CVE-2024-0985`)
- English description
- CVSS base score (v3.1 preferred, fallback to v3.0, then v2)
- Published date

**Rate limits:**

| API Key | Rate |
|---|---|
| No key | 5 requests per 30 seconds (~6 s sleep enforced) |
| With `NVD_API_KEY` | 50 requests per 30 seconds (no sleep inserted) |

Set the environment variable before running:

```bash
export NVD_API_KEY=your-key-here
python3 audit.py --mode docker --container my-postgres
```

Register for a free NVD API key at:
https://nvd.nist.gov/developers/request-an-api-key

---

## CISA KEV Catalog

**Source:** `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`

The KEV catalog is a CISA-maintained list of vulnerabilities that are
actively exploited in the wild. Federal agencies under BOD 22-01 are required
to remediate KEV entries on a fixed timeline. The catalog is useful for any
organization to prioritize patching.

**KEV matching:** After fetching CVEs from NVD, the tool checks whether each
CVE ID appears in the KEV catalog. If so:

- `kev_score` is set to `"HIGH_PRIORITY (CISA KEV - Added: {dateAdded})"`.
- The KEV `requiredAction` field is appended to the remediation text.
- Severity is escalated to `CRITICAL` regardless of CVSS score.

---

## Severity Determination

| Condition | Severity |
|---|---|
| Any CVE in KEV, or any CVSS score >= 9.0 | CRITICAL |
| Any CVSS score >= 7.0 (no KEV) | HIGH |
| CVEs found but all CVSS < 7.0 | MEDIUM |
| No CVEs found | INFO (PASS) |

---

## Cache Management

Cache files live in `data/` inside the project directory.

| File | Contents | Refresh |
|---|---|---|
| `data/cve_cache.json` | NVD results keyed by `product:version` | 24 hours |
| `data/kev_cache.json` | Full CISA KEV catalog | 24 hours |

Cache format:

```json
{
  "cached_at": "2026-03-19T12:00:00+00:00",
  "data": [...]
}
```

For `cve_cache.json`, the top-level structure is a dict of cache keys:

```json
{
  "postgresql:16.2": {
    "cached_at": "2026-03-19T12:00:00+00:00",
    "data": [{"cve_id": "CVE-2024-0985", ...}]
  }
}
```

To force a refresh, delete the cache files:

```bash
rm data/cve_cache.json data/kev_cache.json
```

---

## `--skip-cve` Flag

Pass `--skip-cve` to skip the entire CVE/KEV scan. This is faster and avoids
making network requests, which is useful in air-gapped environments or when
you only need compliance check results.

```bash
python3 audit.py --mode docker --container my-postgres --skip-cve --csv results.csv
```

---

## `NVD_API_KEY` Environment Variable

```bash
export NVD_API_KEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
python3 audit.py --mode docker --container my-postgres
```

With an API key, the tool does not insert a 6-second sleep between NVD
requests, which speeds up scans when checking multiple versions.

---

## Local Path

The `Local_Path` column in CSV output indicates the binary path of the
vulnerable component. For PostgreSQL, this is derived from the major version:

```
/usr/lib/postgresql/{major}/bin/postgres
```

For example, PostgreSQL 16.2 yields `/usr/lib/postgresql/16/bin/postgres`.

---

## Example CSV Output with CVE Columns

The `--csv` output includes four CVE-specific columns appended after the
standard compliance columns:

| Column | Example Value |
|---|---|
| `CVE_ID` | `CVE-2024-0985; CVE-2023-5868` |
| `KEV_Score` | `HIGH_PRIORITY (CISA KEV - Added: 2024-02-15)` |
| `CVE_Remediation` | `Upgrade PostgreSQL to a patched version. Currently running: 16.1. See NVD for affected version ranges. \| CISA KEV required action for CVE-2024-0985: Apply updates per vendor instructions.` |
| `Local_Path` | `/usr/lib/postgresql/16/bin/postgres` |

For standard compliance checks (non-CVE rows), these columns now use explicit semantics instead of empty strings:
- `CVE_ID` → `not_applicable`
- `KEV_Score` → `not_applicable`
- `CVE_Remediation` → `not_applicable`
- `Local_Path` → a scope hint such as `runtime-config`, `runtime-network-config`, `filesystem`, or `container-inspect`

If `--skip-cve` is used, the vulnerability/version row emits `not_scanned` for the CVE-specific columns.

---

## References

- NVD API v2 documentation: https://nvd.nist.gov/developers/vulnerabilities
- CISA KEV catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- BOD 22-01: https://www.cisa.gov/binding-operational-directive-22-01
- NVD API key registration: https://nvd.nist.gov/developers/request-an-api-key
- PostgreSQL security announcements: https://www.postgresql.org/support/security/
