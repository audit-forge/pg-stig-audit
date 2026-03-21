# pg-stig-audit

**PostgreSQL Security Audit Tool for Containerized Databases**

[![CI](https://github.com/audit-forge/pg-stig-audit/actions/workflows/test.yml/badge.svg)](https://github.com/audit-forge/pg-stig-audit/actions/workflows/test.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)

Open-source implementation of security controls from:
- **CIS PostgreSQL 16 Benchmark v1.1.0** (69 controls)
- **DISA STIG PostgreSQL 12 V1R1**
- **NIST SP 800-53 Revision 5** (FedRAMP High)

> **Disclaimer:** This is an independent tool. Not officially certified or endorsed by CIS, DISA, or NIST. See [DISCLAIMER.md](DISCLAIMER.md) for full legal attribution.

---

## What It Does

**Audits PostgreSQL security configuration** in Docker containers, Kubernetes pods, and cloud database instances (Cloud SQL, RDS, Azure Database).

**Why this tool exists:** No official CIS benchmark covers PostgreSQL running inside containers. CIS PostgreSQL covers bare-metal/VM deployments. CIS Docker covers container runtime. Neither covers both. This tool bridges that gap.

---

## Installation

### Prerequisites

- Python 3.9+
- Docker (for Docker mode)
- kubectl (for Kubernetes mode)
- PostgreSQL client tools (`psql`)

### Install

```bash
git clone https://github.com/audit-forge/pg-stig-audit.git
cd pg-stig-audit
python audit.py --version
```

No third-party dependencies — uses Python standard library only.

---

## Quick Start

```bash
# Audit a Docker container
python audit.py --mode docker --container my-postgres

# Audit a Kubernetes pod
python audit.py --mode kubectl --pod postgres-0 --namespace production

# Audit via direct TCP (Cloud SQL proxy, RDS, etc.)
python audit.py --mode direct --host 127.0.0.1 --port 5432 --user postgres

# Full output: SARIF + JSON + evidence bundle
python audit.py --mode docker --container my-postgres \
  --sarif results.sarif.json \
  --json results.json \
  --bundle evidence.zip
```

## Reproducible Local Validation

The repo includes a fixture workflow for repeatable external testing and local validation:
- `pg-hardened`
- `pg-baseline`
- `pg-vulnerable`

Quick start:

```bash
make test-fixtures
```

The primary fixture workflow uses plain `docker run`, so it does not depend on Docker Compose support.
See [test/README.md](test/README.md) for fixture details and [docs/RUN_BENCHMARK.md](docs/RUN_BENCHMARK.md) for the operator runbook.

---

## Usage

### Connection Modes

| Flag | Description |
|---|---|
| `--mode docker` | Run checks via `docker exec` |
| `--mode kubectl` | Run checks via `kubectl exec` |
| `--mode direct` | Connect directly over TCP |
| `--container NAME` | Docker container name |
| `--pod NAME` | Kubernetes pod name |
| `--namespace NS` | Kubernetes namespace (default: `default`) |
| `--host HOST` | Host for direct mode (default: `127.0.0.1`) |
| `--port PORT` | Port for direct mode (default: `5432`) |
| `--user USER` | PostgreSQL user (default: `postgres`) |
| `--database DB` | PostgreSQL database (default: `postgres`) |

Use `PGPASSWORD` environment variable for authentication — never pass passwords as CLI flags.

### Output Flags

| Flag | Description |
|---|---|
| `--sarif FILE` | Write SARIF 2.1.0 output |
| `--json FILE` | Write full JSON results |
| `--csv FILE` | Write CSV with all framework columns |
| `--bundle FILE` | Write ZIP evidence bundle |
| `--wiz FILE` | Write optional Wiz Issues API findings JSON |
| `--scc FILE` | Write optional GCP Security Command Center findings |

### Control Flags

| Flag | Description |
|---|---|
| `--skip-cve` | Skip CVE/KEV scanning (faster, air-gapped) |
| `--fail-on SEVERITY` | Exit non-zero if any finding at or above severity |
| `--verbose` | Show extra detail |
| `--quiet` | Suppress terminal report |

---

## CVE/KEV Scanning

The audit tool queries the NIST National Vulnerability Database (NVD) for CVEs affecting the detected PostgreSQL version and cross-references the CISA Known Exploited Vulnerabilities (KEV) catalog.

**Features:**
- Automatic PostgreSQL version detection via `SELECT version();`
- NVD API v2 query for CVEs matching the running version
- CISA KEV catalog lookup — flags CVEs with active exploitation
- Severity escalation: CRITICAL if KEV hit or CVSS >= 9.0; HIGH if CVSS >= 7.0
- Results cached locally in `data/` for 24 hours (no repeated network calls)
- `--skip-cve` flag to bypass in air-gapped or compliance-only runs
- Optional `NVD_API_KEY` env var for higher rate limits

```bash
# Standard run (includes CVE scan)
python audit.py --mode docker --container my-postgres --csv results.csv

# Skip CVE scan
python audit.py --mode docker --container my-postgres --skip-cve

# With NVD API key
NVD_API_KEY=your-key python audit.py --mode docker --container my-postgres
```

See [docs/CVE_SCANNING.md](docs/CVE_SCANNING.md) for full details.

---

## Coverage

### CIS PostgreSQL 16 Benchmark v1.1.0 (69 controls)

| Section | Controls | Description |
|---|---|---|
| Section 1 | 6 | Installation and Patches |
| Section 2 | 4 | Directory and File Permissions |
| Section 3 | 26 | Logging and Auditing |
| Section 4 | 9 | User Access and Authorization |
| Section 5 | 5 | Connection and Login |
| Section 6 | 11 | PostgreSQL Settings |
| Section 7 | 5 | Replication |
| Section 8 | 3 | Special Configuration Considerations |

### Container Security Addendum (8 controls)

Additional controls for containerized PostgreSQL not covered by the official CIS benchmark:
- Non-root user enforcement
- Privileged container checks
- Linux capability restrictions
- Resource limits (CPU/memory)
- Host namespace isolation
- Read-only root filesystem
- Data volume permissions
- Image provenance

Based on CIS Docker Benchmark and CIS Kubernetes Benchmark.

### Framework Mappings

Every control maps to:
- **CIS PostgreSQL 16 v1.1.0** section/control
- **DISA STIG PostgreSQL 12 V1R1** finding IDs (where applicable)
- **NIST SP 800-53 Rev 5** (AC-3, IA-5, SC-8, AU-2, etc.)
- **NIST SP 800-171 Rev 2** — all 37 automated checks mapped
- **CMMC 2.0** — Level 1 or Level 2 indicator for each control
- **MITRE ATT&CK** — Enterprise techniques each control defends against
- **MITRE D3FEND** — Defensive countermeasures each control implements
- **FedRAMP High** baseline

| CMMC Level | Control Count |
|---|---|
| Level 1 | 10 |
| Level 2 | 27 |

The complete matrices are in `mappings/CMMC-compliance-matrix.csv` and `mappings/MITRE-mappings.csv`.

---

## Output Formats

### Terminal Report (default)

```
════════════════════════════════════════════════════════════════════════════════
  PostgreSQL CIS/STIG Audit Report
════════════════════════════════════════════════════════════════════════════════

Target:   docker → my-postgres
Version:  PostgreSQL 16.3 on x86_64-pc-linux-gnu

Total Controls:     69
✅ Passed:          54
❌ Failed:          10
⚠️  Warnings:        5

Failed by Severity:
  🔴 CRITICAL: 3
  🟠 HIGH:     5
  🟡 MEDIUM:   2
  🟢 LOW:      0

────────────────────────────────────────────────────────────────────────────────
  Control Results
────────────────────────────────────────────────────────────────────────────────

❌ PG-CFG-006 — SSL must be enabled
   Severity: CRITICAL
   Frameworks: CIS:6.7, STIG:V-214070, NIST:SC-8
   ❌ Actual: off
   ✓  Expected: on
   💡 Remediation: Set ssl = on in postgresql.conf. Mount SSL certs via volume.
```

### CSV (framework compliance export)

Spreadsheet-compatible output with NIST 800-171, CMMC, ATT&CK, and D3FEND columns:

```bash
python audit.py --mode docker --container my-postgres --csv results.csv
```

Columns: `Control_ID`, `Title`, `Severity`, `Result`, `Category`, `Actual`, `Expected`, `Description`, `CIS_Control`, `DISA_STIG_ID`, `NIST_800_53`, `NIST_800_171`, `CMMC_Level`, `MITRE_ATTACK`, `MITRE_D3FEND`, `Remediation`, `References`, `CVE_ID`, `KEV_Score`, `CVE_Remediation`, `Local_Path`

Conditional CSV field behavior:
- `CVE_ID`, `KEV_Score`, `CVE_Remediation`
  - `not_scanned` when `--skip-cve` is used
  - `not_applicable` for non-vulnerability findings
  - populated values on the version/CVE finding when CVE scanning runs
- `Local_Path`
  - real binary/path when available
  - otherwise a scope hint such as `runtime-config`, `runtime-network-config`, `filesystem`, or `container-inspect`

### SARIF 2.1.0 (GitHub Security, Azure DevOps, GitLab)

```bash
python audit.py --mode docker --container my-postgres --sarif results.sarif.json
```

Upload to GitHub Code Scanning:

```yaml
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif.json
```

### JSON (machine-readable)

```json
{
  "target": { "mode": "docker", "container": "my-postgres", "version": "PostgreSQL 16.3" },
  "summary": { "total": 69, "passed": 54, "failed": 10, "warnings": 5 },
  "results": [
    {
      "check_id": "PG-CFG-006",
      "title": "SSL must be enabled",
      "status": "FAIL",
      "severity": "CRITICAL",
      "cis_id": "6.7",
      "stig_id": "V-214070",
      "nist_control": "SC-8",
      "actual": "off",
      "expected": "on",
      "remediation": "..."
    }
  ]
}
```

### Evidence Bundle (compliance audits)

```bash
python audit.py --mode docker --container my-postgres --bundle evidence.zip
```

Bundle contents:
- `results.json` — full findings
- `results.sarif.json` — SARIF 2.1.0
- `audit-log.txt` — command output
- `config-snapshot.json` — PostgreSQL settings at audit time
- `executive-summary.md` — human-readable report

### Optional Wiz Integration

Wiz is supported as an **optional integration path** for teams that already operate in Wiz. It is not required to use `pg-stig-audit`, and the core audit workflow stands on its own with terminal, JSON, CSV, SARIF, and evidence-bundle outputs.

```bash
python audit.py --mode docker --container my-postgres --wiz wiz-findings.json
python scripts/push_to_wiz.py issues --findings wiz-findings.json --resource-id my-postgres-prod
```

See [docs/WIZ_SETUP.md](docs/WIZ_SETUP.md) for optional setup details.

### GCP Security Command Center

```bash
python audit.py --mode docker --container my-postgres \
  --scc scc-findings.json \
  --gcp-project my-project \
  --scc-source organizations/123456/sources/789012 \
  --resource-name //container.googleapis.com/projects/my-project/zones/us-central1-a/clusters/prod/k8s/pods/my-postgres
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: PostgreSQL Security Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Start PostgreSQL container
        run: |
          docker run -d --name test-pg \
            -e POSTGRES_PASSWORD=test \
            postgres:16
          sleep 10

      - name: Run pg-stig-audit
        run: |
          python audit.py --mode docker --container test-pg \
            --sarif results.sarif.json \
            --fail-on high

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif.json
```

### GitLab CI

```yaml
postgres_audit:
  stage: test
  image: python:3.11
  services:
    - postgres:16
  script:
    - python audit.py --mode direct --host postgres --user postgres --sarif gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
```

---

## Tested Environments

| Category | Tested |
|---|---|
| PostgreSQL Versions | 12, 13, 14, 15, 16, 17 |
| Container Runtimes | Docker, Kubernetes (GKE, EKS, AKS), Podman |
| Cloud Providers | GCP Cloud SQL, AWS RDS, Azure Database for PostgreSQL |
| Operating Systems | Linux (Ubuntu, RHEL, Alpine), macOS |

---

## Comparison with Other Tools

| Tool | Open Source | Container Support | CIS Benchmark | DISA STIG | SARIF Output |
|---|---|---|---|---|---|
| **pg-stig-audit** | ✅ | ✅ | ✅ (PG 16) | ✅ | ✅ |
| CIS-CAT Pro | ❌ | ❌ | ✅ | ❌ | ❌ |
| Nessus | ❌ | ⚠️ | ⚠️ | ⚠️ | ❌ |
| InSpec | ✅ | ⚠️ | ⚠️ | ⚠️ | ❌ |
| OpenSCAP | ✅ | ❌ | ❌ | ✅ | ❌ |

---

## Documentation

- [DISCLAIMER.md](DISCLAIMER.md) — Legal attribution and usage rights
- [docs/CVE_SCANNING.md](docs/CVE_SCANNING.md) — CVE/KEV scanning details
- [docs/RUN_BENCHMARK.md](docs/RUN_BENCHMARK.md) — Benchmark execution guide
- [docs/WIZ_SETUP.md](docs/WIZ_SETUP.md) — Wiz integration guide
- [CONTRIBUTING.md](CONTRIBUTING.md) — How to contribute

---

## FAQ

**Is this "CIS Certified"?**
No. This is an independent implementation of CIS controls. For official CIS certification, use [CIS-CAT Pro](https://www.cisecurity.org/cybersecurity-tools/cis-cat-pro).

**Can I use this for compliance audits?**
Yes, with caveats. This tool helps assess compliance posture, but official audits may require CIS-CAT Pro or manual validation. Always consult your auditor.

**Does this work with managed databases (RDS, Cloud SQL)?**
Yes — use `--mode direct`. Note: Some controls (file permissions, systemd) are N/A for managed services.

**Why 69 controls?**
We implement every control in CIS PostgreSQL 16 Benchmark v1.1.0 (69 total), plus 8 container-specific controls not in the official benchmark.

**Can I add custom controls?**
Yes. See `checks/`. Each check module follows a simple pattern. PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

Copyright 2026 pg-stig-audit contributors.

Licensed under the [Apache License, Version 2.0](LICENSE).

The CIS PostgreSQL Benchmark is copyright Center for Internet Security and subject to their [Terms of Use](https://www.cisecurity.org/cis-securesuite/cis-securesuite-membership-terms-of-use/). This tool implements the benchmark controls independently and is not affiliated with or endorsed by CIS.

---

## Acknowledgements

Built with reference to:
- CIS PostgreSQL 16 Benchmark v1.1.0
- DISA STIG PostgreSQL 12 V1R1
- NIST SP 800-53 Revision 5
- PostgreSQL Security Documentation
T SP 800-53 Revision 5
- PostgreSQL Security Documentation
