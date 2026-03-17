# pg-stig-audit

**PostgreSQL CIS Benchmark + DISA STIG Audit Tool for Containerized PostgreSQL**

No published security benchmark covers PostgreSQL running inside containers.
CIS PostgreSQL covers bare-metal. CIS Docker covers containers. Neither covers both.
This tool fills that gap — runtime auditing of PostgreSQL configuration inside Docker containers,
Kubernetes pods, and Cloud SQL instances, mapped to CIS, DISA STIG, NIST, and FedRAMP.

---

## What It Checks

| Category | Controls | Key Checks |
|---|---|---|
| Server Configuration | 9 | SSL, TLS version, ciphers, password encryption, listen_addresses, fsync, pgaudit |
| Logging & Auditing | 12 | logging_collector, log_connections, log_line_prefix, log_statement, pgaudit.log |
| Authentication | 7 | No trust auth, no plaintext password, SCRAM over MD5, superuser limits |
| Privileges & Objects | 8 | PUBLIC table access, SECURITY DEFINER, risky extensions, RLS, password hashing |

**Total: 36 checks** mapped to CIS PG 16, DISA STIG PG 12 V1R1, NIST 800-53 Rev5, FedRAMP High.

---

## Requirements

- Python 3.10+ (no dependencies — stdlib only)
- `docker` CLI (for Docker mode) or `kubectl` (for Kubernetes mode)
- `psql` must be available inside the target container
  - Official `postgres:*` Docker images include psql — no action needed
- For direct/Cloud SQL mode: `psql` installed locally

---

## Quick Start

> Note: You do **not** install pg-stig-audit inside the PostgreSQL container.
> Run pg-stig-audit from a host (or CI runner) that has Docker access to the target container.

### Step 1 — Clone / Navigate to the project

```bash
cd workspace/pg-stig-audit
```

### Step 2 — Copy credentials template (Wiz/GCP only)

```bash
cp .env.example .env
# Edit .env and fill in WIZ_CLIENT_ID, WIZ_CLIENT_SECRET, etc.
```

### Step 3 — Run the audit

```bash
# Docker container (most common)
python3 audit.py --mode docker --container my-postgres

# With all outputs
python3 audit.py --mode docker --container my-postgres \
    --json results.json \
    --sarif results.sarif.json \
    --wiz wiz-findings.json
```

---

## Standalone Usage

### Docker Mode

```bash
# Basic audit — prints color report to terminal
python3 audit.py --mode docker --container my-postgres

# Save all output formats
python3 audit.py --mode docker --container my-postgres \
    --json results.json \
    --sarif results.sarif.json \
    --wiz wiz-findings.json \
    --scc scc-findings.json \
    --gcp-project my-project \
    --scc-source organizations/123456/sources/789012

# Fail CI/CD if any CRITICAL or HIGH findings
python3 audit.py --mode docker --container my-postgres --fail-on high
# Exit code 1 if there are CRITICAL or HIGH failures
# Exit code 0 if clean

# Only fail on CRITICAL
python3 audit.py --mode docker --container my-postgres --fail-on critical
```

### Kubernetes Mode

```bash
# Audit a pod by name
python3 audit.py --mode kubectl \
    --pod postgres-0 \
    --namespace production

# Get pod name dynamically
python3 audit.py --mode kubectl \
    --pod $(kubectl get pods -l app=postgres -n prod -o jsonpath='{.items[0].metadata.name}') \
    --namespace prod \
    --sarif results.sarif.json

# Audit all postgres pods in a namespace (shell loop)
for pod in $(kubectl get pods -l app=postgres -n prod -o name | cut -d/ -f2); do
    echo "=== Auditing $pod ==="
    python3 audit.py --mode kubectl --pod "$pod" --namespace prod \
        --json "results-${pod}.json" --fail-on high
done
```

### Cloud SQL / Direct Mode (via Cloud SQL Auth Proxy)

```bash
# Step 1: Start Cloud SQL Auth Proxy
cloud-sql-proxy --port 5432 PROJECT:REGION:INSTANCE &

# Step 2: Run audit against the proxy
python3 audit.py --mode direct \
    --host 127.0.0.1 \
    --port 5432 \
    --user postgres \
    --json results.json \
    --wiz wiz-findings.json \
    --gcp-project my-fedramp-project \
    --scc-source organizations/ORG/sources/SOURCE

# Using PGPASSWORD env var (preferred over --password flag)
PGPASSWORD=mypassword python3 audit.py --mode direct --host 127.0.0.1 --port 5432
```

### CLI Reference

```
python3 audit.py [OPTIONS]

Target:
  --mode          docker | kubectl | direct   (default: docker)
  --container     Docker container name or ID (required for docker mode)
  --pod           Kubernetes pod name         (required for kubectl mode)
  --namespace     Kubernetes namespace        (default: default)
  --host          DB host for direct mode     (default: 127.0.0.1)
  --port          DB port for direct mode     (default: 5432)

Credentials:
  --user          PostgreSQL user             (default: postgres)
  --password      Password (or use PGPASSWORD env var)
  --database      Database name              (default: postgres)

Output:
  --json FILE     Raw results JSON
  --sarif FILE    SARIF 2.1.0 (GitHub, GitLab, Wiz import)
  --wiz FILE      Wiz Issues API JSON
  --scc FILE      GCP Security Command Center JSON
  --no-color      Disable terminal colors
  --quiet         Suppress terminal output (file outputs only)
  --fail-on       any | high | critical | none  (default: high)

GCP / Wiz:
  --gcp-project   GCP project ID
  --scc-source    SCC source resource name
  --wiz-resource-id   Resource label for Wiz findings

Other:
  --verbose       Print SQL queries as they run
  --version       Show version
```

---

## Output Formats

### Terminal Report (default)

Color-coded, grouped by category. Shows PASS/FAIL/WARN per check with:
- Check ID, severity, title
- Compliance IDs (CIS, STIG, FedRAMP/NIST)
- Actual vs. expected values
- Remediation guidance
- Risk rating summary

### JSON (`--json results.json`)

Machine-readable. Full result set including all checks (pass + fail).
Used as input by `push_to_wiz.py`, `push_to_scc.py`, and `gen_remediation.py`.

```json
{
  "target": { "Mode": "docker", "Target": "my-postgres" },
  "pg_version": "PostgreSQL 16.1 ...",
  "results": [
    {
      "check_id": "PG-CFG-006",
      "title": "SSL must be enabled",
      "status": "FAIL",
      "severity": "CRITICAL",
      "cis_id": "CIS-PG-6.7",
      "stig_id": "V-214070",
      "fedramp_control": "SC-8",
      "actual": "off",
      "expected": "on",
      "remediation": "Set ssl = on in postgresql.conf..."
    }
  ]
}
```

### SARIF (`--sarif results.sarif.json`)

SARIF 2.1.0 format for CI/CD security tools:
- **GitHub Advanced Security**: Uploads to Code Scanning tab
- **GitLab SAST**: Import as SAST report artifact
- **Azure DevOps**: PublishTestResults or Code Analysis task
- **Wiz**: Import via Wiz CDR (Cloud Detection & Response)

### Wiz JSON (`--wiz wiz-findings.json`)

Pre-formatted for the Wiz Issues API. Use with `scripts/push_to_wiz.py`.

### GCP SCC JSON (`--scc scc-findings.json`)

Pre-formatted for GCP Security Command Center Findings API. Use with `scripts/push_to_scc.py`.

---

## Wiz Integration

Detailed quickstart: `WIZ_SETUP.md`

There are two ways to integrate with Wiz:

### Method A — Push Runtime Findings as Wiz Issues (Recommended)

This is the most practical approach. You run `audit.py` against your actual PostgreSQL container,
then push the results into Wiz as Issues. They appear in Wiz under **Issues** and can be
assigned, tracked, and reported on like any other Wiz finding.

**Step 1: Set up credentials**

```bash
cp .env.example .env
```

Edit `.env`:
```
WIZ_CLIENT_ID=your-client-id
WIZ_CLIENT_SECRET=your-client-secret
WIZ_API_ENDPOINT=https://api.us1.app.wiz.io/graphql
```

To get credentials:
1. Log into Wiz → **Settings** → **Service Accounts**
2. Click **Add Service Account**
3. Name it `pg-stig-audit`
4. Scopes: **Issues** (Read + Write), **Security Policies** (Read + Write)
5. Save and copy the Client ID and Client Secret

**Step 2: Verify the connection**

```bash
python3 scripts/push_to_wiz.py verify
```

Expected output:
```
🔐 Authenticating to Wiz...
   ✅ Authenticated
🔗 Verifying Wiz API connection...
   ✅ Connected as: pg-stig-audit
   Scopes: issues:read, issues:write, ...
✅ Done.
```

**Step 3: Run the audit and save JSON results**

```bash
python3 audit.py --mode docker --container my-postgres --json audit-results.json
```

**Step 4: Push findings to Wiz**

```bash
# Push only failures (recommended for production)
python3 scripts/push_to_wiz.py issues \
    --findings audit-results.json \
    --only-failures

# Push with a resource ID (links findings to your container in Wiz)
python3 scripts/push_to_wiz.py issues \
    --findings audit-results.json \
    --resource-id "my-postgres-container" \
    --only-failures

# Scope to a specific Wiz project
python3 scripts/push_to_wiz.py issues \
    --findings audit-results.json \
    --project-id "your-wiz-project-id" \
    --only-failures

# Dry run first — see what would be sent
python3 scripts/push_to_wiz.py issues \
    --findings audit-results.json \
    --dry-run --verbose
```

**View in Wiz:** Issues → All Issues → filter by Source: pg-stig-audit

---

### Method B — OPA Custom Control (Policy-as-Code)

This approach registers the Rego policy file directly in Wiz as a Custom Control.
Wiz evaluates it against its cloud inventory. Best for:
- Policy-as-code workflows
- Pre-deployment checks (testing PostgreSQL config before it runs)
- Wiz customers with Sensor deployed in Kubernetes

**Register the Rego policy in Wiz:**

```bash
python3 scripts/push_to_wiz.py custom-control \
    --rego rego/pg_audit.rego \
    --name "PostgreSQL CIS/STIG Container Benchmark"
```

**Manually in the Wiz portal:**
1. Go to **Policies** → **Controls** → **Custom Controls**
2. Click **+ Add Custom Control**
3. Choose **OPA** as the policy type
4. Paste the contents of `rego/pg_audit.rego`
5. Set name: `PostgreSQL CIS/STIG Container Benchmark`
6. Target resource type: **Container** or **Kubernetes Pod**
7. Save and enable

**Test the policy locally before uploading:**
```bash
# Export live PostgreSQL settings to JSON
python3 scripts/export_for_opa.py --mode docker --container my-postgres > pg-settings.json

# Test with OPA (install: brew install opa)
opa eval -d rego/pg_audit.rego -I --format pretty 'data.postgresql.cis_stig.deny' < pg-settings.json

# Test with conftest (install: brew install conftest)
conftest test --policy rego/ pg-settings.json
```

---

### Method C — Both (Full Integration)

Run the audit, push issues, and register the control in one command:

```bash
python3 scripts/push_to_wiz.py all \
    --findings audit-results.json \
    --rego rego/pg_audit.rego \
    --resource-id "my-postgres-container" \
    --only-failures
```

---

## CI/CD Integration

### GitHub Actions (SARIF → Code Scanning)

```yaml
name: PostgreSQL Security Audit

on:
  push:
    branches: [main]
  schedule:
    - cron: '0 6 * * 1'  # Weekly Monday 6 AM

jobs:
  pg-audit:
    runs-on: ubuntu-latest
    permissions:
      security-events: write

    steps:
      - uses: actions/checkout@v4

      - name: Start PostgreSQL
        run: |
          docker run -d --name postgres-test \
            -e POSTGRES_PASSWORD=test \
            postgres:16-alpine

      - name: Wait for PostgreSQL
        run: |
          until docker exec postgres-test pg_isready -U postgres; do sleep 2; done

      - name: Run pg-stig-audit
        run: |
          python3 audit.py \
            --mode docker \
            --container postgres-test \
            --sarif results.sarif.json \
            --json results.json \
            --fail-on critical   # Don't fail CI on HIGH, only CRITICAL

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif.json

      - name: Push to Wiz (optional)
        if: always()
        env:
          WIZ_CLIENT_ID: ${{ secrets.WIZ_CLIENT_ID }}
          WIZ_CLIENT_SECRET: ${{ secrets.WIZ_CLIENT_SECRET }}
        run: |
          python3 scripts/push_to_wiz.py issues \
            --findings results.json \
            --only-failures
```

### GitLab CI

```yaml
pg-security-audit:
  image: python:3.12-alpine
  services:
    - name: postgres:16-alpine
      alias: postgres
      variables:
        POSTGRES_PASSWORD: test
  variables:
    PGPASSWORD: test
  script:
    - python3 audit.py --mode direct --host postgres --user postgres
        --sarif results.sarif.json --json results.json --fail-on critical
    - python3 scripts/push_to_wiz.py issues --findings results.json --only-failures
  artifacts:
    reports:
      sast: results.sarif.json
    paths:
      - results.json
    when: always
```

---

## GCP Security Command Center Integration

### Setup (one-time)

```bash
# 1. Create an SCC Source for pg-stig-audit
gcloud scc sources create \
    --organization=$ORG_ID \
    --display-name="pg-stig-audit" \
    --description="PostgreSQL CIS/STIG container compliance audit"

# 2. Note the source ID from the output, or find it:
gcloud scc sources list --organization=$ORG_ID

# 3. Grant the service account findings editor
gcloud organizations add-iam-policy-binding $ORG_ID \
    --member="serviceAccount:pg-audit@$PROJECT.iam.gserviceaccount.com" \
    --role="roles/securitycenter.findingsEditor"
```

### Run and Push

```bash
# Run audit and save SCC JSON
python3 audit.py --mode direct --host 127.0.0.1 \
    --scc scc-findings.json \
    --gcp-project $PROJECT \
    --scc-source organizations/$ORG/sources/$SOURCE_ID

# Push findings to SCC
python3 scripts/push_to_scc.py \
    --findings results.json \
    --project $PROJECT \
    --source organizations/$ORG/sources/$SOURCE_ID \
    --only-failures

# Dry run first
python3 scripts/push_to_scc.py \
    --findings results.json \
    --project $PROJECT \
    --source organizations/$ORG/sources/$SOURCE_ID \
    --dry-run --verbose
```

Findings appear in: GCP Console → Security Command Center → Findings → Source: pg-stig-audit

---

## Remediation Scripts

After running an audit, generate ready-to-apply fix scripts:

```bash
# Save audit results first
python3 audit.py --mode docker --container my-postgres --json results.json

# Generate remediation scripts
python3 scripts/gen_remediation.py --findings results.json --output-dir ./remediation/
```

Outputs:
- `remediation/remediation.sql` — ALTER SYSTEM + privilege fix SQL
- `remediation/remediation.conf` — postgresql.conf snippet with corrected values
- `remediation/pg_hba.conf.recommended` — Hardened pg_hba.conf template

**Apply the SQL:**
```bash
# Review first
cat remediation/remediation.sql

# Apply to Docker container
docker exec -i my-postgres psql -U postgres < remediation/remediation.sql

# Apply to Kubernetes pod
kubectl exec -i postgres-0 -n production -- psql -U postgres < remediation/remediation.sql

# Some settings require a restart — the SQL file will tell you which ones
```

**Apply the config snippet:**
```bash
# Docker: copy conf into container then reload
docker cp remediation/remediation.conf my-postgres:/tmp/remediation.conf
docker exec my-postgres psql -U postgres -c "
    -- Merge settings (run ALTER SYSTEM commands from remediation.sql instead)
    SELECT pg_reload_conf();
"
```

---

## OPA / conftest Usage

For policy-as-code workflows, export live settings and test against the Rego policy locally:

```bash
# Export settings from a running container
python3 scripts/export_for_opa.py --mode docker --container my-postgres > pg-settings.json

# Test with OPA
opa eval \
    -d rego/pg_audit.rego \
    -I \
    --format pretty \
    'data.postgresql.cis_stig.deny' \
    < pg-settings.json

# Test with conftest
conftest test --policy rego/ pg-settings.json

# Save snapshot for historical comparison
python3 scripts/export_for_opa.py --mode docker --container my-postgres \
    --output snapshots/$(date +%Y-%m-%d)-pg-settings.json
```

---

## Integration Test Suite

Spin up hardened, vulnerable, and baseline containers and compare results:

```bash
# Run all three test containers
bash test/run_tests.sh

# Outputs written to test/output/:
#   hardened.sarif.json    — should pass most checks
#   vulnerable.sarif.json  — should fail many checks
#   baseline.sarif.json    — stock defaults (shows what ships out-of-the-box)
```

Test containers defined in `test/docker-compose.test.yml`:
- **pg-hardened**: SSL on, SCRAM, pgaudit, proper log settings
- **pg-vulnerable**: SSL off, MD5, trust auth, logging disabled
- **pg-baseline**: Stock `postgres:16-alpine` defaults

---

## Framework Coverage

| Framework | Version | Coverage |
|---|---|---|
| CIS PostgreSQL Benchmark | v1.0 for PG 16 | Sections 2, 3, 4, 5, 6, 7 |
| DISA STIG PostgreSQL | V1R1 for PG 12+ | V-214060 through V-214130 |
| NIST SP 800-53 | Rev 5 | AC-2, AC-3, AC-6, AC-12, AU-2, AU-3, CP-9, IA-2, IA-5, SC-7, SC-8, CM-7 |
| FedRAMP | High Baseline | All mapped NIST controls above |

---

## Project Structure

```
pg-stig-audit/
├── audit.py                  # Main entry point
├── runner.py                 # PostgreSQL connection (Docker/kubectl/direct)
├── .env.example              # Credentials template → copy to .env
├── checks/
│   ├── base.py               # CheckResult dataclass, Status/Severity enums
│   ├── config.py             # Server config checks (SSL, password_encryption, etc.)
│   ├── logging.py            # Logging/audit checks (pgaudit, log_statement, etc.)
│   ├── auth.py               # Auth checks (pg_hba, SCRAM, superusers)
│   └── privileges.py         # Privilege checks (PUBLIC access, extensions, RLS)
├── output/
│   ├── report.py             # Terminal report renderer
│   ├── sarif.py              # SARIF 2.1.0 formatter
│   └── wiz_scc.py            # Wiz Issues + GCP SCC formatters
├── scripts/
│   ├── push_to_wiz.py        # Push findings to Wiz (Issues API + Custom Controls)
│   ├── push_to_scc.py        # Push findings to GCP Security Command Center
│   ├── export_for_opa.py     # Export live PG settings to JSON for OPA/conftest
│   └── gen_remediation.py    # Generate SQL/conf remediation scripts
├── rego/
│   └── pg_audit.rego         # OPA policy for Wiz Custom Controls + conftest
├── test/
│   ├── docker-compose.test.yml  # Three test containers (hardened/vulnerable/baseline)
│   └── run_tests.sh          # Run all three and compare
└── benchmarks/               # Benchmark documents (see ../benchmarks/)
    ├── CIS_PostgreSQL_Container_Benchmark_v1.0.md
    ├── DISA_STIG_PostgreSQL_Container_v1.0.md
    └── README.md
```

---

## Shared Responsibility (Cloud SQL / GKE)

Some CIS controls are Google's responsibility in managed services:

| Control | Cloud SQL | GKE | Self-managed containers |
|---|---|---|---|
| OS-level file permissions | Google | Google | **Yours** |
| Disk encryption at rest | Google | Google | **Yours** |
| Network encryption (in transit) | Configurable | Google | **Yours** |
| `postgresql.conf` runtime settings | **Yours** | **Yours** | **Yours** |
| `pg_hba.conf` auth rules | **Yours** | **Yours** | **Yours** |
| User/role privileges | **Yours** | **Yours** | **Yours** |
| pgaudit configuration | **Yours** | **Yours** | **Yours** |

pg-stig-audit focuses on the **"Yours"** controls — the ones the cloud provider doesn't manage.

---

## Version

**v1.0.0-draft** — February 2026
Status: Draft for community review

Applies to: PostgreSQL 12–17 in Docker, Kubernetes (OCI-compatible runtimes), and GCP Cloud SQL.

Does **not** replace the CIS PostgreSQL or DISA STIG benchmarks for bare-metal/VM deployments.
When running PostgreSQL in containers, apply **both** this tool **and** the underlying CIS Docker/Kubernetes benchmark.

---

## Validation and Evidence Artifacts

### 1) Fixture differentiation validation

Run the integration suite (hardened vs baseline vs vulnerable):

```bash
./test/run_tests.sh
# or
make test-fixtures
```

This produces materially different outcomes across fixtures in `test/output/*.json`.

### 2) Fixture delta pack (deterministic deltas)

```bash
python3 scripts/make_fixture_delta_pack.py \
  --input-dir test/output \
  --out-dir artifacts/fixture-pack
# or
make fixture-pack
```

Outputs:
- `artifacts/fixture-pack/fixture-delta-pack.json`
- `artifacts/fixture-pack/README.md`

Includes deterministic before/after deltas (pass-rate delta, fail-count delta, critical/high-fail deltas).

### 3) One-click compliance evidence bundle

```bash
python3 scripts/build_evidence_bundle.py \
  --json test/output/hardened.json \
  --sarif test/output/hardened.sarif.json \
  --out-dir evidence/latest \
  --label hardened-fixture
# or
make evidence-bundle
```

Outputs:
- `evidence/latest/executive-summary.pdf`
- `evidence/latest/executive-summary.txt`
- `evidence/latest/results.json`
- `evidence/latest/results.sarif.json`
- `evidence/latest/control-trace.json`
- `evidence/latest/manifest.json`

### Full wrapper (single command)

```bash
make compliance-pack
```

Runs all three in order: fixture tests → fixture delta pack → compliance evidence bundle.

---

## Existing Docker PostgreSQL → Wiz Report (end-to-end)

### Pre-checks

1. Confirm container is running:

```bash
docker ps --format '{{.Names}}' | grep -E '^my-postgres$'
```

2. Confirm `psql` exists in the container:

```bash
docker exec my-postgres psql --version
```

3. Configure Wiz credentials:

```bash
cp .env.example .env
# set WIZ_CLIENT_ID, WIZ_CLIENT_SECRET, WIZ_API_ENDPOINT
python3 scripts/push_to_wiz.py verify
```

### Generate and push findings

```bash
python3 audit.py --mode docker --container my-postgres \
  --json results.json \
  --sarif results.sarif.json

python3 scripts/push_to_wiz.py issues \
  --findings results.json \
  --resource-id "my-postgres" \
  --only-failures
```

### One-command wrapper

```bash
make wiz-report CONTAINER=my-postgres WIZ_RESOURCE_ID=my-postgres
```

This performs the audit and pushes FAIL/WARN findings to Wiz.
