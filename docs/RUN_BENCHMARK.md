# How to Run the PostgreSQL Container Benchmark

This document is the explicit operator guide for running `pg-stig-audit` as a **standalone benchmark/audit tool**.

Use this when you want to assess a PostgreSQL target directly from your laptop, CI runner, or audit host without involving Wiz.

---

## What this tool does

`pg-stig-audit` evaluates PostgreSQL running in containerized environments and produces:

- terminal findings
- JSON results
- SARIF 2.1.0 output
- Wiz Issues API payload (when explicitly requested)
- GCP Security Command Center findings (when explicitly requested)

It does **not** need to be installed inside the PostgreSQL container.
Run it from a host that can reach the target and, when applicable, can call `docker` or `kubectl`.

---

## Requirements

- Python 3.10+
- PostgreSQL target reachable in one of these modes:
  - direct TCP (`--mode direct`)
  - Docker (`--mode docker`)
  - Kubernetes (`--mode kubectl`)
- For direct mode: network access to PostgreSQL + local `psql` CLI
- For Docker mode: local Docker access plus `docker` CLI
- For Kubernetes mode: cluster access plus `kubectl`
- `psql` must be available inside the target container for Docker/Kubernetes modes
  - Official `postgres:*` images include `psql` by default
- For authenticated PostgreSQL: credentials that allow read-only benchmark interrogation (`SHOW`, `SELECT` from `pg_settings`, `pg_hba_file_rules`, etc.)

---

## Repo location

From the workspace:

```bash
cd /Users/neepai/.openclaw/workspace/pg-stig-audit
```

---

## Quick start

### 1) Terminal-only run

#### Direct mode

```bash
python3 audit.py --mode direct --host 127.0.0.1 --port 5432 --user postgres --database postgres
```

You'll be prompted for the password unless `PGPASSWORD` is set.

#### Docker mode

```bash
python3 audit.py --mode docker --container postgres-test
```

#### Kubernetes mode

```bash
python3 audit.py --mode kubectl --pod postgres-0 --namespace default
```

---

## Generate explicit artifacts

### JSON output

```bash
python3 audit.py --mode docker --container postgres-test --json output/results.json
```

### SARIF output

```bash
python3 audit.py --mode docker --container postgres-test --sarif output/results.sarif
```

### CSV output (with NIST 800-171, CMMC, and MITRE columns)

```bash
python3 audit.py --mode docker --container postgres-test --csv output/results.csv
```

The CSV includes these compliance columns for each control:
- `NIST_800_53` — NIST SP 800-53 Rev 5 controls (e.g. `SC-8; SC-8(1)`)
- `NIST_800_171` — NIST SP 800-171 Rev 2 control IDs (e.g. `3.13.8`)
- `CMMC_Level` — CMMC 2.0 level (1 or 2)
- `MITRE_ATTACK` — ATT&CK technique IDs (e.g. `T1040; T1078`)
- `MITRE_D3FEND` — D3FEND technique IDs (e.g. `D3-ET; D3-ALCA`)
- `DISA_STIG_ID` — DISA STIG finding ID where applicable (e.g. `V-214117`)

Compatible with Excel, Google Sheets, and any standard spreadsheet tool.

Conditional CSV field behavior:
- `CVE_ID`, `KEV_Score`, `CVE_Remediation`
  - `not_scanned` when `--skip-cve` is used
  - `not_applicable` for non-vulnerability findings
  - populated values on the version/CVE finding when CVE scanning runs
- `Local_Path`
  - real binary/path when available
  - otherwise a scope hint such as `runtime-config`, `runtime-network-config`, `filesystem`, or `container-inspect`

### All outputs in one run

```bash
python3 audit.py --mode docker --container postgres-test \
  --json output/results.json \
  --sarif output/results.sarif \
  --csv output/results.csv
```

You can also use the Makefile shortcut:

```bash
make all-outputs
```

---

## Authentication examples

If PostgreSQL requires authentication, provide credentials via environment or flags.

### Password-based auth (environment)

```bash
export PGPASSWORD='your-password'
python3 audit.py --mode direct --host 10.0.0.15 --port 5432 --user postgres --database postgres --json results.json
```

### Password via stdin (interactive)

```bash
python3 audit.py --mode direct --host 10.0.0.15 --port 5432 --user postgres --database postgres
```

You'll be prompted for the password.

### Docker/Kubernetes modes

For container modes, `pg-stig-audit` uses `docker exec` or `kubectl exec` to run `psql` inside the container. Authentication depends on the container's `pg_hba.conf` and whether the default `postgres` user can connect locally without a password.

If the container requires a password for local connections:
- set `PGPASSWORD` in the container environment
- or pass `--password` flag to `audit.py` (it will be forwarded into the `psql` command)

---

## Mode-by-mode examples

## Direct mode

Use this when PostgreSQL is reachable by host/port.

```bash
python3 audit.py --mode direct \
  --host 127.0.0.1 \
  --port 5432 \
  --user postgres \
  --database postgres \
  --json output/direct-results.json \
  --sarif output/direct-results.sarif
```

Good for:
- local development
- bastion/assessment hosts
- externally reachable internal PostgreSQL services
- Cloud SQL instances (via Cloud SQL Auth Proxy)

---

## Docker mode

Use this when PostgreSQL is running in a local Docker container and you want both PostgreSQL runtime checks and container-hardening checks.

### Verify container name first

```bash
docker ps --format '{{.Names}}'
```

### Run audit

```bash
python3 audit.py --mode docker \
  --container postgres-test \
  --json output/docker-results.json \
  --sarif output/docker-results.sarif
```

Good for:
- local validation
- pre-release checks
- container hardening evidence collection

---

## Kubernetes mode

Use this when PostgreSQL runs in a cluster and you want pod-level/container-level checks.

### Verify pod name first

```bash
kubectl get pods -n default
```

### Run audit

```bash
python3 audit.py --mode kubectl \
  --pod postgres-0 \
  --namespace default \
  --json output/k8s-results.json \
  --sarif output/k8s-results.sarif
```

Good for:
- cluster audits
- evidence collection for regulated environments
- comparing baseline vs hardened manifests

---

## What the outputs mean

### Terminal report
Human-readable assessment summary.

### JSON
Full machine-readable document containing:
- target metadata
- summary counts
- risk posture
- runtime snapshot
- findings and evidence

### SARIF
Best for pipeline ingestion and code/security platforms that understand SARIF.

---

## Recommended operator flow

### Simple standalone review

```bash
python3 audit.py --mode docker --container postgres-test
```

### Reviewer-ready package

```bash
python3 audit.py --mode docker --container postgres-test \
  --json output/results.json \
  --sarif output/results.sarif
```

### CI/CD-friendly pattern

```bash
mkdir -p output
python3 audit.py --mode docker --container postgres-test \
  --json output/results.json \
  --sarif output/results.sarif
```

Then archive `output/` as a build artifact.

---

## Validation

Run the current unit test suite:

```bash
python3 -m unittest discover -s test -p 'test_*.py' -v
```

---

## Troubleshooting

### `psql` auth or connectivity fails
- Confirm the target is reachable
- Confirm your auth environment is correct
- Test with `psql` manually before running the benchmark

### Docker mode returns inspect/runtime issues
- Confirm the container exists
- Confirm your user can run Docker commands
- Check `docker inspect <container>` manually

### Kubernetes mode fails
- Confirm kube context/namespace
- Confirm pod name is correct
- Check `kubectl get pod -n <namespace> <pod> -o json`

### No JSON/SARIF files appear
- Confirm the output directory exists if you are writing into a nested path
- Use `mkdir -p output` before running

---

## Related docs

- `README.md`
- `docs/WIZ_SETUP.md`
