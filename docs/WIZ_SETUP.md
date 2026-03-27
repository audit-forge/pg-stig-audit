# Optional Wiz Integration Guide for pg-stig-audit

This guide is for teams that already have Wiz and want to connect `pg-stig-audit` to it. Wiz is an optional integration path, not a required part of the core audit workflow.

This guide shows how to wire `pg-stig-audit` into Wiz using both supported paths:

1. **Push findings as Wiz Issues** (fastest operational path)
2. **Register OPA/Rego as a Wiz Custom Control** (policy-as-code path)

---

## Prerequisites

- Python 3.9+
- Access to a PostgreSQL target (Docker, Kubernetes, or direct TCP)
- Run this tool from the host/runner (no install inside the PostgreSQL container)
- Wiz Service Account credentials with at least:
  - **Issues**: Read/Write
  - **Security Policies / Custom Controls**: Read/Write

From Wiz, collect:
- `WIZ_CLIENT_ID`
- `WIZ_CLIENT_SECRET`
- `WIZ_API_ENDPOINT` (example: `https://api.us1.app.wiz.io/graphql`)

---

## 1) Configure credentials

From repo root:

```bash
cp .env.example .env
```

Edit `.env` and set:

```bash
WIZ_CLIENT_ID=...
WIZ_CLIENT_SECRET=...
WIZ_API_ENDPOINT=https://api.us1.app.wiz.io/graphql
```

Validate connectivity:

```bash
python3 scripts/push_to_wiz.py verify
```

---

## 2) Run an audit and produce JSON findings

### Existing Docker PostgreSQL instance checklist

```bash
# 1) container exists and is running
docker ps --format '{{.Names}}' | grep -E '^my-postgres$'

# 2) psql is available in the container
docker exec my-postgres psql --version

# 3) Host has docker access
id
```

Example (Docker target):

```bash
python3 audit.py --mode docker --container my-postgres --json audit-results.json --sarif audit-results.sarif.json
```

You can also use `--mode kubectl` or `--mode direct`.

---

## 3) Push findings to Wiz Issues

```bash
python3 scripts/push_to_wiz.py issues \
  --findings audit-results.json \
  --resource-id "my-postgres-container" \
  --only-failures
```

Optional flags:
- `--project-id <wiz_project_id>` to scope issues
- `--dry-run` to preview payloads without sending
- `--env-file <path>` if not using default `.env`

---

## 4) Register the Rego policy as a Wiz Custom Control

```bash
python3 scripts/push_to_wiz.py custom-control \
  --rego rego/pg_audit.rego \
  --name "PostgreSQL CIS/STIG Container Benchmark" \
  --description "CIS PostgreSQL 16 + DISA STIG checks for containerized PostgreSQL"
```

---

## 5) Combined flow (Issues + Custom Control)

```bash
python3 scripts/push_to_wiz.py all \
  --findings audit-results.json \
  --rego rego/pg_audit.rego
```

If you want a single command for Docker runtime findings + Wiz Issues push:

```bash
make wiz-report CONTAINER=my-postgres WIZ_RESOURCE_ID=my-postgres
```

---

## Recommended production pattern

1. Run `audit.py` in CI/CD per environment.
2. Export SARIF for GitHub/GitLab visibility.
3. Push failures to Wiz (`issues --only-failures`).
4. Keep Custom Control registered for long-lived policy governance.
5. Store `audit-results.json` + `audit-results.sarif.json` as release artifacts.

---

## Troubleshooting

- **Auth fails on verify**: check service account scopes and endpoint region.
- **No issues appear**: confirm findings file has FAIL/WARN and use `--verbose`.
- **Control registration fails**: validate `rego/pg_audit.rego` syntax and permissions.
- **Wrong tenant/region**: ensure `WIZ_API_ENDPOINT` matches your Wiz region.
