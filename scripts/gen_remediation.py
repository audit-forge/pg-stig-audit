#!/usr/bin/env python3
"""
gen_remediation.py — Generate actionable remediation scripts from audit findings.

Reads pg-audit-results.json and produces:
  - remediation.sql     : SQL commands to fix privilege/config issues (ALTER SYSTEM, REVOKE, etc.)
  - remediation.conf    : postgresql.conf snippet with corrected settings
  - pg_hba.patch        : Suggested pg_hba.conf changes (annotated)
  - remediation.sh      : Shell script for Docker/K8s environments

Usage:
  python3 scripts/gen_remediation.py --findings pg-audit-results.json

  # Apply SQL directly to a Docker container:
  python3 scripts/gen_remediation.py --findings pg-audit-results.json
  docker exec -i my-postgres psql -U postgres < remediation.sql

  # Copy new postgresql.conf into container:
  docker cp remediation.conf my-postgres:/tmp/remediation.conf
  docker exec my-postgres psql -U postgres -c "
    SELECT pg_reload_conf();
  "
"""
import argparse
import json
import sys
from datetime import datetime, timezone

HEADER = f"""-- ============================================================
-- pg-stig-audit Remediation Script
-- Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}
-- Framework: CIS PostgreSQL 16 + DISA STIG + FedRAMP High
-- ============================================================
-- REVIEW ALL COMMANDS BEFORE RUNNING IN PRODUCTION.
-- Test in a non-production environment first.
-- Some settings require a PostgreSQL restart (restart_required = true in pg_settings).
-- ============================================================

"""

# Map check_id → (ALTER SYSTEM command, requires_reload, requires_restart)
ALTER_SYSTEM_MAP = {
    "PG-CFG-002": ("SET password_encryption = 'scram-sha-256'", True, False),
    "PG-CFG-003": ("SET fsync = on", False, True),
    "PG-CFG-004": ("SET full_page_writes = on", False, True),
    "PG-CFG-005": ("SET idle_session_timeout = '15min'", True, False),
    "PG-CFG-006": ("SET ssl = on", False, True),
    "PG-CFG-007": ("SET ssl_min_protocol_version = 'TLSv1.2'", False, True),
    "PG-CFG-008": ("SET ssl_ciphers = 'HIGH:!aNULL:!MD5:!RC4:!3DES'", False, True),
    "PG-CFG-009": ("SET shared_preload_libraries = 'pgaudit'", False, True),
    "PG-LOG-001": ("SET logging_collector = on", False, True),
    "PG-LOG-002": ("SET log_connections = on", True, False),
    "PG-LOG-003": ("SET log_disconnections = on", True, False),
    "PG-LOG-005": ("SET log_error_verbosity = default", True, False),
    "PG-LOG-006": ("SET log_line_prefix = '%t [%p]: [%l-1] user=%u,db=%d,app=%a,client=%h '", True, False),
    "PG-LOG-007": ("SET log_statement = 'ddl'", True, False),
    "PG-LOG-008": ("SET log_min_error_statement = error", True, False),
    "PG-LOG-009": ("SET log_min_messages = warning", True, False),
    "PG-LOG-010": ("SET pgaudit.log = 'ddl,write,role,connection'", True, False),
    "PG-LOG-011": ("SET log_checkpoints = on", True, False),
    "PG-LOG-012": ("SET log_lock_waits = on", True, False),
    "PG-CFG-001": ("SET listen_addresses = 'localhost'", False, True),
}

# postgresql.conf snippet values
CONF_MAP = {
    "PG-CFG-001": ("listen_addresses", "'localhost'"),
    "PG-CFG-002": ("password_encryption", "scram-sha-256"),
    "PG-CFG-003": ("fsync", "on"),
    "PG-CFG-004": ("full_page_writes", "on"),
    "PG-CFG-005": ("idle_session_timeout", "15min"),
    "PG-CFG-006": ("ssl", "on"),
    "PG-CFG-007": ("ssl_min_protocol_version", "TLSv1.2"),
    "PG-CFG-008": ("ssl_ciphers", "'HIGH:!aNULL:!MD5:!RC4:!3DES'"),
    "PG-CFG-009": ("shared_preload_libraries", "'pgaudit'"),
    "PG-LOG-001": ("logging_collector", "on"),
    "PG-LOG-002": ("log_connections", "on"),
    "PG-LOG-003": ("log_disconnections", "on"),
    "PG-LOG-005": ("log_error_verbosity", "default"),
    "PG-LOG-006": ("log_line_prefix", "'%t [%p]: [%l-1] user=%u,db=%d,app=%a,client=%h '"),
    "PG-LOG-007": ("log_statement", "ddl"),
    "PG-LOG-008": ("log_min_error_statement", "error"),
    "PG-LOG-009": ("log_min_messages", "warning"),
    "PG-LOG-010": ("pgaudit.log", "'ddl,write,role,connection'"),
    "PG-LOG-011": ("log_checkpoints", "on"),
    "PG-LOG-012": ("log_lock_waits", "on"),
}


def generate_sql(failures: list[dict]) -> str:
    lines = [HEADER]
    lines.append("-- ── ALTER SYSTEM (runtime config changes) ─────────────────────────\n")

    needs_reload = []
    needs_restart = []

    for r in failures:
        check_id = r.get("check_id", "")
        if check_id in ALTER_SYSTEM_MAP:
            cmd, reload, restart = ALTER_SYSTEM_MAP[check_id]
            comment = f"-- {check_id}: {r.get('title', '')}"
            if r.get("cis_id"):
                comment += f" [{r['cis_id']}]"
            lines.append(comment)
            lines.append(f"ALTER SYSTEM {cmd};\n")
            if reload:
                needs_reload.append(check_id)
            if restart:
                needs_restart.append(check_id)

    lines.append("\n-- ── Privilege Fixes ────────────────────────────────────────────────\n")

    for r in failures:
        check_id = r.get("check_id", "")

        if check_id == "PG-AUTH-006":
            lines.append("-- PG-AUTH-006: Revoke PUBLIC CREATE on public schema")
            lines.append("REVOKE CREATE ON SCHEMA public FROM PUBLIC;")
            lines.append("REVOKE ALL ON DATABASE postgres FROM PUBLIC;\n")

        elif check_id == "PG-PRIV-001":
            lines.append("-- PG-PRIV-001: Revoke PUBLIC table access")
            lines.append("-- Run per-database — adjust schema name as needed")
            lines.append("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;")
            lines.append("REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;")
            lines.append("REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;\n")

        elif check_id == "PG-PRIV-006":
            lines.append("-- PG-PRIV-006: Reset MD5 passwords to SCRAM-SHA-256")
            lines.append("-- Set password_encryption = scram-sha-256 first, then:")
            lines.append("-- ALTER USER <username> WITH PASSWORD '<new_secure_password>';")
            lines.append("-- Repeat for each user listed in the audit finding.\n")

        elif check_id == "PG-PRIV-008":
            lines.append("-- PG-PRIV-008: Set password expiry for login roles")
            lines.append("-- ALTER USER <username> VALID UNTIL '2026-12-31';")
            lines.append("-- Lock expired accounts:")
            lines.append("-- ALTER USER <expired_username> NOLOGIN;\n")

        elif check_id == "PG-AUTH-005":
            actual = r.get("actual", "")
            lines.append(f"-- PG-AUTH-005: Revoke superuser ({actual})")
            lines.append("-- ALTER ROLE <username> NOSUPERUSER;\n")

        elif check_id == "PG-AUTH-007":
            lines.append("-- PG-AUTH-007: Revoke CREATEROLE from application roles")
            lines.append("-- ALTER ROLE <username> NOCREATEROLE;\n")

    lines.append("\n-- ── Apply Configuration ─────────────────────────────────────────────\n")
    if needs_reload and not needs_restart:
        lines.append("-- Reload config (no restart needed for these changes):")
        lines.append("SELECT pg_reload_conf();\n")
    elif needs_restart:
        lines.append(f"-- ⚠️  RESTART REQUIRED for: {', '.join(set(needs_restart))}")
        lines.append("-- After applying ALTER SYSTEM commands above, restart PostgreSQL:")
        lines.append("-- Docker:     docker restart <container>")
        lines.append("-- K8s:        kubectl rollout restart deployment/<name>")
        lines.append("-- systemd:    systemctl restart postgresql")
        lines.append("-- Cloud SQL:  (handled by GCP — modify flags via console/gcloud)\n")

    lines.append("\n-- ── pgaudit Setup (if PG-CFG-009 / PG-LOG-010 failed) ──────────────\n")
    lines.append("-- After restart with pgaudit loaded:")
    lines.append("-- ALTER SYSTEM SET pgaudit.log = 'ddl,write,role,connection';")
    lines.append("-- ALTER SYSTEM SET pgaudit.log_catalog = on;")
    lines.append("-- ALTER SYSTEM SET pgaudit.log_relation = on;")
    lines.append("-- SELECT pg_reload_conf();\n")

    return "\n".join(lines)


def generate_conf(failures: list[dict]) -> str:
    lines = [
        "# postgresql.conf remediation snippet",
        f"# Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "# CIS PostgreSQL 16 Benchmark + DISA STIG + FedRAMP High",
        "# Merge these settings into your postgresql.conf or use ALTER SYSTEM",
        "",
    ]

    seen = set()
    for r in failures:
        check_id = r.get("check_id", "")
        if check_id in CONF_MAP and check_id not in seen:
            seen.add(check_id)
            key, val = CONF_MAP[check_id]
            comment = f"# {check_id}: {r.get('title', '')}"
            if r.get("cis_id"):
                comment += f" [{r['cis_id']}]"
            lines.append(comment)
            lines.append(f"{key} = {val}")
            lines.append("")

    # Always-recommended settings
    lines += [
        "# ── Always recommended ────────────────────────────────────────",
        "log_rotation_age = 1d",
        "log_rotation_size = 100MB",
        "pgaudit.log_catalog = on",
        "pgaudit.log_relation = on",
        "idle_in_transaction_session_timeout = 300000   # 5 min",
        "lock_timeout = 30000                           # 30 sec",
        "statement_timeout = 0                          # Set per-role if needed",
    ]

    return "\n".join(lines)


def generate_hba_notes(failures: list[dict]) -> str:
    lines = [
        "# pg_hba.conf recommended configuration",
        f"# Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "# CIS-PG-4.1/4.2/4.3: No trust, no plaintext password, SCRAM-SHA-256 required",
        "",
        "# TYPE  DATABASE        USER            ADDRESS                 METHOD",
        "",
        "# Local socket — use peer for OS-authenticated postgres superuser",
        "local   all             postgres                                peer",
        "",
        "# Local socket — SCRAM for application users",
        "local   all             all                                     scram-sha-256",
        "",
        "# IPv4 loopback — SCRAM only",
        "host    all             all             127.0.0.1/32            scram-sha-256",
        "",
        "# IPv6 loopback — SCRAM only",
        "host    all             all             ::1/128                 scram-sha-256",
        "",
        "# Remote connections (restrict to specific IPs in production):",
        "# host    all             all             10.0.0.0/8              scram-sha-256",
        "",
        "# SSL-required remote connections (most secure):",
        "# hostssl all             all             10.0.0.0/8              scram-sha-256",
        "",
        "# ⚠️  NEVER use these in production:",
        "# host    all             all             0.0.0.0/0               trust",
        "# host    all             all             0.0.0.0/0               password",
    ]
    return "\n".join(lines)


def main():
    p = argparse.ArgumentParser(
        description="Generate remediation scripts from pg-stig-audit findings",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--findings", required=True, help="Path to pg-audit-results.json")
    p.add_argument("--output-dir", default=".", help="Output directory (default: current dir)")
    p.add_argument("--only-failures", action="store_true",
                   help="Only include FAIL findings (skip WARN)")
    args = p.parse_args()

    try:
        with open(args.findings) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    results = data.get("results", [])
    statuses = {"FAIL", "WARN"} if not args.only_failures else {"FAIL"}
    failures = [r for r in results if r.get("status") in statuses]

    if not failures:
        print("✅ No failures to remediate!")
        sys.exit(0)

    import os
    os.makedirs(args.output_dir, exist_ok=True)

    # SQL
    sql_path = os.path.join(args.output_dir, "remediation.sql")
    with open(sql_path, "w") as f:
        f.write(generate_sql(failures))
    print(f"✅ SQL commands written to: {sql_path}")

    # conf
    conf_path = os.path.join(args.output_dir, "remediation.conf")
    with open(conf_path, "w") as f:
        f.write(generate_conf(failures))
    print(f"✅ postgresql.conf snippet: {conf_path}")

    # pg_hba
    hba_path = os.path.join(args.output_dir, "pg_hba.conf.recommended")
    with open(hba_path, "w") as f:
        f.write(generate_hba_notes(failures))
    print(f"✅ pg_hba.conf template:  {hba_path}")

    print(f"\n📋 Summary: {len(failures)} finding(s) to remediate")
    print("   Review each file carefully before applying to production.")


if __name__ == "__main__":
    main()
