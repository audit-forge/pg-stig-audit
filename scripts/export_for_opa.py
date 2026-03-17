#!/usr/bin/env python3
"""
export_for_opa.py — Export live PostgreSQL settings to JSON for OPA/conftest testing.

Dumps the current PostgreSQL configuration (settings, pg_hba rules, superusers,
installed extensions) into the JSON shape that rego/pg_audit.rego expects.

This lets you:
  1. Test your Rego policies against a real database without running the full audit
  2. Store snapshots of config for historical comparison
  3. Run conftest in CI against a policy-as-code repository

Usage:
  # Against a Docker container:
  python3 scripts/export_for_opa.py --mode docker --container my-postgres > pg-settings.json
  conftest test --policy rego/ pg-settings.json

  # Against Cloud SQL via proxy:
  python3 scripts/export_for_opa.py --mode direct --host 127.0.0.1 --port 5432 > pg-settings.json

  # Validate inline:
  python3 scripts/export_for_opa.py --mode docker --container pg | opa eval \\
      -d rego/pg_audit.rego \\
      -I \\
      --format pretty \\
      'data.postgresql.cis_stig.deny'
"""
import argparse
import json
import sys
import os
import re

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from runner import PgRunner

_SAFE_SETTING_RE = re.compile(r"^[a-zA-Z0-9_.]+$")

# Settings to capture (from postgresql.conf / pg_settings)
SETTINGS_TO_CAPTURE = [
    "ssl",
    "ssl_min_protocol_version",
    "ssl_ciphers",
    "ssl_cert_file",
    "ssl_key_file",
    "ssl_ca_file",
    "password_encryption",
    "listen_addresses",
    "port",
    "max_connections",
    "shared_preload_libraries",
    "logging_collector",
    "log_destination",
    "log_directory",
    "log_filename",
    "log_connections",
    "log_disconnections",
    "log_duration",
    "log_min_duration_statement",
    "log_error_verbosity",
    "log_hostname",
    "log_line_prefix",
    "log_statement",
    "log_min_messages",
    "log_min_error_statement",
    "log_checkpoints",
    "log_lock_waits",
    "log_temp_files",
    "fsync",
    "full_page_writes",
    "idle_session_timeout",
    "idle_in_transaction_session_timeout",
    "statement_timeout",
    "lock_timeout",
    "wal_level",
    "archive_mode",
    "pgaudit.log",
    "pgaudit.log_catalog",
    "pgaudit.log_relation",
]


def export(runner: PgRunner) -> dict:
    """Export all relevant PostgreSQL settings to a dict."""

    # 1. Core settings
    settings = {}
    for name in SETTINGS_TO_CAPTURE:
        if not _SAFE_SETTING_RE.match(name):
            settings[name] = None
            continue
        rows = runner.query_with_cols(
            f"SELECT setting FROM pg_settings WHERE name = '{name}';",  # nosec B608 (allowlisted setting names)
            ["setting"],
        )
        if rows and "_error" not in rows[0]:
            settings[name] = rows[0].get("setting", "")
        else:
            settings[name] = None  # Setting doesn't exist (e.g. pgaudit not loaded)

    # 2. pg_hba rules
    hba_rows = runner.query_with_cols(
        """
        SELECT
            line_number::text,
            type,
            database::text,
            user_name::text,
            address,
            netmask,
            auth_method,
            options::text
        FROM pg_hba_file_rules
        WHERE auth_method IS NOT NULL
        ORDER BY line_number;
        """,
        ["line_number", "type", "database", "user_name", "address", "netmask", "auth_method", "options"],
    )
    hba_rules = [r for r in hba_rows if "_error" not in r and r.get("auth_method")]

    # 3. Superusers
    superuser_rows = runner.query_with_cols(
        "SELECT usename FROM pg_user WHERE usesuper = true;",
        ["usename"]
    )
    superusers = [r.get("usename") for r in superuser_rows if "_error" not in r and r.get("usename")]

    # 4. Installed extensions
    ext_rows = runner.query_with_cols(
        "SELECT extname, extversion FROM pg_extension ORDER BY extname;",
        ["extname", "extversion"]
    )
    extensions = {
        r["extname"]: r["extversion"]
        for r in ext_rows
        if "_error" not in r and r.get("extname")
    }

    # 5. Login roles summary
    role_rows = runner.query_with_cols(
        """
        SELECT
            usename,
            usesuper::text,
            usecreatedb::text,
            usecreaterole::text,
            COALESCE(valuntil::text, 'never') AS password_expiry
        FROM pg_user
        ORDER BY usename;
        """,
        ["usename", "usesuper", "usecreatedb", "usecreaterole", "password_expiry"],
    )
    roles = [r for r in role_rows if "_error" not in r and r.get("usename")]

    # 6. PostgreSQL version
    ver_rows = runner.query_with_cols("SELECT version();", ["version"])
    pg_version = ver_rows[0].get("version", "unknown") if ver_rows and "_error" not in ver_rows[0] else "unknown"

    return {
        "postgresql": {
            "version": pg_version,
            "settings": settings,
            "hba_rules": hba_rules,
            "superusers": superusers,
            "extensions": extensions,
            "roles": roles,
        }
    }


def main():
    p = argparse.ArgumentParser(
        description="Export PostgreSQL config to JSON for OPA/conftest testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--mode", choices=["docker", "kubectl", "direct"], default="docker")
    p.add_argument("--container", help="Docker container name")
    p.add_argument("--pod", help="Kubernetes pod name")
    p.add_argument("--namespace", default="default")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=5432)
    p.add_argument("--user", default="postgres")
    p.add_argument("--password")
    p.add_argument("--database", default="postgres")
    p.add_argument("--output", "-o", help="Output file (default: stdout)")
    p.add_argument("--pretty", action="store_true", default=True, help="Pretty-print JSON")
    args = p.parse_args()

    runner = PgRunner(
        mode=args.mode,
        container=args.container,
        pod=args.pod,
        namespace=args.namespace,
        host=args.host,
        port=args.port,
        user=args.user,
        password=args.password or os.environ.get("PGPASSWORD"),
        database=args.database,
    )

    if not runner.test_connection():
        print("ERROR: Cannot connect to PostgreSQL.", file=sys.stderr)
        sys.exit(1)

    data = export(runner)
    output = json.dumps(data, indent=2 if args.pretty else None, default=str)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"✅ Settings exported to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
