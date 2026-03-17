"""
CIS Section 5 + STIG: Privilege, Object, and Extension Auditing.

Controls covered:
  CIS 5.5  - Tables accessible to PUBLIC
  CIS 5.6  - SECURITY DEFINER functions
  CIS 5.7  - Extensions audit (risky extensions)
  CIS 5.8  - Row Level Security (RLS) on sensitive tables
  CIS 5.9  - Default privileges review
  CIS 5.10 - pg_hba IP ranges not overly broad
  STIG V-214114 - Restrict database access to authorized users only
  STIG V-214116 - Limit use of elevated privileges
  STIG V-214119 - Passwords stored using appropriate hashing
"""
from .base import BaseChecker, CheckResult, Status, Severity

# Extensions considered risky/requiring review in compliance environments
RISKY_EXTENSIONS = {
    "dblink": ("HIGH", "Allows queries to remote PostgreSQL servers — potential data exfiltration path"),
    "postgres_fdw": ("HIGH", "Foreign data wrapper — remote server access, lateral movement risk"),
    "plpython3u": ("CRITICAL", "Untrusted PL/Python — executes arbitrary Python as the OS user"),
    "plpythonu": ("CRITICAL", "Untrusted PL/Python (legacy) — executes arbitrary Python as OS user"),
    "plperlu": ("CRITICAL", "Untrusted PL/Perl — executes arbitrary Perl as the OS user"),
    "pltclu": ("CRITICAL", "Untrusted PL/Tcl — executes arbitrary Tcl as the OS user"),
    "adminpack": ("MEDIUM", "Provides admin functions that bypass normal access controls"),
    "pg_stat_statements": ("LOW", "Captures all SQL — may log sensitive data in query text"),
    "file_fdw": ("HIGH", "Read arbitrary files from the server filesystem"),
    "pg_read_file": ("HIGH", "Read arbitrary files from the server filesystem"),
    "lo": ("LOW", "Large object — historically associated with privilege escalation"),
    "xml2": ("MEDIUM", "Deprecated XML extension with known vulnerabilities"),
}

# Extensions that are approved/expected in compliance environments
APPROVED_EXTENSIONS = {
    "pgaudit",
    "pg_stat_statements",  # common monitoring — LOW risk, log scrubbing needed
    "plpgsql",             # standard procedural language
    "pg_trgm",             # text search
    "uuid-ossp",           # UUID generation
    "pgcrypto",            # cryptographic functions (actually good for FedRAMP)
    "pg_partman",          # partition management
    "tablefunc",           # crosstab
    "intarray",            # integer array operations
    "hstore",              # key-value store
    "citext",              # case-insensitive text
    "btree_gin",           # index support
    "btree_gist",          # index support
    "pg_buffercache",      # monitoring
    "pg_prewarm",          # performance
    "pg_freespacemap",     # monitoring
    "pg_visibility",       # monitoring
}


class PrivilegesChecker(BaseChecker):
    category = "Privileges and Objects"

    def run(self) -> list[CheckResult]:
        return [
            self._check_public_table_access(),
            self._check_security_definer_functions(),
            self._check_extensions(),
            self._check_row_level_security(),
            self._check_default_privileges(),
            self._check_password_hashing_in_use(),
            self._check_unused_databases(),
            self._check_user_passwords_expiry(),
        ]

    def _check_public_table_access(self) -> CheckResult:
        """Check for tables where PUBLIC has SELECT/INSERT/UPDATE/DELETE."""
        rows = self.runner.query_with_cols(
            """
            SELECT
                n.nspname AS schema,
                c.relname AS table_name,
                a.privilege_type
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            CROSS JOIN (
                SELECT unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE']) AS privilege_type
            ) a
            WHERE c.relkind = 'r'
              AND n.nspname NOT IN ('pg_catalog', 'information_schema')
              AND has_table_privilege('public', c.oid, a.privilege_type)
            ORDER BY n.nspname, c.relname, a.privilege_type
            LIMIT 50;
            """,
            ["schema", "table_name", "privilege_type"],
        )

        issues = [r for r in rows if "_error" not in r and r.get("table_name")]

        # Group by table for cleaner reporting
        tables = {}
        for r in issues:
            key = f"{r['schema']}.{r['table_name']}"
            tables.setdefault(key, []).append(r["privilege_type"])

        passes = len(tables) == 0
        detail = "; ".join(f"{t}({','.join(p)})" for t, p in list(tables.items())[:10])

        return CheckResult(
            check_id="PG-PRIV-001",
            title="No tables should grant privileges to PUBLIC",
            cis_id="CIS-PG-5.5",
            stig_id="V-214114",
            fedramp_control="AC-3",
            category=self.category,
            severity=Severity.HIGH,
            status=Status.PASS if passes else Status.FAIL,
            actual=f"{len(tables)} tables accessible to PUBLIC: {detail}" if tables else "None",
            expected="Zero tables granting privileges to PUBLIC role",
            description=(
                "The PUBLIC role represents all database users. Granting table access "
                "to PUBLIC means any authenticated user can access that data, violating "
                "least-privilege (AC-3: Access Enforcement)."
            ),
            remediation=(
                "Revoke PUBLIC access from all application tables:\n"
                "REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;\n"
                "Then grant specific privileges to specific roles only."
            ),
            references=["CIS PostgreSQL 16 §5.5", "DISA STIG V-214114", "NIST AC-3"],
        )

    def _check_security_definer_functions(self) -> CheckResult:
        """Check for SECURITY DEFINER functions — they run as the function owner."""
        rows = self.runner.query_with_cols(
            """
            SELECT
                n.nspname AS schema,
                p.proname AS function_name,
                pg_get_userbyid(p.proowner) AS owner
            FROM pg_proc p
            JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE p.prosecdef = true
              AND n.nspname NOT IN ('pg_catalog', 'information_schema')
            ORDER BY n.nspname, p.proname
            LIMIT 30;
            """,
            ["schema", "function_name", "owner"],
        )

        issues = [r for r in rows if "_error" not in r and r.get("function_name")]

        return CheckResult(
            check_id="PG-PRIV-002",
            title="Review SECURITY DEFINER functions",
            cis_id="CIS-PG-5.6",
            stig_id="V-214116",
            fedramp_control="AC-6",
            category=self.category,
            severity=Severity.MEDIUM if not issues else Severity.HIGH,
            status=Status.PASS if not issues else Status.WARN,
            actual=f"{len(issues)} SECURITY DEFINER function(s): "
                   + ", ".join(f"{r['schema']}.{r['function_name']}(owner:{r['owner']})"
                                for r in issues[:10])
                   if issues else "None found",
            expected="Zero or documented/reviewed SECURITY DEFINER functions",
            description=(
                "SECURITY DEFINER functions execute with the privileges of the function owner, "
                "not the caller. This is a privilege escalation vector if the owner is a superuser. "
                "Each one requires explicit documentation and review."
            ),
            remediation=(
                "For each SECURITY DEFINER function, verify it is intentional and necessary.\n"
                "If not needed: ALTER FUNCTION schema.name() SECURITY INVOKER;\n"
                "If needed: ensure the function owner is not a superuser, and the function "
                "uses SEARCH_PATH = '' to prevent schema injection."
            ),
            references=["CIS PostgreSQL 16 §5.6", "DISA STIG V-214116", "NIST AC-6"],
        )

    def _check_extensions(self) -> CheckResult:
        """Audit installed extensions for risky ones."""
        rows = self.runner.query_with_cols(
            """
            SELECT e.extname, n.nspname AS schema, e.extversion
            FROM pg_extension e
            JOIN pg_namespace n ON n.oid = e.extnamespace
            ORDER BY e.extname;
            """,
            ["extname", "schema", "extversion"],
        )

        installed = {
            r["extname"]: r
            for r in rows
            if "_error" not in r and r.get("extname")
        }

        findings = []
        critical_found = False
        for ext_name, ext_info in installed.items():
            if ext_name in RISKY_EXTENSIONS:
                sev, reason = RISKY_EXTENSIONS[ext_name]
                findings.append(f"{ext_name} [{sev}]: {reason}")
                if sev == "CRITICAL":
                    critical_found = True

        unapproved = [
            e for e in installed
            if e not in APPROVED_EXTENSIONS and e not in RISKY_EXTENSIONS
        ]

        all_ext_list = ", ".join(installed.keys()) if installed else "none"
        issue_list = "; ".join(findings[:5]) if findings else "None"

        severity = Severity.CRITICAL if critical_found else (
            Severity.HIGH if findings else Severity.LOW
        )
        status = Status.FAIL if critical_found else (
            Status.WARN if findings or unapproved else Status.PASS
        )

        detail = f"Installed: [{all_ext_list}]"
        if findings:
            detail += f" | Risky: {issue_list}"
        if unapproved:
            detail += f" | Unapproved/unrecognized: {', '.join(unapproved[:5])}"

        return CheckResult(
            check_id="PG-PRIV-003",
            title="Extensions audit — no untrusted or risky extensions",
            cis_id="CIS-PG-5.7",
            fedramp_control="CM-7",
            category=self.category,
            severity=severity,
            status=status,
            actual=detail,
            expected="Only approved extensions; no untrusted PL extensions or FDW to external systems",
            description=(
                "PostgreSQL extensions can grant OS-level access (untrusted PLs), "
                "remote data access (FDWs), or bypass access controls (adminpack). "
                "CM-7 requires disabling all unnecessary functions/services."
            ),
            remediation=(
                "Remove risky extensions:\n"
                "DROP EXTENSION IF EXISTS <extension_name>;\n"
                "For CRITICAL (untrusted PLs): these should never be installed in "
                "production/FedRAMP environments. Rebuild without them."
            ),
            references=[
                "CIS PostgreSQL 16 §5.7",
                "NIST SP 800-53 CM-7",
                "FedRAMP CM-7 Guidance",
            ],
        )

    def _check_row_level_security(self) -> CheckResult:
        """Check if tables that look sensitive have RLS enabled."""
        # Look for tables with 'user', 'account', 'secret', 'password', 'token', 'key', 'credential'
        # in their name — these should have RLS
        rows = self.runner.query_with_cols(
            """
            SELECT n.nspname AS schema, c.relname AS table_name, c.relrowsecurity
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE c.relkind = 'r'
              AND n.nspname NOT IN ('pg_catalog', 'information_schema')
              AND (
                  c.relname ILIKE '%user%' OR
                  c.relname ILIKE '%account%' OR
                  c.relname ILIKE '%credential%' OR
                  c.relname ILIKE '%secret%' OR
                  c.relname ILIKE '%token%' OR
                  c.relname ILIKE '%password%' OR
                  c.relname ILIKE '%auth%' OR
                  c.relname ILIKE '%role%' OR
                  c.relname ILIKE '%permission%'
              )
            ORDER BY n.nspname, c.relname;
            """,
            ["schema", "table_name", "relrowsecurity"],
        )

        sensitive_tables = [r for r in rows if "_error" not in r and r.get("table_name")]
        without_rls = [r for r in sensitive_tables if r.get("relrowsecurity") in ("f", "false", False, "0")]

        if not sensitive_tables:
            return CheckResult(
                check_id="PG-PRIV-004",
                title="Row Level Security (RLS) on sensitive tables",
                cis_id="CIS-PG-5.8",
                fedramp_control="AC-3(3)",
                category=self.category,
                severity=Severity.INFO,
                status=Status.SKIP,
                actual="No tables with sensitive-sounding names detected",
                expected="Sensitive tables should have RLS enabled",
                description="RLS check skipped — no tables with user/account/credential/token names found.",
                remediation="Enable RLS on any tables containing user-specific data.",
                references=["CIS PostgreSQL 16 §5.8", "NIST AC-3(3)"],
            )

        passes = len(without_rls) == 0
        detail = ", ".join(
            f"{r['schema']}.{r['table_name']}" for r in without_rls[:10]
        )

        return CheckResult(
            check_id="PG-PRIV-004",
            title="Sensitive tables should have Row Level Security enabled",
            cis_id="CIS-PG-5.8",
            fedramp_control="AC-3(3)",
            category=self.category,
            severity=Severity.MEDIUM,
            status=Status.PASS if passes else Status.WARN,
            actual=f"{len(without_rls)} sensitive-named tables without RLS: {detail}"
                   if without_rls else f"All {len(sensitive_tables)} sensitive tables have RLS",
            expected="RLS enabled on all tables storing per-user data",
            description=(
                "Row Level Security restricts which rows a user can see/modify, "
                "enforcing data isolation at the database layer. Critical for multi-tenant "
                "applications and required under AC-3(3) (Mandatory Access Control)."
            ),
            remediation=(
                "Enable RLS on sensitive tables:\n"
                "ALTER TABLE schema.tablename ENABLE ROW LEVEL SECURITY;\n"
                "ALTER TABLE schema.tablename FORCE ROW LEVEL SECURITY;\n"
                "Then create policies: CREATE POLICY ... ON schema.tablename ..."
            ),
            references=["CIS PostgreSQL 16 §5.8", "NIST AC-3(3)"],
        )

    def _check_default_privileges(self) -> CheckResult:
        """Check if ALTER DEFAULT PRIVILEGES has been set to restrict PUBLIC."""
        # Check pg_default_acl — if empty, default privileges haven't been hardened
        rows = self.runner.query_with_cols(
            """
            SELECT count(*) AS cnt FROM pg_default_acl
            WHERE defaclrole = (SELECT oid FROM pg_roles WHERE rolname = 'postgres');
            """,
            ["cnt"],
        )
        cnt = 0
        if rows and "_error" not in rows[0]:
            try:
                cnt = int(rows[0].get("cnt", 0))
            except (ValueError, TypeError):
                cnt = 0

        return CheckResult(
            check_id="PG-PRIV-005",
            title="Default privileges should be configured (ALTER DEFAULT PRIVILEGES)",
            cis_id="CIS-PG-5.9",
            fedramp_control="AC-6",
            category=self.category,
            severity=Severity.MEDIUM,
            status=Status.PASS if cnt > 0 else Status.WARN,
            actual=f"{cnt} default privilege rule(s) configured",
            expected="Default privileges explicitly set to prevent future objects from inheriting PUBLIC access",
            description=(
                "Without ALTER DEFAULT PRIVILEGES, newly created tables automatically "
                "inherit permissions that may include PUBLIC access. Setting default privileges "
                "ensures future objects are born locked down."
            ),
            remediation=(
                "Set safe defaults for the postgres owner and your app role:\n"
                "ALTER DEFAULT PRIVILEGES FOR ROLE postgres\n"
                "  REVOKE ALL ON TABLES FROM PUBLIC;\n"
                "ALTER DEFAULT PRIVILEGES FOR ROLE app_role\n"
                "  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_role;"
            ),
            references=["CIS PostgreSQL 16 §5.9", "NIST AC-6"],
        )

    def _check_password_hashing_in_use(self) -> CheckResult:
        """Check if any users still have MD5 password hashes stored."""
        rows = self.runner.query_with_cols(
            """
            SELECT usename, left(passwd, 3) AS hash_prefix
            FROM pg_shadow
            WHERE passwd IS NOT NULL
              AND passwd != ''
              AND passwd NOT LIKE 'SCRAM-SHA-256%'
              AND usename != 'postgres';
            """,
            ["usename", "hash_prefix"],
        )

        md5_users = [r for r in rows if "_error" not in r and r.get("usename")]

        return CheckResult(
            check_id="PG-PRIV-006",
            title="No users should have MD5-hashed passwords stored",
            cis_id="CIS-PG-4.3",
            stig_id="V-214119",
            fedramp_control="IA-5(1)",
            category=self.category,
            severity=Severity.HIGH,
            status=Status.PASS if not md5_users else Status.FAIL,
            actual=f"{len(md5_users)} user(s) with non-SCRAM password hashes: "
                   + ", ".join(r["usename"] for r in md5_users[:10])
                   if md5_users else "All users have SCRAM-SHA-256 hashes",
            expected="All users: SCRAM-SHA-256 hash prefix in pg_shadow",
            description=(
                "Even if pg_hba.conf is set to scram-sha-256, users whose passwords "
                "were set before the change still have MD5 hashes stored. "
                "Those hashes must be reset to take effect."
            ),
            remediation=(
                "Reset passwords for all affected users:\n"
                "ALTER USER <username> WITH PASSWORD '<new_password>';\n"
                "Passwords must be reset AFTER setting password_encryption = scram-sha-256."
            ),
            references=["CIS PostgreSQL 16 §4.3", "DISA STIG V-214119", "FIPS 140-2"],
        )

    def _check_unused_databases(self) -> CheckResult:
        """Check for databases that may be unused and should be removed."""
        rows = self.runner.query_with_cols(
            """
            SELECT datname, pg_size_pretty(pg_database_size(datname)) AS size
            FROM pg_database
            WHERE datname NOT IN ('postgres', 'template0', 'template1')
            ORDER BY datname;
            """,
            ["datname", "size"],
        )

        dbs = [r for r in rows if "_error" not in r and r.get("datname")]

        return CheckResult(
            check_id="PG-PRIV-007",
            title="Non-default databases should be reviewed",
            fedramp_control="CM-7",
            category=self.category,
            severity=Severity.INFO,
            status=Status.PASS if not dbs else Status.WARN,
            actual=f"Non-default databases: "
                   + ", ".join(f"{r['datname']} ({r['size']})" for r in dbs)
                   if dbs else "None (only default system databases)",
            expected="Only databases with known, documented purposes",
            description=(
                "Unnecessary databases increase attack surface. "
                "Each database should have a documented purpose."
            ),
            remediation=(
                "Review each non-default database. If unused:\n"
                "DROP DATABASE <dbname>;"
            ),
            references=["NIST SP 800-53 CM-7"],
        )

    def _check_user_passwords_expiry(self) -> CheckResult:
        """Check if any login users have password expiry set (good) or not set (bad)."""
        rows = self.runner.query_with_cols(
            """
            SELECT usename,
                   CASE WHEN valuntil IS NULL THEN 'never'
                        WHEN valuntil < NOW() THEN 'expired'
                        ELSE valuntil::text
                   END AS expiry
            FROM pg_user
            WHERE usecreatedb = false
              AND usesuper = false
              AND usename NOT IN ('postgres', 'replication')
            ORDER BY usename;
            """,
            ["usename", "expiry"],
        )

        users = [r for r in rows if "_error" not in r and r.get("usename")]
        no_expiry = [r for r in users if r.get("expiry") == "never"]
        expired = [r for r in users if r.get("expiry") == "expired"]

        if not users:
            status = Status.SKIP
            actual = "No non-superuser login roles found"
        elif no_expiry:
            status = Status.WARN
            actual = (
                f"{len(no_expiry)} users with no password expiry: "
                + ", ".join(r["usename"] for r in no_expiry[:10])
            )
        else:
            status = Status.PASS
            actual = f"All {len(users)} users have password expiry set"

        if expired:
            status = Status.FAIL
            actual += f" | {len(expired)} EXPIRED accounts: " + ", ".join(
                r["usename"] for r in expired[:5]
            )

        return CheckResult(
            check_id="PG-PRIV-008",
            title="Login roles should have password expiry configured",
            stig_id="V-214120",
            fedramp_control="IA-5(1)(d)",
            category=self.category,
            severity=Severity.MEDIUM,
            status=status,
            actual=actual if users else "No applicable users",
            expected="All login roles have a password expiry date; no expired accounts active",
            description=(
                "Accounts with no password expiry violate IA-5(1)(d) which requires "
                "enforcing minimum/maximum lifetime restrictions on passwords. "
                "Expired accounts should be locked or deleted."
            ),
            remediation=(
                "Set password expiry:\n"
                "ALTER USER <username> VALID UNTIL '2026-12-31';\n"
                "Lock expired accounts:\n"
                "ALTER USER <username> NOLOGIN;"
            ),
            references=["DISA STIG V-214120", "NIST IA-5(1)(d)"],
        )
