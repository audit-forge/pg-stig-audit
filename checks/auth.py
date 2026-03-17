"""
CIS Section 4/5 + STIG: Authentication and pg_hba.conf Checks.

Controls covered:
  CIS 4.1  - No 'trust' authentication
  CIS 4.2  - No unencrypted 'password' auth (use md5/scram-sha-256)
  CIS 4.3  - SCRAM-SHA-256 preferred over MD5
  CIS 5.1  - Superuser access limited
  CIS 5.2  - postgres superuser cannot login remotely
  STIG V-214117 - No trust authentication
  STIG V-214118 - Password required for all connections
  STIG V-214115 - Superuser remote login prohibited
"""
from .base import BaseChecker, CheckResult, Status, Severity


class AuthChecker(BaseChecker):
    category = "Authentication"

    def run(self) -> list[CheckResult]:
        return [
            self._check_no_trust_auth(),
            self._check_no_plaintext_password(),
            self._check_scram_over_md5(),
            self._check_superuser_remote_login(),
            self._check_superuser_count(),
            self._check_default_roles(),
            self._check_public_schema_access(),
        ]

    def _get_hba_entries(self) -> list[dict]:
        """Get pg_hba_file_rules (available in PG 10+)."""
        rows = self.runner.query_with_cols(
            """
            SELECT type, database, user_name, address, auth_method
            FROM pg_hba_file_rules
            WHERE auth_method IS NOT NULL
            ORDER BY line_number;
            """,
            ["type", "database", "user_name", "address", "auth_method"],
        )
        return [r for r in rows if "_error" not in r]

    def _check_no_trust_auth(self) -> CheckResult:
        entries = self._get_hba_entries()
        trust_entries = [e for e in entries if e.get("auth_method") == "trust"]

        passes = len(trust_entries) == 0
        detail = ""
        if trust_entries:
            detail = "; ".join(
                f"type={e['type']} db={e['database']} user={e['user_name']} addr={e['address']}"
                for e in trust_entries
            )

        return CheckResult(
            check_id="PG-AUTH-001",
            title="No 'trust' authentication allowed in pg_hba.conf",
            cis_id="CIS-PG-4.1",
            stig_id="V-214117",
            fedramp_control="IA-2",
            category=self.category,
            severity=Severity.CRITICAL,
            status=Status.PASS if passes else Status.FAIL,
            actual=f"{len(trust_entries)} trust entries: {detail}" if trust_entries else "No trust entries",
            expected="Zero trust authentication entries",
            description=(
                "trust authentication allows connections without a password. "
                "This is a critical misconfiguration that bypasses all authentication controls."
            ),
            remediation=(
                "Remove or replace all 'trust' entries in pg_hba.conf with "
                "'scram-sha-256' or 'cert' (certificate-based). "
                "Even localhost trust is prohibited in compliance environments."
            ),
            references=[
                "CIS PostgreSQL 16 §4.1",
                "DISA STIG V-214117",
                "NIST SP 800-53 IA-2",
            ],
        )

    def _check_no_plaintext_password(self) -> CheckResult:
        entries = self._get_hba_entries()
        plain_entries = [e for e in entries if e.get("auth_method") == "password"]

        passes = len(plain_entries) == 0
        detail = ""
        if plain_entries:
            detail = "; ".join(
                f"type={e['type']} db={e['database']} addr={e['address']}"
                for e in plain_entries
            )

        return CheckResult(
            check_id="PG-AUTH-002",
            title="No plaintext 'password' auth method in pg_hba.conf",
            cis_id="CIS-PG-4.2",
            stig_id="V-214118",
            fedramp_control="IA-5(1)",
            category=self.category,
            severity=Severity.HIGH,
            status=Status.PASS if passes else Status.FAIL,
            actual=f"{len(plain_entries)} plaintext password entries: {detail}" if plain_entries else "None",
            expected="Zero 'password' (cleartext) entries",
            description=(
                "The 'password' auth method sends credentials in cleartext over the wire. "
                "Use 'scram-sha-256' which performs challenge-response authentication "
                "without exposing the password."
            ),
            remediation=(
                "Replace 'password' with 'scram-sha-256' in pg_hba.conf. "
                "Ensure password_encryption = scram-sha-256 in postgresql.conf. "
                "Passwords must be reset after changing encryption method."
            ),
            references=["CIS PostgreSQL 16 §4.2", "DISA STIG V-214118"],
        )

    def _check_scram_over_md5(self) -> CheckResult:
        entries = self._get_hba_entries()
        md5_entries = [e for e in entries if e.get("auth_method") == "md5"]
        scram_entries = [e for e in entries if e.get("auth_method") == "scram-sha-256"]

        passes = len(md5_entries) == 0
        return CheckResult(
            check_id="PG-AUTH-003",
            title="SCRAM-SHA-256 should be used instead of MD5",
            cis_id="CIS-PG-4.3",
            fedramp_control="IA-5(1)",
            category=self.category,
            severity=Severity.HIGH,
            status=Status.PASS if passes else Status.FAIL,
            actual=f"{len(md5_entries)} MD5 entries, {len(scram_entries)} SCRAM entries",
            expected="Zero MD5 entries; use scram-sha-256",
            description=(
                "MD5 password hashing is cryptographically broken (vulnerable to collision attacks). "
                "SCRAM-SHA-256 is FIPS-140-2 compatible and required for FedRAMP environments."
            ),
            remediation=(
                "Replace 'md5' with 'scram-sha-256' in pg_hba.conf entries. "
                "Set password_encryption = scram-sha-256 in postgresql.conf. "
                "All user passwords must be re-set to store SCRAM hashes."
            ),
            references=[
                "CIS PostgreSQL 16 §4.3",
                "NIST SP 800-132",
                "FIPS 140-2",
            ],
        )

    def _check_superuser_remote_login(self) -> CheckResult:
        entries = self._get_hba_entries()
        # Check for remote (non-local, non-127.0.0.1) entries allowing all users or superusers
        risky = []
        for e in entries:
            addr = e.get("address", "") or ""
            type_ = e.get("type", "") or ""
            user = e.get("user_name", "") or ""
            method = e.get("auth_method", "") or ""

            is_remote = type_ == "host" and addr not in ("127.0.0.1/32", "::1/128", "")
            is_all_users = user in ("all", "{all}")
            is_not_rejected = method not in ("reject", "deny")

            if is_remote and is_all_users and is_not_rejected:
                risky.append(e)

        # Also check: superuser attribute
        rows = self.runner.query_with_cols(
            "SELECT usename FROM pg_user WHERE usesuper = true;",
            ["usename"]
        )
        superusers = [r.get("usename") for r in rows if "_error" not in r]

        passes = len(risky) == 0
        return CheckResult(
            check_id="PG-AUTH-004",
            title="Superusers should not be accessible via remote broad-access rules",
            cis_id="CIS-PG-5.2",
            stig_id="V-214115",
            fedramp_control="AC-6(2)",
            category=self.category,
            severity=Severity.HIGH,
            status=Status.PASS if passes else Status.WARN,
            actual=(
                f"Broad remote rules: {len(risky)}; Superusers: {', '.join(superusers)}"
            ),
            expected="No broad remote rules that grant all users access; superusers should use local socket",
            description=(
                "Superuser accounts should only connect via local Unix socket. "
                "Remote superuser access violates least-privilege principles (AC-6)."
            ),
            remediation=(
                "Add a specific reject rule for the postgres superuser on remote connections:\n"
                "# TYPE  DATABASE  USER      ADDRESS     METHOD\n"
                "host    all       postgres  0.0.0.0/0   reject\n"
                "Place this BEFORE any 'all users' rules."
            ),
            references=["CIS PostgreSQL 16 §5.2", "DISA STIG V-214115", "NIST AC-6(2)"],
        )

    def _check_superuser_count(self) -> CheckResult:
        rows = self.runner.query_with_cols(
            "SELECT usename FROM pg_user WHERE usesuper = true;",
            ["usename"]
        )
        superusers = [r.get("usename") for r in rows if "_error" not in r and r.get("usename")]
        expected_superusers = {"postgres"}
        unexpected = [u for u in superusers if u not in expected_superusers]

        passes = len(unexpected) == 0
        return CheckResult(
            check_id="PG-AUTH-005",
            title="Only 'postgres' should have superuser privilege",
            cis_id="CIS-PG-5.1",
            stig_id="V-214113",
            fedramp_control="AC-6",
            category=self.category,
            severity=Severity.HIGH,
            status=Status.PASS if passes else Status.FAIL,
            actual=f"Superusers: {', '.join(superusers) if superusers else 'none'}",
            expected="Only 'postgres' (or no application users with superuser)",
            description=(
                "Superuser privilege grants unrestricted database access. "
                "Application accounts must never have superuser rights. "
                "Least-privilege principle (AC-6) requires minimizing superuser accounts."
            ),
            remediation=(
                f"Revoke superuser from: {', '.join(unexpected)}\n"
                "ALTER ROLE <rolename> NOSUPERUSER;"
            ) if unexpected else "No action required.",
            references=["CIS PostgreSQL 16 §5.1", "DISA STIG V-214113", "NIST AC-6"],
        )

    def _check_default_roles(self) -> CheckResult:
        # Check if PUBLIC role has been granted risky privileges
        rows = self.runner.query_with_cols(
            """
            SELECT nspname FROM pg_namespace
            WHERE nspname = 'public'
            AND has_schema_privilege('public', nspname, 'CREATE');
            """,
            ["nspname"]
        )
        public_can_create = bool([r for r in rows if "_error" not in r and r.get("nspname")])

        return CheckResult(
            check_id="PG-AUTH-006",
            title="PUBLIC role should not have CREATE on public schema",
            cis_id="CIS-PG-5.3",
            fedramp_control="AC-6",
            category=self.category,
            severity=Severity.MEDIUM,
            status=Status.FAIL if public_can_create else Status.PASS,
            actual="PUBLIC can CREATE in public schema" if public_can_create else "PUBLIC cannot CREATE in public schema",
            expected="PUBLIC has no CREATE privilege on public schema",
            description=(
                "By default (pre-PG 15), PUBLIC can create objects in the public schema. "
                "This allows any user to inject malicious code or shadow system objects."
            ),
            remediation=(
                "Revoke CREATE from public schema:\n"
                "REVOKE CREATE ON SCHEMA public FROM PUBLIC;\n"
                "REVOKE ALL ON DATABASE <dbname> FROM PUBLIC;"
            ),
            references=["CIS PostgreSQL 16 §5.3", "NIST AC-6", "CVE-2018-1058"],
        )

    def _check_public_schema_access(self) -> CheckResult:
        rows = self.runner.query_with_cols(
            """
            SELECT count(*) AS cnt FROM pg_roles
            WHERE rolname != 'postgres'
            AND rolcanlogin = true
            AND rolsuper = false
            AND rolcreaterole = true;
            """,
            ["cnt"]
        )
        cnt = 0
        if rows and "_error" not in rows[0]:
            try:
                cnt = int(rows[0].get("cnt", 0))
            except (ValueError, TypeError):
                cnt = 0

        return CheckResult(
            check_id="PG-AUTH-007",
            title="Non-superuser login roles should not have CREATEROLE",
            cis_id="CIS-PG-5.4",
            fedramp_control="AC-6",
            category=self.category,
            severity=Severity.MEDIUM,
            status=Status.PASS if cnt == 0 else Status.FAIL,
            actual=f"{cnt} non-superuser login roles with CREATEROLE",
            expected="0",
            description=(
                "CREATEROLE allows a role to create other roles, including granting "
                "themselves elevated privileges via role inheritance. This is a privilege escalation risk."
            ),
            remediation="ALTER ROLE <rolename> NOCREATEROLE; for all application/service accounts.",
            references=["CIS PostgreSQL 16 §5.4", "NIST AC-6"],
        )
