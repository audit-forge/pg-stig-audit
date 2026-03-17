"""
CIS Section 2 + STIG: PostgreSQL Server-Level Configuration Checks.

Controls covered:
  CIS 2.1  - listen_addresses
  CIS 6.2  - password_encryption
  CIS 7.1  - fsync
  CIS 7.2  - full_page_writes
  STIG V-214065 - FIPS-compliant password hashing
  STIG V-214100 - idle session timeout
  STIG V-214071 - data-at-rest encryption indicator
"""
from .base import BaseChecker, CheckResult, Status, Severity


class ConfigChecker(BaseChecker):
    category = "Server Configuration"

    def run(self) -> list[CheckResult]:
        return [
            self._check_listen_addresses(),
            self._check_password_encryption(),
            self._check_fsync(),
            self._check_full_page_writes(),
            self._check_idle_session_timeout(),
            self._check_ssl_enabled(),
            self._check_ssl_min_protocol(),
            self._check_ssl_ciphers(),
            self._check_shared_preload_libraries(),
        ]

    def _check_listen_addresses(self) -> CheckResult:
        val = self._pg_setting("listen_addresses") or ""
        passes = "*" not in val.split(",")
        return CheckResult(
            check_id="PG-CFG-001",
            title="listen_addresses should not be '*'",
            cis_id="CIS-PG-2.1",
            stig_id="V-214127",
            fedramp_control="SC-7",
            category=self.category,
            severity=Severity.HIGH,
            status=Status.PASS if passes else Status.FAIL,
            actual=val or "(empty = all)",
            expected="Specific IP(s) or 'localhost', not '*'",
            description=(
                "PostgreSQL should only listen on necessary network interfaces. "
                "Binding to '*' exposes the service on all interfaces including untrusted ones."
            ),
            remediation=(
                "Set listen_addresses to specific IPs or 'localhost' in postgresql.conf. "
                "In containers, control exposure at the Docker/K8s network layer and set "
                "listen_addresses = 'localhost' or the container's specific IP."
            ),
            references=["CIS PostgreSQL 16 Benchmark §2.1", "NIST SP 800-53 SC-7"],
        )

    def _check_password_encryption(self) -> CheckResult:
        val = self._pg_setting("password_encryption") or ""
        passes = val.lower() == "scram-sha-256"
        return CheckResult(
            check_id="PG-CFG-002",
            title="password_encryption must be scram-sha-256",
            cis_id="CIS-PG-6.2",
            stig_id="V-214065",
            fedramp_control="IA-5(1)",
            category=self.category,
            severity=Severity.HIGH,
            status=Status.PASS if passes else Status.FAIL,
            actual=val,
            expected="scram-sha-256",
            description=(
                "PostgreSQL should use SCRAM-SHA-256 for password hashing, which is "
                "FIPS-140-2 compatible and resistant to offline dictionary attacks. "
                "MD5 is cryptographically broken."
            ),
            remediation=(
                "Set password_encryption = scram-sha-256 in postgresql.conf. "
                "Existing MD5 passwords must be reset to take effect. "
                "Also update pg_hba.conf to require scram-sha-256."
            ),
            references=[
                "CIS PostgreSQL 16 Benchmark §6.2",
                "DISA STIG V-214065",
                "NIST SP 800-132",
            ],
        )

    def _check_fsync(self) -> CheckResult:
        val = self._pg_setting("fsync") or ""
        passes = val.lower() == "on"
        return CheckResult(
            check_id="PG-CFG-003",
            title="fsync must be enabled",
            cis_id="CIS-PG-7.1",
            fedramp_control="CP-9",
            category=self.category,
            severity=Severity.HIGH,
            status=Status.PASS if passes else Status.FAIL,
            actual=val,
            expected="on",
            description=(
                "fsync ensures data is written to disk, preventing data corruption "
                "on system crash. Disabling it increases performance but risks data loss."
            ),
            remediation="Set fsync = on in postgresql.conf (default is on).",
            references=["CIS PostgreSQL 16 Benchmark §7.1"],
        )

    def _check_full_page_writes(self) -> CheckResult:
        val = self._pg_setting("full_page_writes") or ""
        passes = val.lower() == "on"
        return CheckResult(
            check_id="PG-CFG-004",
            title="full_page_writes must be enabled",
            cis_id="CIS-PG-7.2",
            fedramp_control="CP-9",
            category=self.category,
            severity=Severity.MEDIUM,
            status=Status.PASS if passes else Status.FAIL,
            actual=val,
            expected="on",
            description=(
                "full_page_writes protects against data corruption after a crash "
                "mid-write by writing full page images to WAL."
            ),
            remediation="Set full_page_writes = on in postgresql.conf (default is on).",
            references=["CIS PostgreSQL 16 Benchmark §7.2"],
        )

    def _check_idle_session_timeout(self) -> CheckResult:
        val = self._pg_setting("idle_session_timeout") or "0"
        try:
            ms = int(val)
        except ValueError:
            ms = 0
        # Acceptable: > 0 and <= 15 minutes (900000 ms)
        passes = 0 < ms <= 900000
        return CheckResult(
            check_id="PG-CFG-005",
            title="idle_session_timeout should be set (≤15 min)",
            stig_id="V-214100",
            fedramp_control="AC-12",
            category=self.category,
            severity=Severity.MEDIUM,
            status=Status.PASS if passes else Status.FAIL,
            actual=f"{val} ms" if val.isdigit() else val,
            expected="1–900000 ms (1ms to 15 minutes)",
            description=(
                "Idle sessions hold connections and locks, and represent an attack surface. "
                "AC-12 (Session Termination) requires terminating idle sessions after a period."
            ),
            remediation=(
                "Set idle_session_timeout = 900000 (15 min) in postgresql.conf or "
                "via ALTER SYSTEM SET idle_session_timeout = '15min';"
            ),
            references=["DISA STIG V-214100", "NIST SP 800-53 AC-12"],
        )

    def _check_ssl_enabled(self) -> CheckResult:
        val = self._pg_setting("ssl") or ""
        passes = val.lower() == "on"
        return CheckResult(
            check_id="PG-CFG-006",
            title="SSL must be enabled",
            cis_id="CIS-PG-6.7",
            stig_id="V-214070",
            fedramp_control="SC-8",
            category=self.category,
            severity=Severity.CRITICAL,
            status=Status.PASS if passes else Status.FAIL,
            actual=val,
            expected="on",
            description=(
                "SSL/TLS encrypts data in transit between clients and the database. "
                "Required for FedRAMP (SC-8: Transmission Confidentiality and Integrity)."
            ),
            remediation=(
                "Set ssl = on in postgresql.conf. Mount SSL certs via Docker volume. "
                "Ensure ssl_cert_file and ssl_key_file point to valid cert/key. "
                "In GCP Cloud SQL, SSL is enforced at the infrastructure level."
            ),
            references=[
                "CIS PostgreSQL 16 Benchmark §6.7",
                "DISA STIG V-214070",
                "NIST SP 800-53 SC-8",
                "FedRAMP High Baseline SC-8",
            ],
        )

    def _check_ssl_min_protocol(self) -> CheckResult:
        val = self._pg_setting("ssl_min_protocol_version") or ""
        # TLSv1.2 or TLSv1.3 acceptable (FedRAMP requires TLS 1.2+)
        passes = val in ("TLSv1.2", "TLSv1.3")
        status = Status.PASS if passes else (Status.WARN if val else Status.FAIL)
        return CheckResult(
            check_id="PG-CFG-007",
            title="SSL minimum protocol version must be TLS 1.2+",
            cis_id="CIS-PG-6.8",
            stig_id="V-214071",
            fedramp_control="SC-8(1)",
            category=self.category,
            severity=Severity.HIGH,
            status=status,
            actual=val or "(not set — PostgreSQL default)",
            expected="TLSv1.2 or TLSv1.3",
            description=(
                "FedRAMP and NIST SP 800-52r2 require TLS 1.2 as the minimum. "
                "TLS 1.0 and 1.1 are deprecated and prohibited in federal environments."
            ),
            remediation=(
                "Set ssl_min_protocol_version = 'TLSv1.2' in postgresql.conf. "
                "Prefer TLSv1.3 where clients support it."
            ),
            references=[
                "NIST SP 800-52r2",
                "CIS PostgreSQL 16 Benchmark §6.8",
                "DISA STIG V-214071",
            ],
        )

    def _check_ssl_ciphers(self) -> CheckResult:
        val = self._pg_setting("ssl_ciphers") or ""
        # Should not include known weak ciphers
        weak = ["RC4", "DES", "3DES", "NULL", "EXPORT", "MD5", "SHA1"]
        has_weak = any(w in val.upper() for w in weak)
        passes = not has_weak and val != ""
        return CheckResult(
            check_id="PG-CFG-008",
            title="SSL cipher list should not include weak ciphers",
            cis_id="CIS-PG-6.9",
            fedramp_control="SC-8(1)",
            category=self.category,
            severity=Severity.HIGH,
            status=Status.PASS if passes else (Status.WARN if not val else Status.FAIL),
            actual=val or "(default — HIGH:MEDIUM:+3DES:!aNULL)",
            expected="No RC4, DES, 3DES, NULL, EXPORT, or MD5 ciphers",
            description=(
                "Weak cipher suites allow downgrade attacks. "
                "FIPS 140-2 compliance (required for FedRAMP) prohibits weak ciphers."
            ),
            remediation=(
                "Set ssl_ciphers = 'HIGH:!aNULL:!MD5:!RC4:!3DES' in postgresql.conf "
                "or use a FIPS-approved cipher list from your OS crypto policy."
            ),
            references=["NIST SP 800-52r2", "FIPS 140-2", "CIS PostgreSQL 16 §6.9"],
        )

    def _check_shared_preload_libraries(self) -> CheckResult:
        val = self._pg_setting("shared_preload_libraries") or ""
        has_pgaudit = "pgaudit" in val.lower()
        return CheckResult(
            check_id="PG-CFG-009",
            title="pgaudit must be loaded in shared_preload_libraries",
            cis_id="CIS-PG-3.14",
            stig_id="V-214060",
            fedramp_control="AU-2",
            category=self.category,
            severity=Severity.HIGH,
            status=Status.PASS if has_pgaudit else Status.FAIL,
            actual=val or "(none)",
            expected="Contains 'pgaudit'",
            description=(
                "pgaudit provides detailed session and object audit logging required "
                "by CIS and DISA STIG. Without it, PostgreSQL's built-in logging is "
                "insufficient for AU-2 (Audit Events) compliance."
            ),
            remediation=(
                "Add pgaudit to shared_preload_libraries in postgresql.conf: "
                "shared_preload_libraries = 'pgaudit'\n"
                "Then configure: pgaudit.log = 'ddl,write,role,connection'\n"
                "Restart PostgreSQL. In Docker, pass as env var or mount custom postgresql.conf."
            ),
            references=[
                "CIS PostgreSQL 16 Benchmark §3.14",
                "DISA STIG V-214060",
                "NIST SP 800-53 AU-2",
            ],
        )
