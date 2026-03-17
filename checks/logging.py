"""
CIS Section 3 + STIG: Logging and Auditing Checks.

Controls covered:
  CIS 3.1  - logging_collector = on
  CIS 3.2  - log_destination
  CIS 3.4  - log_connections
  CIS 3.5  - log_disconnections
  CIS 3.6  - log_duration
  CIS 3.7  - log_error_verbosity
  CIS 3.8  - log_hostname
  CIS 3.9  - log_line_prefix (must include %t %u %d %p)
  CIS 3.10 - log_statement
  CIS 3.11 - log_min_error_statement
  CIS 3.2  - log_min_messages
  STIG V-214060 - pgaudit.log settings
"""
from .base import BaseChecker, CheckResult, Status, Severity


class LoggingChecker(BaseChecker):
    category = "Logging and Auditing"

    def run(self) -> list[CheckResult]:
        return [
            self._check_logging_collector(),
            self._check_log_connections(),
            self._check_log_disconnections(),
            self._check_log_duration(),
            self._check_log_error_verbosity(),
            self._check_log_line_prefix(),
            self._check_log_statement(),
            self._check_log_min_error_statement(),
            self._check_log_min_messages(),
            self._check_pgaudit_log(),
            self._check_log_checkpoints(),
            self._check_log_lock_waits(),
        ]

    def _check_logging_collector(self) -> CheckResult:
        val = self._pg_setting("logging_collector") or ""
        passes = val.lower() == "on"
        return CheckResult(
            check_id="PG-LOG-001",
            title="logging_collector must be enabled",
            cis_id="CIS-PG-3.1",
            stig_id="V-214060",
            fedramp_control="AU-2",
            category=self.category,
            severity=Severity.HIGH,
            status=Status.PASS if passes else Status.FAIL,
            actual=val,
            expected="on",
            description=(
                "logging_collector enables the background log writer process, "
                "required to capture logs to file. Without it, audit records may be lost."
            ),
            remediation=(
                "Set logging_collector = on in postgresql.conf. "
                "In containers, also set log_destination = 'stderr' and configure "
                "log aggregation (Fluentd, Cloud Logging, etc.) to capture stdout/stderr."
            ),
            references=["CIS PostgreSQL 16 §3.1", "NIST SP 800-53 AU-2"],
        )

    def _check_log_connections(self) -> CheckResult:
        val = self._pg_setting("log_connections") or ""
        passes = val.lower() == "on"
        return CheckResult(
            check_id="PG-LOG-002",
            title="log_connections must be enabled",
            cis_id="CIS-PG-3.4",
            stig_id="V-214062",
            fedramp_control="AU-3",
            category=self.category,
            severity=Severity.MEDIUM,
            status=Status.PASS if passes else Status.FAIL,
            actual=val,
            expected="on",
            description=(
                "Logs each connection attempt. Required for detecting unauthorized "
                "access attempts and for AU-3 (Content of Audit Records)."
            ),
            remediation="Set log_connections = on in postgresql.conf.",
            references=["CIS PostgreSQL 16 §3.4", "DISA STIG V-214062", "NIST AU-3"],
        )

    def _check_log_disconnections(self) -> CheckResult:
        val = self._pg_setting("log_disconnections") or ""
        passes = val.lower() == "on"
        return CheckResult(
            check_id="PG-LOG-003",
            title="log_disconnections must be enabled",
            cis_id="CIS-PG-3.5",
            fedramp_control="AU-3",
            category=self.category,
            severity=Severity.MEDIUM,
            status=Status.PASS if passes else Status.FAIL,
            actual=val,
            expected="on",
            description="Logs session end with duration. Pairs with log_connections for full session tracking.",
            remediation="Set log_disconnections = on in postgresql.conf.",
            references=["CIS PostgreSQL 16 §3.5", "NIST AU-3"],
        )

    def _check_log_duration(self) -> CheckResult:
        val = self._pg_setting("log_min_duration_statement") or ""
        # 0 means log all, -1 means disabled — we want >= 0
        try:
            ms = int(val)
            passes = ms >= 0
        except ValueError:
            passes = False
        return CheckResult(
            check_id="PG-LOG-004",
            title="log_min_duration_statement should be configured",
            cis_id="CIS-PG-3.6",
            fedramp_control="AU-3",
            category=self.category,
            severity=Severity.LOW,
            status=Status.PASS if passes else Status.WARN,
            actual=val if val else "(disabled: -1)",
            expected="0 (log all) or a threshold in ms",
            description=(
                "Logs SQL statements exceeding a duration threshold. "
                "Useful for forensics; setting to 0 logs all statements (high volume)."
            ),
            remediation=(
                "Set log_min_duration_statement = 0 (all) or a reasonable threshold e.g. 1000ms. "
                "Use pgaudit.log for structured statement auditing instead."
            ),
            references=["CIS PostgreSQL 16 §3.6"],
        )

    def _check_log_error_verbosity(self) -> CheckResult:
        val = self._pg_setting("log_error_verbosity") or ""
        passes = val.lower() in ("default", "verbose")
        return CheckResult(
            check_id="PG-LOG-005",
            title="log_error_verbosity must be DEFAULT or VERBOSE",
            cis_id="CIS-PG-3.7",
            fedramp_control="AU-3",
            category=self.category,
            severity=Severity.MEDIUM,
            status=Status.PASS if passes else Status.FAIL,
            actual=val,
            expected="default or verbose",
            description=(
                "Terse error verbosity omits DETAIL, HINT, and CONTEXT fields from logs, "
                "reducing the usefulness of audit records for incident response."
            ),
            remediation="Set log_error_verbosity = default in postgresql.conf.",
            references=["CIS PostgreSQL 16 §3.7"],
        )

    def _check_log_line_prefix(self) -> CheckResult:
        val = self._pg_setting("log_line_prefix") or ""
        required = ["%t", "%u", "%d", "%p"]
        missing = [r for r in required if r not in val]
        passes = not missing
        return CheckResult(
            check_id="PG-LOG-006",
            title="log_line_prefix must include %t %u %d %p",
            cis_id="CIS-PG-3.9",
            stig_id="V-214063",
            fedramp_control="AU-3",
            category=self.category,
            severity=Severity.HIGH,
            status=Status.PASS if passes else Status.FAIL,
            actual=val or "(not set)",
            expected="Must include: %t (timestamp), %u (user), %d (database), %p (PID)",
            description=(
                "log_line_prefix defines what metadata is prepended to each log line. "
                "AU-3 requires timestamp, user identity, and session info in audit records."
            ),
            remediation=(
                f"Set log_line_prefix = '%t [%p]: [%l-1] user=%u,db=%d,app=%a,client=%h '\n"
                f"Missing tokens: {', '.join(missing) if missing else 'none'}"
            ),
            references=["CIS PostgreSQL 16 §3.9", "DISA STIG V-214063", "NIST AU-3"],
        )

    def _check_log_statement(self) -> CheckResult:
        val = self._pg_setting("log_statement") or ""
        # 'ddl' is minimum; 'mod' or 'all' also acceptable
        acceptable = ["ddl", "mod", "all"]
        passes = val.lower() in acceptable
        return CheckResult(
            check_id="PG-LOG-007",
            title="log_statement must be 'ddl', 'mod', or 'all'",
            cis_id="CIS-PG-3.10",
            stig_id="V-214064",
            fedramp_control="AU-2",
            category=self.category,
            severity=Severity.HIGH,
            status=Status.PASS if passes else Status.FAIL,
            actual=val or "(none — no statement logging)",
            expected="ddl, mod, or all",
            description=(
                "log_statement controls which SQL statements are logged. "
                "At minimum, DDL changes (CREATE, ALTER, DROP) must be captured. "
                "Note: pgaudit provides more granular control."
            ),
            remediation=(
                "Set log_statement = 'ddl' in postgresql.conf for minimum compliance. "
                "Prefer pgaudit for structured, object-level auditing."
            ),
            references=["CIS PostgreSQL 16 §3.10", "DISA STIG V-214064", "NIST AU-2"],
        )

    def _check_log_min_error_statement(self) -> CheckResult:
        val = self._pg_setting("log_min_error_statement") or ""
        acceptable = ["debug5", "debug4", "debug3", "debug2", "debug1",
                      "info", "notice", "warning", "error"]
        passes = val.lower() in acceptable
        return CheckResult(
            check_id="PG-LOG-008",
            title="log_min_error_statement must be ERROR or lower",
            cis_id="CIS-PG-3.11",
            fedramp_control="AU-2",
            category=self.category,
            severity=Severity.MEDIUM,
            status=Status.PASS if passes else Status.FAIL,
            actual=val or "(not set)",
            expected="error or lower severity (debug, info, notice, warning, error)",
            description=(
                "Causes the SQL statement to be logged when an error of the specified "
                "severity occurs, enabling forensic reconstruction of failed operations."
            ),
            remediation="Set log_min_error_statement = error in postgresql.conf.",
            references=["CIS PostgreSQL 16 §3.11"],
        )

    def _check_log_min_messages(self) -> CheckResult:
        val = self._pg_setting("log_min_messages") or ""
        # WARNING or lower is acceptable; FATAL/PANIC are too restrictive
        too_high = ["fatal", "panic"]
        passes = val.lower() not in too_high and val != ""
        return CheckResult(
            check_id="PG-LOG-009",
            title="log_min_messages should not be FATAL or PANIC",
            cis_id="CIS-PG-3.2",
            fedramp_control="AU-2",
            category=self.category,
            severity=Severity.MEDIUM,
            status=Status.PASS if passes else Status.FAIL,
            actual=val or "(not set)",
            expected="WARNING or lower (debug, info, notice, warning)",
            description=(
                "Setting log_min_messages too high means many events go unlogged. "
                "WARNING is the recommended minimum for production."
            ),
            remediation="Set log_min_messages = warning in postgresql.conf.",
            references=["CIS PostgreSQL 16 §3.2"],
        )

    def _check_pgaudit_log(self) -> CheckResult:
        rows = self._query(
            "SELECT setting FROM pg_settings WHERE name = 'pgaudit.log';"
        )
        val = ""
        if rows and "_cols" in rows[0]:
            val = rows[0]["_cols"][0] if rows[0]["_cols"] else ""

        required_categories = ["ddl", "write", "role"]
        if val:
            present = [c for c in required_categories if c in val.lower()]
            passes = len(present) == len(required_categories)
        else:
            passes = False

        return CheckResult(
            check_id="PG-LOG-010",
            title="pgaudit.log must cover DDL, WRITE, and ROLE events",
            cis_id="CIS-PG-3.14",
            stig_id="V-214060",
            fedramp_control="AU-2",
            category=self.category,
            severity=Severity.HIGH,
            status=Status.PASS if passes else Status.FAIL,
            actual=val or "(pgaudit not configured or not loaded)",
            expected="Contains: ddl, write, role (at minimum)",
            description=(
                "pgaudit provides structured, object-level audit logging. "
                "DDL captures schema changes; WRITE captures INSERT/UPDATE/DELETE; "
                "ROLE captures privilege changes. All required for AU-2 compliance."
            ),
            remediation=(
                "Ensure pgaudit is in shared_preload_libraries, then set:\n"
                "pgaudit.log = 'ddl,write,role,connection'\n"
                "pgaudit.log_catalog = on\n"
                "pgaudit.log_relation = on"
            ),
            references=["CIS PostgreSQL 16 §3.14", "DISA STIG V-214060", "NIST AU-2"],
        )

    def _check_log_checkpoints(self) -> CheckResult:
        val = self._pg_setting("log_checkpoints") or ""
        passes = val.lower() == "on"
        return CheckResult(
            check_id="PG-LOG-011",
            title="log_checkpoints should be enabled",
            fedramp_control="AU-2",
            category=self.category,
            severity=Severity.LOW,
            status=Status.PASS if passes else Status.WARN,
            actual=val,
            expected="on",
            description="Logs each checkpoint, useful for performance and recovery forensics.",
            remediation="Set log_checkpoints = on in postgresql.conf.",
            references=["CIS PostgreSQL 16 §3.13"],
        )

    def _check_log_lock_waits(self) -> CheckResult:
        val = self._pg_setting("log_lock_waits") or ""
        passes = val.lower() == "on"
        return CheckResult(
            check_id="PG-LOG-012",
            title="log_lock_waits should be enabled",
            fedramp_control="AU-2",
            category=self.category,
            severity=Severity.LOW,
            status=Status.PASS if passes else Status.WARN,
            actual=val,
            expected="on",
            description="Logs lock wait events exceeding deadlock_timeout, useful for detecting contention.",
            remediation="Set log_lock_waits = on in postgresql.conf.",
            references=["CIS PostgreSQL 16 §3.13"],
        )
