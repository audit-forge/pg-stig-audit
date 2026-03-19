"""
Framework mapping data for pg-stig-audit.

Provides NIST SP 800-171 Rev 2, CMMC 2.0, MITRE ATT&CK, and MITRE D3FEND
mappings for each PostgreSQL audit control (keyed by check_id).

Also carries the canonical NIST SP 800-53 Rev 5 control list for each check
(to supplement the single fedramp_control field already on CheckResult).

Mapping rationale
-----------------
NIST 800-171 Rev 2 (110 controls / 14 families) — derived from the NIST
  SP 800-171 Rev 2 Appendix D cross-reference to NIST SP 800-53 Rev 5.

CMMC 2.0 levels:
  Level 1 — 17 "basic safeguarding" practices (FAR 52.204-21 / 800-171 subset)
  Level 2 — all 110 NIST SP 800-171 Rev 2 practices
  Level 3 — NIST SP 800-172 additions (24+ enhanced practices)

MITRE ATT&CK — Enterprise matrix; only techniques with a direct defensive
  relationship to the control are listed.

MITRE D3FEND — Defensive countermeasure knowledge graph (d3fend.mitre.org).

Key 800-53 → 800-171 cross-references used:
  AC-2, AC-3, AC-6  → 3.1.1, 3.1.2, 3.1.5, 3.1.6
  AC-12             → 3.1.11
  AU-2, AU-3, AU-12 → 3.3.1, 3.3.2
  CM-6, CM-7        → 3.4.2, 3.4.6, 3.4.7
  CP-9              → 3.8.9
  IA-2              → 3.5.1, 3.5.2
  IA-5, IA-5(1)     → 3.5.3, 3.5.7, 3.5.8, 3.5.10
  SC-7, SC-8        → 3.13.1, 3.13.5, 3.13.8
  SC-28             → 3.13.16
"""

# ---------------------------------------------------------------------------
# Per-control framework data
# Key: check_id (string, must match checks/*.py)
# ---------------------------------------------------------------------------
FRAMEWORK_MAP: dict[str, dict] = {

    # ------------------------------------------------------------------ #
    # Server Configuration (via checks/config.py)
    # ------------------------------------------------------------------ #

    "PG-CFG-001": {
        # listen_addresses should not be '*' (CIS-PG-2.1, V-214127, SC-7)
        # 800-53: SC-7 → 800-171: 3.13.1 (monitor/control communications at external boundaries)
        # CMMC L1: 3.13.1 is a Level 1 basic-safeguarding practice
        "nist_800_53": ["SC-7"],
        "nist_800_171": ["3.13.1"],
        "cmmc_level": 1,
        # T1133: External Remote Services — binding to '*' exposes PostgreSQL on all interfaces
        "mitre_attack": ["T1133"],
        # D3-NI: Network Isolation — restrict listening interfaces
        # D3-NTF: Network Traffic Filtering
        "mitre_d3fend": ["D3-NI", "D3-NTF"],
    },

    "PG-CFG-002": {
        # password_encryption must be scram-sha-256 (CIS-PG-6.2, V-214065, IA-5(1))
        # 800-53: IA-5(1) → 800-171: 3.5.7 (password complexity), 3.5.8 (prohibit reuse),
        #                              3.5.10 (store only cryptographically-protected passwords)
        # CMMC L2
        "nist_800_53": ["IA-5", "IA-5(1)"],
        "nist_800_171": ["3.5.7", "3.5.8", "3.5.10"],
        "cmmc_level": 2,
        # T1110: Brute Force — weak (MD5) or downgraded hashing enables offline password cracking
        "mitre_attack": ["T1110"],
        # D3-SPP: Strong Password Policy — enforce strong hashing algorithm
        "mitre_d3fend": ["D3-SPP"],
    },

    "PG-CFG-003": {
        # fsync must be on (CIS-PG-7.1, CP-9)
        # 800-53: CP-9 → 800-171: 3.8.9 (protect backup CUI at storage locations)
        # CMMC L2
        "nist_800_53": ["CP-9"],
        "nist_800_171": ["3.8.9"],
        "cmmc_level": 2,
        # T1485: Data Destruction — fsync=off risks data loss on crash (intentional or otherwise)
        "mitre_attack": ["T1485"],
        # D3-ACH: Application Configuration Hardening — enforce durable write behavior
        "mitre_d3fend": ["D3-ACH"],
    },

    "PG-CFG-004": {
        # full_page_writes must be on (CIS-PG-7.2, CP-9)
        # 800-53: CP-9 → 800-171: 3.8.9
        # CMMC L2
        "nist_800_53": ["CP-9"],
        "nist_800_171": ["3.8.9"],
        "cmmc_level": 2,
        # T1485: Data Destruction — disabled full_page_writes may cause WAL corruption after crash
        "mitre_attack": ["T1485"],
        # D3-ACH: Application Configuration Hardening
        "mitre_d3fend": ["D3-ACH"],
    },

    "PG-CFG-005": {
        # Idle session timeout (V-214100, AC-12)
        # 800-53: AC-12 → 800-171: 3.1.11 (terminate sessions after period of inactivity)
        # CMMC L2
        "nist_800_53": ["AC-12"],
        "nist_800_171": ["3.1.11"],
        "cmmc_level": 2,
        # T1078: Valid Accounts — abandoned sessions extend attacker window for session hijacking
        "mitre_attack": ["T1078"],
        # D3-TPAM: Temporary Access Management — enforce session expiry
        "mitre_d3fend": ["D3-TPAM"],
    },

    "PG-CFG-006": {
        # SSL must be enabled (CIS-PG-6.7, SC-8)
        # 800-53: SC-8 → 800-171: 3.13.8 (cryptographic mechanisms to prevent disclosure in transit)
        # CMMC L2
        "nist_800_53": ["SC-8", "SC-8(1)"],
        "nist_800_171": ["3.13.8"],
        "cmmc_level": 2,
        # T1040: Network Sniffing — plaintext PostgreSQL traffic exposes credentials and queries
        "mitre_attack": ["T1040"],
        # D3-ET: Encrypted Tunnels — TLS/SSL for in-transit protection
        "mitre_d3fend": ["D3-ET"],
    },

    "PG-CFG-007": {
        # SSL minimum protocol version (CIS-PG-6.7, SC-8)
        # 800-53: SC-8, SC-13 → 800-171: 3.13.8, 3.13.10 (cryptographic key management)
        # CMMC L2
        "nist_800_53": ["SC-8", "SC-13"],
        "nist_800_171": ["3.13.8", "3.13.10"],
        "cmmc_level": 2,
        # T1040: Network Sniffing — obsolete TLS versions (TLS 1.0/1.1) are subject to POODLE/BEAST
        "mitre_attack": ["T1040"],
        # D3-ET: Encrypted Tunnels
        # D3-MH: Message Hardening — enforce minimum protocol version
        "mitre_d3fend": ["D3-ET", "D3-MH"],
    },

    "PG-CFG-008": {
        # SSL cipher suite restriction (CIS-PG-6.7, SC-8)
        # 800-53: SC-8, SC-13 → 800-171: 3.13.8, 3.13.10
        # CMMC L2
        "nist_800_53": ["SC-8", "SC-13"],
        "nist_800_171": ["3.13.8", "3.13.10"],
        "cmmc_level": 2,
        # T1040: Network Sniffing — weak ciphers allow decryption of intercepted traffic
        "mitre_attack": ["T1040"],
        # D3-ET: Encrypted Tunnels
        # D3-MH: Message Hardening
        "mitre_d3fend": ["D3-ET", "D3-MH"],
    },

    "PG-CFG-009": {
        # pgaudit loaded in shared_preload_libraries (CIS-PG-3.2, AU-2)
        # 800-53: AU-2 → 800-171: 3.3.1 (create and retain audit records)
        # CMMC L2
        "nist_800_53": ["AU-2", "AU-12"],
        "nist_800_171": ["3.3.1", "3.3.2"],
        "cmmc_level": 2,
        # T1562.001: Disable or Modify Tools — absence of pgaudit eliminates statement-level audit trail
        "mitre_attack": ["T1562.001"],
        # D3-ALCA: Application Log Audit — pgaudit provides detailed SQL-level audit records
        "mitre_d3fend": ["D3-ALCA"],
    },

    # ------------------------------------------------------------------ #
    # Logging and Auditing (via checks/logging.py)
    # ------------------------------------------------------------------ #

    "PG-LOG-001": {
        # logging_collector must be enabled (CIS-PG-3.1, V-214060, AU-2)
        # 800-53: AU-2 → 800-171: 3.3.1
        "nist_800_53": ["AU-2"],
        "nist_800_171": ["3.3.1"],
        "cmmc_level": 2,
        # T1562.001: Disable or Modify Tools — disabled logging_collector loses all file-based audit records
        "mitre_attack": ["T1562.001"],
        "mitre_d3fend": ["D3-ALCA"],
    },

    "PG-LOG-002": {
        # log_connections must be on (CIS-PG-3.4, AU-3)
        # 800-53: AU-3 → 800-171: 3.3.1
        "nist_800_53": ["AU-3"],
        "nist_800_171": ["3.3.1"],
        "cmmc_level": 2,
        # T1078: Valid Accounts — unlogged connections hide unauthorized authentication attempts
        "mitre_attack": ["T1078"],
        "mitre_d3fend": ["D3-ALCA"],
    },

    "PG-LOG-003": {
        # log_disconnections must be on (CIS-PG-3.5, AU-3)
        # 800-53: AU-3 → 800-171: 3.3.1
        "nist_800_53": ["AU-3"],
        "nist_800_171": ["3.3.1"],
        "cmmc_level": 2,
        # T1078: Valid Accounts — session tracking requires both connect and disconnect events
        "mitre_attack": ["T1078"],
        "mitre_d3fend": ["D3-ALCA"],
    },

    "PG-LOG-004": {
        # log_duration / log_min_duration_statement (CIS-PG-3.6, AU-3)
        # 800-53: AU-3 → 800-171: 3.3.1
        "nist_800_53": ["AU-3"],
        "nist_800_171": ["3.3.1"],
        "cmmc_level": 2,
        # T1059.001: Command and Scripting Interpreter — long-running queries may indicate data exfiltration
        "mitre_attack": ["T1059.001"],
        "mitre_d3fend": ["D3-ALCA"],
    },

    "PG-LOG-005": {
        # log_error_verbosity should be verbose (CIS-PG-3.7, AU-3)
        # 800-53: AU-3 → 800-171: 3.3.1
        "nist_800_53": ["AU-3"],
        "nist_800_171": ["3.3.1"],
        "cmmc_level": 2,
        # T1562.001: Disable or Modify Tools — terse errors hide exploitation attempts
        "mitre_attack": ["T1562.001"],
        "mitre_d3fend": ["D3-ALCA"],
    },

    "PG-LOG-006": {
        # log_line_prefix must include %t %u %d %p (CIS-PG-3.9, AU-3)
        # 800-53: AU-3 → 800-171: 3.3.1, 3.3.2 (trace individual user actions)
        "nist_800_53": ["AU-3"],
        "nist_800_171": ["3.3.1", "3.3.2"],
        "cmmc_level": 2,
        # T1562.001: Disable or Modify Tools — missing user/timestamp in prefix prevents attribution
        "mitre_attack": ["T1562.001"],
        "mitre_d3fend": ["D3-ALCA"],
    },

    "PG-LOG-007": {
        # log_statement should be ddl or all (CIS-PG-3.10, AU-2)
        # 800-53: AU-2 → 800-171: 3.3.1, 3.3.2
        "nist_800_53": ["AU-2", "AU-12"],
        "nist_800_171": ["3.3.1", "3.3.2"],
        "cmmc_level": 2,
        # T1059.001: Command and Scripting Interpreter — DDL changes without logging hide schema manipulation
        "mitre_attack": ["T1059.001"],
        "mitre_d3fend": ["D3-ALCA"],
    },

    "PG-LOG-008": {
        # log_min_error_statement (CIS-PG-3.11, AU-2)
        # 800-53: AU-2 → 800-171: 3.3.1
        "nist_800_53": ["AU-2"],
        "nist_800_171": ["3.3.1"],
        "cmmc_level": 2,
        # T1562.001: Disable or Modify Tools
        "mitre_attack": ["T1562.001"],
        "mitre_d3fend": ["D3-ALCA"],
    },

    "PG-LOG-009": {
        # log_min_messages (CIS-PG-3.12, AU-2)
        # 800-53: AU-2 → 800-171: 3.3.1
        "nist_800_53": ["AU-2"],
        "nist_800_171": ["3.3.1"],
        "cmmc_level": 2,
        "mitre_attack": ["T1562.001"],
        "mitre_d3fend": ["D3-ALCA"],
    },

    "PG-LOG-010": {
        # pgaudit.log settings (V-214060, AU-2)
        # 800-53: AU-2, AU-12 → 800-171: 3.3.1, 3.3.2
        "nist_800_53": ["AU-2", "AU-12"],
        "nist_800_171": ["3.3.1", "3.3.2"],
        "cmmc_level": 2,
        # T1562.001: Disable or Modify Tools — inadequate pgaudit categories miss critical events
        # T1059.001: Command and Scripting Interpreter — DDL/DML queries without audit trail
        "mitre_attack": ["T1562.001", "T1059.001"],
        "mitre_d3fend": ["D3-ALCA"],
    },

    "PG-LOG-011": {
        # log_checkpoints (additional WAL auditing)
        # 800-53: AU-2 → 800-171: 3.3.1
        "nist_800_53": ["AU-2"],
        "nist_800_171": ["3.3.1"],
        "cmmc_level": 2,
        "mitre_attack": [],
        "mitre_d3fend": ["D3-ALCA"],
    },

    "PG-LOG-012": {
        # log_lock_waits
        # 800-53: AU-2 → 800-171: 3.3.1
        "nist_800_53": ["AU-2"],
        "nist_800_171": ["3.3.1"],
        "cmmc_level": 2,
        # T1499: Endpoint Denial of Service — lock contention can indicate a DoS condition
        "mitre_attack": ["T1499"],
        "mitre_d3fend": ["D3-ALCA"],
    },

    # ------------------------------------------------------------------ #
    # Authentication (via checks/auth.py)
    # ------------------------------------------------------------------ #

    "PG-AUTH-001": {
        # No 'trust' authentication in pg_hba.conf (CIS-PG-4.1, V-214117, IA-2)
        # 800-53: IA-2 → 800-171: 3.5.1 (identify users), 3.5.2 (authenticate before access)
        # CMMC L1: 3.5.2 is a Level 1 practice
        "nist_800_53": ["IA-2"],
        "nist_800_171": ["3.5.1", "3.5.2"],
        "cmmc_level": 1,
        # T1078: Valid Accounts — trust auth bypasses authentication entirely
        # T1078.001: Default Accounts — trust is often the default for local connections
        "mitre_attack": ["T1078", "T1078.001"],
        # D3-UAP: User Account Permissions — require authentication before access
        "mitre_d3fend": ["D3-UAP"],
    },

    "PG-AUTH-002": {
        # No plaintext 'password' auth method in pg_hba.conf (CIS-PG-4.2, IA-5)
        # 800-53: IA-5 → 800-171: 3.5.3, 3.5.7
        # CMMC L2
        "nist_800_53": ["IA-5"],
        "nist_800_171": ["3.5.3", "3.5.7"],
        "cmmc_level": 2,
        # T1110: Brute Force — plaintext password method transmits passwords in cleartext
        # T1040: Network Sniffing — cleartext passwords interceptable on wire
        "mitre_attack": ["T1110", "T1040"],
        # D3-SPP: Strong Password Policy
        "mitre_d3fend": ["D3-SPP"],
    },

    "PG-AUTH-003": {
        # Prefer SCRAM-SHA-256 over MD5 (CIS-PG-4.3, IA-5(1))
        # 800-53: IA-5(1) → 800-171: 3.5.7, 3.5.8, 3.5.10
        # CMMC L2
        "nist_800_53": ["IA-5", "IA-5(1)"],
        "nist_800_171": ["3.5.7", "3.5.8", "3.5.10"],
        "cmmc_level": 2,
        # T1110: Brute Force — MD5 is cryptographically broken; offline cracking is fast
        "mitre_attack": ["T1110"],
        # D3-SPP: Strong Password Policy
        "mitre_d3fend": ["D3-SPP"],
    },

    "PG-AUTH-004": {
        # Superuser remote login prohibited (CIS-PG-5.2, V-214115, AC-6)
        # 800-53: AC-6 → 800-171: 3.1.5 (least privilege), 3.1.6 (non-privileged for non-security functions)
        # CMMC L1: 3.1.5 is Level 1
        "nist_800_53": ["AC-6"],
        "nist_800_171": ["3.1.5", "3.1.6"],
        "cmmc_level": 1,
        # T1078: Valid Accounts — superuser remote login creates a high-value remote authentication target
        # T1133: External Remote Services — superuser access from external hosts
        "mitre_attack": ["T1078", "T1133"],
        # D3-UAP: User Account Permissions
        "mitre_d3fend": ["D3-UAP"],
    },

    "PG-AUTH-005": {
        # Superuser count should be minimal (CIS-PG-5.1, V-214114, AC-6)
        # 800-53: AC-6 → 800-171: 3.1.5
        # CMMC L1: 3.1.5 is Level 1
        "nist_800_53": ["AC-6"],
        "nist_800_171": ["3.1.5"],
        "cmmc_level": 1,
        # T1078: Valid Accounts — excess superuser accounts increase attack surface
        "mitre_attack": ["T1078"],
        "mitre_d3fend": ["D3-UAP"],
    },

    "PG-AUTH-006": {
        # Default role privilege review (AC-3)
        # 800-53: AC-3 → 800-171: 3.1.2, 3.1.5
        # CMMC L1: 3.1.2 is Level 1
        "nist_800_53": ["AC-3", "AC-6"],
        "nist_800_171": ["3.1.2", "3.1.5"],
        "cmmc_level": 1,
        # T1078: Valid Accounts — default roles with broad privileges
        "mitre_attack": ["T1078"],
        # D3-RBAC: Role-Based Access Control
        "mitre_d3fend": ["D3-RBAC"],
    },

    "PG-AUTH-007": {
        # Public schema access restriction (AC-6)
        # 800-53: AC-6 → 800-171: 3.1.2, 3.1.5
        # CMMC L1
        "nist_800_53": ["AC-6"],
        "nist_800_171": ["3.1.2", "3.1.5"],
        "cmmc_level": 1,
        # T1078: Valid Accounts — PUBLIC role access to schema enables unprivileged data access
        "mitre_attack": ["T1078"],
        # D3-UAP: User Account Permissions
        "mitre_d3fend": ["D3-UAP"],
    },

    # ------------------------------------------------------------------ #
    # Privileges and Objects (via checks/privileges.py)
    # ------------------------------------------------------------------ #

    "PG-PRIV-001": {
        # Tables accessible to PUBLIC (CIS-PG-5.5, V-214114)
        # 800-53: AC-3, AC-6 → 800-171: 3.1.2, 3.1.5
        # CMMC L1
        "nist_800_53": ["AC-3", "AC-6"],
        "nist_800_171": ["3.1.2", "3.1.5"],
        "cmmc_level": 1,
        # T1078: Valid Accounts — broad PUBLIC grants allow any authenticated user to read all tables
        # T1005: Data from Local System — PUBLIC SELECT allows bulk data retrieval
        "mitre_attack": ["T1078", "T1005"],
        # D3-UAP: User Account Permissions
        "mitre_d3fend": ["D3-UAP"],
    },

    "PG-PRIV-002": {
        # SECURITY DEFINER functions (CIS-PG-5.6, V-214116)
        # 800-53: AC-6 → 800-171: 3.1.5, 3.1.6
        # CMMC L2
        "nist_800_53": ["AC-6"],
        "nist_800_171": ["3.1.5", "3.1.6"],
        "cmmc_level": 2,
        # T1134: Access Token Manipulation — SECURITY DEFINER runs with the definer's privileges
        # T1068: Exploitation for Privilege Escalation — misconfigured SECURITY DEFINER elevates privileges
        "mitre_attack": ["T1134", "T1068"],
        # D3-UAP: User Account Permissions
        "mitre_d3fend": ["D3-UAP"],
    },

    "PG-PRIV-003": {
        # Risky extensions audit (CIS-PG-5.7)
        # 800-53: CM-7 → 800-171: 3.4.6, 3.4.7 (least functionality / restrict nonessential)
        # CMMC L2
        "nist_800_53": ["CM-7"],
        "nist_800_171": ["3.4.6", "3.4.7"],
        "cmmc_level": 2,
        # T1190: Exploit Public-Facing Application — risky extensions (plpython3u) enable arbitrary code
        # T1068: Exploitation for Privilege Escalation — untrusted PLs execute as OS user
        "mitre_attack": ["T1190", "T1068"],
        # D3-ACH: Application Configuration Hardening — remove nonessential/untrusted extensions
        "mitre_d3fend": ["D3-ACH"],
    },

    "PG-PRIV-004": {
        # Row Level Security (RLS) on sensitive tables (CIS-PG-5.8)
        # 800-53: AC-3 → 800-171: 3.1.2, 3.1.3 (control flow of CUI)
        # CMMC L2 (3.1.3 is Level 2 — flow control)
        "nist_800_53": ["AC-3"],
        "nist_800_171": ["3.1.2", "3.1.3"],
        "cmmc_level": 2,
        # T1005: Data from Local System — without RLS, any table-level grant exposes all rows
        "mitre_attack": ["T1005"],
        # D3-UAP: User Account Permissions — RLS enforces fine-grained row-level access control
        "mitre_d3fend": ["D3-UAP"],
    },

    "PG-PRIV-005": {
        # Default privileges review (CIS-PG-5.9, AC-6)
        # 800-53: AC-6 → 800-171: 3.1.2, 3.1.5
        # CMMC L1
        "nist_800_53": ["AC-6"],
        "nist_800_171": ["3.1.2", "3.1.5"],
        "cmmc_level": 1,
        # T1078: Valid Accounts — default privileges allow unintended access to new objects
        "mitre_attack": ["T1078"],
        "mitre_d3fend": ["D3-UAP"],
    },

    "PG-PRIV-006": {
        # MD5 password hashes detected (V-214119, IA-5(1))
        # 800-53: IA-5(1) → 800-171: 3.5.7, 3.5.8, 3.5.10
        # CMMC L2
        "nist_800_53": ["IA-5", "IA-5(1)"],
        "nist_800_171": ["3.5.7", "3.5.8", "3.5.10"],
        "cmmc_level": 2,
        # T1110: Brute Force — MD5 hashes can be cracked offline with GPU acceleration
        "mitre_attack": ["T1110"],
        "mitre_d3fend": ["D3-SPP"],
    },

    "PG-PRIV-007": {
        # Unused/non-default databases (least functionality)
        # 800-53: CM-7 → 800-171: 3.4.6 (least functionality)
        # CMMC L2
        "nist_800_53": ["CM-7"],
        "nist_800_171": ["3.4.6"],
        "cmmc_level": 2,
        # T1190: Exploit Public-Facing Application — orphaned databases may have weaker access controls
        "mitre_attack": ["T1190"],
        # D3-ACH: Application Configuration Hardening — remove unused databases
        "mitre_d3fend": ["D3-ACH"],
    },

    "PG-PRIV-008": {
        # Password expiry configuration (IA-5)
        # 800-53: IA-5 → 800-171: 3.5.7, 3.5.10 (password management)
        # CMMC L2
        "nist_800_53": ["IA-5"],
        "nist_800_171": ["3.5.7", "3.5.10"],
        "cmmc_level": 2,
        # T1078: Valid Accounts — passwords that never expire extend attacker dwell time
        "mitre_attack": ["T1078"],
        "mitre_d3fend": ["D3-SPP"],
    },
}


def enrich(result) -> None:
    """
    Enrich a CheckResult in-place with NIST 800-53, NIST 800-171, CMMC,
    MITRE ATT&CK, and MITRE D3FEND data from the FRAMEWORK_MAP.

    Only sets values if the check_id is present in the map AND the field
    is currently empty (avoids overwriting manually-set values in check files).
    """
    data = FRAMEWORK_MAP.get(result.check_id)
    if not data:
        return
    if not result.nist_800_53_controls:
        result.nist_800_53_controls = data.get("nist_800_53", [])
    if not result.nist_800_171:
        result.nist_800_171 = data.get("nist_800_171", [])
    if result.cmmc_level is None:
        result.cmmc_level = data.get("cmmc_level")
    if not result.mitre_attack:
        result.mitre_attack = data.get("mitre_attack", [])
    if not result.mitre_d3fend:
        result.mitre_d3fend = data.get("mitre_d3fend", [])


def enrich_all(results: list) -> list:
    """Enrich a list of CheckResult objects in-place; returns the same list."""
    for r in results:
        enrich(r)
    return results
