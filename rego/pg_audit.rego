# pg_audit.rego
# PostgreSQL CIS Benchmark + DISA STIG controls expressed in OPA/Rego.
#
# Compatible with:
#   - Wiz Custom Controls (OPA-based)
#   - Open Policy Agent (standalone)
#   - Conftest (CI/CD policy testing)
#
# Usage in Wiz:
#   Policies → Custom Controls → Create → OPA → paste this policy
#   Target: Container / Kubernetes workload running PostgreSQL
#
# Usage with conftest:
#   conftest test --policy rego/ postgresql_config.json
#
# Input shape (from pg-stig-audit JSON export or K8s manifest):
# {
#   "postgresql": {
#     "settings": {
#       "ssl": "on",
#       "password_encryption": "scram-sha-256",
#       "logging_collector": "on",
#       ...
#     },
#     "hba_rules": [...],
#     "superusers": [...]
#   }
# }

package postgresql.cis_stig

import future.keywords.every
import future.keywords.in

# ─── DENY RULES ──────────────────────────────────────────────────────────────

# PG-CFG-006 / CIS 6.7 / STIG V-214070 / FedRAMP SC-8
deny[msg] {
    input.postgresql.settings.ssl != "on"
    msg := {
        "check_id": "PG-CFG-006",
        "title": "SSL must be enabled",
        "severity": "CRITICAL",
        "cis_id": "CIS-PG-6.7",
        "stig_id": "V-214070",
        "fedramp_control": "SC-8",
        "actual": input.postgresql.settings.ssl,
        "expected": "on",
        "remediation": "Set ssl = on in postgresql.conf",
    }
}

# PG-CFG-002 / CIS 6.2 / STIG V-214065 / FedRAMP IA-5(1)
deny[msg] {
    input.postgresql.settings.password_encryption != "scram-sha-256"
    msg := {
        "check_id": "PG-CFG-002",
        "title": "password_encryption must be scram-sha-256",
        "severity": "HIGH",
        "cis_id": "CIS-PG-6.2",
        "stig_id": "V-214065",
        "fedramp_control": "IA-5(1)",
        "actual": input.postgresql.settings.password_encryption,
        "expected": "scram-sha-256",
        "remediation": "Set password_encryption = scram-sha-256 in postgresql.conf",
    }
}

# PG-LOG-001 / CIS 3.1 / STIG V-214060 / FedRAMP AU-2
deny[msg] {
    input.postgresql.settings.logging_collector != "on"
    msg := {
        "check_id": "PG-LOG-001",
        "title": "logging_collector must be enabled",
        "severity": "HIGH",
        "cis_id": "CIS-PG-3.1",
        "stig_id": "V-214060",
        "fedramp_control": "AU-2",
        "actual": input.postgresql.settings.logging_collector,
        "expected": "on",
        "remediation": "Set logging_collector = on in postgresql.conf",
    }
}

# PG-LOG-007 / CIS 3.10 / STIG V-214064 / FedRAMP AU-2
deny[msg] {
    not acceptable_log_statement(input.postgresql.settings.log_statement)
    msg := {
        "check_id": "PG-LOG-007",
        "title": "log_statement must be ddl, mod, or all",
        "severity": "HIGH",
        "cis_id": "CIS-PG-3.10",
        "stig_id": "V-214064",
        "fedramp_control": "AU-2",
        "actual": input.postgresql.settings.log_statement,
        "expected": "ddl, mod, or all",
        "remediation": "Set log_statement = ddl in postgresql.conf",
    }
}

acceptable_log_statement(val) { val == "ddl" }
acceptable_log_statement(val) { val == "mod" }
acceptable_log_statement(val) { val == "all" }

# PG-LOG-006 / CIS 3.9 / STIG V-214063 / FedRAMP AU-3
deny[msg] {
    prefix := input.postgresql.settings.log_line_prefix
    not contains(prefix, "%t")
    msg := {
        "check_id": "PG-LOG-006a",
        "title": "log_line_prefix must include %t (timestamp)",
        "severity": "HIGH",
        "cis_id": "CIS-PG-3.9",
        "stig_id": "V-214063",
        "fedramp_control": "AU-3",
        "actual": prefix,
        "expected": "Must contain %t",
        "remediation": "Set log_line_prefix to include %t %u %d %p",
    }
}

deny[msg] {
    prefix := input.postgresql.settings.log_line_prefix
    not contains(prefix, "%u")
    msg := {
        "check_id": "PG-LOG-006b",
        "title": "log_line_prefix must include %u (username)",
        "severity": "HIGH",
        "cis_id": "CIS-PG-3.9",
        "stig_id": "V-214063",
        "fedramp_control": "AU-3",
        "actual": prefix,
        "expected": "Must contain %u",
        "remediation": "Set log_line_prefix to include %t %u %d %p",
    }
}

# PG-AUTH-001 / CIS 4.1 / STIG V-214117 / FedRAMP IA-2
deny[msg] {
    some rule in input.postgresql.hba_rules
    rule.auth_method == "trust"
    msg := {
        "check_id": "PG-AUTH-001",
        "title": "No trust authentication allowed",
        "severity": "CRITICAL",
        "cis_id": "CIS-PG-4.1",
        "stig_id": "V-214117",
        "fedramp_control": "IA-2",
        "actual": sprintf("trust entry: type=%v db=%v user=%v", [rule.type, rule.database, rule.user_name]),
        "expected": "No trust entries in pg_hba.conf",
        "remediation": "Replace trust with scram-sha-256 in pg_hba.conf",
    }
}

# PG-AUTH-002 / CIS 4.2 / STIG V-214118 / FedRAMP IA-5(1)
deny[msg] {
    some rule in input.postgresql.hba_rules
    rule.auth_method == "password"
    msg := {
        "check_id": "PG-AUTH-002",
        "title": "No plaintext password auth allowed",
        "severity": "HIGH",
        "cis_id": "CIS-PG-4.2",
        "stig_id": "V-214118",
        "fedramp_control": "IA-5(1)",
        "actual": sprintf("password entry: type=%v db=%v", [rule.type, rule.database]),
        "expected": "Use scram-sha-256 instead of password",
        "remediation": "Replace password with scram-sha-256 in pg_hba.conf",
    }
}

# PG-AUTH-003 / CIS 4.3 / FedRAMP IA-5(1)
deny[msg] {
    some rule in input.postgresql.hba_rules
    rule.auth_method == "md5"
    msg := {
        "check_id": "PG-AUTH-003",
        "title": "MD5 auth should be replaced with scram-sha-256",
        "severity": "HIGH",
        "cis_id": "CIS-PG-4.3",
        "fedramp_control": "IA-5(1)",
        "actual": sprintf("md5 entry: type=%v db=%v", [rule.type, rule.database]),
        "expected": "Use scram-sha-256; MD5 is cryptographically broken",
        "remediation": "Replace md5 with scram-sha-256 in pg_hba.conf",
    }
}

# PG-CFG-003 / CIS 7.1 / FedRAMP CP-9
deny[msg] {
    input.postgresql.settings.fsync == "off"
    msg := {
        "check_id": "PG-CFG-003",
        "title": "fsync must be enabled",
        "severity": "HIGH",
        "cis_id": "CIS-PG-7.1",
        "fedramp_control": "CP-9",
        "actual": "off",
        "expected": "on",
        "remediation": "Set fsync = on in postgresql.conf",
    }
}

# PG-CFG-009 / CIS 3.14 / STIG V-214060 / FedRAMP AU-2
deny[msg] {
    libs := input.postgresql.settings.shared_preload_libraries
    not contains(libs, "pgaudit")
    msg := {
        "check_id": "PG-CFG-009",
        "title": "pgaudit must be in shared_preload_libraries",
        "severity": "HIGH",
        "cis_id": "CIS-PG-3.14",
        "stig_id": "V-214060",
        "fedramp_control": "AU-2",
        "actual": libs,
        "expected": "Contains pgaudit",
        "remediation": "Add pgaudit to shared_preload_libraries in postgresql.conf",
    }
}

# PG-AUTH-005 / CIS 5.1 / STIG V-214113 / FedRAMP AC-6
deny[msg] {
    some user in input.postgresql.superusers
    user != "postgres"
    msg := {
        "check_id": "PG-AUTH-005",
        "title": "Non-postgres superuser detected",
        "severity": "HIGH",
        "cis_id": "CIS-PG-5.1",
        "stig_id": "V-214113",
        "fedramp_control": "AC-6",
        "actual": sprintf("Superuser: %v", [user]),
        "expected": "Only 'postgres' should have superuser",
        "remediation": sprintf("ALTER ROLE %v NOSUPERUSER;", [user]),
    }
}

# ─── WARN RULES ──────────────────────────────────────────────────────────────

warn[msg] {
    input.postgresql.settings.log_connections != "on"
    msg := {
        "check_id": "PG-LOG-002",
        "title": "log_connections should be enabled",
        "severity": "MEDIUM",
        "cis_id": "CIS-PG-3.4",
        "fedramp_control": "AU-3",
        "remediation": "Set log_connections = on",
    }
}

warn[msg] {
    input.postgresql.settings.log_disconnections != "on"
    msg := {
        "check_id": "PG-LOG-003",
        "title": "log_disconnections should be enabled",
        "severity": "MEDIUM",
        "cis_id": "CIS-PG-3.5",
        "fedramp_control": "AU-3",
        "remediation": "Set log_disconnections = on",
    }
}

warn[msg] {
    not contains(input.postgresql.settings.listen_addresses, "localhost")
    contains(input.postgresql.settings.listen_addresses, "*")
    msg := {
        "check_id": "PG-CFG-001",
        "title": "listen_addresses should not be '*'",
        "severity": "HIGH",
        "cis_id": "CIS-PG-2.1",
        "fedramp_control": "SC-7",
        "remediation": "Set listen_addresses to specific IPs",
    }
}

# ─── COMPLIANCE SUMMARY ───────────────────────────────────────────────────────

compliant {
    count(deny) == 0
}

compliance_summary := {
    "compliant": compliant,
    "violations": count(deny),
    "warnings": count(warn),
    "framework": "CIS PostgreSQL 16 Benchmark + DISA STIG + FedRAMP High",
}
