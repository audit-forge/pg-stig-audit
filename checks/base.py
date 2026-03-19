"""Base check class for pg-stig-audit."""
from dataclasses import dataclass, field
from enum import Enum
import re
from typing import Optional


class Status(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    SKIP = "SKIP"
    ERROR = "ERROR"


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class CheckResult:
    check_id: str
    title: str
    status: Status
    severity: Severity
    cis_id: Optional[str] = None
    stig_id: Optional[str] = None
    fedramp_control: Optional[str] = None
    nist_800_53_controls: list = field(default_factory=list)
    # CMMC 2.0 / NIST 800-171 Rev 2 mappings
    nist_800_171: list = field(default_factory=list)
    cmmc_level: Optional[int] = None
    # MITRE framework mappings
    mitre_attack: list = field(default_factory=list)
    mitre_d3fend: list = field(default_factory=list)
    description: str = ""
    actual: str = ""
    expected: str = ""
    remediation: str = ""
    references: list = field(default_factory=list)
    category: str = ""
    # CVE/KEV vulnerability fields
    cve_ids: list = field(default_factory=list)
    kev_score: str = ""
    cve_remediation: str = ""
    local_path: str = ""

    def to_dict(self):
        return {
            "check_id": self.check_id,
            "title": self.title,
            "status": self.status.value,
            "severity": self.severity.value,
            "cis_id": self.cis_id,
            "stig_id": self.stig_id,
            "fedramp_control": self.fedramp_control,
            "nist_800_53_controls": self.nist_800_53_controls,
            "nist_800_171": self.nist_800_171,
            "cmmc_level": self.cmmc_level,
            "mitre_attack": self.mitre_attack,
            "mitre_d3fend": self.mitre_d3fend,
            "description": self.description,
            "actual": self.actual,
            "expected": self.expected,
            "remediation": self.remediation,
            "references": self.references,
            "category": self.category,
            "cve_ids": self.cve_ids,
            "kev_score": self.kev_score,
            "cve_remediation": self.cve_remediation,
            "local_path": self.local_path,
        }


class BaseChecker:
    """Base class for all check modules."""

    _SAFE_SETTING_RE = re.compile(r"^[a-zA-Z0-9_.]+$")

    def __init__(self, runner):
        self.runner = runner  # PgRunner instance

    def _safe_setting_name(self, name: str) -> str:
        if not self._SAFE_SETTING_RE.match(name):
            raise ValueError(f"Unsafe setting name: {name!r}")
        return name

    def run(self) -> list[CheckResult]:
        raise NotImplementedError

    def _query(self, sql: str) -> list[dict]:
        return self.runner.query(sql)

    def _setting(self, name: str) -> Optional[str]:
        safe = self._safe_setting_name(name)
        rows = self.runner.query(f"SHOW {safe};")  # nosec B608 (validated setting name)
        if not rows:
            return None
        row = rows[0]
        if "_error" in row:
            return None
        # SHOW output is parsed as {"<setting>": "<value>"}
        if name in row:
            return row[name]
        # Fallback for legacy parser shapes
        if "_cols" in row and row["_cols"]:
            return row["_cols"][0]
        vals = list(row.values())
        return vals[0] if vals else None

    def _pg_setting(self, name: str) -> Optional[str]:
        safe = self._safe_setting_name(name)
        rows = self.runner.query_with_cols(
            f"SELECT setting FROM pg_settings WHERE name = '{safe}';",  # nosec B608 (validated setting name)
            ["setting"],
        )
        if not rows:
            return None
        row = rows[0]
        if "_error" in row:
            return None
        return row.get("setting")
