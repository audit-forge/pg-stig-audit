"""
SARIF 2.1.0 output formatter.

SARIF (Static Analysis Results Interchange Format) is the standard format
for security findings in CI/CD pipelines. Supported by:
  - GitHub Advanced Security (Code Scanning)
  - GitLab SAST
  - Azure DevOps
  - Wiz (via import)
  - Google Cloud Security Command Center (via SCC API integration)
"""
import json
from datetime import datetime, timezone
from checks.base import CheckResult, Status, Severity

TOOL_VERSION = "1.0.0"
TOOL_NAME = "pg-stig-audit"
TOOL_URI = "https://github.com/your-org/pg-stig-audit"

SEVERITY_MAP = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}

STATUS_SKIP = {Status.PASS, Status.SKIP}


def _sarif_artifact_uri(target_uri: str) -> str:
    """Return a GitHub Code Scanning-safe artifact URI."""
    return "scan-targets/postgresql-target"


def generate(results: list[CheckResult], target_uri: str = "postgresql://localhost:5432") -> dict:
    """Generate a SARIF 2.1.0 document from audit results."""

    # Build rules list (one per check)
    rules = []
    for r in results:
        tags = []
        if r.cis_id:
            tags.append(r.cis_id)
        if r.stig_id:
            tags.append(r.stig_id)
        if r.fedramp_control:
            tags.append(r.fedramp_control)

        rule = {
            "id": r.check_id,
            "name": r.title.replace(" ", ""),
            "shortDescription": {"text": r.title},
            "fullDescription": {"text": r.description or r.title},
            "defaultConfiguration": {
                "level": SEVERITY_MAP.get(r.severity, "warning")
            },
            "properties": {
                "tags": tags,
                "category": r.category,
                "cis_id": r.cis_id,
                "stig_id": r.stig_id,
                "fedramp_control": r.fedramp_control,
            },
        }
        if r.remediation:
            rule["help"] = {"text": r.remediation}
        if r.references:
            rule["helpUri"] = r.references[0]

        rules.append(rule)

    # Build results list (only failures and warnings)
    sarif_results = []
    artifact_uri = _sarif_artifact_uri(target_uri)
    for r in results:
        if r.status in STATUS_SKIP:
            continue

        level = SEVERITY_MAP.get(r.severity, "warning")
        if r.status == Status.WARN:
            level = "warning"
        elif r.status == Status.ERROR:
            level = "error"

        message_text = (
            f"{r.title}. "
            f"Actual: {r.actual}. "
            f"Expected: {r.expected}."
        )
        if r.remediation:
            message_text += f" Remediation: {r.remediation}"

        sarif_results.append({
            "ruleId": r.check_id,
            "level": level,
            "message": {"text": message_text},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": artifact_uri,
                        },
                        "region": {"startLine": 1},
                    }
                }
            ],
            "properties": {
                "status": r.status.value,
                "severity": r.severity.value,
                "cis_id": r.cis_id,
                "stig_id": r.stig_id,
                "fedramp_control": r.fedramp_control,
                "actual": r.actual,
                "expected": r.expected,
            },
        })

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "informationUri": TOOL_URI,
                        "rules": rules,
                    }
                },
                "results": sarif_results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": datetime.now(timezone.utc).isoformat(),
                    }
                ],
                "properties": {
                    "scanTarget": target_uri,
                    "scanTimestamp": datetime.now(timezone.utc).isoformat(),
                    "framework": "CIS PostgreSQL 16 Benchmark + DISA STIG",
                },
            }
        ],
    }

    return sarif_doc


def write(results: list[CheckResult], path: str, target_uri: str = "postgresql://localhost:5432") -> None:
    """Write SARIF output to a file."""
    doc = generate(results, target_uri)
    with open(path, "w") as f:
        json.dump(doc, f, indent=2, default=str)
    print(f"[sarif] Written to {path}")
