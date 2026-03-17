"""
Wiz and Google Cloud Security Command Center (SCC) output formatters.

Wiz: Custom findings can be pushed via the Wiz Issues API or imported
     as custom controls via the Wiz portal.

GCP SCC: Findings pushed via the SCC Findings API (v1).
         Requires a SCC source registered in your GCP org.

Usage:
  - wiz_json():   Wiz-compatible findings JSON (for API upload or portal import)
  - scc_json():   GCP SCC Findings API format
  - write_wiz():  Write Wiz JSON to file
  - write_scc():  Write SCC JSON to file
"""
import json
from datetime import datetime, timezone
from checks.base import CheckResult, Status, Severity

# Wiz severity mapping
WIZ_SEVERITY = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW",
    Severity.INFO: "INFORMATIONAL",
}

# SCC severity mapping
SCC_SEVERITY = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW",
    Severity.INFO: "LOW",
}

# Map our statuses to Wiz finding states
WIZ_STATUS = {
    Status.FAIL: "OPEN",
    Status.WARN: "OPEN",
    Status.PASS: "RESOLVED",
    Status.ERROR: "OPEN",
    Status.SKIP: "WONT_FIX",
}

# SCC finding states
SCC_STATUS = {
    Status.FAIL: "ACTIVE",
    Status.WARN: "ACTIVE",
    Status.PASS: "INACTIVE",
    Status.ERROR: "ACTIVE",
    Status.SKIP: "INACTIVE",
}


def wiz_json(
    results: list[CheckResult],
    resource_id: str = "postgresql-container",
    resource_type: str = "CONTAINER",
) -> list[dict]:
    """
    Generate Wiz-compatible findings.

    These can be uploaded to Wiz via:
      POST /api/v1/issues  (requires Wiz API credentials)

    Or imported manually via Wiz Portal → Policies → Custom Controls.
    """
    findings = []
    now = datetime.now(timezone.utc).isoformat()

    for r in results:
        if r.status == Status.PASS:
            continue  # Only export non-passing results

        tags = {}
        if r.cis_id:
            tags["CIS"] = r.cis_id
        if r.stig_id:
            tags["STIG"] = r.stig_id
        if r.fedramp_control:
            tags["FedRAMP"] = r.fedramp_control
            tags["NIST"] = r.fedramp_control

        finding = {
            "id": f"pg-stig-audit-{r.check_id.lower()}",
            "title": r.title,
            "description": r.description,
            "severity": WIZ_SEVERITY.get(r.severity, "MEDIUM"),
            "status": WIZ_STATUS.get(r.status, "OPEN"),
            "category": r.category,
            "resource": {
                "id": resource_id,
                "type": resource_type,
                "name": resource_id,
            },
            "finding_details": {
                "actual_value": r.actual,
                "expected_value": r.expected,
                "check_id": r.check_id,
                "compliance_ids": tags,
            },
            "remediation": {
                "steps": r.remediation,
                "references": r.references,
            },
            "detected_at": now,
            "source_tool": "pg-stig-audit",
            "framework": "CIS PostgreSQL 16 + DISA STIG",
        }
        findings.append(finding)

    return findings


def scc_json(
    results: list[CheckResult],
    project_id: str,
    source_name: str,
    resource_name: str = None,
) -> list[dict]:
    """
    Generate Google Cloud Security Command Center (SCC) findings.

    Format: SCC Findings API v1
    Endpoint: POST https://securitycenter.googleapis.com/v1/{source_name}/findings

    Prerequisites:
      1. Create a SCC Source in your org:
         gcloud scc sources create --organization=ORG_ID --display-name='pg-stig-audit'
      2. Grant SCC Findings Editor role to the service account
      3. Use source_name = 'organizations/ORG_ID/sources/SOURCE_ID'

    For FedRAMP environments, use the restricted endpoint:
      https://securitycenter.googleapis.com  (FedRAMP High)
    """
    findings = []
    now = datetime.now(timezone.utc).isoformat()

    if not resource_name:
        resource_name = f"//container.googleapis.com/projects/{project_id}/locations/us/clusters/default"

    for r in results:
        finding_id = r.check_id.lower().replace("-", "_")

        compliance_standards = []
        if r.cis_id:
            compliance_standards.append({
                "standard": "CIS PostgreSQL 16 Benchmark",
                "version": "1.0.0",
                "ids": [r.cis_id],
            })
        if r.stig_id:
            compliance_standards.append({
                "standard": "DISA STIG PostgreSQL",
                "version": "V12R1",
                "ids": [r.stig_id],
            })
        if r.fedramp_control:
            compliance_standards.append({
                "standard": "NIST SP 800-53",
                "version": "Rev 5",
                "ids": [r.fedramp_control],
            })

        finding = {
            "name": f"{source_name}/findings/{finding_id}",
            "parent": source_name,
            "resourceName": resource_name,
            "state": SCC_STATUS.get(r.status, "ACTIVE"),
            "category": f"PG-STIG/{r.category.upper().replace(' ', '_')}",
            "externalUri": r.references[0] if r.references else "",
            "sourceProperties": {
                "check_id": r.check_id,
                "title": r.title,
                "actual_value": r.actual,
                "expected_value": r.expected,
                "remediation": r.remediation,
                "cis_id": r.cis_id or "",
                "stig_id": r.stig_id or "",
                "fedramp_control": r.fedramp_control or "",
                "tool": "pg-stig-audit",
            },
            "securityMarks": {
                "marks": {
                    "severity": SCC_SEVERITY.get(r.severity, "MEDIUM"),
                    "framework": "fedramp-high" if r.fedramp_control else "cis",
                }
            },
            "eventTime": now,
            "createTime": now,
            "severity": SCC_SEVERITY.get(r.severity, "MEDIUM"),
            "findingClass": "MISCONFIGURATION",
            "indicator": {
                "domains": [],
                "ipAddresses": [],
            },
            "vulnerability": {},
            "compliance": compliance_standards,
            "description": r.description,
        }
        findings.append(finding)

    return findings


def write_wiz(
    results: list[CheckResult],
    path: str,
    resource_id: str = "postgresql-container",
    resource_type: str = "CONTAINER",
) -> None:
    """Write Wiz findings JSON to a file."""
    findings = wiz_json(results, resource_id, resource_type)
    with open(path, "w") as f:
        json.dump({"findings": findings, "count": len(findings)}, f, indent=2, default=str)
    print(f"[wiz] Written {len(findings)} findings to {path}")


def write_scc(
    results: list[CheckResult],
    path: str,
    project_id: str = "your-project-id",
    source_name: str = "organizations/YOUR_ORG/sources/YOUR_SOURCE",
    resource_name: str = None,
) -> None:
    """Write SCC findings JSON to a file."""
    findings = scc_json(results, project_id, source_name, resource_name)
    with open(path, "w") as f:
        json.dump({"findings": findings, "count": len(findings)}, f, indent=2, default=str)
    print(f"[scc] Written {len(findings)} findings to {path}")
