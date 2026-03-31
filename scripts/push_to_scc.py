#!/usr/bin/env python3
"""
push_to_scc.py — Push pg-stig-audit findings to Google Cloud Security Command Center.

Prerequisites:
  1. A registered SCC Source in your GCP org:
     gcloud scc sources create --organization=ORG_ID --display-name='pg-stig-audit'

  2. Authentication (one of):
     a. Application Default Credentials (ADC) via:
        gcloud auth application-default login
        OR: GOOGLE_APPLICATION_CREDENTIALS=/path/to/sa.json
     b. gcloud print-access-token (passed via --token flag)

  3. IAM Role on the Source:
     roles/securitycenter.findingsEditor

FedRAMP Note:
  GCP Security Command Center is FedRAMP High authorized.
  For FedRAMP restricted environments use the standard endpoint:
  https://securitycenter.googleapis.com  (covered under GCP FedRAMP ATO)

Usage:
  python3 scripts/push_to_scc.py \\
      --findings pg-audit-results.json \\
      --project my-fedramp-project \\
      --source organizations/123456/sources/789012 \\
      --resource-name "//container.googleapis.com/projects/my-project/locations/us-central1/clusters/prod"

  # With explicit token (e.g. in CI/CD after gcloud auth):
  python3 scripts/push_to_scc.py \\
      --findings pg-audit-results.json \\
      --project my-project \\
      --source organizations/123/sources/456 \\
      --token "$(gcloud auth print-access-token)"
"""
import argparse
import json
import os
import subprocess  # nosec B404 (needed to call gcloud for token acquisition)
import shutil
import sys
import urllib.request
import urllib.error
from urllib.parse import urlparse
from datetime import datetime, timezone

SCC_BASE = "https://securitycenter.googleapis.com/v1"


def _validate_url(url: str, allow_metadata_http: bool = False) -> str:
    parsed = urlparse(url)
    if parsed.scheme == "https" and parsed.netloc:
        return url
    if allow_metadata_http and parsed.scheme == "http" and parsed.netloc == "metadata.google.internal":
        return url
    raise ValueError(f"Invalid URL: {url}")

SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "INFO": "LOW",
}

STATE_MAP = {
    "FAIL": "ACTIVE",
    "WARN": "ACTIVE",
    "PASS": "INACTIVE",
    "ERROR": "ACTIVE",
    "SKIP": "INACTIVE",
}


def get_access_token(token: str = None) -> str:
    """Get a GCP access token via gcloud or from the argument."""
    if token:
        return token.strip()
    try:
        gcloud_bin = shutil.which("gcloud")
        if gcloud_bin:
            result = subprocess.run(  # nosec B603 (fixed binary path + fixed args)
                [gcloud_bin, "auth", "print-access-token"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0:
                return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Try ADC token endpoint (metadata server — works in GKE/Cloud Run/GCE)
    try:
        req = urllib.request.Request(
            _validate_url("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", allow_metadata_http=True),
            headers={"Metadata-Flavor": "Google"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:  # nosec B310 (metadata URL validated)
            data = json.loads(resp.read())
            return data.get("access_token", "")
    except Exception as e:
        # Metadata endpoint may be unavailable outside GCP; continue to next auth method.
        if os.environ.get("PG_AUDIT_DEBUG"):
            print(f"[debug] metadata token lookup failed: {e}", file=sys.stderr)

    print("ERROR: Could not obtain GCP access token.", file=sys.stderr)
    print("  Run: gcloud auth application-default login", file=sys.stderr)
    print("  Or pass: --token $(gcloud auth print-access-token)", file=sys.stderr)
    sys.exit(1)


def build_finding(result: dict, source_name: str, resource_name: str) -> dict:
    """Convert a pg-stig-audit result dict to SCC Finding format."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    finding_id = result["check_id"].lower().replace("-", "_")

    compliance = []
    if result.get("cis_id"):
        compliance.append({
            "standard": "CIS",
            "version": "CIS PostgreSQL 16 Benchmark v1.1.0",
            "ids": [result["cis_id"]],
        })
    if result.get("stig_id"):
        compliance.append({
            "standard": "DISA STIG",
            "version": "PostgreSQL STIG V1R1",
            "ids": [result["stig_id"]],
        })
    if result.get("fedramp_control"):
        compliance.append({
            "standard": "NIST SP 800-53",
            "version": "Rev 5",
            "ids": [result["fedramp_control"]],
        })

    return {
        "name": f"{source_name}/findings/{finding_id}",
        "parent": source_name,
        "resourceName": resource_name,
        "state": STATE_MAP.get(result.get("status", ""), "ACTIVE"),
        "category": f"PG-STIG/{result.get('category', 'CONFIG').upper().replace(' ', '_')}",
        "severity": SEVERITY_MAP.get(result.get("severity", ""), "MEDIUM"),
        "findingClass": "MISCONFIGURATION",
        "eventTime": now,
        "createTime": now,
        "description": result.get("description", ""),
        "externalUri": result.get("references", [""])[0] if result.get("references") else "",
        "sourceProperties": {
            "check_id": {"stringValue": result.get("check_id", "")},
            "title": {"stringValue": result.get("title", "")},
            "actual_value": {"stringValue": str(result.get("actual", ""))},
            "expected_value": {"stringValue": str(result.get("expected", ""))},
            "remediation": {"stringValue": result.get("remediation", "")},
            "cis_id": {"stringValue": result.get("cis_id") or ""},
            "stig_id": {"stringValue": result.get("stig_id") or ""},
            "fedramp_control": {"stringValue": result.get("fedramp_control") or ""},
            "tool": {"stringValue": "pg-stig-audit"},
            "framework": {"stringValue": "CIS PostgreSQL 16 + DISA STIG + FedRAMP High"},
        },
        "compliance": compliance,
    }


def push_finding(finding: dict, token: str, dry_run: bool = False) -> bool:
    """Push a single finding to SCC. Returns True on success."""
    source = finding["parent"]
    finding_id = finding["name"].split("/")[-1]
    url = _validate_url(f"{SCC_BASE}/{source}/findings/{finding_id}?updateMask=state,severity,category,sourceProperties,eventTime,compliance,description,externalUri,findingClass,resourceName")

    payload = json.dumps(finding).encode("utf-8")

    if dry_run:
        print(f"  [DRY RUN] Would PATCH: {url}")
        return True

    req = urllib.request.Request(
        url,
        data=payload,
        method="PATCH",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # nosec B310 (URL validated)
            return resp.status == 200
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        print(f"  ❌ HTTP {e.code} for {finding_id}: {body[:200]}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"  ❌ Error pushing {finding_id}: {e}", file=sys.stderr)
        return False


def main():
    p = argparse.ArgumentParser(
        description="Push pg-stig-audit findings to Google Cloud Security Command Center",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--findings", required=True,
                   help="Path to pg-audit-results.json (from audit.py --json)")
    p.add_argument("--project", required=True, help="GCP project ID")
    p.add_argument("--source", required=True,
                   help="SCC source name: organizations/ORG/sources/SOURCE_ID")
    p.add_argument("--resource-name",
                   help="GCP resource name for findings (default: generic container path)")
    p.add_argument("--token", help="GCP access token (default: use gcloud ADC)")
    p.add_argument("--dry-run", action="store_true",
                   help="Print what would be sent without actually sending")
    p.add_argument("--only-failures", action="store_true",
                   help="Only push FAIL/WARN findings (skip PASS)")
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args()

    # Load findings
    try:
        with open(args.findings) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"ERROR: Cannot load {args.findings}: {e}", file=sys.stderr)
        sys.exit(1)

    results = data.get("results", [])
    if not results:
        print("No results found in findings file.")
        sys.exit(0)

    # Filter
    if args.only_failures:
        results = [r for r in results if r.get("status") in ("FAIL", "WARN", "ERROR")]

    resource_name = args.resource_name or (
        f"//container.googleapis.com/projects/{args.project}/locations/global/clusters/unknown"
    )

    # Get token
    token = get_access_token(args.token)

    print(f"\n📡 Pushing {len(results)} findings to GCP SCC")
    print(f"   Source: {args.source}")
    print(f"   Resource: {resource_name}")
    if args.dry_run:
        print("   Mode: DRY RUN (no actual API calls)")
    print()

    success = 0
    failure = 0

    for r in results:
        finding = build_finding(r, args.source, resource_name)
        finding_id = finding["name"].split("/")[-1]
        status = r.get("status", "")
        severity = r.get("severity", "")

        if args.verbose:
            print(f"  → {finding_id} [{status}/{severity}]")

        ok = push_finding(finding, token, dry_run=args.dry_run)
        if ok:
            success += 1
            if args.verbose:
                print(f"    ✅ OK")
        else:
            failure += 1

    print(f"\n{'✅' if failure == 0 else '⚠️ '} Complete: {success} pushed, {failure} failed")

    if failure > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
