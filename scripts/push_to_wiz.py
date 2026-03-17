#!/usr/bin/env python3
"""
push_to_wiz.py — Push pg-stig-audit findings to Wiz as Custom Issues.

Wiz Integration Methods (both covered here):
  A. Custom Issues API — push findings as individual Wiz issues via GraphQL
  B. Custom Control (OPA) — upload/update the Rego policy as a Wiz Custom Control

Prerequisites:
  1. A Wiz Service Account with:
       - Scope: Issues (Read/Write) + Security Policies (Read/Write)
  2. Wiz API credentials:
       WIZ_CLIENT_ID=<client_id>
       WIZ_CLIENT_SECRET=<client_secret>
       WIZ_API_ENDPOINT=https://api.us1.app.wiz.io/graphql   # or EU
  3. (Optional) A Wiz entity/resource ID to attach findings to.
     If you don't have one, findings are created as standalone issues.

Setup:
  cp .env.example .env
  # Edit .env with your Wiz credentials

Usage:
  # Step 1: Run the audit and save JSON results
  python3 audit.py --mode docker --container my-postgres --json audit-results.json

  # Step 2A: Push findings as Wiz Issues
  python3 scripts/push_to_wiz.py issues \\
      --findings audit-results.json \\
      --resource-id "my-postgres-container"

  # Step 2B: Register the OPA Rego as a Wiz Custom Control
  python3 scripts/push_to_wiz.py custom-control \\
      --rego rego/pg_audit.rego \\
      --name "PostgreSQL CIS/STIG Container Benchmark" \\
      --description "CIS PostgreSQL 16 + DISA STIG controls for containerized PostgreSQL"

  # Combined: push issues + register control
  python3 scripts/push_to_wiz.py all \\
      --findings audit-results.json \\
      --rego rego/pg_audit.rego

Options:
  --dry-run         Print what would be sent without making API calls
  --only-failures   Only push FAIL findings (skip WARN, PASS)
  --env-file        Path to .env file (default: .env in repo root)
  --endpoint        Wiz API endpoint (overrides env var)
  --project-id      Wiz project ID to associate issues with
"""

import argparse
import json
import os
import sys
import urllib.request
import urllib.error
from urllib.parse import urlparse
from datetime import datetime, timezone
from pathlib import Path

# ─── Constants ────────────────────────────────────────────────────────────────

WIZ_AUTH_URL = "https://auth.app.wiz.io/oauth/token"
WIZ_API_US = "https://api.us1.app.wiz.io/graphql"
WIZ_API_EU = "https://api.eu1.app.wiz.io/graphql"

SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "INFO": "INFORMATIONAL",
}

STATUS_MAP = {
    "FAIL": "OPEN",
    "WARN": "OPEN",
    "ERROR": "OPEN",
    "PASS": "RESOLVED",
    "SKIP": "RESOLVED",
}

# ─── Environment Loading ───────────────────────────────────────────────────────

def load_env(env_file: str = None):
    """Load .env file into os.environ if it exists."""
    paths_to_try = []
    if env_file:
        paths_to_try.append(Path(env_file))
    # Try repo root .env
    repo_root = Path(__file__).parent.parent
    paths_to_try.append(repo_root / ".env")

    for path in paths_to_try:
        if path.exists():
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        key, _, val = line.partition("=")
                        val = val.strip().strip('"').strip("'")
                        os.environ.setdefault(key.strip(), val)
            print(f"[env] Loaded from {path}", file=sys.stderr)
            return

    print("[env] No .env file found — using environment variables directly", file=sys.stderr)


def require_env(key: str) -> str:
    val = os.environ.get(key, "").strip()
    if not val:
        print(f"ERROR: Missing required env var: {key}", file=sys.stderr)
        print(f"  Add it to .env or export {key}=...", file=sys.stderr)
        sys.exit(1)
    return val


def _validate_https_url(url: str, label: str = "url") -> str:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError(f"Invalid {label}: must be https URL")
    return url

# ─── Wiz Authentication ────────────────────────────────────────────────────────

def get_wiz_token(client_id: str, client_secret: str) -> str:
    """
    Obtain a Wiz API bearer token via OAuth2 client credentials.

    Tokens are valid for 60 minutes. For long-running jobs, refresh periodically.
    """
    payload = json.dumps({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "audience": "wiz-api",
    }).encode("utf-8")

    _validate_https_url(WIZ_AUTH_URL, "WIZ_AUTH_URL")
    req = urllib.request.Request(
        WIZ_AUTH_URL,
        data=payload,
        method="POST",
        headers={"Content-Type": "application/json"},
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # nosec B310 (validated https URL)
            data = json.loads(resp.read())
            token = data.get("access_token", "")
            if not token:
                print(f"ERROR: Auth response had no access_token: {data}", file=sys.stderr)
                sys.exit(1)
            return token
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        print(f"ERROR: Wiz auth failed ({e.code}): {body[:400]}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: Wiz auth request failed: {e}", file=sys.stderr)
        sys.exit(1)


# ─── GraphQL Helper ───────────────────────────────────────────────────────────

def gql(endpoint: str, token: str, query: str, variables: dict = None, dry_run: bool = False) -> dict:
    """Execute a GraphQL request against the Wiz API."""
    payload = {"query": query}
    if variables:
        payload["variables"] = variables

    encoded = json.dumps(payload).encode("utf-8")

    if dry_run:
        print(f"\n[dry-run] POST {endpoint}")
        print(f"[dry-run] Query: {query[:200]}...")
        if variables:
            print(f"[dry-run] Variables: {json.dumps(variables, indent=2)[:400]}")
        return {"data": {}}

    _validate_https_url(endpoint, "Wiz endpoint")
    req = urllib.request.Request(
        endpoint,
        data=encoded,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # nosec B310 (validated https URL)
            data = json.loads(resp.read())
            if "errors" in data:
                print(f"  ⚠️  GraphQL errors: {data['errors']}", file=sys.stderr)
            return data
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        print(f"  ❌ HTTP {e.code}: {body[:300]}", file=sys.stderr)
        return {}
    except Exception as e:
        print(f"  ❌ Request error: {e}", file=sys.stderr)
        return {}


# ─── Issue Pushing ────────────────────────────────────────────────────────────

CREATE_ISSUE_MUTATION = """
mutation CreateIssue($input: CreateIssueInput!) {
  createIssue(input: $input) {
    issue {
      id
      status
      severity
      createdAt
    }
  }
}
"""

def build_issue_input(result: dict, resource_id: str = None, project_id: str = None) -> dict:
    """Convert an audit result dict to a Wiz CreateIssueInput."""
    compliance_refs = []
    if result.get("cis_id"):
        compliance_refs.append(f"CIS: {result['cis_id']}")
    if result.get("stig_id"):
        compliance_refs.append(f"STIG: {result['stig_id']}")
    if result.get("fedramp_control"):
        compliance_refs.append(f"FedRAMP/NIST: {result['fedramp_control']}")

    description = result.get("description", "")
    if compliance_refs:
        description += f"\n\nCompliance: {' | '.join(compliance_refs)}"
    description += f"\n\nActual: {result.get('actual', '')}"
    description += f"\nExpected: {result.get('expected', '')}"

    notes = f"pg-stig-audit check: {result.get('check_id')}\n"
    notes += f"Category: {result.get('category', '')}\n"
    notes += f"Status: {result.get('status', '')}\n"
    if result.get("references"):
        notes += f"References: {', '.join(result['references'][:3])}"

    issue_input = {
        "title": f"[pg-stig-audit] {result.get('title', '')}",
        "description": description,
        "severity": SEVERITY_MAP.get(result.get("severity", "MEDIUM"), "MEDIUM"),
        "status": STATUS_MAP.get(result.get("status", "FAIL"), "OPEN"),
        "notes": notes,
        "remediation": result.get("remediation", ""),
    }

    if resource_id:
        issue_input["entityId"] = resource_id

    if project_id:
        issue_input["projectId"] = project_id

    return issue_input


def push_issues(
    results: list[dict],
    token: str,
    endpoint: str,
    resource_id: str = None,
    project_id: str = None,
    only_failures: bool = False,
    dry_run: bool = False,
    verbose: bool = False,
) -> tuple[int, int]:
    """Push audit results to Wiz as issues. Returns (success, failure) counts."""

    if only_failures:
        to_push = [r for r in results if r.get("status") in ("FAIL", "WARN", "ERROR")]
    else:
        to_push = [r for r in results if r.get("status") not in ("PASS", "SKIP")]

    print(f"\n📤 Pushing {len(to_push)} findings to Wiz Issues API")
    if resource_id:
        print(f"   Resource: {resource_id}")
    if project_id:
        print(f"   Project: {project_id}")
    if dry_run:
        print("   Mode: DRY RUN\n")

    success, failure = 0, 0

    for r in to_push:
        check_id = r.get("check_id", "?")
        severity = r.get("severity", "?")
        status = r.get("status", "?")

        if verbose:
            print(f"  → {check_id} [{severity}/{status}]")

        issue_input = build_issue_input(r, resource_id, project_id)
        resp = gql(endpoint, token, CREATE_ISSUE_MUTATION, {"input": issue_input}, dry_run=dry_run)

        issue = resp.get("data", {}).get("createIssue", {}).get("issue", {})
        if issue or dry_run:
            success += 1
            if verbose and issue:
                print(f"    ✅ Created issue {issue.get('id', '?')}")
        else:
            failure += 1
            if verbose:
                print(f"    ❌ Failed to create issue for {check_id}")

    return success, failure


# ─── Custom Control (OPA Rego) ────────────────────────────────────────────────

LIST_CONTROLS_QUERY = """
query ListCustomControls($search: String) {
  controls(
    filterBy: { origin: [CUSTOM], search: $search }
    first: 10
  ) {
    nodes {
      id
      name
      description
      createdAt
      enabled
    }
  }
}
"""

CREATE_CONTROL_MUTATION = """
mutation CreateControl($input: CreateControlInput!) {
  createControl(input: $input) {
    control {
      id
      name
      enabled
      createdAt
    }
  }
}
"""

UPDATE_CONTROL_MUTATION = """
mutation UpdateControl($input: UpdateControlInput!) {
  updateControl(input: $input) {
    control {
      id
      name
      enabled
    }
  }
}
"""

def push_custom_control(
    rego_path: str,
    name: str,
    description: str,
    token: str,
    endpoint: str,
    dry_run: bool = False,
    verbose: bool = False,
) -> bool:
    """
    Register or update the Rego policy as a Wiz Custom Control.

    In Wiz, Custom Controls are OPA policies that run against your cloud inventory.
    They appear under: Policies → Controls → Custom Controls.

    The input shape expected by pg_audit.rego:
      - Wiz scans Kubernetes workloads and containers
      - It passes resource metadata as 'input'
      - Our Rego expects: input.postgresql.settings, input.postgresql.hba_rules, etc.
      - In Wiz, this is most useful with the export_for_opa.py JSON as a policy test

    NOTE: Wiz Custom Controls via OPA work best when paired with:
      - Wiz Sensor (for runtime data collection from Kubernetes clusters)
      - Or via CSPM data models for cloud resource properties

    For full runtime PostgreSQL auditing, use the Issues API approach (push_issues)
    which works with the actual runtime audit results from audit.py.
    """
    if not Path(rego_path).exists():
        print(f"ERROR: Rego file not found: {rego_path}", file=sys.stderr)
        return False

    with open(rego_path) as f:
        rego_content = f.read()

    # Check if control already exists
    print(f"\n🔍 Checking for existing control: '{name}'")
    resp = gql(endpoint, token, LIST_CONTROLS_QUERY, {"search": name}, dry_run=dry_run)
    existing = resp.get("data", {}).get("controls", {}).get("nodes", [])
    existing_match = next((c for c in existing if c.get("name") == name), None)

    if existing_match:
        print(f"   Found existing control: {existing_match['id']}")
        print(f"   Updating...")
        update_input = {
            "id": existing_match["id"],
            "patch": {
                "name": name,
                "description": description,
                "opaPolicy": rego_content,
                "enabled": True,
            }
        }
        resp = gql(endpoint, token, UPDATE_CONTROL_MUTATION, {"input": update_input}, dry_run=dry_run)
        control = resp.get("data", {}).get("updateControl", {}).get("control", {})
        if control or dry_run:
            print(f"   ✅ Control updated: {control.get('id', 'N/A')}")
            return True
    else:
        print(f"   Creating new control...")
        create_input = {
            "name": name,
            "description": description,
            "opaPolicy": rego_content,
            "enabled": True,
            "severity": "HIGH",
            "targetNativeTypes": ["container", "pod"],
        }
        resp = gql(endpoint, token, CREATE_CONTROL_MUTATION, {"input": create_input}, dry_run=dry_run)
        control = resp.get("data", {}).get("createControl", {}).get("control", {})
        if control or dry_run:
            print(f"   ✅ Control created: {control.get('id', 'N/A')}")
            return True

    print("   ❌ Failed to create/update custom control", file=sys.stderr)
    return False


# ─── Verify Wiz Connectivity ──────────────────────────────────────────────────

WHOAMI_QUERY = """
query WhoAmI {
  me {
    ... on ServiceAccount {
      name
      scopes
    }
    ... on User {
      email
    }
  }
}
"""

def verify_connection(token: str, endpoint: str, dry_run: bool = False) -> bool:
    """Verify Wiz API connectivity and credentials."""
    print("🔗 Verifying Wiz API connection...")
    resp = gql(endpoint, token, WHOAMI_QUERY, dry_run=dry_run)
    me = resp.get("data", {}).get("me", {})
    if me or dry_run:
        name = me.get("name") or me.get("email") or "(dry-run)"
        scopes = me.get("scopes", [])
        print(f"   ✅ Connected as: {name}")
        if scopes:
            print(f"   Scopes: {', '.join(scopes)}")
        return True
    print("   ❌ Could not verify connection — check credentials and endpoint", file=sys.stderr)
    return False


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description="Push pg-stig-audit findings to Wiz",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    sub = p.add_subparsers(dest="command", required=True)

    # ── issues subcommand
    issues_p = sub.add_parser("issues", help="Push findings as Wiz Issues")
    issues_p.add_argument("--findings", required=True,
                          help="Path to audit-results.json (from audit.py --json)")
    issues_p.add_argument("--resource-id", default=None,
                          help="Wiz resource/entity ID to attach findings to")
    issues_p.add_argument("--project-id", default=None,
                          help="Wiz project ID to scope issues")
    issues_p.add_argument("--only-failures", action="store_true",
                          help="Only push FAIL/WARN findings (skip PASS/SKIP)")

    # ── custom-control subcommand
    cc_p = sub.add_parser("custom-control", help="Register OPA Rego as a Wiz Custom Control")
    cc_p.add_argument("--rego", default="rego/pg_audit.rego",
                      help="Path to Rego policy file (default: rego/pg_audit.rego)")
    cc_p.add_argument("--name", default="PostgreSQL CIS/STIG Container Benchmark",
                      help="Control name in Wiz")
    cc_p.add_argument("--description",
                      default="CIS PostgreSQL 16 Benchmark + DISA STIG controls for containerized PostgreSQL instances",
                      help="Control description")

    # ── all subcommand
    all_p = sub.add_parser("all", help="Push issues + register custom control")
    all_p.add_argument("--findings", required=True, help="Path to audit-results.json")
    all_p.add_argument("--rego", default="rego/pg_audit.rego", help="Path to Rego policy file")
    all_p.add_argument("--resource-id", default=None)
    all_p.add_argument("--project-id", default=None)
    all_p.add_argument("--only-failures", action="store_true")
    all_p.add_argument("--control-name", default="PostgreSQL CIS/STIG Container Benchmark")

    # ── verify subcommand
    sub.add_parser("verify", help="Verify Wiz API connection and credentials")

    # ── common args
    for sp in [issues_p, cc_p, all_p, p]:
        sp.add_argument("--env-file", default=None, help="Path to .env file")
        sp.add_argument("--endpoint", default=None,
                        help="Wiz API endpoint (default: WIZ_API_ENDPOINT env var)")
        sp.add_argument("--dry-run", action="store_true",
                        help="Print requests without making API calls")
        sp.add_argument("--verbose", "-v", action="store_true")

    # Add common args to verify too
    verify_p = [s for s in sub.choices.values() if hasattr(s, 'prog') and 'verify' in s.prog]
    if verify_p:
        verify_p[0].add_argument("--env-file", default=None)
        verify_p[0].add_argument("--endpoint", default=None)
        verify_p[0].add_argument("--dry-run", action="store_true")
        verify_p[0].add_argument("--verbose", "-v", action="store_true")

    args = p.parse_args()

    # Load env
    load_env(getattr(args, "env_file", None))

    # Get credentials
    client_id = require_env("WIZ_CLIENT_ID")
    client_secret = require_env("WIZ_CLIENT_SECRET")
    endpoint = (
        getattr(args, "endpoint", None)
        or os.environ.get("WIZ_API_ENDPOINT", WIZ_API_US)
    )

    dry_run = getattr(args, "dry_run", False)
    verbose = getattr(args, "verbose", False)

    print(f"\n🔐 Authenticating to Wiz...")
    if dry_run:
        print("   [dry-run] Skipping real auth")
        token = "dry-run-token"
    else:
        token = get_wiz_token(client_id, client_secret)
        print("   ✅ Authenticated")

    # ── verify
    if args.command == "verify":
        ok = verify_connection(token, endpoint, dry_run=dry_run)
        sys.exit(0 if ok else 1)

    # ── issues
    if args.command in ("issues", "all"):
        try:
            with open(args.findings) as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"ERROR: Cannot load findings file: {e}", file=sys.stderr)
            sys.exit(1)

        results = data.get("results", [])
        if not results:
            print("No results found in findings file.")
        else:
            verify_connection(token, endpoint, dry_run=dry_run)
            success, failure = push_issues(
                results=results,
                token=token,
                endpoint=endpoint,
                resource_id=getattr(args, "resource_id", None),
                project_id=getattr(args, "project_id", None),
                only_failures=getattr(args, "only_failures", False),
                dry_run=dry_run,
                verbose=verbose,
            )
            print(f"\n{'✅' if failure == 0 else '⚠️ '} Issues: {success} created, {failure} failed")
            if failure > 0 and args.command != "all":
                sys.exit(1)

    # ── custom-control
    if args.command in ("custom-control", "all"):
        rego_path = getattr(args, "rego", "rego/pg_audit.rego")
        # Resolve relative to repo root
        if not Path(rego_path).is_absolute():
            rego_path = str(Path(__file__).parent.parent / rego_path)

        name = getattr(args, "control_name", None) or getattr(args, "name", "PostgreSQL CIS/STIG Container Benchmark")
        description = getattr(args, "description", "CIS PostgreSQL 16 Benchmark + DISA STIG controls for containerized PostgreSQL")

        ok = push_custom_control(
            rego_path=rego_path,
            name=name,
            description=description,
            token=token,
            endpoint=endpoint,
            dry_run=dry_run,
            verbose=verbose,
        )
        if not ok and args.command != "all":
            sys.exit(1)

    print("\n✅ Done.")


if __name__ == "__main__":
    main()
