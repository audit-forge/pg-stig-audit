#!/usr/bin/env python3
"""
pg-stig-audit — PostgreSQL CIS Benchmark / DISA STIG Audit Tool
for Containerized PostgreSQL Instances.

Maps controls to:
  - CIS PostgreSQL 16 Benchmark (v1.0.0)
  - DISA STIG PostgreSQL 12 (V1R1)
  - NIST SP 800-53 Rev 5 (FedRAMP High controls)

Outputs:
  - Terminal report (colored)
  - SARIF 2.1.0 (CI/CD, GitHub Security, Azure DevOps)
  - Wiz custom findings JSON
  - Google Cloud SCC findings JSON

Usage examples:
  # Docker container
  python audit.py --mode docker --container my-postgres

  # Kubernetes pod
  python audit.py --mode kubectl --pod postgres-0 --namespace prod

  # Direct TCP (Cloud SQL with proxy, or any host:port)
  python audit.py --mode direct --host 127.0.0.1 --port 5432 --user postgres

  # Output to files
  python audit.py --mode docker --container pg --sarif results.sarif.json
  python audit.py --mode docker --container pg --wiz wiz-findings.json
  python audit.py --mode docker --container pg --scc scc-findings.json \\
    --gcp-project my-project --scc-source organizations/123/sources/456
"""
import argparse
import csv
import json
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(__file__))

from runner import PgRunner
from checks import ALL_CHECKERS
from checks.base import Status, Severity
from mappings.frameworks import enrich_all
from output import report, sarif, wiz_scc, bundle


def parse_args():
    p = argparse.ArgumentParser(
        description="PostgreSQL CIS/STIG security audit for containerized instances",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # Target mode
    mode = p.add_argument_group("Target (choose one mode)")
    mode.add_argument(
        "--mode",
        choices=["docker", "kubectl", "direct"],
        default="docker",
        help="Connection mode (default: docker)",
    )
    mode.add_argument("--container", help="Docker container name or ID")
    mode.add_argument("--pod", help="Kubernetes pod name")
    mode.add_argument("--namespace", default="default", help="K8s namespace (default: default)")
    mode.add_argument("--host", default="127.0.0.1", help="Direct mode: DB host")
    mode.add_argument("--port", type=int, default=5432, help="Direct mode: DB port")

    # DB credentials
    creds = p.add_argument_group("Database credentials")
    creds.add_argument("--user", default="postgres", help="PostgreSQL user (default: postgres)")
    creds.add_argument("--password", help="Password (direct mode; or set PGPASSWORD env var)")
    creds.add_argument("--database", default="postgres", help="Database name (default: postgres)")

    # Output options
    out = p.add_argument_group("Output")
    out.add_argument("--sarif", metavar="FILE", help="Write SARIF 2.1.0 output to FILE")
    out.add_argument("--bundle", metavar="FILE", help="Write evidence bundle (zip) to FILE")
    out.add_argument("--wiz", metavar="FILE", help="Write Wiz findings JSON to FILE")
    out.add_argument("--scc", metavar="FILE", help="Write GCP SCC findings JSON to FILE")
    out.add_argument("--json", metavar="FILE", help="Write raw results JSON to FILE")
    out.add_argument("--csv", metavar="FILE", help="Write CSV results to FILE (includes NIST 800-171, CMMC, MITRE columns)")
    out.add_argument("--no-color", action="store_true", help="Disable terminal color output")
    out.add_argument("--quiet", action="store_true", help="Suppress terminal report (output files only)")
    out.add_argument("--fail-on", choices=["any", "high", "critical", "none"],
                     default="high", help="Exit code 1 if findings at this level or above (default: high)")

    # GCP/Wiz options
    gcp = p.add_argument_group("GCP / Wiz options")
    gcp.add_argument("--gcp-project", default="your-project-id", help="GCP project ID for SCC output")
    gcp.add_argument("--scc-source", default="organizations/YOUR_ORG/sources/YOUR_SOURCE",
                     help="SCC source resource name")
    gcp.add_argument("--resource-name", help="GCP resource name for SCC findings")
    gcp.add_argument("--wiz-resource-id", default="postgresql-container",
                     help="Resource ID label for Wiz findings")

    # Misc
    p.add_argument("--verbose", action="store_true", help="Print SQL queries as they run")
    p.add_argument("--version", action="version", version="pg-stig-audit 1.0.0")
    p.add_argument("--skip-cve", action="store_true", help="Skip CVE/KEV vulnerability scan (faster, compliance-only)")

    return p.parse_args()


def _csv_local_path(result) -> str:
    if getattr(result, "local_path", ""):
        return result.local_path
    evidence_type = getattr(result, "evidence_type", "")
    if evidence_type == "container-config":
        return "container-inspect"
    if evidence_type == "runtime-config":
        return "runtime-config"
    if evidence_type == "filesystem":
        return "filesystem"
    if evidence_type in ("network", "network-exposure"):
        return "runtime-network-config"
    return "not_applicable"


def write_csv(filepath: str, results: list, cve_scanned: bool) -> None:
    """Write audit results to a CSV file suitable for spreadsheet analysis.

    CVE/KEV fields are conditional:
      - vulnerability findings populate them directly
      - non-vulnerability findings emit not_applicable
      - if CVE scanning was skipped, vulnerability fields emit not_scanned
    """
    fieldnames = [
        "Control_ID",
        "Title",
        "Severity",
        "Result",
        "Category",
        "Actual",
        "Expected",
        "Description",
        "CIS_Control",
        "DISA_STIG_ID",
        "NIST_800_53",
        "NIST_800_171",
        "CMMC_Level",
        "MITRE_ATTACK",
        "MITRE_D3FEND",
        "Remediation",
        "References",
        "CVE_ID",
        "KEV_Score",
        "CVE_Remediation",
        "Local_Path",
    ]
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        for r in results:
            is_vuln_row = r.category == "vulnerability-management" or r.check_id.endswith("VER-001")
            if is_vuln_row:
                cve_id = "; ".join(r.cve_ids) if r.cve_ids else ("none_found" if cve_scanned else "not_scanned")
                kev_score = r.kev_score or ("none_known_exploited" if cve_scanned else "not_scanned")
                cve_remediation = r.cve_remediation or ("none_required" if cve_scanned else "not_scanned")
            else:
                cve_id = "not_applicable"
                kev_score = "not_applicable"
                cve_remediation = "not_applicable"

            writer.writerow({
                "Control_ID": r.check_id,
                "Title": r.title,
                "Severity": r.severity.value,
                "Result": r.status.value,
                "Category": r.category,
                "Actual": r.actual,
                "Expected": r.expected,
                "Description": r.description,
                "CIS_Control": r.cis_id or "",
                "DISA_STIG_ID": r.stig_id or "",
                "NIST_800_53": "; ".join(r.nist_800_53_controls),
                "NIST_800_171": "; ".join(r.nist_800_171),
                "CMMC_Level": str(r.cmmc_level) if r.cmmc_level is not None else "",
                "MITRE_ATTACK": "; ".join(r.mitre_attack),
                "MITRE_D3FEND": "; ".join(r.mitre_d3fend),
                "Remediation": r.remediation,
                "References": "; ".join(r.references),
                "CVE_ID": cve_id,
                "KEV_Score": kev_score,
                "CVE_Remediation": cve_remediation,
                "Local_Path": _csv_local_path(r),
            })


def main():
    args = parse_args()

    # Validate required args per mode
    if args.mode == "docker" and not args.container:
        print("ERROR: --container is required for --mode docker", file=sys.stderr)
        sys.exit(2)
    if args.mode == "kubectl" and not args.pod:
        print("ERROR: --pod is required for --mode kubectl", file=sys.stderr)
        sys.exit(2)

    # Build runner
    runner = PgRunner(
        mode=args.mode,
        container=args.container,
        pod=args.pod,
        namespace=args.namespace,
        host=args.host,
        port=args.port,
        user=args.user,
        password=args.password or os.environ.get("PGPASSWORD"),
        database=args.database,
        verbose=args.verbose,
    )

    # Test connection
    print(f"\n🔍 Connecting to PostgreSQL via {args.mode}...", end=" ", flush=True)
    if not runner.test_connection():
        print("FAILED")
        print("ERROR: Cannot connect to PostgreSQL. Check container name, credentials, and that psql is available.", file=sys.stderr)
        print("  Docker: docker exec <container> psql -U postgres -c 'SELECT 1'", file=sys.stderr)
        print("  kubectl: kubectl exec <pod> -- psql -U postgres -c 'SELECT 1'", file=sys.stderr)
        sys.exit(2)
    print("✅ Connected")

    # Get PostgreSQL version
    ver_rows = runner.query_with_cols("SELECT version();", ["version"])
    pg_version = ver_rows[0].get("version", "unknown") if ver_rows else "unknown"
    print(f"   {pg_version[:80]}")

    target_info = {
        "Mode": args.mode,
        "Target": args.container or args.pod or f"{args.host}:{args.port}",
        "User": args.user,
        "Database": args.database,
    }

    # Run all check modules
    print(f"\n⚡ Running {sum(len(c(runner).run()) for c in ALL_CHECKERS)} checks across {len(ALL_CHECKERS)} categories...\n")
    all_results = []
    for checker_cls in ALL_CHECKERS:
        checker = checker_cls(runner)
        results = checker.run()
        all_results.extend(results)
        passed = sum(1 for r in results if r.status == Status.PASS)
        print(f"   ✓ {checker_cls.__name__.replace('Checker', '')} — {passed}/{len(results)} passed")

    # Enrich results with NIST 800-171, CMMC, and MITRE framework mappings
    enrich_all(all_results)

    # CVE/KEV vulnerability scan (appended after enrich_all so it is not enriched)
    if not args.skip_cve:
        from checks.cve_scanner import detect_pg_version, fetch_cve_data, load_kev_catalog, cve_to_check_result
        cache_dir = os.path.join(os.path.dirname(__file__), "data")
        os.makedirs(cache_dir, exist_ok=True)

        version = detect_pg_version(runner)
        if version:
            print(f"[cve] Detected version: {version}")
            kev = load_kev_catalog(cache_dir)
            cves = fetch_cve_data("postgresql", version, cache_dir)
            major = version.split(".")[0]
            local_path = f"/usr/lib/postgresql/{major}/bin/postgres"
            cve_result = cve_to_check_result(cves, kev, "postgresql", version, local_path)
            all_results.append(cve_result)
        else:
            print("[cve] Could not detect version, skipping CVE scan")

    print()

    # Terminal report
    if not args.quiet:
        report.render(all_results, target_info)

    # File outputs
    target_uri = f"postgresql://{args.user}@{args.container or args.host}:{args.port}/{args.database}"

    if args.sarif:
        sarif.write(all_results, args.sarif, target_uri)

    if args.bundle:
        bundle.write(all_results, args.bundle, target_info, runner.snapshot())

    if args.wiz:
        wiz_scc.write_wiz(all_results, args.wiz, args.wiz_resource_id)

    if args.scc:
        wiz_scc.write_scc(
            all_results,
            args.scc,
            project_id=args.gcp_project,
            source_name=args.scc_source,
            resource_name=args.resource_name,
        )

    if args.json:
        with open(args.json, "w") as f:
            json.dump(
                {
                    "target": target_info,
                    "pg_version": pg_version,
                    "results": [r.to_dict() for r in all_results],
                },
                f,
                indent=2,
                default=str,
            )
        print(f"[json] Written to {args.json}")

    if args.csv:
        write_csv(args.csv, all_results, cve_scanned=not args.skip_cve)
        print(f"[csv]  Written to {args.csv}")

    # Exit code based on fail-on level
    fail_severities = {
        "any": {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW},
        "high": {Severity.CRITICAL, Severity.HIGH},
        "critical": {Severity.CRITICAL},
        "none": set(),
    }
    fail_set = fail_severities.get(args.fail_on, {Severity.CRITICAL, Severity.HIGH})
    has_failures = any(
        r.status == Status.FAIL and r.severity in fail_set
        for r in all_results
    )

    sys.exit(1 if has_failures else 0)


if __name__ == "__main__":
    main()
