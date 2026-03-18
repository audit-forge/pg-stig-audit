#!/usr/bin/env python3
"""Evidence bundle output (zip archive) for pg-stig-audit."""
import json
import zipfile
from datetime import datetime, timezone


def write(results, bundle_path, target_info, snapshot_data):
    """
    Write an evidence bundle (zip) containing:
    - manifest.json
    - results.json
    - summary.txt
    - evidence/<check_id>.json for each finding
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    
    with zipfile.ZipFile(bundle_path, "w", zipfile.ZIP_DEFLATED) as zf:
        # Manifest
        manifest = {
            "tool": "pg-stig-audit",
            "version": "1.0.0",
            "timestamp": timestamp,
            "target": target_info,
            "contents": [
                "manifest.json",
                "results.json",
                "summary.txt",
                "snapshot.json",
            ],
        }
        
        # Results JSON
        results_doc = {
            "target": target_info,
            "timestamp": timestamp,
            "results": [
                {
                    "check_id": r.check_id,
                    "title": r.title,
                    "status": r.status.value,
                    "severity": r.severity.value,
                    "description": r.description,
                    "remediation": r.remediation,
                }
                for r in results
            ],
        }
        
        # Summary text
        status_counts = {}
        severity_counts = {}
        for r in results:
            status_counts[r.status.value] = status_counts.get(r.status.value, 0) + 1
            severity_counts[r.severity.value] = severity_counts.get(r.severity.value, 0) + 1
        
        summary_lines = [
            "pg-stig-audit Evidence Bundle",
            f"Generated: {timestamp}",
            f"Target: {target_info}",
            "",
            "Summary:",
            f"  PASS: {status_counts.get('PASS', 0)}",
            f"  FAIL: {status_counts.get('FAIL', 0)}",
            f"  WARN: {status_counts.get('WARN', 0)}",
            f"  SKIP: {status_counts.get('SKIP', 0)}",
            f"  ERROR: {status_counts.get('ERROR', 0)}",
            "",
            "Severity Distribution:",
            f"  CRITICAL: {severity_counts.get('CRITICAL', 0)}",
            f"  HIGH: {severity_counts.get('HIGH', 0)}",
            f"  MEDIUM: {severity_counts.get('MEDIUM', 0)}",
            f"  LOW: {severity_counts.get('LOW', 0)}",
            f"  INFO: {severity_counts.get('INFO', 0)}",
        ]
        
        # Write to zip
        zf.writestr("manifest.json", json.dumps(manifest, indent=2))
        zf.writestr("results.json", json.dumps(results_doc, indent=2))
        zf.writestr("summary.txt", "\n".join(summary_lines))
        zf.writestr("snapshot.json", json.dumps(snapshot_data, indent=2))
        
        # Per-check evidence files
        for r in results:
            evidence_doc = {
                "check_id": r.check_id,
                "title": r.title,
                "status": r.status.value,
                "severity": r.severity.value,
                "description": r.description,
                "remediation": r.remediation,
                "rationale": r.rationale if hasattr(r, "rationale") else None,
                "references": r.references if hasattr(r, "references") else [],
            }
            zf.writestr(f"evidence/{r.check_id}.json", json.dumps(evidence_doc, indent=2))
            manifest["contents"].append(f"evidence/{r.check_id}.json")
        
        # Update manifest with full file list
        zf.writestr("manifest.json", json.dumps(manifest, indent=2))
    
    print(f"[bundle] Written to {bundle_path}")
