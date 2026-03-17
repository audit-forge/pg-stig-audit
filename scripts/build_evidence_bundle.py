#!/usr/bin/env python3
"""One-click compliance evidence bundle: executive PDF + JSON/SARIF + control trace."""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess  # nosec B404 (used for local cupsfilter PDF rendering)
import os
from datetime import datetime, UTC
from pathlib import Path

from evidence_utils import load_results, summarize, build_control_trace


def _render_pdf_from_text(text_file: Path, pdf_file: Path) -> bool:
    cupsfilter = shutil.which("cupsfilter")
    if not cupsfilter:
        return False
    if not os.path.exists(text_file):
        return False
    cmd = [cupsfilter, "-m", "application/pdf", str(text_file)]
    with pdf_file.open("wb") as f:
        res = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, check=False)  # nosec B603 (list args, no shell)  # nosec B603
    return res.returncode == 0


def main():
    p = argparse.ArgumentParser(description="Build compliance evidence bundle")
    p.add_argument("--json", default="test/output/hardened.json", help="Raw JSON output from audit run")
    p.add_argument("--sarif", default="test/output/hardened.sarif.json", help="SARIF output from audit run")
    p.add_argument("--out-dir", default="evidence/latest", help="Bundle output directory")
    p.add_argument("--label", default="hardened-fixture", help="Evidence label")
    args = p.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    raw = load_results(Path(args.json))
    results = raw.get("results", [])
    summary = summarize(results)
    trace = build_control_trace(results)

    stamp = datetime.now(UTC).isoformat()
    manifest = {
        "generated_at": stamp,
        "label": args.label,
        "artifacts": {
            "executive_pdf": "executive-summary.pdf",
            "executive_txt": "executive-summary.txt",
            "raw_json": "results.json",
            "sarif": "results.sarif.json",
            "control_trace": "control-trace.json",
        },
        "summary": summary,
    }

    # Copy core machine-readable artifacts
    (out_dir / "results.json").write_text(json.dumps(raw, indent=2))
    shutil.copyfile(args.sarif, out_dir / "results.sarif.json")
    (out_dir / "control-trace.json").write_text(json.dumps(trace, indent=2))
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))

    # Executive summary text + PDF
    text = "\n".join([
        "pg-stig-audit — Executive Summary",
        f"Generated: {stamp}",
        f"Label: {args.label}",
        "",
        f"Total checks: {summary['total']}",
        f"Pass rate: {summary['pass_rate']}%",
        f"PASS: {summary['status'].get('PASS',0)}",
        f"FAIL: {summary['status'].get('FAIL',0)}",
        f"WARN: {summary['status'].get('WARN',0)}",
        "",
        "Failed by severity:",
        f"- CRITICAL: {summary['failed_by_severity'].get('CRITICAL',0)}",
        f"- HIGH: {summary['failed_by_severity'].get('HIGH',0)}",
        f"- MEDIUM: {summary['failed_by_severity'].get('MEDIUM',0)}",
        "",
        "Top failing controls:",
    ])

    top_fails = [r for r in results if r.get("status") == "FAIL"][:10]
    for r in top_fails:
        text += f"\n- {r.get('check_id')} [{r.get('severity')}] {r.get('title')}"

    txt_file = out_dir / "executive-summary.txt"
    txt_file.write_text(text + "\n")

    pdf_file = out_dir / "executive-summary.pdf"
    ok_pdf = _render_pdf_from_text(txt_file, pdf_file)

    print(f"[ok] Wrote {out_dir / 'manifest.json'}")
    print(f"[ok] Wrote {out_dir / 'results.json'}")
    print(f"[ok] Wrote {out_dir / 'results.sarif.json'}")
    print(f"[ok] Wrote {out_dir / 'control-trace.json'}")
    print(f"[ok] Wrote {txt_file}")
    if ok_pdf:
        print(f"[ok] Wrote {pdf_file}")
    else:
        print("[warn] Could not render PDF (cupsfilter unavailable or failed)")


if __name__ == "__main__":
    main()
