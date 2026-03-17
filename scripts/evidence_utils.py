#!/usr/bin/env python3
"""Shared helpers for demo/evidence generation."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path


def load_results(path: Path) -> dict:
    with path.open() as f:
        return json.load(f)


def summarize(results: list[dict]) -> dict:
    status = Counter(r.get("status", "UNKNOWN") for r in results)
    severity_fail = Counter(
        r.get("severity", "UNKNOWN")
        for r in results
        if r.get("status") == "FAIL"
    )
    total = len(results)
    passed = status.get("PASS", 0)
    score = round((passed / total) * 100, 1) if total else 0.0
    return {
        "total": total,
        "status": dict(status),
        "failed_by_severity": dict(severity_fail),
        "pass_rate": score,
    }


def build_control_trace(results: list[dict]) -> list[dict]:
    trace = []
    for r in results:
        trace.append(
            {
                "check_id": r.get("check_id"),
                "title": r.get("title"),
                "status": r.get("status"),
                "severity": r.get("severity"),
                "category": r.get("category"),
                "cis_id": r.get("cis_id"),
                "stig_id": r.get("stig_id"),
                "fedramp_control": r.get("fedramp_control"),
                "actual": r.get("actual"),
                "expected": r.get("expected"),
            }
        )
    return trace


def compare(a: dict, b: dict) -> dict:
    """Return b-a deltas for key demo metrics."""
    out = {
        "pass_rate_delta": round(b["pass_rate"] - a["pass_rate"], 1),
        "pass_count_delta": b["status"].get("PASS", 0) - a["status"].get("PASS", 0),
        "fail_count_delta": b["status"].get("FAIL", 0) - a["status"].get("FAIL", 0),
        "critical_fail_delta": b["failed_by_severity"].get("CRITICAL", 0) - a["failed_by_severity"].get("CRITICAL", 0),
        "high_fail_delta": b["failed_by_severity"].get("HIGH", 0) - a["failed_by_severity"].get("HIGH", 0),
    }
    return out
