#!/usr/bin/env python3
"""Create deterministic fixture delta artifacts from test outputs."""
from __future__ import annotations

import argparse
import json
from datetime import datetime, UTC
from pathlib import Path

from evidence_utils import load_results, summarize, compare


def main():
    p = argparse.ArgumentParser(description="Build fixture delta pack with deterministic deltas")
    p.add_argument("--input-dir", default="test/output", help="Directory containing hardened/baseline/vulnerable JSON")
    p.add_argument("--out-dir", default="artifacts/fixture-pack", help="Output directory")
    args = p.parse_args()

    in_dir = Path(args.input_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    fixtures = {}
    for name in ("hardened", "baseline", "vulnerable"):
        data = load_results(in_dir / f"{name}.json")
        fixtures[name] = {
            "target": data.get("target", {}),
            "pg_version": data.get("pg_version"),
            "summary": summarize(data.get("results", [])),
        }

    deltas = {
        "hardened_vs_baseline": compare(fixtures["baseline"]["summary"], fixtures["hardened"]["summary"]),
        "hardened_vs_vulnerable": compare(fixtures["vulnerable"]["summary"], fixtures["hardened"]["summary"]),
        "baseline_vs_vulnerable": compare(fixtures["vulnerable"]["summary"], fixtures["baseline"]["summary"]),
    }

    pack = {
        "generated_at": datetime.now(UTC).isoformat(),
        "fixtures": fixtures,
        "deltas": deltas,
        "deterministic": True,
        "notes": [
            "Generated from test/output fixture JSON artifacts.",
            "Use this file to validate deterministic before/after security posture changes.",
        ],
    }

    (out_dir / "fixture-delta-pack.json").write_text(json.dumps(pack, indent=2))

    md = [
        "# Fixture Delta Pack",
        "",
        f"Generated: {pack['generated_at']}",
        "",
        "## Fixture Summaries",
        "",
    ]
    for name in ("hardened", "baseline", "vulnerable"):
        s = fixtures[name]["summary"]
        md.append(f"- **{name}**: pass_rate={s['pass_rate']}% | PASS={s['status'].get('PASS',0)} FAIL={s['status'].get('FAIL',0)} WARN={s['status'].get('WARN',0)}")

    md.extend(["", "## Deterministic Deltas", ""])
    for label, d in deltas.items():
        md.append(f"- **{label}**: pass_rate_delta={d['pass_rate_delta']} pts, pass_count_delta={d['pass_count_delta']}, fail_count_delta={d['fail_count_delta']}, critical_fail_delta={d['critical_fail_delta']}")

    (out_dir / "README.md").write_text("\n".join(md) + "\n")
    print(f"[ok] Wrote {out_dir / 'fixture-delta-pack.json'}")
    print(f"[ok] Wrote {out_dir / 'README.md'}")


if __name__ == "__main__":
    main()
