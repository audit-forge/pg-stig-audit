"""Terminal report renderer with color output."""
from checks.base import CheckResult, Status, Severity

RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
GRAY = "\033[90m"
WHITE = "\033[97m"

STATUS_COLORS = {
    Status.PASS: GREEN,
    Status.FAIL: RED,
    Status.WARN: YELLOW,
    Status.SKIP: GRAY,
    Status.ERROR: RED,
}

SEVERITY_COLORS = {
    Severity.CRITICAL: "\033[41m",   # red bg
    Severity.HIGH: RED,
    Severity.MEDIUM: YELLOW,
    Severity.LOW: CYAN,
    Severity.INFO: GRAY,
}

STATUS_ICONS = {
    Status.PASS: "✅",
    Status.FAIL: "❌",
    Status.WARN: "⚠️ ",
    Status.SKIP: "⏭️ ",
    Status.ERROR: "💥",
}


def _color(text: str, color: str) -> str:
    return f"{color}{text}{RESET}"


def render(results: list[CheckResult], target_info: dict = None) -> None:
    """Print a formatted terminal report."""
    total = len(results)
    passed = sum(1 for r in results if r.status == Status.PASS)
    failed = sum(1 for r in results if r.status == Status.FAIL)
    warned = sum(1 for r in results if r.status == Status.WARN)
    errors = sum(1 for r in results if r.status == Status.ERROR)

    critical_fails = sum(
        1 for r in results
        if r.status == Status.FAIL and r.severity == Severity.CRITICAL
    )
    high_fails = sum(
        1 for r in results
        if r.status == Status.FAIL and r.severity == Severity.HIGH
    )

    print()
    print(_color("=" * 72, BOLD))
    print(_color("  PostgreSQL CIS/STIG Security Audit Report", BOLD + WHITE))
    print(_color("  Mapped to: CIS PostgreSQL 16 Benchmark + DISA STIG + FedRAMP", GRAY))
    if target_info:
        for k, v in target_info.items():
            print(f"  {k}: {v}")
    print(_color("=" * 72, BOLD))
    print()

    # Group by category
    categories = {}
    for r in results:
        categories.setdefault(r.category, []).append(r)

    for category, cat_results in categories.items():
        cat_passed = sum(1 for r in cat_results if r.status == Status.PASS)
        cat_total = len(cat_results)
        print(_color(f"▶ {category} ({cat_passed}/{cat_total} passed)", BOLD + CYAN))
        print()

        for r in cat_results:
            status_icon = STATUS_ICONS.get(r.status, "?")
            status_color = STATUS_COLORS.get(r.status, "")
            sev_color = SEVERITY_COLORS.get(r.severity, "")

            # Main line
            print(
                f"  {status_icon} "
                f"{_color(r.check_id, BOLD)} "
                f"{_color('[' + r.severity.value + ']', sev_color)} "
                f"{r.title}"
            )

            # IDs line
            ids = []
            if r.cis_id:
                ids.append(f"CIS: {r.cis_id}")
            if r.stig_id:
                ids.append(f"STIG: {r.stig_id}")
            if r.fedramp_control:
                ids.append(f"FedRAMP: {r.fedramp_control}")
            if ids:
                print(_color(f"     {'  |  '.join(ids)}", GRAY))

            # Actual vs expected (for failures/warnings)
            if r.status in (Status.FAIL, Status.WARN, Status.ERROR):
                print(f"     {_color('Actual:', BOLD)}   {r.actual}")
                print(f"     {_color('Expected:', BOLD)} {r.expected}")
                if r.remediation:
                    print(f"     {_color('Fix:', BOLD)}      {r.remediation[:120]}{'...' if len(r.remediation) > 120 else ''}")

            print()

        print()

    # Summary
    print(_color("=" * 72, BOLD))
    print(_color("  SUMMARY", BOLD + WHITE))
    print(_color("=" * 72, BOLD))
    print(f"  Total checks:      {total}")
    print(f"  {_color('Passed:', GREEN)}           {passed}")
    print(f"  {_color('Failed:', RED)}           {failed}  "
          f"({_color(str(critical_fails) + ' CRITICAL', RED)}, "
          f"{_color(str(high_fails) + ' HIGH', YELLOW)})")
    print(f"  {_color('Warnings:', YELLOW)}         {warned}")
    if errors:
        print(f"  {_color('Errors:', RED)}           {errors}")

    # Risk rating
    if critical_fails > 0:
        rating = _color("🔴 CRITICAL RISK — immediate remediation required", RED + BOLD)
    elif high_fails >= 3:
        rating = _color("🔴 HIGH RISK — significant findings present", RED)
    elif high_fails > 0 or warned > 3:
        rating = _color("🟡 MEDIUM RISK — findings require attention", YELLOW)
    elif failed > 0:
        rating = _color("🟡 LOW RISK — minor findings present", YELLOW)
    else:
        rating = _color("🟢 COMPLIANT — all checks passed", GREEN)

    print()
    print(f"  Risk Rating: {rating}")
    print(_color("=" * 72, BOLD))
    print()
