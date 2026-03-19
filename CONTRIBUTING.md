# Contributing to pg-stig-audit

Thank you for your interest in contributing! This document covers how to get involved.

---

## Ways to Contribute

- **Bug reports** — open a GitHub Issue with steps to reproduce
- **New checks** — implement additional CIS/STIG controls (see below)
- **Framework mappings** — improve NIST/CMMC/MITRE coverage
- **Documentation** — clarify usage, add examples
- **Test coverage** — add test cases for edge conditions

---

## Development Setup

```bash
git clone https://github.com/audit-forge/pg-stig-audit.git
cd pg-stig-audit
python -m pytest test/ -v
```

No dependencies beyond Python 3.9+ standard library.

---

## Code Style

- Python 3.9+ compatible — no walrus operators, no 3.10+ match statements
- Follow existing patterns in `checks/` — each checker is a class inheriting `BaseChecker`
- Use `list[CheckResult]` return types (not `List[CheckResult]`)
- Prefer explicit over clever — this is audit tooling, clarity matters more than brevity
- Run `python -m py_compile <file>` to catch syntax errors before committing

---

## Adding a New Check

1. Open the relevant checker module in `checks/` (or create a new one)
2. Add a new `CheckResult` entry following the existing pattern:

```python
CheckResult(
    check_id="PG-XYZ-001",        # Unique ID — prefix matches category
    title="Descriptive title",
    status=Status.PASS,            # or FAIL, WARN, SKIP, ERROR
    severity=Severity.HIGH,        # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category="Category Name",
    cis_id="6.7",                  # CIS benchmark section.control
    stig_id="V-214070",            # DISA STIG finding ID (if applicable)
    description="What this checks and why it matters.",
    actual=str(observed_value),
    expected="on",
    remediation="Steps to fix the finding.",
    references=["https://..."],
)
```

3. Add framework mappings in `mappings/frameworks.py` for your new `check_id`
4. Add a test case in `test/test_checks.py`
5. Document the control in the relevant section of the README

---

## Adding Framework Mappings

All framework mappings (NIST 800-53, NIST 800-171, CMMC, MITRE ATT&CK, MITRE D3FEND) are in `mappings/frameworks.py`. The `enrich_all()` function applies them to every `CheckResult` automatically.

To add or update a mapping:

```python
# In mappings/frameworks.py, find the CONTROL_MAP dict
"PG-XYZ-001": {
    "nist_800_53": ["AC-3", "SC-8"],
    "nist_800_171": ["3.1.1", "3.13.8"],
    "cmmc_level": 2,
    "mitre_attack": ["T1040", "T1078"],
    "mitre_d3fend": ["D3-ET", "D3-NI"],
},
```

---

## Testing Requirements

All PRs must pass the test suite:

```bash
python -m pytest test/ -v
```

For new checks, include at least one test case demonstrating:
- A PASS result when the control is satisfied
- A FAIL or WARN result when it is not

The test suite uses a `FakeRunner` mock — do not add tests that require a live PostgreSQL instance in the unit test suite.

---

## Pull Request Process

1. Fork the repo and create a branch: `git checkout -b feature/my-check`
2. Make your changes with clear, focused commits
3. Ensure `python -m pytest test/ -v` passes
4. Ensure `python -m py_compile audit.py checks/*.py` has no errors
5. Open a PR with a clear description of what you changed and why
6. Reference any relevant CIS/STIG/NIST control IDs in the PR description

---

## Benchmark and Compliance Accuracy

This tool implements controls from publicly available security benchmarks. If you believe a control implementation is incorrect:

- Cite the specific benchmark version and section
- Describe the correct expected behavior
- Include a reference to the official benchmark text

**Note:** CIS benchmarks are copyrighted by Center for Internet Security. Contributions must implement controls independently — do not reproduce benchmark text verbatim.

---

## Security Issues

If you discover a security vulnerability in this tool itself (not in PostgreSQL), please open a GitHub Issue marked `[SECURITY]`. Do not include exploit details in the public issue — describe the class of vulnerability and we will coordinate disclosure.

---

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
