# pg-stig-audit Release Readiness Scorecard
**Date:** 2026-02-25  
**Owner:** Project Team  
**Scope:** CIS/STIG/FedRAMP-mapped container PostgreSQL audit tool

## Overall Score
**72 / 100 — Conditional Go (internal testing), No-Go (external compliance claim)**

---

## Scoring Rubric
- **90–100:** External release ready (claims supportable)
- **75–89:** Release candidate (minor gaps)
- **60–74:** Internal beta only (major gaps remain)
- **<60:** Not ready

---

## Category Scores

| Category | Weight | Score | Weighted | Status | Notes |
|---|---:|---:|---:|---|---|
| Core scanner functionality | 20 | 18 | 18.0 | ✅ | 36 checks execute; deterministic output generated |
| Control coverage quality | 20 | 14 | 14.0 | ⚠️ | Good runtime depth, but still limited vs full FedRAMP scope |
| FedRAMP alignment evidence | 20 | 13 | 13.0 | ⚠️ | 36/36 checks mapped; 15 unique controls; mapping ≠ full compliance |
| Test fixture quality | 15 | 10 | 10.0 | ⚠️ | Hardened/baseline/vuln now differentiated, but hardened still has criticals |
| Multi-mode runtime validation | 10 | 3 | 3.0 | ❌ | Docker validated; direct/kubectl not validated on this host |
| CI/CD & integration outputs | 10 | 8 | 8.0 | ✅ | SARIF/Wiz/SCC outputs present and usable |
| Documentation & operator UX | 5 | 6 | 6.0 | ✅ | README + setup docs strong; add release checklist and claims language |

**Total:** **72 / 100**

---

## Current Validation Snapshot

### Fixture outcomes (latest)
- **Hardened:** 26 PASS / 5 FAIL / 3 WARN / 2 SKIP
- **Baseline:** 18 PASS / 12 FAIL / 4 WARN / 2 SKIP
- **Vulnerable:** 16 PASS / 14 FAIL / 4 WARN / 2 SKIP

### Mapping completeness
- Checks with FedRAMP mapping: **36 / 36**
- Unique FedRAMP controls represented: **15**
- Families represented: **AC, AU, CM, CP, IA, SC**

---

## Release Gate (Pass/Fail)

| Gate | Requirement | Result |
|---|---|---|
| G1 | Scanner runs clean in Docker mode | ✅ Pass |
| G2 | Hardened fixture has **0 critical** findings | ❌ Fail |
| G3 | Direct mode validated in runnable environment | ❌ Fail |
| G4 | kubectl mode validated in runnable environment | ❌ Fail |
| G5 | Output artifacts generated (JSON/SARIF/Wiz/SCC) | ✅ Pass |
| G6 | External claims language legally/technically safe | ⚠️ Partial |

**Decision:** **Internal beta only** until G2–G4 are closed.

---

## Top Risks
1. **Over-claim risk:** “FedRAMP compliant” wording without full authorization package evidence.
2. **Validation gap risk:** direct/kubectl paths untested in current host setup.
3. **Demo credibility risk:** hardened profile still showing critical findings.

---

## 7-Day Closure Plan
1. **Fix hardened profile to 0 criticals** (TLS/auth first).
2. **Run direct mode in environment with local `psql` installed** and capture proof.
3. **Run kubectl mode in test cluster** and capture proof.
4. **Generate one deterministic evidence bundle** per mode.
5. **Publish claims language:** “FedRAMP-mapped runtime audit” (not “FedRAMP compliant”).

---

## Suggested External Positioning (Safe)
> “pg-stig-audit provides CIS/STIG/FedRAMP-mapped runtime security auditing for containerized PostgreSQL, with machine-readable outputs for CI and GRC workflows.”

Avoid until fully justified:
- “FedRAMP compliant by default”
- “FedRAMP certified”

---

## Next Score Target
- **Target:** 88+ (release candidate)
- **Required:** G2, G3, G4 pass + updated evidence pack
