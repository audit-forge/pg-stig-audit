# pg-stig-audit — Pilot-to-Revenue Roadmap (Saved for Later)

Status: parked (not active yet)
Owner: Keith
Purpose: reusable plan when ready to commercialize

---

## Revenue model (realistic ranges)

### Near term (3–6 months)
- Likely: **$5k–$25k/month**
- Most probable steady early target: **$10k–$15k/month**

### Mid term (6–12 months)
- Plausible with strong execution: **$30k–$75k/month**

### Offer structure
- Pilot: **$7.5k–$20k** one-time
- Recurring: **$2k–$8k/month per customer**

---

## 30-day execution plan (when activated)

### Week 1 — Foundation / Productization
Goal: one-command install + run + docs

1. Package versioned release artifact
2. Add install script + checksum verification
3. Harden `make wiz-report` and add `make pilot-check`
4. Keep docs focused (`README.md`, `WIZ_SETUP.md`)
5. Lock output schemas (`results.json`, `results.sarif.json`, `control-trace.json`)

Deliverable: pilot-ready runnable package

---

### Week 2 — Wiz-native Differentiation
Goal: improve value inside Wiz

1. Enrich issue payloads (tags: framework/severity/control/environment)
2. Ship custom control pack v1 (versioned)
3. Add drift mode (net-new regressions)
4. Generate `pilot-summary.md`

Deliverable: meaningful Wiz-native operational workflow

---

### Week 3 — Evidence / Audit Readiness
Goal: auditor confidence + retention-ready artifacts

1. Evidence bundle v2 (PDF + SARIF + JSON + trace + run metadata)
2. Integrity manifest (hashes/signing if available)
3. Machine-readable control mapping matrix
4. Deterministic auditor-mode output

Deliverable: compliance evidence set ready for audits

---

### Week 4 — Pilot Launch Readiness
Goal: close first paid pilots

1. Pilot motion: Day 0 install, Day 1 first report, Day 7 delta, Day 30 packet
2. Define tiers:
   - Starter
   - Pro
   - FedRAMP Assist
3. Set weekly scan + monthly update cadence
4. Track pilot success KPIs

Deliverable: repeatable pilot sales package

---

## KPIs to track

- Critical/High reduction % in 30 days
- Time-to-remediation
- Audit prep time reduction
- False positive rate
- Pilot-to-recurring conversion rate

---

## Activation checklist (when you are ready)

1. Confirm go-live date
2. Set target customer profile (first 3 prospects)
3. Set pilot pricing + scope guardrails
4. Create `ROADMAP-30D-ACTIVE.md` from this file
5. Start Week 1 execution

---

## Notes

- This file is intentionally parked and can be used as the baseline commercialization model later.
- Keep the core project execution-focused until activation.
