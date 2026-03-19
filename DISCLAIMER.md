# Legal Disclaimer & Framework Attribution

## CIS Benchmark Attribution

**pg-stig-audit** implements security controls based on the following official benchmarks:

- **CIS PostgreSQL 16 Benchmark v1.1.0** (released 2025-06-30)
- **DISA STIG PostgreSQL 12 V1R1**
- **NIST SP 800-53 Revision 5**

### Important Legal Notices

⚠️ **This tool is NOT officially certified, endorsed, or approved by:**
- The Center for Internet Security (CIS)
- Defense Information Systems Agency (DISA)
- National Institute of Standards and Technology (NIST)

⚠️ **This is an independent, open-source implementation** of the security controls described in these frameworks.

### Official CIS Benchmark Coverage

The following controls are **directly based on official CIS PostgreSQL 16 Benchmark v1.1.0:**

- Sections 1–8 (69 controls total)
- We implement the audit procedures as described in the official benchmark
- Remediation steps reference the official CIS guidance

**Download the official CIS Benchmark:**
https://www.cisecurity.org/benchmark/postgresql

### Container Security Addendum (NOT in official CIS)

⚠️ **No official CIS benchmark exists for containerized PostgreSQL.**

The following controls are **our own additions** for container runtime security:
- `PG-CONT-001` through `PG-CONT-008` (Container Hardening)

These are based on:
- CIS Docker Benchmark
- CIS Kubernetes Benchmark  
- Container security best practices

**These container controls are NOT part of the official CIS PostgreSQL Benchmark.**

## Usage & Distribution

### Permitted Use

✅ You may:
- Use this tool to audit your PostgreSQL instances
- Reference our findings in internal compliance reports
- Cite this tool in documentation as "based on CIS PostgreSQL 16 v1.1.0"

### Prohibited Claims

❌ You may NOT:
- Claim this tool is "CIS Certified" or "CIS Approved"
- Represent this tool as an official CIS product
- Use CIS trademarks without permission
- Host copies of the official CIS Benchmark PDFs publicly

### Correct Attribution

**✅ Correct:**
- "Audited using pg-stig-audit, which implements CIS PostgreSQL 16 Benchmark v1.1.0 controls"
- "Based on CIS PostgreSQL 16 Benchmark v1.1.0, DISA STIG, and NIST 800-53"
- "Independent implementation of CIS security recommendations"

**❌ Incorrect:**
- "CIS Certified" or "CIS Compliant" (only official CIS-CAT tools can make this claim)
- "Approved by CIS" or "Official CIS tool"

## CIS SecureSuite Membership

If you need **official CIS certification**, consider:
- **CIS-CAT Pro Assessor** (official CIS tool, requires SecureSuite membership)
- **CIS WorkBench** (community participation, free registration)

Learn more: https://www.cisecurity.org/cis-securesuite

## DISA STIG Notice

This tool references **DISA STIG PostgreSQL 12 V1R1**. STIG findings are publicly available from:
https://public.cyber.mil/stigs/downloads/

**This is not a DISA-endorsed tool.** For official STIG validation, use DISA's STIG Viewer.

## NIST Notice

NIST SP 800-53 control mappings are provided for reference. This tool does not constitute official NIST validation or certification.

## License

This tool is released under [LICENSE TBD — recommend Apache 2.0 or MIT].

The official CIS, DISA, and NIST benchmark documents are copyright their respective organizations and subject to their terms of use.

---

**Questions about usage or attribution?** Contact: [your contact]

**Last Updated:** 2026-03-18
