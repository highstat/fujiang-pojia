---
id: "rt-reporting-retest"
title: "Evidence-led reporting and remediation retest"
kind: "workflow"
cve: null
related-cves: null
cve-note: null
severity: "info"
cvss: 0
severity-basis: "cvss"
severity-note: null
product: "Pentest reporting"
versions: "-"
ports: "Any"
keywords: "Pentest reporting, Evidence-led reporting and remediation retest, red-team, evidence, authorized assessment"
entry: "Evidence-led reporting and remediation retest"
verified: false
verified-on: null
verification-evidence: null
source-url: "https://csrc.nist.gov/pubs/sp/800/115/final"
vendor-advisory: null
cwe: null
patch-date: null
sources: "Project-authored operational checklist with primary-source background; documentation URL availability checked during the 2026-11-13 expansion. No lab or production validation is claimed."
kev: null
kev-date: null
kev-source: null
epss: null
epss-percentile: null
epss-date: null
epss-source: null
enrichment-updated: null
---

# Evidence-led reporting and remediation retest

## Objective and scope

Assess the stated security boundary using an explicitly authorized, bounded and reversible test. This is a workflow, not a CVE or a severity-scored finding.

## Preconditions

- Written scope or an incident-response mandate, a named system owner and agreed stop/escalation conditions.
- Approved test identities/data and a private evidence location with a defined retention period.
- Current product documentation and visibility into the control being assessed.

## Procedure

1. Separate inventory observations, plausible exposure, lab reproduction and confirmed target findings.
2. Include scope, account roles, timestamps, prerequisites, minimal redacted evidence and affected business action.
3. Agree an owner, severity rationale, fix plan and deadline without deriving business impact from CVSS alone.
4. Retest the original control and relevant negative cases after remediation; record residual risk and remove synthetic artifacts.

## Evidence and acceptance criteria

Reproducible evidence bundle, owner-approved remediation plan and dated retest outcomes. Record expected behavior before the test and the actual outcome afterward; mark missing evidence as unknown.

## False positives and limits

A screenshot or scanner label without scope and prerequisites is insufficient; do not present public intelligence as target verification. Do not change the record's laboratory-verification fields merely because a checklist was read or an inventory match was found.

## Handoff and cleanup

Deliver machine-readable issue IDs and regression cases alongside the human-readable report. Remove synthetic accounts, objects, markers and temporary permissions introduced by the exercise, or record an owner-approved retention exception. Keep incident evidence under the agreed retention policy.

## References

- [Primary-source background](https://csrc.nist.gov/pubs/sp/800/115/final). This project-authored checklist is not a verbatim vendor procedure and must be adapted to the deployed product and authorization.
