---
id: "rt-rules-of-engagement"
title: "Rules of engagement and stop conditions"
kind: "workflow"
cve: null
related-cves: null
cve-note: null
severity: "info"
cvss: 0
severity-basis: "cvss"
severity-note: null
product: "Assessment governance"
versions: "-"
ports: "Any"
keywords: "Assessment governance, Rules of engagement and stop conditions, red-team, evidence, authorized assessment"
entry: "Rules of engagement and stop conditions"
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

# Rules of engagement and stop conditions

## Objective and scope

Assess the stated security boundary using an explicitly authorized, bounded and reversible test. This is a workflow, not a CVE or a severity-scored finding.

## Preconditions

- Written scope or an incident-response mandate, a named system owner and agreed stop/escalation conditions.
- Approved test identities/data and a private evidence location with a defined retention period.
- Current product documentation and visibility into the control being assessed.

## Procedure

1. List exact domains, CIDRs, tenants, applications, account roles and third-party exclusions; distinguish ownership from authorization.
2. Agree allowed techniques, traffic ceilings, test windows, emergency contacts, notification rules and a kill-switch procedure.
3. Identify sensitive data classes, storage location, retention/deletion dates and who may view evidence.
4. Write down prohibited actions and separate approvals for social engineering, credential use, persistence or availability-impacting tests.

## Evidence and acceptance criteria

Signed scope, technique allowlist, contact tree, dated approval and agreed stop conditions. Record expected behavior before the test and the actual outcome afterward; mark missing evidence as unknown.

## False positives and limits

A publicly reachable asset or a bug-bounty label does not automatically authorize every technique or third-party dependency. Do not change the record's laboratory-verification fields merely because a checklist was read or an inventory match was found.

## Handoff and cleanup

The exercise lead and defender receive the same scope and emergency process before any activity. Remove synthetic accounts, objects, markers and temporary permissions introduced by the exercise, or record an owner-approved retention exception. Keep incident evidence under the agreed retention policy.

## References

- [Primary-source background](https://csrc.nist.gov/pubs/sp/800/115/final). This project-authored checklist is not a verbatim vendor procedure and must be adapted to the deployed product and authorization.
