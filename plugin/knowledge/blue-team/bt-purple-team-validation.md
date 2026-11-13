---
id: "bt-purple-team-validation"
title: "Purple-team control validation"
kind: "workflow"
cve: null
related-cves: null
cve-note: null
severity: "info"
cvss: 0
severity-basis: "cvss"
severity-note: null
product: "Detection and response validation"
versions: "-"
ports: "Any"
keywords: "Detection and response validation, Purple-team control validation, blue-team, evidence, authorized assessment"
entry: "Purple-team control validation"
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

# Purple-team control validation

## Objective and scope

Investigate and improve the stated control with validated telemetry, explicit ownership and reversible changes. This is a workflow, not a CVE or a severity-scored finding.

## Preconditions

- Written scope or an incident-response mandate, a named system owner and agreed stop/escalation conditions.
- Approved test identities/data and a private evidence location with a defined retention period.
- Current product documentation and visibility into the control being assessed.

## Procedure

1. Agree a benign behavior, approved target/account, exact time window, stop conditions and expected telemetry.
2. Validate collection, enrichment, analytic match, alert routing, analyst action and response separately.
3. Use synthetic markers and reversible configuration changes; never assume authorization for malware, persistence or credential capture.
4. Record detection/triage/containment timing, explain failures and retest the specific corrected checkpoint.

## Evidence and acceptance criteria

Exercise approval, marker/timeline, checkpoint outcomes and a dated retest record. Record expected behavior before the test and the actual outcome afterward; mark missing evidence as unknown.

## False positives and limits

An alert firing does not establish correct triage or containment; silence can result from missing ingestion rather than a weak rule. Do not change the record's laboratory-verification fields merely because a checklist was read or an inventory match was found.

## Handoff and cleanup

Deliver a jointly owned backlog with measurable acceptance criteria. Remove synthetic accounts, objects, markers and temporary permissions introduced by the exercise, or record an owner-approved retention exception. Keep incident evidence under the agreed retention policy.

## References

- [Primary-source background](https://csrc.nist.gov/pubs/sp/800/115/final). This project-authored checklist is not a verbatim vendor procedure and must be adapted to the deployed product and authorization.
