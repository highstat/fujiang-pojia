---
id: "bt-sbom-applicability"
title: "SBOM dependency applicability and VEX review"
kind: "workflow"
cve: null
related-cves: null
cve-note: null
severity: "info"
cvss: 0
severity-basis: "cvss"
severity-note: null
product: "SBOM dependency risk"
versions: "-"
ports: "Any"
keywords: "SBOM dependency risk, SBOM dependency applicability and VEX review, blue-team, evidence, authorized assessment"
entry: "SBOM dependency applicability and VEX review"
verified: false
verified-on: null
verification-evidence: null
source-url: "https://www.cisa.gov/sbom"
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

# SBOM dependency applicability and VEX review

## Objective and scope

Investigate and improve the stated control with validated telemetry, explicit ownership and reversible changes. This is a workflow, not a CVE or a severity-scored finding.

## Preconditions

- Written scope or an incident-response mandate, a named system owner and agreed stop/escalation conditions.
- Approved test identities/data and a private evidence location with a defined retention period.
- Current product documentation and visibility into the control being assessed.

## Procedure

1. Link each SBOM to the exact deployed artifact digest and distinguish build-time, bundled and runtime-loaded components.
2. Normalize component identity/version and compare vendor-supported affected ranges, backports and deployment configuration.
3. Review VEX statements for issuer, product scope, timestamp and justification rather than treating any not-affected label as authoritative.
4. Confirm a representative finding with artifact/runtime evidence and retain the decision rationale for future advisory updates.

## Evidence and acceptance criteria

Artifact/SBOM hashes, component identifiers, advisory references and a dated applicability decision. Record expected behavior before the test and the actual outcome afterward; mark missing evidence as unknown.

## False positives and limits

A package name match can be wrong or unused at runtime; an old VEX statement may no longer cover the current artifact or deployment. Do not change the record's laboratory-verification fields merely because a checklist was read or an inventory match was found.

## Handoff and cleanup

Give application owners a maintained dependency/applicability record and a reassessment trigger. Remove synthetic accounts, objects, markers and temporary permissions introduced by the exercise, or record an owner-approved retention exception. Keep incident evidence under the agreed retention policy.

## References

- [Primary-source background](https://www.cisa.gov/sbom). This project-authored checklist is not a verbatim vendor procedure and must be adapted to the deployed product and authorization.
