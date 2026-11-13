---
id: "bt-software-provenance"
title: "Software artifact and provenance review"
kind: "workflow"
cve: null
related-cves: null
cve-note: null
severity: "info"
cvss: 0
severity-basis: "cvss"
severity-note: null
product: "Software supply chain"
versions: "-"
ports: "Any"
keywords: "Software supply chain, Software artifact and provenance review, blue-team, evidence, authorized assessment"
entry: "Software artifact and provenance review"
verified: false
verified-on: null
verification-evidence: null
source-url: "https://slsa.dev/spec/v1.1/"
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

# Software artifact and provenance review

## Objective and scope

Investigate and improve the stated control with validated telemetry, explicit ownership and reversible changes. This is a workflow, not a CVE or a severity-scored finding.

## Preconditions

- Written scope or an incident-response mandate, a named system owner and agreed stop/escalation conditions.
- Approved test identities/data and a private evidence location with a defined retention period.
- Current product documentation and visibility into the control being assessed.

## Procedure

1. Identify the exact deployed artifact digest, publisher, source revision, build identity and distribution path.
2. Validate signatures and provenance against an explicit trust policy rather than accepting the presence of a signature.
3. Compare unexpected artifacts or dependencies with approved build outputs and isolate analysis copies without executing them.
4. Review signing-key access, build-runner isolation and the response path for a compromised dependency or publisher.

## Evidence and acceptance criteria

Artifact hashes, verified identity/trust decisions and provenance links without embedded credentials. Record expected behavior before the test and the actual outcome afterward; mark missing evidence as unknown.

## False positives and limits

A valid signature can still belong to an untrusted or compromised publisher; reproducibility and provenance answer different questions. Do not change the record's laboratory-verification fields merely because a checklist was read or an inventory match was found.

## Handoff and cleanup

Assign publisher/build trust policy and artifact quarantine decisions to accountable owners. Remove synthetic accounts, objects, markers and temporary permissions introduced by the exercise, or record an owner-approved retention exception. Keep incident evidence under the agreed retention policy.

## References

- [Primary-source background](https://slsa.dev/spec/v1.1/). This project-authored checklist is not a verbatim vendor procedure and must be adapted to the deployed product and authorization.
