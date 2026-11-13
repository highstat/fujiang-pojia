---
id: "rt-saml-trust-review"
title: "SAML trust and signing review"
kind: "workflow"
cve: null
related-cves: null
cve-note: null
severity: "info"
cvss: 0
severity-basis: "cvss"
severity-note: null
product: "SAML federation"
versions: "-"
ports: "Any"
keywords: "SAML federation, SAML trust and signing review, red-team, evidence, authorized assessment"
entry: "SAML trust and signing review"
verified: false
verified-on: null
verification-evidence: null
source-url: "https://docs.oasis-open.org/security/saml/v2.0/saml-sec-consider-2.0-os.pdf"
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

# SAML trust and signing review

## Objective and scope

Assess the stated security boundary using an explicitly authorized, bounded and reversible test. This is a workflow, not a CVE or a severity-scored finding.

## Preconditions

- Written scope or an incident-response mandate, a named system owner and agreed stop/escalation conditions.
- Approved test identities/data and a private evidence location with a defined retention period.
- Current product documentation and visibility into the control being assessed.

## Procedure

1. Inventory service providers, identity providers, entity IDs, assertion consumer endpoints and signing-key ownership.
2. Review signature requirements, trusted certificates, issuer/audience constraints and response-to-request correlation using a test federation.
3. Confirm replay lifetime, clock-skew handling, account mapping and deprovisioning behavior without modifying production trust.
4. Plan signing-certificate rollover and break-glass recovery with the identity owner.

## Evidence and acceptance criteria

Trust metadata, certificate fingerprints, sanitized assertion structure and test-account acceptance/rejection outcomes. Record expected behavior before the test and the actual outcome afterward; mark missing evidence as unknown.

## False positives and limits

A certificate in metadata is not proof that signature enforcement or account mapping is correct; never retain full live assertions. Do not change the record's laboratory-verification fields merely because a checklist was read or an inventory match was found.

## Handoff and cleanup

Document trust assumptions, certificate rotation and the events defenders need to audit federation changes. Remove synthetic accounts, objects, markers and temporary permissions introduced by the exercise, or record an owner-approved retention exception. Keep incident evidence under the agreed retention policy.

## References

- [Primary-source background](https://docs.oasis-open.org/security/saml/v2.0/saml-sec-consider-2.0-os.pdf). This project-authored checklist is not a verbatim vendor procedure and must be adapted to the deployed product and authorization.
