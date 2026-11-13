---
id: "rt-external-exposure-inventory"
title: "External exposure and ownership inventory"
kind: "workflow"
cve: null
related-cves: null
cve-note: null
severity: "info"
cvss: 0
severity-basis: "cvss"
severity-note: null
product: "External attack surface"
versions: "-"
ports: "Any"
keywords: "External attack surface, External exposure and ownership inventory, red-team, evidence, authorized assessment"
entry: "External exposure and ownership inventory"
verified: false
verified-on: null
verification-evidence: null
source-url: "https://owasp.org/www-project-web-security-testing-guide/stable/"
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

# External exposure and ownership inventory

## Objective and scope

Assess the stated security boundary using an explicitly authorized, bounded and reversible test. This is a workflow, not a CVE or a severity-scored finding.

## Preconditions

- Written scope or an incident-response mandate, a named system owner and agreed stop/escalation conditions.
- Approved test identities/data and a private evidence location with a defined retention period.
- Current product documentation and visibility into the control being assessed.

## Procedure

1. Reconcile the owner-provided inventory with certificate, DNS and hosting records; label passive discoveries separately from authorized targets.
2. Associate each hostname with the application owner, environment and service purpose; flag abandoned records without claiming takeover.
3. Validate approved endpoints using normal protocol handshakes and bounded requests, not exploit payloads or recursive enumeration.
4. Record management interfaces, unexpected public services, exposure vantage and the exact time of the observation.

## Evidence and acceptance criteria

Ownership confirmation, DNS evidence, service metadata and an exposure table with timestamps. Record expected behavior before the test and the actual outcome afterward; mark missing evidence as unknown.

## False positives and limits

CDNs, shared hosting, wildcard certificates and stale DNS can misattribute assets; obtain owner confirmation before expanding scope. Do not change the record's laboratory-verification fields merely because a checklist was read or an inventory match was found.

## Handoff and cleanup

Give the blue team an asset-owner map and exposure deltas to reconcile against the CMDB. Remove synthetic accounts, objects, markers and temporary permissions introduced by the exercise, or record an owner-approved retention exception. Keep incident evidence under the agreed retention policy.

## References

- [Primary-source background](https://owasp.org/www-project-web-security-testing-guide/stable/). This project-authored checklist is not a verbatim vendor procedure and must be adapted to the deployed product and authorization.
