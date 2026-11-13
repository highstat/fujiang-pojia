---
id: "rt-web-authorization-matrix"
title: "Web authorization with synthetic accounts"
kind: "workflow"
cve: null
related-cves: null
cve-note: null
severity: "info"
cvss: 0
severity-basis: "cvss"
severity-note: null
product: "Web applications"
versions: "-"
ports: "Any"
keywords: "Web applications, Web authorization with synthetic accounts, red-team, evidence, authorized assessment"
entry: "Web authorization with synthetic accounts"
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

# Web authorization with synthetic accounts

## Objective and scope

Assess the stated security boundary using an explicitly authorized, bounded and reversible test. This is a workflow, not a CVE or a severity-scored finding.

## Preconditions

- Written scope or an incident-response mandate, a named system owner and agreed stop/escalation conditions.
- Approved test identities/data and a private evidence location with a defined retention period.
- Current product documentation and visibility into the control being assessed.

## Procedure

1. Create owner-approved users with at least two roles and two tenants plus synthetic records for each.
2. Build a subject-action-object matrix for read, update, export and administrative actions before testing.
3. Repeat normal requests with the other test identity and confirm both the response and backend state; avoid unrelated customer records.
4. Validate server-side denial across UI, direct API and asynchronous export paths; distinguish authentication failure from missing authorization.

## Evidence and acceptance criteria

Redacted paired requests, synthetic object IDs, role/tenant mapping and expected-versus-observed decisions. Record expected behavior before the test and the actual outcome afterward; mark missing evidence as unknown.

## False positives and limits

A different response length or hidden UI control is not proof of cross-tenant access; prove the outcome using only synthetic objects. Do not change the record's laboratory-verification fields merely because a checklist was read or an inventory match was found.

## Handoff and cleanup

Provide the matrix as regression cases for application owners and detection engineers. Remove synthetic accounts, objects, markers and temporary permissions introduced by the exercise, or record an owner-approved retention exception. Keep incident evidence under the agreed retention policy.

## References

- [Primary-source background](https://owasp.org/www-project-web-security-testing-guide/stable/). This project-authored checklist is not a verbatim vendor procedure and must be adapted to the deployed product and authorization.
