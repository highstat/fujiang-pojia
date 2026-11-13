---
id: "rt-api-object-function-access"
title: "API object and function access-control review"
kind: "workflow"
cve: null
related-cves: null
cve-note: null
severity: "info"
cvss: 0
severity-basis: "cvss"
severity-note: null
product: "REST and GraphQL APIs"
versions: "-"
ports: "Any"
keywords: "REST and GraphQL APIs, API object and function access-control review, red-team, evidence, authorized assessment"
entry: "API object and function access-control review"
verified: false
verified-on: null
verification-evidence: null
source-url: "https://owasp.org/www-project-api-security/"
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

# API object and function access-control review

## Objective and scope

Assess the stated security boundary using an explicitly authorized, bounded and reversible test. This is a workflow, not a CVE or a severity-scored finding.

## Preconditions

- Written scope or an incident-response mandate, a named system owner and agreed stop/escalation conditions.
- Approved test identities/data and a private evidence location with a defined retention period.
- Current product documentation and visibility into the control being assessed.

## Procedure

1. Enumerate documented operations and approved test endpoints from OpenAPI or GraphQL schemas supplied by the owner.
2. Check object ownership, tenant binding, field-level filtering and administrative function access with synthetic identities.
3. Include batch, search, export and background-job results; set strict page and request ceilings.
4. Validate that authorization is performed per object and action rather than inferred from a caller-supplied role or tenant field.

## Evidence and acceptance criteria

Operation matrix, test account roles, synthetic record ownership and minimal response/state evidence. Record expected behavior before the test and the actual outcome afterward; mark missing evidence as unknown.

## False positives and limits

API schema visibility alone is not an authorization defect; pagination and caches can create misleading comparisons. Do not change the record's laboratory-verification fields merely because a checklist was read or an inventory match was found.

## Handoff and cleanup

Map each failed control to the precise operation and an automated negative test. Remove synthetic accounts, objects, markers and temporary permissions introduced by the exercise, or record an owner-approved retention exception. Keep incident evidence under the agreed retention policy.

## References

- [Primary-source background](https://owasp.org/www-project-api-security/). This project-authored checklist is not a verbatim vendor procedure and must be adapted to the deployed product and authorization.
