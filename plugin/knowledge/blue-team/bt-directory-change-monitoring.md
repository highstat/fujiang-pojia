---
id: "bt-directory-change-monitoring"
title: "Privileged directory and identity-change monitoring"
kind: "workflow"
cve: null
related-cves: null
cve-note: null
severity: "info"
cvss: 0
severity-basis: "cvss"
severity-note: null
product: "Active Directory change auditing"
versions: "-"
ports: "Any"
keywords: "Active Directory change auditing, Privileged directory and identity-change monitoring, blue-team, evidence, authorized assessment"
entry: "Privileged directory and identity-change monitoring"
verified: false
verified-on: null
verification-evidence: null
source-url: "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory"
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

# Privileged directory and identity-change monitoring

## Objective and scope

Investigate and improve the stated control with validated telemetry, explicit ownership and reversible changes. This is a workflow, not a CVE or a severity-scored finding.

## Preconditions

- Written scope or an incident-response mandate, a named system owner and agreed stop/escalation conditions.
- Approved test identities/data and a private evidence location with a defined retention period.
- Current product documentation and visibility into the control being assessed.

## Procedure

1. List protected groups, delegated administration, federation trusts and service identities with accountable owners.
2. Enable and validate the relevant directory-change and group-management audit paths for those objects.
3. Correlate group/ACL/policy changes with the actor's logon, source workstation, change ticket and timing.
4. Exercise an approved test-group change and confirm alert ownership, evidence retention and rollback.

## Evidence and acceptance criteria

Object IDs, actor identity, before/after state, change approval and a controlled detection test. Record expected behavior before the test and the actual outcome afterward; mark missing evidence as unknown.

## False positives and limits

Provisioning systems and delegated help-desk operations can legitimately change sensitive objects; validate the effective permission change. Do not change the record's laboratory-verification fields merely because a checklist was read or an inventory match was found.

## Handoff and cleanup

Maintain an exception registry and a tested escalation path for unauthorized privilege changes. Remove synthetic accounts, objects, markers and temporary permissions introduced by the exercise, or record an owner-approved retention exception. Keep incident evidence under the agreed retention policy.

## References

- [Primary-source background](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory). This project-authored checklist is not a verbatim vendor procedure and must be adapted to the deployed product and authorization.
