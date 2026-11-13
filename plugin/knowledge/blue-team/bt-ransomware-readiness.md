---
id: "bt-ransomware-readiness"
title: "Ransomware readiness and containment tabletop"
kind: "workflow"
cve: null
related-cves: null
cve-note: null
severity: "info"
cvss: 0
severity-basis: "cvss"
severity-note: null
product: "Incident response readiness"
versions: "-"
ports: "Any"
keywords: "Incident response readiness, Ransomware readiness and containment tabletop, blue-team, evidence, authorized assessment"
entry: "Ransomware readiness and containment tabletop"
verified: false
verified-on: null
verification-evidence: null
source-url: "https://www.cisa.gov/stopransomware/ransomware-guide"
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

# Ransomware readiness and containment tabletop

## Objective and scope

Investigate and improve the stated control with validated telemetry, explicit ownership and reversible changes. This is a workflow, not a CVE or a severity-scored finding.

## Preconditions

- Written scope or an incident-response mandate, a named system owner and agreed stop/escalation conditions.
- Approved test identities/data and a private evidence location with a defined retention period.
- Current product documentation and visibility into the control being assessed.

## Procedure

1. Identify critical services, dependency owners, emergency communications and preapproved isolation authority.
2. Review privileged identity separation, remote access, endpoint coverage and offline/immutable backup controls.
3. Run a tabletop with synthetic events, decision checkpoints and a restoration objective; never deploy encryption or malware.
4. Validate out-of-band contacts, evidence handling and the sequence for containment, recovery and notification.

## Evidence and acceptance criteria

Tabletop timeline, decision/authority gaps, recovery objectives and tested communication paths. Record expected behavior before the test and the actual outcome afterward; mark missing evidence as unknown.

## False positives and limits

A tabletop or backup-success message does not establish that recovery meets business objectives. Do not change the record's laboratory-verification fields merely because a checklist was read or an inventory match was found.

## Handoff and cleanup

Assign measurable fixes to identity, network, endpoint, backup and business owners. Remove synthetic accounts, objects, markers and temporary permissions introduced by the exercise, or record an owner-approved retention exception. Keep incident evidence under the agreed retention policy.

## References

- [Primary-source background](https://www.cisa.gov/stopransomware/ransomware-guide). This project-authored checklist is not a verbatim vendor procedure and must be adapted to the deployed product and authorization.
