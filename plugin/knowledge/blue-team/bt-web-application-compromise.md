---
id: "bt-web-application-compromise"
title: "Web application compromise triage"
kind: "workflow"
cve: null
related-cves: null
cve-note: null
severity: "info"
cvss: 0
severity-basis: "cvss"
severity-note: null
product: "Web server application EDR"
versions: "-"
ports: "Any"
keywords: "Web server application EDR, Web application compromise triage, blue-team, evidence, authorized assessment"
entry: "Web application compromise triage"
verified: false
verified-on: null
verification-evidence: null
source-url: "https://attack.mitre.org/techniques/T1505/003/"
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

# Web application compromise triage

## Objective and scope

Investigate and improve the stated control with validated telemetry, explicit ownership and reversible changes. This is a workflow, not a CVE or a severity-scored finding.

## Preconditions

- Written scope or an incident-response mandate, a named system owner and agreed stop/escalation conditions.
- Approved test identities/data and a private evidence location with a defined retention period.
- Current product documentation and visibility into the control being assessed.

## Procedure

1. Preserve reverse-proxy, application, authentication and endpoint logs for the suspected time window.
2. Compare deployed files and dependencies with the trusted artifact; identify unauthorized writes without executing suspicious content.
3. Correlate web requests with service-account activity, unexpected child processes, new accounts and outbound connections.
4. Scope adjacent credentials and systems before approved isolation, rebuilding and secret rotation.

## Evidence and acceptance criteria

Artifact/file hashes, deployment baseline, redacted request references and process/network correlation. Record expected behavior before the test and the actual outcome afterward; mark missing evidence as unknown.

## False positives and limits

Administrative tools and deployment hooks can spawn shells; unreviewed uploads must not be executed during analysis. Do not change the record's laboratory-verification fields merely because a checklist was read or an inventory match was found.

## Handoff and cleanup

Agree recovery from trusted artifacts and follow-up application control tests. Remove synthetic accounts, objects, markers and temporary permissions introduced by the exercise, or record an owner-approved retention exception. Keep incident evidence under the agreed retention policy.

## References

- [Primary-source background](https://attack.mitre.org/techniques/T1505/003/). This project-authored checklist is not a verbatim vendor procedure and must be adapted to the deployed product and authorization.
