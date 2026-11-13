---
id: "bt-dns-beaconing-triage"
title: "DNS anomaly and periodic-traffic triage"
kind: "workflow"
cve: null
related-cves: null
cve-note: null
severity: "info"
cvss: 0
severity-basis: "cvss"
severity-note: null
product: "DNS and network telemetry"
versions: "-"
ports: "Any"
keywords: "DNS and network telemetry, DNS anomaly and periodic-traffic triage, blue-team, evidence, authorized assessment"
entry: "DNS anomaly and periodic-traffic triage"
verified: false
verified-on: null
verification-evidence: null
source-url: "https://attack.mitre.org/techniques/T1071/004/"
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

# DNS anomaly and periodic-traffic triage

## Objective and scope

Investigate and improve the stated control with validated telemetry, explicit ownership and reversible changes. This is a workflow, not a CVE or a severity-scored finding.

## Preconditions

- Written scope or an incident-response mandate, a named system owner and agreed stop/escalation conditions.
- Approved test identities/data and a private evidence location with a defined retention period.
- Current product documentation and visibility into the control being assessed.

## Procedure

1. Confirm resolver, endpoint and proxy visibility and normalize source identities and timestamps.
2. Baseline query volume, domain rarity, response codes and periodicity for comparable devices and applications.
3. Correlate suspicious domains with the originating process, destination ownership and subsequent connections.
4. Use a controlled benign domain to test visibility; escalate based on multiple corroborating signals rather than string entropy alone.

## Evidence and acceptance criteria

Resolver/proxy event references, process attribution, baseline comparison and the bounded time window. Record expected behavior before the test and the actual outcome afterward; mark missing evidence as unknown.

## False positives and limits

Telemetry agents, CDNs, software updates and generated subdomains can mimic periodic or high-entropy traffic. Do not change the record's laboratory-verification fields merely because a checklist was read or an inventory match was found.

## Handoff and cleanup

Deliver a tuned hypothesis and an enrichment/containment decision, not a blanket block on all unusual domains. Remove synthetic accounts, objects, markers and temporary permissions introduced by the exercise, or record an owner-approved retention exception. Keep incident evidence under the agreed retention policy.

## References

- [Primary-source background](https://attack.mitre.org/techniques/T1071/004/). This project-authored checklist is not a verbatim vendor procedure and must be adapted to the deployed product and authorization.
