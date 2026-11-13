---
id: "bt-logging-baseline"
title: "Logging coverage and collection validation"
kind: "workflow"
cve: null
related-cves: null
cve-note: null
severity: "info"
cvss: 0
severity-basis: "cvss"
severity-note: null
product: "Security telemetry"
versions: "-"
ports: "Any"
keywords: "Security telemetry, Logging coverage and collection validation, blue-team, evidence, authorized assessment"
entry: "Logging coverage and collection validation"
verified: false
verified-on: null
verification-evidence: null
source-url: "https://csrc.nist.gov/pubs/sp/800/61/r3/final"
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

# Logging coverage and collection validation

## Objective and scope

Investigate and improve the stated control with validated telemetry, explicit ownership and reversible changes. This is a workflow, not a CVE or a severity-scored finding.

## Preconditions

- Written scope or an incident-response mandate, a named system owner and agreed stop/escalation conditions.
- Approved test identities/data and a private evidence location with a defined retention period.
- Current product documentation and visibility into the control being assessed.

## Procedure

1. Inventory identity, endpoint, application, DNS, proxy, firewall and cloud control-plane log sources.
2. Record schema, clock synchronization, retention, access controls and gaps in each collection path.
3. Generate approved benign markers and confirm ingestion, parsing, identity/asset attribution and searchability.
4. Alert on collection gaps and document the evidence unavailable for each incident hypothesis.

## Evidence and acceptance criteria

Telemetry coverage map, canary event IDs, ingestion latency and retention verification. Record expected behavior before the test and the actual outcome afterward; mark missing evidence as unknown.

## False positives and limits

An empty search may indicate a collection gap or wrong schema/time zone rather than absence of activity. Do not change the record's laboratory-verification fields merely because a checklist was read or an inventory match was found.

## Handoff and cleanup

Assign owners and deadlines for blind spots before promising detection coverage. Remove synthetic accounts, objects, markers and temporary permissions introduced by the exercise, or record an owner-approved retention exception. Keep incident evidence under the agreed retention policy.

## References

- [Primary-source background](https://csrc.nist.gov/pubs/sp/800/61/r3/final). This project-authored checklist is not a verbatim vendor procedure and must be adapted to the deployed product and authorization.
