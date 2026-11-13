---
id: "bt-linux-persistence-review"
title: "Linux startup and service-change investigation"
kind: "workflow"
cve: null
related-cves: null
cve-note: null
severity: "info"
cvss: 0
severity-basis: "cvss"
severity-note: null
product: "Linux systemd cron"
versions: "-"
ports: "Any"
keywords: "Linux systemd cron, Linux startup and service-change investigation, blue-team, evidence, authorized assessment"
entry: "Linux startup and service-change investigation"
verified: false
verified-on: null
verification-evidence: null
source-url: "https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html"
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

# Linux startup and service-change investigation

## Objective and scope

Investigate and improve the stated control with validated telemetry, explicit ownership and reversible changes. This is a workflow, not a CVE or a severity-scored finding.

## Preconditions

- Written scope or an incident-response mandate, a named system owner and agreed stop/escalation conditions.
- Approved test identities/data and a private evidence location with a defined retention period.
- Current product documentation and visibility into the control being assessed.

## Procedure

1. Inventory expected system/user services, timers, cron jobs, package ownership and configuration-management sources.
2. Review new or modified startup configuration together with file metadata, account identity and deployment changes.
3. Correlate suspicious changes with process execution, authentication and network telemetry; preserve files before disabling them.
4. Validate persistence removal after reboot or service reload only in an owner-approved recovery window.

## Evidence and acceptance criteria

Service/timer/job definitions, file hashes, ownership and a linked process/login timeline. Record expected behavior before the test and the actual outcome afterward; mark missing evidence as unknown.

## False positives and limits

Package updates, endpoint agents and configuration management routinely create services; a new unit is not automatically persistence. Do not change the record's laboratory-verification fields merely because a checklist was read or an inventory match was found.

## Handoff and cleanup

Assign configuration ownership and monitor changes outside approved deployment paths. Remove synthetic accounts, objects, markers and temporary permissions introduced by the exercise, or record an owner-approved retention exception. Keep incident evidence under the agreed retention policy.

## References

- [Primary-source background](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html). This project-authored checklist is not a verbatim vendor procedure and must be adapted to the deployed product and authorization.
