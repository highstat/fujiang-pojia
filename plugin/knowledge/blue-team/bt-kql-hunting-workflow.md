---
id: "bt-kql-hunting-workflow"
title: "KQL hunting with schema and result validation"
kind: "workflow"
cve: null
related-cves: null
cve-note: null
severity: "info"
cvss: 0
severity-basis: "cvss"
severity-note: null
product: "Microsoft Defender XDR KQL"
versions: "-"
ports: "Any"
keywords: "Microsoft Defender XDR KQL, KQL hunting with schema and result validation, blue-team, evidence, authorized assessment"
entry: "KQL hunting with schema and result validation"
verified: false
verified-on: null
verification-evidence: null
source-url: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-overview"
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

# KQL hunting with schema and result validation

## Objective and scope

Investigate and improve the stated control with validated telemetry, explicit ownership and reversible changes. This is a workflow, not a CVE or a severity-scored finding.

## Preconditions

- Written scope or an incident-response mandate, a named system owner and agreed stop/escalation conditions.
- Approved test identities/data and a private evidence location with a defined retention period.
- Current product documentation and visibility into the control being assessed.

## Procedure

1. Confirm the licensed product, available tables, timestamp fields, retention and identity/host keys before writing a query.
2. Start with a bounded time window and a small projection; establish the normal behavior baseline for the intended population.
3. Validate joins, missing data, duplicate events and positive/negative fixtures before interpreting counts.
4. Review resulting event IDs and raw context with an analyst; export only redacted evidence needed for the hypothesis.

## Evidence and acceptance criteria

Query text, schema/table availability, time range, fixture outcomes and validated investigation references. Record expected behavior before the test and the actual outcome afterward; mark missing evidence as unknown.

## False positives and limits

A sample query for Defender XDR is not automatically portable to Sentinel or Entra tables; an empty result is not proof of safety. Do not change the record's laboratory-verification fields merely because a checklist was read or an inventory match was found.

## Handoff and cleanup

Convert a successful hunt into a reviewed detection only after testing telemetry coverage and false positives. Remove synthetic accounts, objects, markers and temporary permissions introduced by the exercise, or record an owner-approved retention exception. Keep incident evidence under the agreed retention policy.

### Illustrative read-only hunt

This uses Microsoft Defender XDR `DeviceProcessEvents`, not an Entra or generic Sentinel schema. Run only where that table and the required columns exist. It is an unvalidated starting query, not a shipped production detection.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName in~ ("w3wp.exe", "java.exe", "httpd", "nginx")
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "sh", "bash")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ReportId
```

Investigate deployment hooks, support actions and application behavior before classifying any result. Missing endpoint telemetry invalidates a negative conclusion.

## References

- [Primary-source background](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-overview). This project-authored checklist is not a verbatim vendor procedure and must be adapted to the deployed product and authorization.
