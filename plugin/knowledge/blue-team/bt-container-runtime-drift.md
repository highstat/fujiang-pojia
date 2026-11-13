---
id: "bt-container-runtime-drift"
title: "Container runtime and workload drift"
kind: "workflow"
cve: null
related-cves: null
cve-note: null
severity: "info"
cvss: 0
severity-basis: "cvss"
severity-note: null
product: "Container platform telemetry"
versions: "-"
ports: "Any"
keywords: "Container platform telemetry, Container runtime and workload drift, blue-team, evidence, authorized assessment"
entry: "Container runtime and workload drift"
verified: false
verified-on: null
verification-evidence: null
source-url: "https://kubernetes.io/docs/concepts/security/pod-security-standards/"
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

# Container runtime and workload drift

## Objective and scope

Investigate and improve the stated control with validated telemetry, explicit ownership and reversible changes. This is a workflow, not a CVE or a severity-scored finding.

## Preconditions

- Written scope or an incident-response mandate, a named system owner and agreed stop/escalation conditions.
- Approved test identities/data and a private evidence location with a defined retention period.
- Current product documentation and visibility into the control being assessed.

## Procedure

1. Baseline approved images/digests, process expectations, mounts, privileges and service identities per workload.
2. Correlate unexpected process or filesystem changes with deployment events, interactive sessions and runtime configuration.
3. Distinguish an image rebuild from an altered running container and preserve the node/workload identity chain.
4. Use an isolated canary workload to test collection and rule behavior before enforcing a response.

## Evidence and acceptance criteria

Image digest, workload revision, process/file events and a documented baseline difference. Record expected behavior before the test and the actual outcome afterward; mark missing evidence as unknown.

## False positives and limits

Debug containers, migrations and infrastructure agents can legitimately deviate; process names alone are weak evidence. Do not change the record's laboratory-verification fields merely because a checklist was read or an inventory match was found.

## Handoff and cleanup

Provide workload owners hardening actions and a tested exception process. Remove synthetic accounts, objects, markers and temporary permissions introduced by the exercise, or record an owner-approved retention exception. Keep incident evidence under the agreed retention policy.

## References

- [Primary-source background](https://kubernetes.io/docs/concepts/security/pod-security-standards/). This project-authored checklist is not a verbatim vendor procedure and must be adapted to the deployed product and authorization.
