---
id: "rt-assumed-breach-exercise"
title: "Assumed-breach exercise with explicit boundaries"
kind: "workflow"
cve: null
related-cves: null
cve-note: null
severity: "info"
cvss: 0
severity-basis: "cvss"
severity-note: null
product: "Adversary emulation"
versions: "-"
ports: "Any"
keywords: "Adversary emulation, Assumed-breach exercise with explicit boundaries, red-team, evidence, authorized assessment"
entry: "Assumed-breach exercise with explicit boundaries"
verified: false
verified-on: null
verification-evidence: null
source-url: "https://attack.mitre.org/"
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

# Assumed-breach exercise with explicit boundaries

## Objective and scope

Assess the stated security boundary using an explicitly authorized, bounded and reversible test. This is a workflow, not a CVE or a severity-scored finding.

## Preconditions

- Written scope or an incident-response mandate, a named system owner and agreed stop/escalation conditions.
- Approved test identities/data and a private evidence location with a defined retention period.
- Current product documentation and visibility into the control being assessed.

## Procedure

1. Choose a business scenario, authorized starting identity, approved systems and specific control objectives.
2. Define allowed benign behaviors, step-level approvals, emergency stops and prohibited data or persistence actions.
3. Have defenders agree telemetry prerequisites and evidence checkpoints before the exercise starts.
4. Execute only the approved steps and record detection, triage and containment timing without expanding access outside scope.

## Evidence and acceptance criteria

Scenario, approvals, step timeline, expected control outcomes and defender observations. Record expected behavior before the test and the actual outcome afterward; mark missing evidence as unknown.

## False positives and limits

A missed alert can be a collection, routing, rule or analyst-workflow failure; do not equate it automatically with invisible activity. Do not change the record's laboratory-verification fields merely because a checklist was read or an inventory match was found.

## Handoff and cleanup

Produce a purple-team improvement backlog with retest owners and dates. Remove synthetic accounts, objects, markers and temporary permissions introduced by the exercise, or record an owner-approved retention exception. Keep incident evidence under the agreed retention policy.

## References

- [Primary-source background](https://attack.mitre.org/). This project-authored checklist is not a verbatim vendor procedure and must be adapted to the deployed product and authorization.
