---
id: "rt-cloud-iam-policy-review"
title: "Cloud IAM least-privilege review"
kind: "workflow"
cve: null
related-cves: null
cve-note: null
severity: "info"
cvss: 0
severity-basis: "cvss"
severity-note: null
product: "AWS IAM and cloud identities"
versions: "-"
ports: "Any"
keywords: "AWS IAM and cloud identities, Cloud IAM least-privilege review, red-team, evidence, authorized assessment"
entry: "Cloud IAM least-privilege review"
verified: false
verified-on: null
verification-evidence: null
source-url: "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"
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

# Cloud IAM least-privilege review

## Objective and scope

Assess the stated security boundary using an explicitly authorized, bounded and reversible test. This is a workflow, not a CVE or a severity-scored finding.

## Preconditions

- Written scope or an incident-response mandate, a named system owner and agreed stop/escalation conditions.
- Approved test identities/data and a private evidence location with a defined retention period.
- Current product documentation and visibility into the control being assessed.

## Procedure

1. Map human, workload and cross-account identities to their actual owners and business actions.
2. Review trust policies, resource restrictions, explicit denies, temporary-credential requirements and emergency access.
3. Use provider policy-analysis tools and authorized read-only exports; validate a small set of synthetic resources instead of modifying live policies.
4. Assess privilege combinations and identity lifecycle, not only wildcard strings in one policy.

## Evidence and acceptance criteria

Policy/trust documents with account identifiers redacted, role paths, intended actions and policy-analysis results. Record expected behavior before the test and the actual outcome afterward; mark missing evidence as unknown.

## False positives and limits

A wildcard can be constrained by conditions or higher-level policies; conversely, several modest permissions can form a risky combination. Do not change the record's laboratory-verification fields merely because a checklist was read or an inventory match was found.

## Handoff and cleanup

Deliver owner-approved least-privilege diffs and logging requirements for role and policy changes. Remove synthetic accounts, objects, markers and temporary permissions introduced by the exercise, or record an owner-approved retention exception. Keep incident evidence under the agreed retention policy.

## References

- [Primary-source background](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html). This project-authored checklist is not a verbatim vendor procedure and must be adapted to the deployed product and authorization.
