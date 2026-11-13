---
id: "rt-cicd-trust-boundaries"
title: "CI/CD pipeline and artifact trust review"
kind: "workflow"
cve: null
related-cves: null
cve-note: null
severity: "info"
cvss: 0
severity-basis: "cvss"
severity-note: null
product: "CI CD build systems"
versions: "-"
ports: "Any"
keywords: "CI CD build systems, CI/CD pipeline and artifact trust review, red-team, evidence, authorized assessment"
entry: "CI/CD pipeline and artifact trust review"
verified: false
verified-on: null
verification-evidence: null
source-url: "https://slsa.dev/spec/v1.1/"
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

# CI/CD pipeline and artifact trust review

## Objective and scope

Assess the stated security boundary using an explicitly authorized, bounded and reversible test. This is a workflow, not a CVE or a severity-scored finding.

## Preconditions

- Written scope or an incident-response mandate, a named system owner and agreed stop/escalation conditions.
- Approved test identities/data and a private evidence location with a defined retention period.
- Current product documentation and visibility into the control being assessed.

## Procedure

1. Map source changes, forked pull requests, runners, credentials, artifact stores and deployment approvals.
2. Review which untrusted inputs can influence trusted jobs and where signing or deployment authority is available.
3. Use an isolated test repository and nonsecret markers to validate boundaries; do not run attacker-controlled code on a production runner.
4. Check provenance verification, runner isolation, token scope and the lifetime of build credentials.

## Evidence and acceptance criteria

Trust-boundary diagram, redacted job configuration and benign test-run outcomes with artifact provenance. Record expected behavior before the test and the actual outcome afterward; mark missing evidence as unknown.

## False positives and limits

A signed artifact does not prove a trustworthy build; the signer identity and provenance verification policy both matter. Do not change the record's laboratory-verification fields merely because a checklist was read or an inventory match was found.

## Handoff and cleanup

Give engineering owners changes to runner isolation and approvals plus monitoring for workflow and signing-policy changes. Remove synthetic accounts, objects, markers and temporary permissions introduced by the exercise, or record an owner-approved retention exception. Keep incident evidence under the agreed retention policy.

## References

- [Primary-source background](https://slsa.dev/spec/v1.1/). This project-authored checklist is not a verbatim vendor procedure and must be adapted to the deployed product and authorization.
