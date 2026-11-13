---
id: "rt-container-isolation"
title: "Container workload isolation review"
kind: "workflow"
cve: null
related-cves: null
cve-note: null
severity: "info"
cvss: 0
severity-basis: "cvss"
severity-note: null
product: "Containers and Kubernetes"
versions: "-"
ports: "Any"
keywords: "Containers and Kubernetes, Container workload isolation review, red-team, evidence, authorized assessment"
entry: "Container workload isolation review"
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

# Container workload isolation review

## Objective and scope

Assess the stated security boundary using an explicitly authorized, bounded and reversible test. This is a workflow, not a CVE or a severity-scored finding.

## Preconditions

- Written scope or an incident-response mandate, a named system owner and agreed stop/escalation conditions.
- Approved test identities/data and a private evidence location with a defined retention period.
- Current product documentation and visibility into the control being assessed.

## Procedure

1. Review workload manifests for privileged mode, host namespace use, host mounts, capabilities and service-account exposure.
2. Check admission policy, runtime identity, image provenance and the justification for host integration.
3. Validate with configuration inspection or an isolated canary workload; do not attempt a production container escape.
4. Review rollout impact, node pools and exceptions before enforcing restricted workload policy.

## Evidence and acceptance criteria

Redacted workload manifests, admission decisions and owner-approved exception inventory. Record expected behavior before the test and the actual outcome afterward; mark missing evidence as unknown.

## False positives and limits

A host mount or capability may be required by an infrastructure agent; document the threat boundary rather than automatically claiming escape. Do not change the record's laboratory-verification fields merely because a checklist was read or an inventory match was found.

## Handoff and cleanup

Provide workload owners a staged hardening plan and blue-team visibility into privileged workload creation. Remove synthetic accounts, objects, markers and temporary permissions introduced by the exercise, or record an owner-approved retention exception. Keep incident evidence under the agreed retention policy.

## References

- [Primary-source background](https://kubernetes.io/docs/concepts/security/pod-security-standards/). This project-authored checklist is not a verbatim vendor procedure and must be adapted to the deployed product and authorization.
