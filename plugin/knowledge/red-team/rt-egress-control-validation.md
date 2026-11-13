---
id: "rt-egress-control-validation"
title: "Controlled egress-policy validation"
kind: "workflow"
cve: null
related-cves: null
cve-note: null
severity: "info"
cvss: 0
severity-basis: "cvss"
severity-note: null
product: "DNS HTTP proxy egress"
versions: "-"
ports: "Any"
keywords: "DNS HTTP proxy egress, Controlled egress-policy validation, red-team, evidence, authorized assessment"
entry: "Controlled egress-policy validation"
verified: false
verified-on: null
verification-evidence: null
source-url: "https://attack.mitre.org/techniques/T1071/"
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

# Controlled egress-policy validation

## Objective and scope

Assess the stated security boundary using an explicitly authorized, bounded and reversible test. This is a workflow, not a CVE or a severity-scored finding.

## Preconditions

- Written scope or an incident-response mandate, a named system owner and agreed stop/escalation conditions.
- Approved test identities/data and a private evidence location with a defined retention period.
- Current product documentation and visibility into the control being assessed.

## Procedure

1. Agree an organization-controlled sink, benign markers, test identities, destinations and volume limits.
2. Use ordinary requests containing only a synthetic marker to assess DNS, proxy and outbound policy enforcement.
3. Check identity attribution and correlation across endpoint, proxy, resolver and firewall logs.
4. Validate approved business exceptions and stop if policy changes or sensitive data would be needed.

## Evidence and acceptance criteria

Synthetic marker, source identity, allowed/denied destinations and correlated logs; no real data transfer. Record expected behavior before the test and the actual outcome afterward; mark missing evidence as unknown.

## False positives and limits

An allowed CDN or proxy path can be a business requirement; assess the approved policy rather than labeling all egress as exfiltration. Do not change the record's laboratory-verification fields merely because a checklist was read or an inventory match was found.

## Handoff and cleanup

Give defenders measurable control outcomes and a repeatable benign telemetry test. Remove synthetic accounts, objects, markers and temporary permissions introduced by the exercise, or record an owner-approved retention exception. Keep incident evidence under the agreed retention policy.

## References

- [Primary-source background](https://attack.mitre.org/techniques/T1071/). This project-authored checklist is not a verbatim vendor procedure and must be adapted to the deployed product and authorization.
