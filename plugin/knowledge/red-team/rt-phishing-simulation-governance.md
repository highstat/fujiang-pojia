---
id: "rt-phishing-simulation-governance"
title: "Consent-based phishing simulation planning"
kind: "workflow"
cve: null
related-cves: null
cve-note: null
severity: "info"
cvss: 0
severity-basis: "cvss"
severity-note: null
product: "Security awareness exercises"
versions: "-"
ports: "Any"
keywords: "Security awareness exercises, Consent-based phishing simulation planning, red-team, evidence, authorized assessment"
entry: "Consent-based phishing simulation planning"
verified: false
verified-on: null
verification-evidence: null
source-url: "https://attack.mitre.org/techniques/T1566/"
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

# Consent-based phishing simulation planning

## Objective and scope

Assess the stated security boundary using an explicitly authorized, bounded and reversible test. This is a workflow, not a CVE or a severity-scored finding.

## Preconditions

- Written scope or an incident-response mandate, a named system owner and agreed stop/escalation conditions.
- Approved test identities/data and a private evidence location with a defined retention period.
- Current product documentation and visibility into the control being assessed.

## Procedure

1. Obtain written sponsor, legal/HR approval, audience scope, accessibility review and an incident contact.
2. Use a controlled sender/domain and a benign landing page; never collect passwords, session tokens or sensitive personal data.
3. Agree reporting and aggregate success metrics, data retention and an employee-support/debrief process.
4. Validate mail routing and SOC notification using a small approved pilot before a wider campaign.

## Evidence and acceptance criteria

Approved campaign plan, benign landing-page design, aggregate reporting criteria and deletion schedule. Record expected behavior before the test and the actual outcome afterward; mark missing evidence as unknown.

## False positives and limits

Link previews and mail-security scanners can inflate click metrics; avoid individual blame or deceptive credential collection. Do not change the record's laboratory-verification fields merely because a checklist was read or an inventory match was found.

## Handoff and cleanup

Share reporting-channel improvements and aggregated training outcomes with defenders and the sponsor. Remove synthetic accounts, objects, markers and temporary permissions introduced by the exercise, or record an owner-approved retention exception. Keep incident evidence under the agreed retention policy.

## References

- [Primary-source background](https://attack.mitre.org/techniques/T1566/). This project-authored checklist is not a verbatim vendor procedure and must be adapted to the deployed product and authorization.
