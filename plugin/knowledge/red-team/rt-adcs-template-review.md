---
id: "rt-adcs-template-review"
title: "AD CS certificate-template configuration review"
kind: "workflow"
cve: null
related-cves: null
cve-note: null
severity: "info"
cvss: 0
severity-basis: "cvss"
severity-note: null
product: "Active Directory Certificate Services"
versions: "-"
ports: "Any"
keywords: "Active Directory Certificate Services, AD CS certificate-template configuration review, red-team, evidence, authorized assessment"
entry: "AD CS certificate-template configuration review"
verified: false
verified-on: null
verification-evidence: null
source-url: "https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/"
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

# AD CS certificate-template configuration review

## Objective and scope

Assess the stated security boundary using an explicitly authorized, bounded and reversible test. This is a workflow, not a CVE or a severity-scored finding.

## Preconditions

- Written scope or an incident-response mandate, a named system owner and agreed stop/escalation conditions.
- Approved test identities/data and a private evidence location with a defined retention period.
- Current product documentation and visibility into the control being assessed.

## Procedure

1. Obtain the approved template, enrollment-permission and CA-policy exports from the PKI owner.
2. Review who can request certificates, which identities may be asserted, approval controls and intended authentication usages.
3. Use a disposable test identity and template only when enrollment testing is separately approved; never request another user's identity.
4. Review strong certificate mapping, template changes, revocation and service dependencies before proposing enforcement.

## Evidence and acceptance criteria

Template/CA configuration, enrollment ACLs, test certificate metadata and documented mapping policy. Record expected behavior before the test and the actual outcome afterward; mark missing evidence as unknown.

## False positives and limits

Risk labels depend on combined template, CA and domain settings; a template flag alone is not a reproduced escalation. Do not change the record's laboratory-verification fields merely because a checklist was read or an inventory match was found.

## Handoff and cleanup

Provide PKI owners a safe configuration change plan and a certificate issuance/audit baseline. Remove synthetic accounts, objects, markers and temporary permissions introduced by the exercise, or record an owner-approved retention exception. Keep incident evidence under the agreed retention policy.

## References

- [Primary-source background](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/). This project-authored checklist is not a verbatim vendor procedure and must be adapted to the deployed product and authorization.
