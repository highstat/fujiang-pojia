---
id: "bt-mailbox-compromise-response"
title: "Mailbox-compromise scoping and recovery"
kind: "workflow"
cve: null
related-cves: null
cve-note: null
severity: "info"
cvss: 0
severity-basis: "cvss"
severity-note: null
product: "Microsoft 365 Exchange Online"
versions: "-"
ports: "Any"
keywords: "Microsoft 365 Exchange Online, Mailbox-compromise scoping and recovery, blue-team, evidence, authorized assessment"
entry: "Mailbox-compromise scoping and recovery"
verified: false
verified-on: null
verification-evidence: null
source-url: "https://learn.microsoft.com/en-us/defender-office-365/responding-to-a-compromised-email-account"
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

# Mailbox-compromise scoping and recovery

## Objective and scope

Investigate and improve the stated control with validated telemetry, explicit ownership and reversible changes. This is a workflow, not a CVE or a severity-scored finding.

## Preconditions

- Written scope or an incident-response mandate, a named system owner and agreed stop/escalation conditions.
- Approved test identities/data and a private evidence location with a defined retention period.
- Current product documentation and visibility into the control being assessed.

## Procedure

1. Confirm the mailbox, identity owner, incident scope and availability of audit, sign-in and message-trace evidence.
2. Review forwarding, inbox rules, delegated access, application grants and suspicious outbound messaging.
3. Preserve relevant evidence before approved session/credential containment and removal of malicious configuration.
4. Check other affected accounts, external recipients and any business-process abuse; validate the repaired mailbox with the user.

## Evidence and acceptance criteria

Redacted audit references, rule/delegation diffs, sign-in timeline and owner-approved recovery actions. Record expected behavior before the test and the actual outcome afterward; mark missing evidence as unknown.

## False positives and limits

Legitimate assistants, mobile clients and mail-routing automation can resemble suspicious access; inspect the exact actor and rule purpose. Do not change the record's laboratory-verification fields merely because a checklist was read or an inventory match was found.

## Handoff and cleanup

Coordinate identity, messaging, legal and business-response owners without exposing message contents unnecessarily. Remove synthetic accounts, objects, markers and temporary permissions introduced by the exercise, or record an owner-approved retention exception. Keep incident evidence under the agreed retention policy.

## References

- [Primary-source background](https://learn.microsoft.com/en-us/defender-office-365/responding-to-a-compromised-email-account). This project-authored checklist is not a verbatim vendor procedure and must be adapted to the deployed product and authorization.
