---
id: "rt-object-storage-access"
title: "Object-storage public-access review"
kind: "workflow"
cve: null
related-cves: null
cve-note: null
severity: "info"
cvss: 0
severity-basis: "cvss"
severity-note: null
product: "AWS S3 and object storage"
versions: "-"
ports: "Any"
keywords: "AWS S3 and object storage, Object-storage public-access review, red-team, evidence, authorized assessment"
entry: "Object-storage public-access review"
verified: false
verified-on: null
verification-evidence: null
source-url: "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
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

# Object-storage public-access review

## Objective and scope

Assess the stated security boundary using an explicitly authorized, bounded and reversible test. This is a workflow, not a CVE or a severity-scored finding.

## Preconditions

- Written scope or an incident-response mandate, a named system owner and agreed stop/escalation conditions.
- Approved test identities/data and a private evidence location with a defined retention period.
- Current product documentation and visibility into the control being assessed.

## Procedure

1. Obtain the bucket inventory, intended sharing model, account-level controls and data-classification map.
2. Review public-access blocks, resource policies, object ownership, ACLs and expiring-link behavior using approved configuration exports.
3. Use a dedicated harmless canary object to check access from the intended and unintended principals; never list or download customer datasets.
4. Confirm remediation at the account, bucket and object boundary and document legitimate public-content exceptions.

## Evidence and acceptance criteria

Redacted policy/control exports and allow/deny observations for a named synthetic object. Record expected behavior before the test and the actual outcome afterward; mark missing evidence as unknown.

## False positives and limits

A public website bucket can be intentional; a successful signed URL says nothing about anonymous access. Do not change the record's laboratory-verification fields merely because a checklist was read or an inventory match was found.

## Handoff and cleanup

Provide cloud owners the exact boundary to fix and defenders a baseline for public-access policy changes. Remove synthetic accounts, objects, markers and temporary permissions introduced by the exercise, or record an owner-approved retention exception. Keep incident evidence under the agreed retention policy.

## References

- [Primary-source background](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html). This project-authored checklist is not a verbatim vendor procedure and must be adapted to the deployed product and authorization.
