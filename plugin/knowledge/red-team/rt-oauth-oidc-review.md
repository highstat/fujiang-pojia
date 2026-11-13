---
id: "rt-oauth-oidc-review"
title: "OAuth and OIDC trust-boundary review"
kind: "workflow"
cve: null
related-cves: null
cve-note: null
severity: "info"
cvss: 0
severity-basis: "cvss"
severity-note: null
product: "OAuth OIDC identity providers"
versions: "-"
ports: "Any"
keywords: "OAuth OIDC identity providers, OAuth and OIDC trust-boundary review, red-team, evidence, authorized assessment"
entry: "OAuth and OIDC trust-boundary review"
verified: false
verified-on: null
verification-evidence: null
source-url: "https://www.rfc-editor.org/rfc/rfc9700.html"
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

# OAuth and OIDC trust-boundary review

## Objective and scope

Assess the stated security boundary using an explicitly authorized, bounded and reversible test. This is a workflow, not a CVE or a severity-scored finding.

## Preconditions

- Written scope or an incident-response mandate, a named system owner and agreed stop/escalation conditions.
- Approved test identities/data and a private evidence location with a defined retention period.
- Current product documentation and visibility into the control being assessed.

## Procedure

1. Inventory registered clients, redirect URIs, grant types, trusted issuers and confidential-versus-public client assumptions.
2. Use test clients and accounts to review PKCE, state/nonce handling, issuer/audience validation and redirect matching.
3. Confirm token lifetime, refresh-token revocation and the privileges requested by each client without disclosing real tokens.
4. Validate logout and account-linking behavior against the intended identity-provider and application session boundaries.

## Evidence and acceptance criteria

Redacted client configuration, claim names without token values, test flow diagram and expected rejection cases. Record expected behavior before the test and the actual outcome afterward; mark missing evidence as unknown.

## False positives and limits

A decoded JWT or a long-lived session is not by itself a vulnerability; assess the documented client threat model. Do not change the record's laboratory-verification fields merely because a checklist was read or an inventory match was found.

## Handoff and cleanup

Agree minimal scopes, client ownership and token/session revocation responsibilities. Remove synthetic accounts, objects, markers and temporary permissions introduced by the exercise, or record an owner-approved retention exception. Keep incident evidence under the agreed retention policy.

## References

- [Primary-source background](https://www.rfc-editor.org/rfc/rfc9700.html). This project-authored checklist is not a verbatim vendor procedure and must be adapted to the deployed product and authorization.
