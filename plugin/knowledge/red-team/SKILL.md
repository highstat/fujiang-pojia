---
name: "kb-red-team"
description: "Authorized red-team and pentest planning: scope, exposure inventory, web/API authorization, identity, cloud IAM, Kubernetes, CI/CD, secrets, segmentation and reporting. Non-exploit workflows."
verified: false
sources: "Project-authored checklists with primary-source background; see individual references and docs/knowledge-sources.json."
---

# Authorized Red Team / Pentest (20 entries)

Choose a workflow for the requested control and obtain the required scope, owner and telemetry before using it. These documents are guidance, not CVEs, exploitation tools or tested production detection rules. No workflow carries a vulnerability severity score.

## Entries

| File | Vulnerability | Severity | Entry Point |
|---|---|---|---|
| `rt-ad-identity-posture.md` | Active Directory identity and delegation posture | info | Active Directory identity and delegation posture |
| `rt-adcs-template-review.md` | AD CS certificate-template configuration review | info | AD CS certificate-template configuration review |
| `rt-api-object-function-access.md` | API object and function access-control review | info | API object and function access-control review |
| `rt-assumed-breach-exercise.md` | Assumed-breach exercise with explicit boundaries | info | Assumed-breach exercise with explicit boundaries |
| `rt-cicd-trust-boundaries.md` | CI/CD pipeline and artifact trust review | info | CI/CD pipeline and artifact trust review |
| `rt-cloud-iam-policy-review.md` | Cloud IAM least-privilege review | info | Cloud IAM least-privilege review |
| `rt-container-isolation.md` | Container workload isolation review | info | Container workload isolation review |
| `rt-egress-control-validation.md` | Controlled egress-policy validation | info | Controlled egress-policy validation |
| `rt-entra-conditional-access.md` | Entra identity and conditional-access review | info | Entra identity and conditional-access review |
| `rt-external-exposure-inventory.md` | External exposure and ownership inventory | info | External exposure and ownership inventory |
| `rt-kubernetes-rbac.md` | Kubernetes RBAC and service-account review | info | Kubernetes RBAC and service-account review |
| `rt-network-segmentation.md` | Network segmentation validation | info | Network segmentation validation |
| `rt-oauth-oidc-review.md` | OAuth and OIDC trust-boundary review | info | OAuth and OIDC trust-boundary review |
| `rt-object-storage-access.md` | Object-storage public-access review | info | Object-storage public-access review |
| `rt-phishing-simulation-governance.md` | Consent-based phishing simulation planning | info | Consent-based phishing simulation planning |
| `rt-reporting-retest.md` | Evidence-led reporting and remediation retest | info | Evidence-led reporting and remediation retest |
| `rt-rules-of-engagement.md` | Rules of engagement and stop conditions | info | Rules of engagement and stop conditions |
| `rt-saml-trust-review.md` | SAML trust and signing review | info | SAML trust and signing review |
| `rt-secrets-lifecycle.md` | Secrets lifecycle and application configuration review | info | Secrets lifecycle and application configuration review |
| `rt-web-authorization-matrix.md` | Web authorization with synthetic accounts | info | Web authorization with synthetic accounts |

## How to use this page

- Read the objective, preconditions, procedure, evidence criteria and false-positive limits before starting.
- Use synthetic identities and data for exercises; preserve incident evidence before approved remediation.
- Record gaps as unknown, and keep provider/vendor guidance and organizational authorization authoritative.
