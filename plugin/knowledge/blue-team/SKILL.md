---
name: "kb-blue-team"
description: "Blue-team and SOC playbooks: identity/cloud/endpoint/network triage, incident evidence, patching, recovery, Sigma, KQL, Suricata, SBOM and purple-team validation. Detection ideas require local testing."
verified: false
sources: "Project-authored checklists with primary-source background; see individual references and docs/knowledge-sources.json."
---

# Blue Team / SOC / Incident Response (27 entries)

Choose a workflow for the requested control and obtain the required scope, owner and telemetry before using it. These documents are guidance, not CVEs, exploitation tools or tested production detection rules. No workflow carries a vulnerability severity score.

## Entries

| File | Vulnerability | Severity | Entry Point |
|---|---|---|---|
| `bt-attack-coverage-map.md` | ATT&CK-informed detection coverage map | info | ATT&CK-informed detection coverage map |
| `bt-backup-restore-assurance.md` | Backup isolation and restore assurance | info | Backup isolation and restore assurance |
| `bt-cloudtrail-triage.md` | AWS control-plane investigation with CloudTrail | info | AWS control-plane investigation with CloudTrail |
| `bt-container-runtime-drift.md` | Container runtime and workload drift | info | Container runtime and workload drift |
| `bt-credential-exposure-triage.md` | Credential exposure scoping | info | Credential exposure scoping |
| `bt-directory-change-monitoring.md` | Privileged directory and identity-change monitoring | info | Privileged directory and identity-change monitoring |
| `bt-dns-beaconing-triage.md` | DNS anomaly and periodic-traffic triage | info | DNS anomaly and periodic-traffic triage |
| `bt-edge-appliance-response.md` | Edge appliance compromise response | info | Edge appliance compromise response |
| `bt-entra-signin-investigation.md` | Entra sign-in and consent investigation | info | Entra sign-in and consent investigation |
| `bt-incident-evidence-handling.md` | Incident evidence preservation and handoff | info | Incident evidence preservation and handoff |
| `bt-kerberos-anomaly-review.md` | Kerberos service-ticket anomaly review | info | Kerberos service-ticket anomaly review |
| `bt-kql-hunting-workflow.md` | KQL hunting with schema and result validation | info | KQL hunting with schema and result validation |
| `bt-kubernetes-audit-triage.md` | Kubernetes audit investigation | info | Kubernetes audit investigation |
| `bt-linux-persistence-review.md` | Linux startup and service-change investigation | info | Linux startup and service-change investigation |
| `bt-logging-baseline.md` | Logging coverage and collection validation | info | Logging coverage and collection validation |
| `bt-mailbox-compromise-response.md` | Mailbox-compromise scoping and recovery | info | Mailbox-compromise scoping and recovery |
| `bt-patch-verification.md` | Patch applicability and post-change verification | info | Patch applicability and post-change verification |
| `bt-purple-team-validation.md` | Purple-team control validation | info | Purple-team control validation |
| `bt-ransomware-readiness.md` | Ransomware readiness and containment tabletop | info | Ransomware readiness and containment tabletop |
| `bt-risk-based-vulnerability-triage.md` | Risk-based vulnerability prioritization | info | Risk-based vulnerability prioritization |
| `bt-sbom-applicability.md` | SBOM dependency applicability and VEX review | info | SBOM dependency applicability and VEX review |
| `bt-secret-rotation-runbook.md` | Dependency-aware secret rotation | info | Dependency-aware secret rotation |
| `bt-sigma-rule-engineering.md` | Sigma rule development and validation | info | Sigma rule development and validation |
| `bt-software-provenance.md` | Software artifact and provenance review | info | Software artifact and provenance review |
| `bt-suricata-rule-validation.md` | Suricata network-rule validation | info | Suricata network-rule validation |
| `bt-web-application-compromise.md` | Web application compromise triage | info | Web application compromise triage |
| `bt-windows-authentication-triage.md` | Windows authentication failure and success triage | info | Windows authentication failure and success triage |

## How to use this page

- Read the objective, preconditions, procedure, evidence criteria and false-positive limits before starting.
- Use synthetic identities and data for exercises; preserve incident evidence before approved remediation.
- Record gaps as unknown, and keep provider/vendor guidance and organizational authorization authoritative.
