# Knowledge index

[Project overview](../../README.md) · [Expansion guide](../../docs/knowledge-expansion.md) · [Schema](SCHEMA.md) · [Contributing](CONTRIBUTING.md) · [History](CHANGELOG.md)

**300 records across 11 categories:** 180 CVE records, 50 workflows and 70 other security-issue records. Category indexes list every file with its purpose and classification.

| Category skill | Records | Coverage |
| --- | --- | --- |
| [`kb-java-deser`](java-deser/SKILL.md) | 14 | Java serialization, expression and logging-library risks |
| [`kb-java-web`](java-web/SKILL.md) | 33 | Java servers, frameworks, developer and transfer platforms |
| [`kb-edge-device`](edge-device/SKILL.md) | 36 | VPN, gateway, firewall, NAS and remote-support appliances |
| [`kb-exchange-ad`](exchange-ad/SKILL.md) | 31 | Windows, Active Directory, Exchange, Outlook and SharePoint |
| [`kb-web-cms`](web-cms/SKILL.md) | 28 | Web applications, CMS and application dependencies |
| [`kb-linux-priv`](linux-priv/SKILL.md) | 22 | Linux packages, services, kernel and privilege boundaries |
| [`kb-cloud-container`](cloud-container/SKILL.md) | 27 | Virtualization, container/build runtimes and middleware |
| [`kb-gray-market`](gray-market/SKILL.md) | 59 | Business logic, API, account, payment and data-access risks |
| [`kb-triage`](triage/SKILL.md) | 3 | Triage, evidence and reporting templates |
| [`kb-red-team`](red-team/SKILL.md) | 20 | Authorized assessment planning and security-control validation |
| [`kb-blue-team`](blue-team/SKILL.md) | 27 | SOC investigation, detection engineering, response and recovery |

## Where to start

- For an authorized pentest, begin with [rules of engagement](red-team/rt-rules-of-engagement.md), then choose a control-specific workflow and keep target findings distinct from inventory candidates.
- For a defender, begin with [logging coverage](blue-team/bt-logging-baseline.md), [incident evidence](blue-team/bt-incident-evidence-handling.md) or [risk-based CVE prioritization](blue-team/bt-risk-based-vulnerability-triage.md).
- For joint testing, use [purple-team validation](blue-team/bt-purple-team-validation.md) and agree collection, detection, triage and response checkpoints.
- For a candidate CVE, read affected-version evidence, configuration prerequisites, safe validation limits, remediation and references; do not execute a payload merely because a fingerprint matches.

Public intelligence, checklists and detection ideas are not proof of exploitation. All new records remain unverified. The original legacy entries and their code examples are retained; their presence is not evidence of laboratory validation. Use only explicitly authorized systems and synthetic test data.
