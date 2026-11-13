# Red team, pentest and blue team knowledge

[Project overview](../README.md) · [Knowledge index](../plugin/knowledge/README.md) · [Schema](../plugin/knowledge/SCHEMA.md) · [Contributing](../plugin/knowledge/CONTRIBUTING.md)

## Scope of this expansion

The corpus now contains **300 entries in 11 categories**: 180 CVE records, 50 workflows and 70 other implementation/configuration/business-logic records. This update adds **86 CVEs**, **20 red-team/pentest workflows**, and **27 blue-team/SOC workflows** to the previous 167 records. Existing record bodies and the source prompt are preserved.

The added CVE coverage includes Tomcat, Spring, GeoServer, Log4j, Cleo, MOVEit, React Server Components, Next.js, Ruby SAML, Citrix, Ivanti, Fortinet, Cisco, PAN-OS, remote-support products, VMware, Docker/BuildKit, NVIDIA Container Toolkit, MongoDB, OpenSSH, sudo, Linux libraries, Windows, Kerberos, LDAP, Outlook and SharePoint. This is a curated expansion, not an exhaustive or continuously current vulnerability feed.

## Assessment and defense together

- **Red team / pentest:** scope and stop conditions, external inventory, synthetic-account authorization matrices, OAuth/OIDC/SAML trust, AD/AD CS configuration, cloud IAM, storage, Entra, Kubernetes, container policy, CI/CD, secrets, segmentation, egress, assumed-breach planning and evidence-led reporting.
- **Blue team / SOC:** logging, Windows/Kerberos/directory changes, CloudTrail, Entra, mailbox response, Kubernetes audits, container drift, Linux startup changes, DNS, web/appliance incidents, vulnerability prioritization, patching, ransomware readiness, restores, credentials, provenance, Sigma, KQL, Suricata, ATT&CK coverage, evidence, purple teaming and SBOM applicability.

Every new workflow includes preconditions, a bounded procedure, evidence criteria, false-positive limits, handoff and cleanup. The KQL sample targets Microsoft Defender XDR's schema and is explicitly illustrative; Sigma/Suricata workflows require tool-specific syntax checks and positive/negative fixtures. No production detection accuracy or live-environment validation is claimed.

## CVE provenance and limits

The [source manifest](knowledge-sources.json) records the retrieval date, CVE Program source URL, SHA-256 of the fetched JSON, record update date, selected CNA/ADP CVSS metric/vector and original `affected` data. Scores come from structured source metrics, not from guessed severity labels. Product/version arrays preserve default-status and version-change semantics in the manifest; a card's displayed table may be partial and is not a universal fixed-version list.

Records were fetched and checked on **November 13, 2026**. Candidates with non-published records, a product mismatch, an ambiguous cross-product record or no structured numeric CVSS score were excluded and logged in the manifest. This does not assert that all excluded candidates are invalid; they need separate review.

Primary background documentation links for the workflows were checked for HTTP availability. This is not a complete technical review or a guarantee that a page will remain available. Vendor links carried by CVE records are labeled as CNA-supplied and not separately verified. New cards leave `vendor-advisory` and `patch-date` unknown rather than inventing review or release dates.

CISA KEV membership and FIRST EPSS were checked for the **86 new CVEs**. **48** were present in the retrieved KEV snapshot; score dates and retrieval dates are stored separately. Risk feeds describe the primary CVE, not an entire chain, a specific target or proof of compromise. Existing records retain their earlier metadata snapshot until explicitly refreshed.

## Safe validation and verification status

The new CVE cards provide version/configuration assessment plans and defensive investigation ideas. Their canonical `PoC` and `Exploitation Steps` sections explicitly distinguish non-exploit assessment from separately authorized isolated reproduction; no executable exploit payloads were added. A product banner, CVSS score, KEV listing, EPSS value or version match is never sufficient to claim successful exploitation.

All new records start with `verified: false`, `verified-on: null`, and `verification-evidence: null`. Changing those fields requires a dated, redacted laboratory report under the schema's rules. Detection hypotheses likewise require environment-specific testing and tuning.

## Using the new content

Harness discovers `kb-red-team` and `kb-blue-team` through the same category provider as the existing skills. Keyword lookup can find the individual workflow cards. The OpenCode installer copies all 11 category directories, including their current records, without changing their content or editing the source prompt. Re-run the adapter for your intended project/configuration to refresh an already installed snapshot; repository edits alone do not update it.

```sh
npm test
npm run knowledge:check
npm run knowledge:normalize
```

These checks are offline and do not contact targets, execute payloads or make model requests. The public-source manifest is an audit snapshot, not a runtime dependency.
