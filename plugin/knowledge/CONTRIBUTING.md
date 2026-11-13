# Contributing knowledge records

## Adding or editing a record

1. Choose one of the registered category directories. Use a globally unique lowercase, hyphen-separated filename and matching `id`. Use `red-team` for authorized assessment workflows and `blue-team` for SOC, detection and response workflows; these are `kind: workflow`, `severity: info`, `cvss: 0`, not invented CVEs.
2. Copy a current record of the same `kind` as a complete frontmatter template. `SCHEMA.md` documents every field. For a non-CVE technique use `cve: null`, not a placeholder such as `None`.
3. Write a concise `entry` describing the entry surface, affected versions and prerequisites, minimal confirmation criteria, remediation, and real source references. Do not label assumptions as verified behavior.
4. For CVE chains, select a primary `cve`, retain other IDs in `related-cves`, and explain the relationship in `cve-note` and the body. Do not attach a merely related CVE to a generic technique without explaining the distinction.
5. For non-workflow entries use the six canonical sections. Keep version warnings and PoC limitations as subsections. Workflow documents keep their original structure.
6. Add one row to the category table. The normalizer can update counts, severity and entry-point cells, but does not invent a new row or silently delete broken references.
7. Start with `verified: false`, `verified-on: null`, and `verification-evidence: null`. Only an authorized, isolated laboratory reproduction with a dated, redacted report can change this status. Never put credentials, personal data, live target evidence, or secret tokens in the repository.
8. Add a dated entry to `CHANGELOG.md`, then run the checks below. Updating source files does not silently update installed OpenCode snapshots; re-run the installer for the intended profile when ready.

## Offline normalization

```sh
npm run knowledge:check
npm run knowledge:normalize
node scripts/normalize-knowledge.mjs --patch > /tmp/fujiang-normalization.patch
```

The default check exits unsuccessfully if a normalization patch is needed. `--patch` only prints a patch; it does not modify files. Review the patch and apply it using the development environment's `apply_patch` command:

```sh
apply_patch < /tmp/fujiang-normalization.patch
npm test
```

`apply_patch` is a development-environment helper, not a prerequisite for using the installed plugin. Outside that environment, make the reviewed edits in an editor, or use a patch tool that explicitly supports the emitted format. The normalizer preserves workflow bodies, fenced examples, and Markdown two-space hard line breaks; it removes accidental single trailing spaces in non-workflow prose. It is not a translator and does not validate a vulnerability against a target.

## Optional public-metadata refresh

```sh
npm run knowledge:enrich
node scripts/enrich-knowledge.mjs --patch > /tmp/fujiang-metadata.patch
```

The first command fetches metadata and reports how many records would change, without writing anything. The second prints a reviewable patch. It reads only these public primary sources:

- CISA KEV catalog: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- FIRST EPSS API: `https://api.first.org/data/v1/epss`

Only CVE identifiers are sent to FIRST, in batches of at most 100. No target URLs, credentials, conversation history, prompt text, or PoC bodies are sent. No API key is required. Requests time out, and malformed, duplicate, incomplete, or failed responses abort patch generation. Review the entire generated patch before applying it, then run `npm test` and `npm run knowledge:normalize`.

This operation changes KEV/EPSS metadata, source/retrieval dates, and valid CWE identifiers supplied by CISA. It does not change PoCs, commands, severity, patch dates, vendor-advisory links, verification evidence, or `verified`. Missing scores remain `null`. A negative KEV result means only that the primary CVE was absent from that retrieved catalog. EPSS is a dated probability estimate, not proof of exploitation. Git history retains earlier snapshots after maintainers commit reviewed changes.

Do not put live metadata calls in ordinary tests or require the network for installation/runtime knowledge lookup. The CI suite tests enrichment with deterministic mock responses.

## Releases and archive identity

The [knowledge index](README.md) lists all categories. The [expansion guide](../../docs/knowledge-expansion.md) explains the new CVE cards, safe validation limits, source manifest, and detection-template caveats. Do not replace unknown affected versions or missing CVSS values with guessed data; unsupported candidates must be reviewed separately.

The release version is `plugin/package.json`. The workspace `package.json` only defines development commands. Record schema revision, content changes, verification scope and metadata snapshot dates separately in this directory's changelog.

Our `0.20.14` is a locally modified English fork based on upstream `0.20.13`, not a newer author release. The Telegram ZIP published on November 12, 2026 was compared to upstream commit `338b598386aed60d4e7bdbf60ebb526af0b47697`: all 202 files were byte-identical. Do not infer freshness from an archive's upload date or replace translated/custom files with an older upstream snapshot.
