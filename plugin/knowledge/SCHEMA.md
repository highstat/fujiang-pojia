# Knowledge schema, revision 2

The executable schema and parser are in `../lib/knowledge-schema.js`. This document defines their semantics. Records are UTF-8 Markdown files in the explicitly supported category directories listed in `KNOWLEDGE_CATEGORIES`. Category `SKILL.md` files and root-level documentation are not vulnerability records. Revision 2 adds the `red-team` and `blue-team` workflow categories without changing the entry fields or migrating existing record bodies.

## Frontmatter format

Use flat `key: value` frontmatter enclosed by `---`. Strings should use JSON double quoting, which is compatible with this scalar subset. Numbers, booleans, and `null` are actual typed values, not quoted strings. BOM and CRLF are accepted. Nested mappings, sequences, duplicate fields, and unknown entry fields are rejected. The normalizer emits the canonical field order.

All fields below must be present. `null` means unknown or not applicable, never a negative finding.

| Field | Type and meaning |
|---|---|
| `id` | Globally unique lowercase hyphenated ID, exactly the filename without `.md`. |
| `title` | Nonempty human-readable title. |
| `kind` | `cve`, `implementation`, `configuration`, `business-logic`, or `workflow`. The `triage`, `red-team`, and `blue-team` categories use `workflow`; other categories do not. |
| `cve` | One `CVE-YYYY-NNNN...` ID for `kind: cve`; otherwise `null`. |
| `related-cves` | Comma-separated additional CVE IDs in a chain or related record, or `null`. These remain searchable. |
| `cve-note` | Original classification or chain description preserved during migration, or `null`. A note mentioning a special-case CVE does not turn a generic technique into that CVE. |
| `severity` | `critical`, `high`, `medium`, `low`, or `info`. |
| `cvss` | Finite numeric score from 0 through 10. Workflow entries use 0 and `info`. Legacy scores are not independently revalidated by migration. |
| `severity-basis` | `cvss` when the severity follows the stored numeric score; `editorial` for an explicitly retained project-specific classification. |
| `severity-note` | Required nonempty explanation when severity differs from the score band; otherwise `null`. An editorial label is not a vendor or NVD assessment. |
| `product`, `versions`, `ports`, `keywords` | Nonempty strings. Use `-` for versions that do not apply; ports may be comma-separated numbers, `Any`, or an explicit local-only description. |
| `entry` | Nonempty, concise entry surface or workflow purpose used by the settings catalog. Do not put payloads here. |
| `verified` | Boolean laboratory-reproduction status, independent of public advisories and risk feeds. |
| `verified-on` | Real calendar date `YYYY-MM-DD` for laboratory reproduction, or `null`. |
| `verification-evidence` | Redacted laboratory-report reference supporting `verified: true`, or `null`. |
| `source-url` | HTTPS reference for the record, or `null`. Migrated CVE records link to NVD; a link is not proof that its contents were checked. |
| `vendor-advisory` | Reviewed HTTPS vendor advisory, or `null`. Do not guess URLs. |
| `cwe` | Comma-separated `CWE-N` identifiers, or `null`. The enrichment tool can copy these from CISA KEV. |
| `patch-date` | Reviewed patch release date, or `null`. A KEV remediation due date is not a patch date. |
| `sources` | Nonempty human-readable source and provenance description. |
| `kev` | `true`: primary CVE listed in the retrieved CISA KEV catalog; `false`: not listed in that snapshot; `null`: not checked or not applicable. |
| `kev-date` | CISA `dateAdded` when `kev: true`; otherwise `null`. |
| `kev-source` | HTTPS catalog URL when checked; otherwise `null`. |
| `epss`, `epss-percentile` | Numeric FIRST EPSS score and percentile in [0,1], or both `null`. Missing data must not become 0. |
| `epss-date` | FIRST's score date, or `null`; this may differ from the retrieval date. |
| `epss-source` | HTTPS FIRST EPSS API URL when a score is present; otherwise `null`. |
| `enrichment-updated` | Retrieval date for public CVE metadata, or `null`. |

No CVE enrichment is attached to non-CVE records. In a multi-CVE entry, KEV and EPSS fields describe the **primary** `cve` only, not every related CVE or the combined chain.

## Severity policy

The stored-score bands are: 0 = info, greater than 0 to 3.9 = low, 4.0 to 6.9 = medium, 7.0 to 8.9 = high, and 9.0 to 10.0 = critical. Two pre-migration `high` labels with a stored score of 9.8 were aligned to `critical`. Other existing, higher editorial labels were retained with explicit explanations rather than silently rewritten or falsely attributed to a vendor. This migration does not supply missing CVSS vectors or certify historical scores.

`verified: true` requires both a valid `verified-on` date and `verification-evidence`. Unverified records must have both fields set to `null`. KEV membership, EPSS, an advisory, and a successful fingerprint match do not constitute laboratory verification. Migration leaves every existing record unverified.

## Body structure

Non-workflow records have exactly these level-two headings, in this order:

1. `Fingerprinting`
2. `Prerequisites`
3. `PoC`
4. `Exploitation Steps`
5. `Remediation and Mitigation`
6. `References`

Keep additional version checks, PoC restrictions, and hardening qualifiers as level-three subsections. Fenced code is opaque: normalization must not alter commands or headings inside it. Workflow records retain their own meaningful section structure and are exempt from the six-heading template.

## Category catalog

Each category has a `SKILL.md` with a unique `name: kb-<category>`, a nonempty description without hardcoded entry counts, and a level-one heading ending in `(N entries)`. Its table header is `| File | Vulnerability | Severity | Entry Point |`. Every record appears exactly once, and table severity and entry-point cells must match frontmatter. The normalizer regenerates these derived values.

The runtime reads current category descriptions and entries on each catalog/list/get request. The displayed library version comes directly from `plugin/package.json`; the root workspace package intentionally has no release version.

## Validation

Run `npm run knowledge:check`, `npm run knowledge:normalize`, and `npm test` from the repository root. All normal tests are offline and never execute the Markdown PoCs. Public metadata refresh is an explicit separate operation described in `CONTRIBUTING.md`.
