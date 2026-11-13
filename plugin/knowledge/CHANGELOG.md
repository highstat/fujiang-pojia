# Knowledge changelog

## 2026-11-13 — red/blue expansion, schema revision 2

- Expanded the corpus from 167 to 300 records across 11 categories: 86 additional CVE cards, 20 authorized red-team/pentest workflows, and 27 blue-team/SOC workflows.
- Added CNA/ADP score/version provenance, source hashes, original affected-version semantics, and a dated import manifest in `docs/knowledge-sources.json`. Excluded non-published, mismatched, ambiguous and unscored candidates instead of inventing metadata.
- Checked CISA KEV and FIRST EPSS for the 86 new CVEs; 48 were present in the retrieved KEV snapshot. Public metadata does not establish laboratory reproduction or target compromise.
- New CVE cards contain non-exploit version/configuration assessment plans, remediation and detection hypotheses; they do not supply executable exploit payloads. All new records remain unverified.
- Added `red-team` and `blue-team` as workflow categories. Existing record bodies and the source prompt are unchanged by this expansion; all category tables and OpenCode skill-copy coverage include the new records.

## 2026-11-13 — schema revision 1 and metadata maintenance

- Migrated all 167 entries in nine categories to typed flat frontmatter with stable IDs and explicit entry kinds. Preserved original non-CVE labels and multi-CVE relationships.
- Filled 47 missing entry-point descriptions and the three workflow version placeholders. Regenerated category table metadata and corrected the stale gray-market description count.
- Standardized non-workflow section headings while retaining version-check warnings, PoC qualifiers, fenced examples, and all workflow bodies.
- Aligned two severity labels to their existing 9.8 scores. Preserved ten other editorial severity differences with explicit policy notes; historical numeric scores are not independently certified.
- Added nullable advisory, CWE, patch-date, verification-evidence and risk-feed fields. No record was promoted to laboratory-verified status.
- Added an explicit refresh tool for official CISA KEV and FIRST EPSS metadata. The November 13, 2026 retrieval enriched 94 primary CVEs; related CVE chains are preserved but are not combined into the primary CVE's risk fields.
- Fixed stale runtime catalogs after content additions/removals and made the displayed library version follow the plugin package version.
- Added schema, normalization, matching, catalog lifecycle, metadata-response and localization regressions. Network calls and Markdown PoC execution remain outside ordinary tests.

## Earlier content

The initial English corpus was translated from the author's 0.20.13 snapshot. Translation and local prompt changes are described in the repository-level `CHANGELOG.md`; they do not imply laboratory reproduction of the bundled vulnerabilities.
