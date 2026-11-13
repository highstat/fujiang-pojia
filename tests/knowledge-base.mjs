import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { createKbIndex, createSkillIndex } from '../plugin/lib/automation.js';
import { ENTRY_FIELDS, ENTRY_HEADINGS, KNOWLEDGE_CATEGORIES, documentHeadings, knowledgeFiles, parseKnowledgeDocument,
  serializeKnowledgeDocument, validateKnowledgeCorpus, validateKnowledgeEntry } from '../plugin/lib/knowledge-schema.js';
import { corpusRoot, normalizationChanges, normalizeBody, normalizeEntry } from '../scripts/normalize-knowledge.mjs';

const sampleFile = 'cve-2024-23897-jenkins-file-read.md';
const sample = fs.readFileSync(path.join(corpusRoot, 'java-web', sampleFile), 'utf8');
const sampleDocument = parseKnowledgeDocument(sample);

function invalidFields(overrides) {
  return validateKnowledgeEntry(serializeKnowledgeDocument({ ...sampleDocument.fields, ...overrides }, sampleDocument.body), sampleFile, 'java-web');
}

test('the complete corpus conforms to the documented schema and table metadata', () => {
  assert.deepEqual(validateKnowledgeCorpus(corpusRoot), []);
  assert.ok(knowledgeFiles(corpusRoot).length > 0);
});

test('normalization is idempotent for every category and entry', () => {
  assert.deepEqual(normalizationChanges(corpusRoot), []);
});

test('frontmatter parser supports typed scalars, BOM, CRLF, quoted colons, and apostrophes', () => {
  const document = parseKnowledgeDocument('\uFEFF---\r\nid: example\r\ncve: null\r\ncvss: 9.8\r\nverified: false\r\ntitle: "Quoted: title"\r\nsource: \'Author\'\'s text\'\r\n---\r\nBody\r\n');
  assert.deepEqual(document.fields, { id: 'example', cve: null, cvss: 9.8, verified: false, title: 'Quoted: title', source: "Author's text" });
  assert.equal(document.body, 'Body\r\n');
  assert.throws(() => parseKnowledgeDocument('---\nid: first\nid: second\n---\n'), /Duplicate/);
  assert.throws(() => parseKnowledgeDocument('---\n  nested: invalid\n---\n'), /flat frontmatter/);
  assert.throws(() => parseKnowledgeDocument('---\ntitle: "unterminated\n---\n'));
  assert.throws(() => parseKnowledgeDocument('---\ntitle: [nested, sequence]\n---\n'), /not supported/);
  assert.throws(() => parseKnowledgeDocument('---\ntitle: {nested: mapping}\n---\n'), /not supported/);
});

test('schema rejects missing fields, wrong scalar types, invalid dates, and unsupported fields', () => {
  for (const overrides of [{ id: 'wrong' }, { kind: 'unknown' }, { verified: 'false' }, { cvss: '9.8' },
    { cve: 'None' }, { 'patch-date': '2026-02-30' }, { 'source-url': 'javascript:alert(1)' },
    { 'source-url': 'https://user:password@example.com/' }, { cwe: 'NVD-CWE-noinfo' },
    { unknown: 'unsupported' }, { kev: false, 'kev-date': '2024-08-19' }, { epss: 0.6, 'epss-date': null }]) {
    assert.ok(invalidFields(overrides).length, JSON.stringify(overrides));
  }
  for (const field of ENTRY_FIELDS) {
    const fields = { ...sampleDocument.fields };
    delete fields[field];
    assert.ok(validateKnowledgeEntry(serializeKnowledgeDocument(fields, sampleDocument.body), sampleFile, 'java-web').length, field);
  }
});

test('verification and severity require explicit evidence and policy rather than invented trust', () => {
  assert.ok(invalidFields({ verified: true }).some((error) => error.includes('laboratory')));
  assert.deepEqual(invalidFields({ verified: true, 'verified-on': '2026-11-13', 'verification-evidence': 'Redacted local lab report: LAB-001' }), []);
  assert.ok(invalidFields({ severity: 'high', 'severity-basis': 'cvss' }).length);
  assert.deepEqual(invalidFields({ severity: 'high', 'severity-basis': 'editorial', 'severity-note': 'Retained project-specific editorial classification.' }), []);
});

test('normalization preserves fenced PoCs, qualifiers, and version-check warnings', () => {
  const body = '## Fingerprints\n\n## Prerequisites\n\n## Version check (do this first)\nImportant warning.\n\n## PoC (probing only)\n```text\n## Fingerprints\n## PoC (keep this literal)\n```\n\n## Exploitation steps\n\n## Remediation and Mitigation (Hardening)\n\n## References\n';
  const normalized = normalizeBody(body);
  assert.deepEqual(documentHeadings(normalized), ENTRY_HEADINGS);
  assert.ok(normalized.includes('### Version check (do this first)\nImportant warning.'));
  assert.ok(normalized.includes('### PoC (probing only)'));
  assert.ok(normalized.includes('### Remediation and Mitigation (Hardening)'));
  assert.ok(normalized.includes('```text\n## Fingerprints\n## PoC (keep this literal)\n```'));
  assert.equal(normalizeBody('Prose \nHard break  \n```\nCode \n```\n'), 'Prose\nHard break  \n```\nCode \n```\n');
  assert.deepEqual(documentHeadings('````text\n```\n## Not a real heading\n````\n## References\n'), ['References']);
});

test('CVE chains remain searchable by every affected CVE and non-CVE notes survive migration', () => {
  const index = createKbIndex(corpusRoot);
  const chain = index.match({ text: 'CVE-2024-21887' }, 20).find((entry) => entry.file === 'cve-2023-46805-2024-21887-ivanti.md');
  assert.ok(chain);
  assert.equal(chain.cve, 'CVE-2023-46805');
  assert.ok(chain.relatedCves.includes('CVE-2024-21887'));
  assert.match(chain.cveNote, /CVE-2024-21887/);
  const implementation = index.list().find((entry) => entry.file === 'admin-api-unauthenticated.md');
  assert.equal(implementation.cve, null);
  assert.equal(implementation.kind, 'business-logic');
  assert.match(implementation.cveNote, /business logic/);
  assert.equal(index.list().filter((entry) => entry.verified).length, 0);
});

test('workflow bodies are preserved and schema documentation is not indexed as a vulnerability', () => {
  const workflowFile = path.join(corpusRoot, 'triage', 'report-template.md');
  const workflow = fs.readFileSync(workflowFile, 'utf8');
  assert.equal(parseKnowledgeDocument(normalizeEntry(workflow, 'report-template.md', 'triage')).body, parseKnowledgeDocument(workflow).body);
  const skills = createSkillIndex({ home: os.tmpdir(), knowledgeDir: corpusRoot, aboutSecurityEnabled: () => false });
  assert.equal(skills.size(), knowledgeFiles(corpusRoot).length + KNOWLEDGE_CATEGORIES.length);
  assert.throws(() => skills.read(path.join(corpusRoot, 'SCHEMA.md')), /Skill not found/);
  assert.throws(() => skills.read(path.join(corpusRoot, 'CONTRIBUTING.md')), /Skill not found/);
  assert.equal(createKbIndex(corpusRoot).size(), knowledgeFiles(corpusRoot).length);
});

test('corpus validation rejects missing, duplicate, broken, and stale category table references', (context) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'fujiang-schema-'));
  context.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  fs.cpSync(corpusRoot, directory, { recursive: true });
  const skill = path.join(directory, 'java-web', 'SKILL.md');
  const original = fs.readFileSync(skill, 'utf8');
  fs.writeFileSync(skill, original.replace('`' + sampleFile + '`', '`missing.md`'));
  assert.ok(validateKnowledgeCorpus(directory).some((error) => error.includes('Broken entry reference')));
  fs.writeFileSync(skill, original.replace('| critical |', '| low |'));
  assert.ok(validateKnowledgeCorpus(directory).some((error) => error.includes('Stale table')));
  const entry = path.join(directory, 'java-web', sampleFile);
  fs.writeFileSync(entry, fs.readFileSync(entry, 'utf8').replace('id: "cve-2024-23897-jenkins-file-read"', 'id: "cve-2020-14882-weblogic-console"'));
  assert.ok(validateKnowledgeCorpus(directory).some((error) => error.includes('Duplicate entry id')));
});
