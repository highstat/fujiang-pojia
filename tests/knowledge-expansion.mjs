import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { createKbIndex, createSkillIndex } from '../plugin/lib/automation.js';
import { KNOWLEDGE_CATEGORIES, WORKFLOW_CATEGORIES, knowledgeFiles, parseKnowledgeDocument,
  serializeKnowledgeDocument, validateKnowledgeEntry } from '../plugin/lib/knowledge-schema.js';

const root = fileURLToPath(new URL('../', import.meta.url));
const corpus = path.join(root, 'plugin/knowledge');
const manifest = JSON.parse(fs.readFileSync(path.join(root, 'docs/knowledge-sources.json'), 'utf8'));
const records = knowledgeFiles(corpus).map((item) => ({ ...item,
  ...parseKnowledgeDocument(fs.readFileSync(item.path, 'utf8')) }));

test('the expansion has substantial CVE coverage with published-record provenance and no invented verification', () => {
  assert.ok(manifest.entries.length >= 80);
  const newIds = new Set();
  for (const source of manifest.entries) {
    assert.equal(newIds.has(source.id), false, source.id);
    newIds.add(source.id);
    const entry = records.find((item) => item.fields.id === source.id);
    assert.ok(entry, source.id);
    assert.equal(path.relative(root, entry.path), source.file.split('/').join(path.sep));
    assert.equal(entry.fields.kind, 'cve');
    assert.equal(entry.fields.cve, source.cve);
    assert.equal(entry.fields.cvss, source.cvss);
    assert.equal(entry.fields['source-url'], source.source);
    assert.match(source.source, /^https:\/\/raw\.githubusercontent\.com\/CVEProject\/cvelistV5\/main\/cves\//);
    assert.match(source.sourceSha256, /^[a-f0-9]{64}$/);
    assert.ok(Array.isArray(source.affected));
    assert.equal(entry.fields.verified, false);
    assert.equal(entry.fields['verified-on'], null);
    assert.equal(entry.fields['verification-evidence'], null);
    assert.equal(entry.fields['patch-date'], null);
    assert.equal(entry.fields['vendor-advisory'], null);
    assert.match(entry.body, /non-exploit validation plan/);
    assert.match(entry.body, /Detection ideas are starting hypotheses/);
  }
  for (const excluded of manifest.excluded) {
    assert.equal(manifest.entries.some((entry) => entry.cve === excluded.cve), false);
    assert.ok(excluded.reason);
  }
});

test('red and blue workflows carry scope, evidence, limits and cleanup without CVE risk metadata', () => {
  for (const category of ['red-team', 'blue-team']) {
    assert.ok(KNOWLEDGE_CATEGORIES.includes(category));
    assert.ok(WORKFLOW_CATEGORIES.includes(category));
    const members = records.filter((entry) => entry.category === category);
    assert.ok(members.length >= 20);
    for (const entry of members) {
      assert.equal(entry.fields.kind, 'workflow');
      assert.equal(entry.fields.cve, null);
      assert.equal(entry.fields.cvss, 0);
      assert.equal(entry.fields.severity, 'info');
      assert.equal(entry.fields.kev, null);
      assert.equal(entry.fields.epss, null);
      assert.equal(entry.fields.verified, false);
      for (const heading of ['Objective and scope', 'Preconditions', 'Procedure',
        'Evidence and acceptance criteria', 'False positives and limits', 'Handoff and cleanup', 'References']) {
        assert.ok(entry.body.includes('## ' + heading), entry.file + ': ' + heading);
      }
      assert.ok(manifest.workflowBackgroundChecks.some((check) => check.url === entry.fields['source-url'] && check.status === 200));
    }
  }
});

test('workflow category rules reject vulnerability records and numeric workflow severity', () => {
  const entry = records.find((item) => item.category === 'blue-team');
  assert.deepEqual(validateKnowledgeEntry(serializeKnowledgeDocument(entry.fields, entry.body), entry.file, entry.category), []);
  assert.ok(validateKnowledgeEntry(serializeKnowledgeDocument({ ...entry.fields, kind: 'configuration' }, entry.body),
    entry.file, entry.category).some((error) => error.includes('Workflow entries belong')));
  assert.ok(validateKnowledgeEntry(serializeKnowledgeDocument({ ...entry.fields, cvss: 5, severity: 'medium' }, entry.body),
    entry.file, entry.category).some((error) => error.includes('Workflow severity')));
  assert.ok(validateKnowledgeEntry(serializeKnowledgeDocument(entry.fields, entry.body), entry.file, 'java-web')
    .some((error) => error.includes('Workflow entries belong')));
});

test('new CVEs and team workflows are discoverable without indexing root documentation', () => {
  const index = createKbIndex(corpus);
  assert.ok(index.match({ text: 'CVE-2025-24813' }, 20).some((entry) => entry.cve === 'CVE-2025-24813'));
  const skills = createSkillIndex({ home: root, knowledgeDir: corpus, aboutSecurityEnabled: () => false });
  assert.ok(skills.search('CloudTrail', 20).some((entry) => entry.name === 'bt-cloudtrail-triage'));
  assert.ok(skills.search('rules of engagement', 20).some((entry) => entry.name === 'rt-rules-of-engagement'));
  assert.throws(() => skills.read(path.join(corpus, 'README.md')), /Skill not found/);
  assert.equal(skills.size(), records.length + KNOWLEDGE_CATEGORIES.length);
});

test('overview counts match the actual corpus and source snapshot', () => {
  const readme = fs.readFileSync(path.join(root, 'README.md'), 'utf8');
  assert.ok(readme.includes('**' + records.length + ' knowledge entries across ' + KNOWLEDGE_CATEGORIES.length + ' categories**'));
  const index = fs.readFileSync(path.join(corpus, 'README.md'), 'utf8');
  assert.ok(index.includes('**' + records.length + ' records across ' + KNOWLEDGE_CATEGORIES.length + ' categories:**'));
  const primaryCves = records.filter((entry) => entry.fields.cve).map((entry) => entry.fields.cve);
  assert.equal(new Set(primaryCves).size, primaryCves.length);
});
