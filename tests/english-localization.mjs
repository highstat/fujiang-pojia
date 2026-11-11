import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { createKbIndex } from '../plugin/lib/automation.js';

const root = fileURLToPath(new URL('../', import.meta.url));
const textExtensions = new Set(['.md', '.js', '.mjs', '.json', '.ps1', '.cmd', '.yml', '.yaml', '.txt']);
const han = /\p{Script=Han}/u;

function filesWithin(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    if (entry.name.startsWith('.') || entry.name === 'node_modules') return [];
    const filename = path.join(directory, entry.name);
    return entry.isDirectory() ? filesWithin(filename) : [filename];
  });
}

const files = filesWithin(root);
const knowledgeRoot = path.join(root, 'plugin', 'knowledge');
const knowledgeFiles = filesWithin(knowledgeRoot).filter((filename) => filename.endsWith('.md'));

test('repository text and filenames contain no untranslated Han characters', () => {
  for (const filename of files) {
    const relative = path.relative(root, filename);
    assert.equal(han.test(relative), false, `Untranslated filename: ${relative}`);
    if (!textExtensions.has(path.extname(filename))) continue;
    assert.equal(han.test(readFileSync(filename, 'utf8')), false, `Untranslated text: ${relative}`);
  }
});

test('all knowledge entries remain indexed with complete frontmatter', () => {
  const entries = createKbIndex(knowledgeRoot).list();
  const entryFiles = knowledgeFiles.filter((filename) => path.basename(filename) !== 'SKILL.md');
  assert.equal(entries.length, entryFiles.length);
  for (const entry of entries) {
    assert.notEqual(entry.title, entry.file, `Missing title: ${entry.file}`);
    assert.ok(entry.cve, `Missing CVE classification: ${entry.file}`);
    assert.ok(entry.product, `Missing product: ${entry.file}`);
    assert.ok(['critical', 'high', 'medium', 'low', 'info'].includes(entry.severity));
    assert.equal(han.test(JSON.stringify(entry)), false, `Untranslated entry: ${entry.file}`);
  }
});

test('knowledge Markdown code fences and category-entry links remain intact', () => {
  for (const filename of knowledgeFiles) {
    const content = readFileSync(filename, 'utf8');
    assert.equal((content.match(/^```/gm) || []).length % 2, 0, `Unclosed fence: ${filename}`);
    if (path.basename(filename) !== 'SKILL.md') continue;
    const siblings = new Set(readdirSync(path.dirname(filename)));
    for (const match of content.matchAll(/`([^`/]+\.md)`/g)) {
      assert.ok(siblings.has(match[1]), `Broken category reference: ${filename}: ${match[1]}`);
    }
  }
});

test('English fingerprints still match the bundled ActiveMQ entry', () => {
  const matches = createKbIndex(knowledgeRoot).match({ port: 61616, banner: 'ActiveMQ 5.17.3' });
  assert.equal(matches[0].cve, 'CVE-2023-46604');
  assert.equal(matches[0].category, 'java-web');
  assert.equal(han.test(JSON.stringify(matches)), false);
});
