import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const root = fileURLToPath(new URL('../', import.meta.url));
const documents = ['README.md', 'CHANGELOG.md', 'DISCLAIMER.md', 'docs/installation.md',
  'docs/features.md', 'docs/screenshots/README.md', 'scripts/README.md', 'scripts/installers/README.md',
  'docs/knowledge-expansion.md', 'docs/tool-integrations.md', 'plugin/knowledge/README.md', 'plugin/knowledge/SCHEMA.md',
  'plugin/knowledge/CONTRIBUTING.md', 'plugin/knowledge/CHANGELOG.md'];

test('documentation links and local images point at existing files', () => {
  for (const document of documents) {
    const filename = path.join(root, document);
    const text = fs.readFileSync(filename, 'utf8');
    const references = [...text.matchAll(/!?\[[^\]]*\]\(([^)]+)\)/g)].map((match) => match[1]);
    references.push(...[...text.matchAll(/<img\s[^>]*src="([^"]+)"/g)].map((match) => match[1]));
    for (const reference of references) {
      if (/^(?:https?:|mailto:|#)/.test(reference)) continue;
      const target = decodeURIComponent(reference.split('#')[0]);
      assert.ok(fs.existsSync(path.resolve(path.dirname(filename), target)), document + ': Broken local reference: ' + reference);
    }
  }
});

test('installation entry points documented in the README remain available', () => {
  for (const filename of ['run-installer.cmd', 'run-installer.command', 'install.ps1', 'install.sh',
    'install-opencode.cmd', 'install-opencode.command', 'install-opencode.ps1', 'install-opencode.sh']) {
    assert.ok(fs.statSync(path.join(root, 'scripts/installers', filename)).isFile(), filename);
    assert.equal(fs.existsSync(path.join(root, filename)), false, filename + ' must not remain in the root');
  }
  const workspace = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  assert.equal(workspace.version, undefined);
  assert.doesNotMatch(workspace.scripts.test, /keyboard-browser\.mjs/);
});

test('README describes the fork version and links to the organized documentation', () => {
  const readme = fs.readFileSync(path.join(root, 'README.md'), 'utf8');
  const plugin = JSON.parse(fs.readFileSync(path.join(root, 'plugin/package.json'), 'utf8'));
  assert.ok(readme.includes('**Fork version: ' + plugin.version + '**'));
  assert.match(readme, /based on upstream \*\*0\.20\.13\*\*/);
  assert.doesNotMatch(readme, /DeepSeek22|telegram-channel\.png|Join the channel/);
  for (const document of ['docs/installation.md', 'docs/features.md', 'docs/screenshots/README.md']) {
    assert.ok(readme.includes('](' + document), document);
  }
  assert.equal(fs.readFileSync(path.join(root, 'docs/activation-word-fujiang.txt'), 'utf8').trim(),
    'Activation word: fujiang (case-insensitive)');
  assert.equal(fs.existsSync(path.join(root, 'activation-word-fujiang.txt')), false);
});
