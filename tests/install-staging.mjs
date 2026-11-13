import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { installOpenCode } from '../scripts/install.mjs';

// Regression guard for the Windows + Node 22 failure: fs.cpSync(source, freshPath,
// { recursive: true }) can return without creating the destination directory, so staging a
// knowledge-skill directory used to fail with ENOENT on the following statSync. The installer
// now stages directories with explicit mkdir/readdir/copyFileSync instead. Making recursive
// cpSync throw here reproduces that platform bug on every OS, so the guard runs everywhere.
test('staging skill directories does not depend on recursive fs.cpSync', context => {
  const home = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'fujiang staging test '));
  context.after(() => fs.rmSync(home, { recursive: true, force: true }));

  const original = fs.cpSync;
  fs.cpSync = (source, destination, options) => {
    if (options?.recursive) throw new Error('simulated Windows cpSync ENOENT for directory staging');
    return original(source, destination, options);
  };
  try {
    const logs = [];
    installOpenCode({ configDir: home }, message => logs.push(message));

    const agent = path.join(home, 'agents', 'fujiang.md');
    assert.ok(fs.statSync(agent).isFile(), 'agent prompt must be staged as a file');
    assert.match(fs.readFileSync(agent, 'utf8'), /You are an AI agent powered by DeepSeek Harness/);

    const skills = path.join(home, 'skills');
    const names = fs.readdirSync(skills).sort();
    assert.equal(names.length, 11);
    for (const name of names) {
      const directory = path.join(skills, name);
      assert.ok(fs.statSync(directory).isDirectory(), name + ' must be staged as a directory');
      assert.ok(fs.existsSync(path.join(directory, 'SKILL.md')), name + ' must contain SKILL.md');
      assert.ok(fs.readdirSync(directory).length > 1, name + ' must contain its entries');
    }
    assert.equal(fs.readdirSync(path.join(skills, 'kb-gray-market')).length, 60);

    // A second run must be a no-op (idempotent), still without recursive cpSync.
    const second = [];
    installOpenCode({ configDir: home }, message => second.push(message));
    assert.ok(second.includes('Installed files are already up to date.'));
    assert.equal(logs.length > 0, true);
  } finally {
    fs.cpSync = original;
  }
});
