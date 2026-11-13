import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { setImmediate } from 'node:timers/promises';
import test from 'node:test';
import { createKnowledgeLibrary } from '../plugin/lib/knowledge.js';
import { KNOWLEDGE_VERSION } from '../plugin/lib/knowledge-schema.js';

async function fixture(context) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'fujiang-runtime-'));
  const corpus = path.join(directory, 'corpus');
  const category = path.join(corpus, 'java-web');
  fs.mkdirSync(category, { recursive: true });
  fs.writeFileSync(path.join(category, 'SKILL.md'), '---\nname: kb-java-web\ndescription: Original description\n---\n# Test category\n');
  fs.writeFileSync(path.join(category, 'first.md'), '---\ntitle: First\nseverity: high\nentry: First endpoint\n---\nFirst body\n');
  let provider;
  const cleanups = [];
  let disposed = 0;
  const ctx = {
    effect(callback) { cleanups.push(callback()); },
    inject(dependencies, callback) {
      callback({
        effect(cleanup) { cleanups.push(cleanup()); },
        skills: { registerProvider(factory) { provider = factory(); return () => { disposed++; }; } },
      });
    },
  };
  const library = createKnowledgeLibrary(ctx, { home: path.join(directory, 'home'), corpus });
  context.after(async () => { for (const cleanup of cleanups.reverse()) await cleanup?.(); fs.rmSync(directory, { recursive: true, force: true }); });
  await library.ready;
  await setImmediate();
  return { library, corpus, category, get provider() { return provider; }, get disposed() { return disposed; } };
}

test('snapshot and provider metadata use the plugin package version', async (context) => {
  const state = await fixture(context);
  assert.equal(state.library.snapshot().skills[0].version, KNOWLEDGE_VERSION);
  assert.equal((await state.provider.list())[0].metadata.version, KNOWLEDGE_VERSION);
  assert.equal(state.library.snapshot().skills[0].enabled, true);
});

test('catalog, snapshot, list, and get agree after live additions, edits, and removals', async (context) => {
  const state = await fixture(context);
  const candidate = (await state.provider.list())[0];
  fs.writeFileSync(path.join(state.category, 'second.md'), '---\ntitle: Second\nseverity: low\nentry: Second endpoint\n---\nBody\n');
  assert.equal(state.library.catalog()[0].count, 2);
  assert.equal(state.library.snapshot().skills[0].entries, 2);
  assert.equal((await state.provider.list())[0].metadata.entries, 2);
  assert.match((await state.provider.get(candidate)).content, /second\.md/);
  fs.writeFileSync(path.join(state.category, 'SKILL.md'), '---\nname: kb-java-web\ndescription: Changed description\n---\n# Changed category\n');
  assert.equal((await state.provider.list())[0].description, 'Changed description');
  assert.equal((await state.provider.get(candidate)).description, 'Changed description');
  assert.equal(state.library.catalog()[0].title, 'Changed category');
  fs.rmSync(path.join(state.category, 'second.md'));
  assert.equal(state.library.catalog()[0].count, 1);
  assert.doesNotMatch((await state.provider.get(candidate)).content, /second\.md/);
  fs.rmSync(state.category, { recursive: true });
  assert.equal((await state.provider.list()).length, 0);
  await assert.rejects(state.provider.get(candidate), /no longer valid/);
});

test('provider get does not trust arbitrary locator paths', async (context) => {
  const state = await fixture(context);
  const outside = path.join(state.corpus, 'private.md');
  fs.writeFileSync(outside, 'private content');
  await assert.rejects(state.provider.get({ name: 'not-a-category', locator: { file: outside } }), /no longer valid/);
});

test('disabling and re-enabling releases the provider and preserves saved state', async (context) => {
  const state = await fixture(context);
  assert.equal(state.library.action({ id: 'knowledge', action: 'disable' }).status, 202);
  await setImmediate();
  assert.equal(state.disposed, 1);
  assert.equal(state.library.snapshot().skills[0].phase, 'disabled');
  assert.equal(state.library.snapshot().skills[0].enabled, false);
  assert.equal(state.library.action({ id: 'knowledge', action: 'enable' }).status, 202);
  await setImmediate();
  assert.equal(state.library.snapshot().skills[0].phase, 'ready');
});
