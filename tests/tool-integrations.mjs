import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { CONTEXT7_URL, REA_VERSION, TOOL_USE_POLICY, context7Headers,
  createContext7Bridge, effectivePrompt } from '../plugin/lib/tool-integrations.js';
import { openCodeToolEntry } from '../scripts/tool-config.mjs';
import { parseOptions } from '../scripts/install.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const installer = path.join(root, 'scripts/install.mjs');
const silent = { warn() {} };

function directory(context) {
  const result = fs.mkdtempSync(path.join(os.tmpdir(), 'fujiang-tools-'));
  context.after(() => fs.rmSync(result, { recursive: true, force: true }));
  return result;
}

function runtimeFixture({ fail = false, count = 2 } = {}) {
  let cleanup;
  let configuration;
  let disposed = 0;
  let names = [];
  const runtime = {
    tools: { schemas: () => names.map(name => ({ name })) },
    effect(callback) { cleanup = callback(); },
    plugin(client, config) {
      configuration = config;
      const fiber = fail ? Promise.reject(new Error('private-fixture-secret')) : Promise.resolve();
      if (!fail) names = Array.from({ length: count }, (_, index) => 'mcp__fujiang_context7__tool' + index);
      fiber.dispose = async () => { disposed++; names = []; };
      return fiber;
    },
  };
  return {
    ctx: { inject(dependencies, callback) { callback(runtime); }, logger: silent },
    configuration: () => configuration, disposed: () => disposed, cleanup: () => cleanup(),
    removeTools: () => { names = []; },
  };
}

test('tool guidance is strictly additive and task-specific, not a source prompt rewrite', () => {
  const prompt = JSON.parse(fs.readFileSync(path.join(root, 'prompt-custom.json'), 'utf8')).text;
  const effective = effectivePrompt(prompt);
  assert.equal(effective.slice(0, prompt.length), prompt);
  assert.equal(effective.slice(prompt.length), '\n\n' + TOOL_USE_POLICY + '\n');
  assert.match(TOOL_USE_POLICY, /resolve-library-id[\s\S]*query-docs/);
  assert.match(TOOL_USE_POLICY, /Ordinary work on a complete source repository does not require/);
  assert.match(TOOL_USE_POLICY, /Never claim a tool ran/);
});

test('MCP registration is an explicit OpenCode installer option', () => {
  assert.equal(parseOptions(['opencode', '--with-tools']).withTools, true);
  assert.throws(() => parseOptions(['harness', '--with-tools']), /other installation target/);
});

test('tool config preserves unrelated settings and uses a pinned REA and env-only authentication', context => {
  const location = directory(context);
  const original = { model: 'deepseek/example', permission: { bash: 'ask' },
    mcp: { timeout: { catalog: 5000 }, servers: { existing: { type: 'remote', url: 'https://example.test/mcp' } } } };
  fs.writeFileSync(path.join(location, 'opencode.json'), JSON.stringify(original));
  const entry = openCodeToolEntry(location, { CONTEXT7_API_KEY: 'fixture-private-secret' });
  const configuration = JSON.parse(entry.content);
  assert.equal(configuration.model, original.model);
  assert.deepEqual(configuration.permission, original.permission);
  assert.deepEqual(configuration.mcp.timeout, original.mcp.timeout);
  assert.deepEqual(configuration.mcp.servers.existing, original.mcp.servers.existing);
  assert.equal(configuration.mcp.servers.fujiang_context7.url, CONTEXT7_URL);
  assert.equal(configuration.mcp.servers.fujiang_context7.headers.Authorization, 'Bearer {env:CONTEXT7_API_KEY}');
  assert.equal(entry.content.includes('fixture-private-secret'), false);
  assert.deepEqual(configuration.mcp.servers.fujiang_rea.command, ['npx', '-y', 'rea-agents@' + REA_VERSION, '--mcp']);
  assert.equal(configuration.mcp.servers.fujiang_context7.oauth, false);
  assert.deepEqual(JSON.parse(fs.readFileSync(entry.destination, 'utf8')), original);
});

test('JSONC, malformed JSON, and server-name conflicts are rejected before installation', context => {
  const location = directory(context);
  fs.writeFileSync(path.join(location, 'opencode.jsonc'), '// private configuration');
  assert.throws(() => openCodeToolEntry(location, {}), /does not rewrite JSONC/);
  const result = spawnSync(process.execPath, [installer, 'opencode', '--config-dir', location, '--with-tools'], { encoding: 'utf8' });
  assert.notEqual(result.status, 0);
  assert.equal(fs.existsSync(path.join(location, 'agents')), false);
  fs.unlinkSync(path.join(location, 'opencode.jsonc'));
  for (const content of ['{bad', '[]', 'null', '{"mcp":[]}', '{"mcp":{"servers":[]}}',
    '{"mcp":{"servers":{"fujiang_rea":{"type":"local","command":["other"]}}}}',
    '{"mcp":{"fujiang_context7":{"type":"remote","url":"https://example.test"}}}']) {
    fs.writeFileSync(path.join(location, 'opencode.json'), content);
    assert.throws(() => openCodeToolEntry(location, {}));
    assert.equal(fs.readFileSync(path.join(location, 'opencode.json'), 'utf8'), content);
  }
});

test('tool-enabled installation is dry-run safe, backed up, idempotent, and contains no secret values', context => {
  const location = directory(context);
  const filename = path.join(location, 'opencode.json');
  const original = '{"model":"deepseek/example"}\n';
  fs.writeFileSync(filename, original);
  const args = [installer, 'opencode', '--config-dir', location, '--with-tools'];
  const env = { ...process.env, CONTEXT7_API_KEY: 'fixture-private-secret' };
  const dry = spawnSync(process.execPath, [...args, '--dry-run'], { encoding: 'utf8', env });
  assert.equal(dry.status, 0, dry.stderr);
  assert.equal(fs.readFileSync(filename, 'utf8'), original);
  assert.equal(fs.existsSync(path.join(location, 'agents')), false);
  const installed = spawnSync(process.execPath, args, { encoding: 'utf8', env });
  assert.equal(installed.status, 0, installed.stderr);
  assert.equal((installed.stdout + installed.stderr + fs.readFileSync(filename, 'utf8')).includes('fixture-private-secret'), false);
  const backups = fs.readdirSync(path.join(location, 'fujiang-backups'));
  assert.equal(backups.length, 1);
  assert.equal(fs.readFileSync(path.join(location, 'fujiang-backups', backups[0], 'opencode.json'), 'utf8'), original);
  const repeated = spawnSync(process.execPath, args, { encoding: 'utf8', env });
  assert.equal(repeated.status, 0, repeated.stderr);
  assert.match(repeated.stdout, /already up to date/);
  assert.deepEqual(fs.readdirSync(path.join(location, 'fujiang-backups')), backups);
});

test('MCP config symlinks are never followed', { skip: process.platform === 'win32' }, context => {
  const location = directory(context);
  const target = path.join(location, 'other.json');
  fs.writeFileSync(target, '{}');
  fs.symlinkSync(target, path.join(location, 'opencode.json'));
  assert.throws(() => openCodeToolEntry(location, {}), /symbolic-link/);
  assert.equal(fs.readFileSync(target, 'utf8'), '{}');
});

test('Harness uses the real HTTP MCP transport and reports actual registered tools', async () => {
  const fixture = runtimeFixture();
  const bridge = createContext7Bridge(fixture.ctx, { environment: { CONTEXT7_API_KEY: ' fixture-secret ' }, loadClient: async () => ({}) });
  await bridge.settled();
  assert.equal(fixture.configuration().transport, 'streamable-http');
  assert.deepEqual(fixture.configuration().headers, { Authorization: 'Bearer fixture-secret' });
  assert.equal(bridge.snapshot().phase, 'ready');
  assert.equal(bridge.snapshot().tools, 2);
  assert.equal(JSON.stringify(bridge.snapshot()).includes('fixture-secret'), false);
  fixture.removeTools();
  assert.equal(bridge.snapshot().phase, 'unavailable');
  await fixture.cleanup();
  assert.equal(fixture.disposed(), 1);
  assert.equal(bridge.snapshot().phase, 'stopped');
});

test('Harness connection failures are nonfatal, cleaned up, and do not expose raw secrets', async () => {
  const fixture = runtimeFixture({ fail: true });
  const bridge = createContext7Bridge(fixture.ctx, { environment: {}, loadClient: async () => ({}) });
  await bridge.settled();
  assert.equal(bridge.snapshot().phase, 'unavailable');
  assert.equal(bridge.snapshot().tools, 0);
  assert.doesNotMatch(JSON.stringify(bridge.snapshot()), /private-fixture-secret/);
  assert.equal(fixture.disposed(), 1);
  await fixture.cleanup();
  assert.equal(fixture.disposed(), 1);
});

test('Harness does not mistake a loaded MCP client without tools for readiness', async () => {
  const fixture = runtimeFixture({ count: 0 });
  const bridge = createContext7Bridge(fixture.ctx, { environment: {}, loadClient: async () => ({}) });
  await bridge.settled();
  assert.equal(bridge.snapshot().phase, 'unavailable');
  assert.equal(bridge.snapshot().error, 'no_tools_registered');
  await fixture.cleanup();
});

test('offline opt-out never loads or connects the MCP client', async () => {
  const bridge = createContext7Bridge({ inject() { assert.fail('must not inject'); } }, {
    environment: { FUJIANG_CONTEXT7: '0' }, loadClient() { assert.fail('must not load'); },
  });
  await bridge.settled();
  assert.equal(bridge.snapshot().phase, 'disabled');
  assert.deepEqual(context7Headers({}), {});
});

test('disposal during asynchronous client loading cannot start an orphan MCP connection', async () => {
  const fixture = runtimeFixture();
  let loaded;
  const load = new Promise(resolve => { loaded = resolve; });
  const bridge = createContext7Bridge(fixture.ctx, { environment: {}, loadClient: () => load });
  await fixture.cleanup();
  loaded({});
  await bridge.settled();
  assert.equal(fixture.configuration(), undefined);
  assert.equal(bridge.snapshot().phase, 'stopped');
});

test('native OpenCode reads the generated MCP document without launching servers', { skip: !process.env.FUJIANG_OPENCODE_BIN }, context => {
  const location = directory(context);
  const config = path.join(location, 'config');
  fs.mkdirSync(config);
  const entry = openCodeToolEntry(config, {});
  const content = JSON.parse(entry.content);
  for (const server of Object.values(content.mcp.servers)) server.disabled = true;
  fs.writeFileSync(entry.destination, JSON.stringify(content));
  const result = spawnSync(process.env.FUJIANG_OPENCODE_BIN, ['debug', 'config', '--standalone'], {
    cwd: location, encoding: 'utf8', timeout: 30000,
    env: { ...process.env, HOME: location, USERPROFILE: location, OPENCODE_CONFIG_DIR: config,
      XDG_CONFIG_HOME: path.join(location, 'xdg-config'), XDG_DATA_HOME: path.join(location, 'data'),
      XDG_CACHE_HOME: path.join(location, 'cache'), XDG_STATE_HOME: path.join(location, 'state') },
  });
  assert.equal(result.status, 0, result.stderr);
  const actual = JSON.parse(result.stdout).find(document => document.type === 'document' && document.path.endsWith('opencode.json'))?.info;
  assert.ok(actual, 'OpenCode must load the generated configuration document');
  assert.equal(actual.mcp.servers.fujiang_context7.url, CONTEXT7_URL);
  assert.deepEqual(actual.mcp.servers.fujiang_rea.command, content.mcp.servers.fujiang_rea.command);
  assert.equal(actual.mcp.servers.fujiang_rea.disabled, true);
});
