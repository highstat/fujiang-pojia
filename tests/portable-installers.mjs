import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { parseOptions, resolveDsh } from '../scripts/install.mjs';
import { KNOWLEDGE_CATEGORIES, parseKnowledgeDocument } from '../plugin/lib/knowledge-schema.js';
import { effectivePrompt } from '../plugin/lib/tool-integrations.js';

const root = fileURLToPath(new URL('../', import.meta.url));
const installer = path.join(root, 'scripts/install.mjs');
const launcherDirectory = path.join(root, 'scripts/installers');
const unix = process.platform !== 'win32';

function fixture(context) {
  const directory = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'fujiang portable \u6d4b\u8bd5 '));
  context.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

function run(arguments_, directory, env = {}) {
  return spawnSync(process.execPath, [installer, ...arguments_], {
    cwd: directory, encoding: 'utf8', env: { ...process.env, ...env }, timeout: 30000,
  });
}

function successful(result) {
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, result.stdout + result.stderr);
}

function compareDirectory(source, destination) {
  assert.deepEqual(fs.readdirSync(destination).sort(), fs.readdirSync(source).sort());
  for (const entry of fs.readdirSync(source, { withFileTypes: true })) {
    const original = path.join(source, entry.name);
    const installed = path.join(destination, entry.name);
    if (entry.isDirectory()) compareDirectory(original, installed);
    else assert.deepEqual(fs.readFileSync(installed), fs.readFileSync(original), entry.name);
  }
}

function fakeHarness(directory, { running = false, fail = false } = {}) {
  const bin = path.join(directory, 'bin');
  const home = path.join(directory, 'Harness data');
  const app = path.join(directory, 'Custom Harness.app');
  const command = path.join(app, 'Contents/Resources/runtime/cli/bin/dsh');
  fs.mkdirSync(path.dirname(command), { recursive: true });
  fs.mkdirSync(bin);
  fs.mkdirSync(path.join(home, 'profiles/desktop'), { recursive: true });
  fs.writeFileSync(path.join(home, 'profiles/desktop/package.json'), '{}');
  fs.writeFileSync(path.join(bin, 'ps'), '#!/bin/sh\nprintf "%s\\n" "' + (running ? 'DeepSeek Harness' : 'unrelated-process') + '"\n', { mode: 0o755 });
  fs.writeFileSync(command, '#!/bin/sh\nprintf "%s\\n" "$DSH_HOME" "$@" > "$DSH_HOME/invocation.txt"\nexit ' + (fail ? '17' : '0') + '\n', { mode: 0o755 });
  return { home, app, command, env: { PATH: bin + path.delimiter + process.env.PATH } };
}

test('installer validates target, options, and model references', () => {
  assert.equal(parseOptions([]).target, 'harness');
  assert.equal(parseOptions(['opencode', '--model', 'deepseek/example#high']).model, 'deepseek/example#high');
  for (const arguments_ of [['other'], ['--unknown'], ['--dsh-home'], ['--profile', '../escape'],
    ['opencode', '--project', 'one', '--config-dir', 'two'], ['opencode', '--model', 'invalid'],
    ['opencode', '--dsh-home', '/tmp'], ['harness', '--model', 'deepseek/example']]) {
    assert.throws(() => parseOptions(arguments_));
  }
});

test('OpenCode dry run creates no directories', (context) => {
  const directory = fixture(context);
  const destination = path.join(directory, 'not created');
  const result = run(['opencode', '--config-dir', destination, '--dry-run'], directory);
  successful(result);
  assert.equal(fs.existsSync(destination), false);
  assert.match(result.stdout, /Dry run/);
});

test('OpenCode preserves the source prompt plus tool guidance and all knowledge skills without config edits', (context) => {
  const directory = fixture(context);
  const destination = path.join(directory, 'custom config');
  fs.mkdirSync(destination);
  const originalConfig = '{\n // Keep comments and settings\n "default_agent": "build",\n}\n';
  fs.writeFileSync(path.join(destination, 'opencode.jsonc'), originalConfig);
  fs.writeFileSync(path.join(destination, 'auth.json'), '{"fixture":"unchanged"}');
  const result = run(['opencode', '--config-dir', destination, '--model', 'deepseek/example'], directory);
  successful(result);
  const agent = fs.readFileSync(path.join(destination, 'agents/fujiang.md'), 'utf8');
  const marker = '\n---\n\n';
  assert.equal(agent.slice(agent.indexOf(marker) + marker.length), effectivePrompt(JSON.parse(fs.readFileSync(path.join(root, 'prompt-custom.json'))).text));
  assert.match(agent, /^model: "deepseek\/example"$/m);
  assert.doesNotMatch(agent.slice(0, agent.indexOf(marker)), /permissions?:|tools:/);
  assert.equal(fs.readFileSync(path.join(destination, 'opencode.jsonc'), 'utf8'), originalConfig);
  assert.equal(fs.readFileSync(path.join(destination, 'auth.json'), 'utf8'), '{"fixture":"unchanged"}');
  const categories = fs.readdirSync(path.join(root, 'plugin/knowledge'), { withFileTypes: true })
    .filter((entry) => entry.isDirectory()).map((entry) => entry.name);
  assert.deepEqual(categories.sort(), [...KNOWLEDGE_CATEGORIES].sort());
  for (const category of categories) {
    const source = path.join(root, 'plugin/knowledge', category);
    const name = parseKnowledgeDocument(fs.readFileSync(path.join(source, 'SKILL.md'), 'utf8')).fields.name;
    compareDirectory(source, path.join(destination, 'skills', name));
  }
  assert.equal(fs.existsSync(path.join(destination, 'plugins')), false);
});

test('OpenCode project installs are local and inherit model selection unless explicitly set', (context) => {
  const directory = fixture(context);
  const project = path.join(directory, 'project with spaces');
  successful(run(['opencode', '--project', project], directory));
  const agent = fs.readFileSync(path.join(project, '.opencode/agents/fujiang.md'), 'utf8');
  assert.doesNotMatch(agent.split('\n---\n')[0], /^model:/m);
  assert.equal(fs.existsSync(path.join(directory, '.opencode')), false);
});

test('OpenCode respects OPENCODE_CONFIG_DIR and XDG_CONFIG_HOME', (context) => {
  const directory = fixture(context);
  const config = path.join(directory, 'explicit config');
  const xdg = path.join(directory, 'xdg config');
  successful(run(['opencode'], directory, { OPENCODE_CONFIG_DIR: config, XDG_CONFIG_HOME: xdg }));
  assert.ok(fs.existsSync(path.join(config, 'agents/fujiang.md')));
  assert.equal(fs.existsSync(xdg), false);
  successful(run(['opencode'], directory, { OPENCODE_CONFIG_DIR: '', XDG_CONFIG_HOME: xdg }));
  assert.ok(fs.existsSync(path.join(xdg, 'opencode/agents/fujiang.md')));
});

test('OpenCode updates back up existing files, preserve other agents, and are idempotent', (context) => {
  const directory = fixture(context);
  const destination = path.join(directory, 'config');
  fs.mkdirSync(path.join(destination, 'agents'), { recursive: true });
  fs.writeFileSync(path.join(destination, 'agents/fujiang.md'), 'previous custom agent');
  fs.writeFileSync(path.join(destination, 'agents/reviewer.md'), 'unrelated agent');
  successful(run(['opencode', '--config-dir', destination], directory));
  const backups = path.join(destination, 'fujiang-backups');
  const names = fs.readdirSync(backups);
  assert.equal(names.length, 1);
  assert.equal(fs.readFileSync(path.join(backups, names[0], 'agents/fujiang.md'), 'utf8'), 'previous custom agent');
  assert.equal(fs.readFileSync(path.join(destination, 'agents/reviewer.md'), 'utf8'), 'unrelated agent');
  const repeated = run(['opencode', '--config-dir', destination], directory);
  successful(repeated);
  assert.match(repeated.stdout, /already up to date/);
  assert.deepEqual(fs.readdirSync(backups), names);
  assert.equal(fs.readdirSync(destination).some((name) => name.startsWith('.fujiang-install-')), false);
});

test('OpenCode refuses destination directory symlinks without changing their target', { skip: !unix }, (context) => {
  const directory = fixture(context);
  const destination = path.join(directory, 'config');
  const outside = path.join(directory, 'outside');
  fs.mkdirSync(destination);
  fs.mkdirSync(outside);
  fs.symlinkSync(outside, path.join(destination, 'agents'));
  const result = run(['opencode', '--config-dir', destination], directory);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /symbolic link/);
  assert.deepEqual(fs.readdirSync(outside), []);
});

test('Harness resolves explicit macOS apps and rejects invalid explicit paths instead of falling back', { skip: !unix }, (context) => {
  const directory = fixture(context);
  const fake = fakeHarness(directory);
  assert.equal(resolveDsh(fake.app), fake.command);
  assert.equal(resolveDsh(fake.command), fake.command);
  assert.throws(() => resolveDsh(path.join(directory, 'missing'), { env: fake.env }), /not found/);
});

test('Harness dry run neither copies files nor calls registration', { skip: !unix }, (context) => {
  const directory = fixture(context);
  const fake = fakeHarness(directory, { running: true });
  successful(run(['harness', '--dsh-command', fake.app, '--dsh-home', fake.home, '--dry-run'], directory, fake.env));
  assert.equal(fs.existsSync(path.join(fake.home, 'invocation.txt')), false);
  assert.equal(fs.existsSync(path.join(fake.home, 'local-plugins')), false);
});

test('Harness running-process protection refuses installation without copying files', { skip: !unix }, (context) => {
  const directory = fixture(context);
  const fake = fakeHarness(directory, { running: true });
  const result = run(['harness', '--dsh-command', fake.app, '--dsh-home', fake.home], directory, fake.env);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Quit DeepSeek Harness/);
  assert.equal(fs.existsSync(path.join(fake.home, 'local-plugins')), false);
});

test('Harness copies byte-identical files and registers with literal paths and the selected profile', { skip: !unix }, (context) => {
  const directory = fixture(context);
  const fake = fakeHarness(directory);
  successful(run(['harness', '--dsh-command', fake.app, '--dsh-home', fake.home, '--profile', 'cli-test'], directory, fake.env));
  compareDirectory(path.join(root, 'plugin'), path.join(fake.home, 'local-plugins/dsh-prompt-custom'));
  assert.deepEqual(fs.readFileSync(path.join(fake.home, 'prompt-custom.json')), fs.readFileSync(path.join(root, 'prompt-custom.json')));
  assert.deepEqual(fs.readFileSync(path.join(fake.home, 'invocation.txt'), 'utf8').trimEnd().split('\n'),
    [fake.home, 'plugin', '--profile', 'cli-test', 'add', path.join(fake.home, 'local-plugins/dsh-prompt-custom')]);
});

test('Harness registration failure restores the previous plugin and prompt', { skip: !unix }, (context) => {
  const directory = fixture(context);
  const fake = fakeHarness(directory, { fail: true });
  const plugin = path.join(fake.home, 'local-plugins/dsh-prompt-custom');
  fs.mkdirSync(plugin, { recursive: true });
  fs.writeFileSync(path.join(plugin, 'previous.txt'), 'old plugin');
  fs.writeFileSync(path.join(fake.home, 'prompt-custom.json'), 'old prompt');
  const result = run(['harness', '--dsh-command', fake.app, '--dsh-home', fake.home], directory, fake.env);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /registration failed/);
  assert.deepEqual(fs.readdirSync(plugin), ['previous.txt']);
  assert.equal(fs.readFileSync(path.join(plugin, 'previous.txt'), 'utf8'), 'old plugin');
  assert.equal(fs.readFileSync(path.join(fake.home, 'prompt-custom.json'), 'utf8'), 'old prompt');
});

test('Harness Desktop installation requires an initialized Desktop profile', { skip: !unix }, (context) => {
  const directory = fixture(context);
  const fake = fakeHarness(directory);
  fs.rmSync(path.join(fake.home, 'profiles'), { recursive: true });
  const result = run(['harness', '--dsh-command', fake.app, '--dsh-home', fake.home], directory, fake.env);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Desktop profile not found/);
  assert.equal(fs.existsSync(path.join(fake.home, 'local-plugins')), false);
});

test('Unix launchers parse and run from outside the repository', { skip: !unix }, (context) => {
  const directory = fixture(context);
  for (const filename of ['install.sh', 'run-installer.command', 'install-opencode.sh', 'install-opencode.command']) {
    successful(spawnSync('/bin/sh', ['-n', path.join(launcherDirectory, filename)], { encoding: 'utf8' }));
    successful(spawnSync('/bin/sh', [path.join(launcherDirectory, filename), '--help'], { cwd: directory, encoding: 'utf8' }));
  }
  const destination = path.join(directory, 'shell config');
  successful(spawnSync('/bin/sh', [path.join(launcherDirectory, 'install-opencode.sh'), '--config-dir', destination], { cwd: directory, encoding: 'utf8' }));
  assert.ok(fs.existsSync(path.join(destination, 'agents/fujiang.md')));
});

test('native OpenCode discovers the primary agent with source prompt and additive tool guidance', { skip: !process.env.FUJIANG_OPENCODE_BIN }, (context) => {
  const directory = fixture(context);
  const config = path.join(directory, 'config');
  successful(run(['opencode', '--config-dir', config], directory));
  const result = spawnSync(process.env.FUJIANG_OPENCODE_BIN, ['debug', 'agents', '--standalone'], {
    cwd: directory, encoding: 'utf8', timeout: 30000,
    env: { PATH: process.env.PATH, LANG: process.env.LANG || 'en_US.UTF-8',
      ...(process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {}),
      HOME: directory, USERPROFILE: directory, OPENCODE_CONFIG_DIR: config,
      XDG_CONFIG_HOME: path.join(directory, 'xdg-config'), XDG_DATA_HOME: path.join(directory, 'data'),
      XDG_CACHE_HOME: path.join(directory, 'cache'), XDG_STATE_HOME: path.join(directory, 'state') },
  });
  successful(result);
  const agent = JSON.parse(result.stdout).find((entry) => entry.id === 'fujiang');
  assert.ok(agent, 'OpenCode must discover fujiang');
  assert.equal(agent.mode, 'primary');
  assert.equal(agent.system, effectivePrompt(JSON.parse(fs.readFileSync(path.join(root, 'prompt-custom.json'))).text).trimEnd());
});
