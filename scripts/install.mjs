import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parseKnowledgeDocument } from '../plugin/lib/knowledge-schema.js';
import { effectivePrompt } from '../plugin/lib/tool-integrations.js';
import { openCodeToolEntry } from './tool-config.mjs';

const bundleRoot = fileURLToPath(new URL('../', import.meta.url));
const valueOptions = new Set(['--profile', '--dsh-command', '--dsh-home', '--project', '--config-dir', '--model']);
const help = `Usage:
  node scripts/install.mjs harness [--profile desktop] [--dsh-command PATH] [--dsh-home PATH] [--dry-run]
  node scripts/install.mjs opencode [--project PATH | --config-dir PATH] [--model PROVIDER/MODEL] [--with-tools] [--dry-run]

Harness: macOS/Linux; use scripts/installers/run-installer.cmd or install.ps1 in that directory on Windows.
OpenCode: all platforms; installs an agent and offline knowledge skills, not the Harness UI.
Requires Node.js 20 or newer. No credentials, default agents, or permissions are changed.
`;

export function parseOptions(arguments_) {
  const remaining = [...arguments_];
  const options = { target: 'harness', profile: 'desktop', dryRun: false };
  if (remaining[0] && !remaining[0].startsWith('-')) options.target = remaining.shift();
  while (remaining.length) {
    const flag = remaining.shift();
    if (flag === '--help' || flag === '-h') return { help: true };
    if (flag === '--dry-run') { options.dryRun = true; continue; }
    if (flag === '--with-tools') { options.withTools = true; continue; }
    if (!valueOptions.has(flag)) throw new Error('Unknown option: ' + flag);
    const value = remaining.shift();
    if (!value || value.startsWith('--')) throw new Error('Missing value for ' + flag);
    options[flag.slice(2).replace(/-([a-z])/g, (_, letter) => letter.toUpperCase())] = value;
  }
  if (!['harness', 'opencode'].includes(options.target)) throw new Error('Target must be harness or opencode.');
  if (options.project && options.configDir) throw new Error('Use either --project or --config-dir, not both.');
  if (!/^[A-Za-z0-9._-]+$/.test(options.profile)) throw new Error('Invalid profile name.');
  if (options.model && !/^[A-Za-z0-9._-]+\/[^\s\x00-\x1f]+$/.test(options.model)) {
    throw new Error('Model must use provider/model format, without whitespace.');
  }
  const unavailable = options.target === 'harness' ? ['project', 'configDir', 'model', 'withTools'] : ['dshCommand', 'dshHome'];
  if (unavailable.some((key) => options[key]) || (options.target === 'opencode' && options.profile !== 'desktop')) {
    throw new Error('An option belongs to the other installation target.');
  }
  return options;
}

function exists(filename) {
  try { fs.lstatSync(filename); return true; } catch (error) {
    if (error.code === 'ENOENT') return false;
    throw error;
  }
}

function validateSource(filename) {
  const stat = fs.lstatSync(filename);
  if (stat.isSymbolicLink() || (!stat.isFile() && !stat.isDirectory())) {
    throw new Error('Unsupported source file or symbolic link: ' + filename);
  }
  if (stat.isDirectory()) for (const name of fs.readdirSync(filename)) validateSource(path.join(filename, name));
}

function guardDestination(root, destination) {
  const relative = path.relative(root, destination);
  if (!relative || relative.startsWith('..' + path.sep) || path.isAbsolute(relative)) {
    throw new Error('Destination must be inside the selected installation directory.');
  }
  let current = root;
  for (const segment of ['', ...relative.split(path.sep)]) {
    current = path.join(current, segment);
    if (exists(current) && fs.lstatSync(current).isSymbolicLink()) {
      throw new Error('Refusing to replace or follow a destination symbolic link: ' + current);
    }
  }
}

function sameSource(source, destination) {
  if (!exists(destination)) return false;
  const sourceStat = fs.statSync(source);
  const destinationStat = fs.statSync(destination);
  if (sourceStat.isDirectory() !== destinationStat.isDirectory()) return false;
  if (sourceStat.isFile()) return fs.readFileSync(source).equals(fs.readFileSync(destination));
  const names = fs.readdirSync(source).sort();
  return JSON.stringify(names) === JSON.stringify(fs.readdirSync(destination).sort())
    && names.every((name) => {
      const child = path.join(destination, name);
      return !fs.lstatSync(child).isSymbolicLink() && sameSource(path.join(source, name), child);
    });
}

function applyPlan(root, entries, afterInstall, log) {
  for (const entry of entries) {
    guardDestination(root, entry.destination);
    if (entry.source) validateSource(entry.source);
  }
  const changes = entries.filter((entry) => entry.source
    ? !sameSource(entry.source, entry.destination)
    : !exists(entry.destination) || !fs.statSync(entry.destination).isFile()
      || fs.readFileSync(entry.destination, 'utf8') !== entry.content);
  if (!changes.length) {
    afterInstall?.();
    log('Installed files are already up to date.');
    return;
  }
  fs.mkdirSync(root, { recursive: true, mode: 0o700 });
  const stage = fs.mkdtempSync(path.join(root, '.fujiang-install-'));
  const backup = path.join(root, 'fujiang-backups', path.basename(stage));
  const replaced = [];
  try {
    for (const [index, entry] of changes.entries()) {
      entry.staged = path.join(stage, String(index));
      if (entry.source) fs.cpSync(entry.source, entry.staged, { recursive: true });
      else fs.writeFileSync(entry.staged, entry.content, { mode: 0o600 });
      if (fs.statSync(entry.staged).isFile()) fs.chmodSync(entry.staged, 0o600);
      if (exists(entry.destination)) {
        entry.backup = path.join(backup, path.relative(root, entry.destination));
        guardDestination(root, entry.backup);
        fs.mkdirSync(path.dirname(entry.backup), { recursive: true, mode: 0o700 });
        fs.cpSync(entry.destination, entry.backup, { recursive: true });
      }
    }
    for (const entry of changes) {
      fs.mkdirSync(path.dirname(entry.destination), { recursive: true, mode: 0o700 });
      replaced.push(entry);
      fs.rmSync(entry.destination, { recursive: true, force: true });
      fs.renameSync(entry.staged, entry.destination);
    }
    afterInstall?.();
    if (changes.some((entry) => entry.backup)) log('Previous files backed up to: ' + backup);
  } catch (error) {
    for (const entry of replaced.reverse()) {
      fs.rmSync(entry.destination, { recursive: true, force: true });
      if (entry.backup) fs.cpSync(entry.backup, entry.destination, { recursive: true });
    }
    throw error;
  } finally {
    fs.rmSync(stage, { recursive: true, force: true });
  }
}

function executable(filename) {
  try { fs.accessSync(filename, fs.constants.X_OK); return fs.statSync(filename).isFile(); } catch { return false; }
}

export function resolveDsh(command, { env = process.env, home = os.homedir(), platform = process.platform } = {}) {
  const fromPath = (name) => (env.PATH || '').split(path.delimiter).map((directory) => path.join(directory, name));
  const locations = command
    ? command.includes(path.sep) || fs.existsSync(command) ? [path.resolve(command)] : fromPath(command)
    : [...fromPath('dsh'), path.join(home, '.local/bin/dsh'), '/usr/local/bin/dsh', '/usr/bin/dsh',
      ...(platform === 'darwin' ? ['/Applications/DeepSeek Harness.app', path.join(home, 'Applications/DeepSeek Harness.app')] :
        ['/opt/deepseek-harness', '/opt/DeepSeek Harness', path.join(home, '.local/share/deepseek-harness')])];
  for (const location of locations) {
    for (const candidate of [location, path.join(location, 'resources/runtime/cli/bin/dsh'),
      path.join(location, 'Contents/Resources/runtime/cli/bin/dsh')]) {
      if (executable(candidate)) return path.resolve(candidate);
    }
  }
  throw new Error('DSH CLI not found. Pass --dsh-command with the dsh executable, Desktop install directory, or macOS .app path.');
}

function harnessProcesses() {
  const result = spawnSync('ps', ['-A', '-o', 'comm='], { encoding: 'utf8' });
  if (result.error || result.status !== 0) throw new Error('Cannot check running Harness processes; no installation was performed.');
  return result.stdout.split('\n').filter((command) => /^deepseek[ -]+harnes(?:s(?: helper(?: .*)?)?)?$/i.test(path.basename(command.trim())));
}

export function installHarness(options, log = console.log) {
  if (!['darwin', 'linux'].includes(process.platform)) throw new Error('Use scripts/installers/install.ps1 or run-installer.cmd in that directory for Harness on Windows.');
  const root = path.resolve(options.dshHome || process.env.DSH_HOME?.trim() || path.join(os.homedir(), '.dsh'));
  const command = resolveDsh(options.dshCommand);
  const profile = options.profile || 'desktop';
  if (profile === 'desktop' && !fs.existsSync(path.join(root, 'profiles/desktop/package.json'))) {
    throw new Error('Desktop profile not found. Start Harness Desktop once, or select your existing CLI profile with --profile.');
  }
  const entries = [
    { source: path.join(bundleRoot, 'plugin'), destination: path.join(root, 'local-plugins/dsh-prompt-custom') },
    { source: path.join(bundleRoot, 'prompt-custom.json'), destination: path.join(root, 'prompt-custom.json') },
  ];
  for (const entry of entries) { validateSource(entry.source); guardDestination(root, entry.destination); }
  const running = harnessProcesses();
  log('DSH CLI: ' + command);
  log('Profile: ' + profile + '; Harness: ' + (running.length ? 'running' : 'not running'));
  for (const entry of entries) log('Install: ' + entry.destination);
  if (options.dryRun) { log('Dry run; no files changed and no registration command executed.'); return; }
  if (running.length) throw new Error('Quit DeepSeek Harness completely before installing. No files were changed.');
  applyPlan(root, entries, () => {
    const result = spawnSync(command, ['plugin', '--profile', profile, 'add', entries[0].destination], {
      env: { ...process.env, DSH_HOME: root }, stdio: 'inherit',
    });
    if (result.error || result.status !== 0) {
      throw new Error('DSH registration failed' + (result.error ? ': ' + result.error.message : ' (exit ' + result.status + ')')
        + '. Copied plugin/prompt files were restored; inspect the DSH profile before retrying.');
    }
  }, log);
  log('Harness installation complete. Start Harness yourself to load the plugin.');
}

export function installOpenCode(options, log = console.log) {
  const globalRoot = process.env.OPENCODE_CONFIG_DIR || path.join(process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config'), 'opencode');
  const root = path.resolve(options.project ? path.join(options.project, '.opencode') : options.configDir || globalRoot);
  const configuration = JSON.parse(fs.readFileSync(path.join(bundleRoot, 'prompt-custom.json'), 'utf8'));
  if (typeof configuration.text !== 'string' || !configuration.text.trim()) throw new Error('prompt-custom.json must contain non-empty text.');
  const metadata = ['---', 'description: Fujiang Pojia custom prompt and offline knowledge base', 'mode: primary'];
  if (options.model) metadata.push('model: ' + JSON.stringify(options.model));
  const entries = [{
    destination: path.join(root, 'agents/fujiang.md'),
    content: metadata.join('\n') + '\n---\n\n' + effectivePrompt(configuration.text),
  }];
  const knowledge = path.join(bundleRoot, 'plugin/knowledge');
  const skillNames = new Set();
  for (const category of fs.readdirSync(knowledge, { withFileTypes: true })) {
    if (!category.isDirectory()) continue;
    const source = path.join(knowledge, category.name);
    validateSource(source);
    const skill = fs.readFileSync(path.join(source, 'SKILL.md'), 'utf8');
    const name = parseKnowledgeDocument(skill).fields.name;
    if (typeof name !== 'string' || !/^kb-[a-z0-9]+(?:-[a-z0-9]+)*$/.test(name)
      || skillNames.has(name)) throw new Error('Invalid or duplicate knowledge skill name: ' + category.name);
    skillNames.add(name);
    entries.push({ source, destination: path.join(root, 'skills', name) });
  }
  if (!skillNames.size) throw new Error('No knowledge skills found.');
  if (options.withTools) {
    guardDestination(root, path.join(root, 'opencode.json'));
    entries.push(openCodeToolEntry(root));
  }
  for (const entry of entries) { guardDestination(root, entry.destination); log('Install: ' + entry.destination); }
  log('Source prompt is preserved and an additive Context7/REA tool-use section is appended; cards and Harness injection modes are not imported.');
  if (options.withTools) log('Register Context7 remote MCP and REA 6.9.0 local MCP. Starting OpenCode may download REA via npx; Node.js must satisfy REA runtime requirements.');
  if (options.dryRun) { log('Dry run; no files changed.'); return; }
  applyPlan(root, entries, undefined, log);
  log('OpenCode adapter installed: agent fujiang and ' + skillNames.size + ' knowledge skills.');
  log('Connect DeepSeek in OpenCode using /connect, then select fujiang and your DeepSeek model.');
  log(options.withTools ? 'MCP servers registered in opencode.json; no secret values, permissions, or defaults were written.'
    : 'No API keys, permissions, default agents, or opencode.json/jsonc files were changed. Use --with-tools to register MCP servers.');
  log('Harness UI, campaign tools, and automatic continuation are not available in this adapter.');
}

export function main(arguments_ = process.argv.slice(2)) {
  const options = parseOptions(arguments_);
  if (options.help) { console.log(help); return; }
  if (Number(process.versions.node.split('.')[0]) < 20) throw new Error('Node.js 20 or newer is required.');
  if (options.target === 'harness') installHarness(options);
  else installOpenCode(options);
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  try { main(); } catch (error) { console.error('[fujiang installer] ' + error.message); process.exitCode = 1; }
}
