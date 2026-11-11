import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawn } from 'node:child_process';

const OWNER = 'dsh-prompt-custom:skill-library:v1';
const MARKER = '.fujiang-owner.json';
const PROVIDER = 'fujiang-aboutsecurity';
const MAX_ARCHIVE_BYTES = 64 * 1024 * 1024;
const MAX_SKILLS = 1000;
const MAX_SKILL_BYTES = 2 * 1024 * 1024;
const CATALOG = Object.freeze({
  id: 'aboutsecurity', name: 'Penetration Testing', projectName: 'WgpSec AboutSecurity',
  repositoryUrl: 'https://github.com/wgpsec/AboutSecurity',
  installUrl: 'https://codeload.github.com/wgpsec/AboutSecurity/zip/refs/heads/master',
});
const messageOf = error => String(error?.message || error).slice(0, 1600);
const isInside = (base, file) => {
  const relative = path.relative(base, file);
  return relative !== '' && relative !== '..' && !relative.startsWith('..' + path.sep) && !path.isAbsolute(relative);
};
const readJson = file => JSON.parse(fs.readFileSync(file, 'utf8'));

function writeJson(file, value) {
  const temp = file + '.tmp';
  fs.writeFileSync(temp, JSON.stringify(value, null, 2) + '\n', 'utf8');
  fs.renameSync(temp, file);
}

function run(command, args, { cwd, signal, timeout = 10 * 60 * 1000 } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd, signal, windowsHide: true, shell: false, stdio: ['ignore', 'pipe', 'pipe'] });
    let output = '';
    const append = chunk => { output = (output + chunk.toString()).slice(-8000); };
    child.stdout.on('data', append);
    child.stderr.on('data', append);
    let timedOut = false;
    let spawnError = null;
    const timer = setTimeout(() => { timedOut = true; child.kill(); }, timeout);
    child.on('error', error => { spawnError = error; });
    child.on('close', code => {
      clearTimeout(timer);
      if (timedOut) reject(new Error('Skill library extraction timed out. Please retry.'));
      else if (spawnError) reject(spawnError);
      else if (code !== 0) reject(new Error(`Skill library extraction failed (${code}): ${output.trim().slice(-1200)}`));
      else resolve(output.trim());
    });
  });
}

function unquote(value) {
  const text = value.trim();
  if (text.startsWith('"') && text.endsWith('"')) {
    try { return JSON.parse(text); } catch { return text.slice(1, -1); }
  }
  if (text.startsWith("'") && text.endsWith("'")) return text.slice(1, -1).replaceAll("''", "'");
  return text;
}

function parseSkill(markdown, file) {
  const match = /^(?:\uFEFF)?---\r?\n([\s\S]*?)\r?\n---(?:\r?\n|$)/.exec(markdown);
  if (!match) throw new Error(`Skill is missing valid frontmatter: ${file}`);
  const lines = match[1].split(/\r?\n/);
  const field = key => lines.find(line => new RegExp(`^${key}:\\s*`).test(line));
  const nameLine = field('name');
  const name = nameLine ? unquote(nameLine.replace(/^name:\s*/, '')) : '';
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(name)) throw new Error(`Invalid skill name: ${file}`);
  const descriptionIndex = lines.findIndex(line => /^description:\s*/.test(line));
  let description = '';
  if (descriptionIndex >= 0) {
    const value = lines[descriptionIndex].replace(/^description:\s*/, '');
    if (/^[|>][-+]?\s*$/.test(value)) {
      const collected = [];
      for (let i = descriptionIndex + 1; i < lines.length && /^(?:\s|$)/.test(lines[i]); i++) collected.push(lines[i].trim());
      description = collected.join(' ').trim();
    } else description = unquote(value);
  }
  if (!description) description = name.replaceAll('-', ' ');
  description = description.replace(/\s+/g, ' ').trim().slice(0, 1200);
  const flag = (key, fallback) => {
    const line = field(key);
    if (!line) return fallback;
    return !/^(?:false|no|0)\s*$/i.test(line.replace(new RegExp(`^${key}:\\s*`), ''));
  };
  return {
    name, description,
    invocation: {
      modelInvocable: !flag('disable-model-invocation', false),
      userInvocable: flag('user-invocable', true),
    },
    content: markdown.slice(match[0].length),
  };
}

function scanSkills(skillsRoot) {
  const entries = [];
  const names = new Set();
  const pending = [skillsRoot];
  while (pending.length) {
    const dir = pending.pop();
    for (const item of fs.readdirSync(dir, { withFileTypes: true })) {
      const file = path.join(dir, item.name);
      if (item.isSymbolicLink()) throw new Error(`The skill library does not support symbolic links: ${file}`);
      if (item.isDirectory()) {
        pending.push(file);
        continue;
      }
      if (!item.isFile() || item.name !== 'SKILL.md') continue;
      const stat = fs.statSync(file);
      if (stat.size > MAX_SKILL_BYTES) throw new Error(`Skill file exceeds the size limit: ${file}`);
      const parsed = parseSkill(fs.readFileSync(file, 'utf8'), file);
      if (names.has(parsed.name)) throw new Error(`Duplicate skill name found: ${parsed.name}`);
      names.add(parsed.name);
      entries.push({ ...parsed, path: file, directory: path.dirname(file) });
      if (entries.length > MAX_SKILLS) throw new Error('The number of skills exceeds the allowed limit.');
    }
  }
  return entries.sort((a, b) => a.name.localeCompare(b.name));
}

export function createAboutSecuritySkillLibrary(ctx, options = {}) {
  const home = path.resolve(options.home || process.env.DSH_HOME?.trim() || path.join(os.homedir(), '.dsh'));
  const root = path.join(home, 'fujiang-skills');
  const installDir = path.join(root, 'aboutsecurity');
  const skillsRoot = path.join(installDir, 'skills');
  const stateFile = path.join(root, 'aboutsecurity-state.json');
  const controller = new AbortController();
  let state = { enabled: false };
  let entries = [];
  let installed = false;
  let phase = 'not_installed';
  let error = null;
  let detail = null;
  let busy = false;
  let closed = false;
  let operation = null;
  let operationController = null;
  let cancelRequested = false;
  let progress = null;
  let canCancel = false;
  let providerDispose = null;
  let runtimeCtx = null;
  let active = false;
  let restored = false;

  function assertOwned(dir) {
    if (!isInside(home, dir)) throw new Error('The skill directory is outside the area managed by this plugin.');
    if (fs.lstatSync(dir).isSymbolicLink()) throw new Error('The skill directory is a link. Cleanup stopped to protect other files.');
    if (readJson(path.join(dir, MARKER)).owner !== OWNER) throw new Error('This directory does not belong to the plugin. Operation stopped.');
    if (!isInside(fs.realpathSync(home), fs.realpathSync(dir))) throw new Error('The actual skill directory location is outside the area managed by this plugin.');
  }
  function ensureRoot() {
    fs.mkdirSync(home, { recursive: true });
    if (fs.existsSync(root)) assertOwned(root);
    else {
      fs.mkdirSync(root);
      writeJson(path.join(root, MARKER), { owner: OWNER });
    }
  }
  function save() { ensureRoot(); writeJson(stateFile, { schema: 1, enabled: state.enabled }); }
  function verifyInstallation(dir = installDir) {
    assertOwned(root);
    assertOwned(dir);
    const skillsPath = path.join(dir, 'skills');
    if (!fs.statSync(skillsPath).isDirectory()) throw new Error('The AboutSecurity skill directory is missing. Delete the installation and download again.');
    const found = scanSkills(skillsPath);
    if (!found.length) throw new Error('No usable SKILL.md files were found. Delete the installation and download again.');
    return found;
  }
  function removeOwned(dir) {
    assertOwned(root);
    assertOwned(dir);
    if (path.dirname(dir) !== root) throw new Error('Refusing to clean an unmanaged skill directory.');
    fs.rmSync(dir, { recursive: true, force: true });
  }
  const snapshot = () => ({ ok: true, skills: [{ ...CATALOG, installed, enabled: active,
    busy, phase, version: null, skillCount: entries.length, message: error || detail,
    progress: progress && { ...progress }, canCancel }] });
  const operationSignal = () => AbortSignal.any([controller.signal, operationController?.signal || new AbortController().signal]);
  const formatBytes = bytes => bytes < 1024 * 1024 ? `${(bytes / 1024).toFixed(0)} KB` : `${(bytes / (1024 * 1024)).toFixed(1)} MB`;

  async function downloadArchive(destination, signal) {
    const fetcher = options.fetch || globalThis.fetch;
    progress = { stage: 'metadata', percent: null, receivedBytes: null, totalBytes: null };
    detail = 'Connecting to the latest AboutSecurity version…';
    const response = await fetcher(CATALOG.installUrl, {
      signal: AbortSignal.any([signal, AbortSignal.timeout(10 * 60 * 1000)]), redirect: 'error',
    });
    if (!response.ok || !response.body) throw new Error(`AboutSecurity download failed (HTTP ${response.status}).`);
    const totalHeader = Number(response.headers?.get?.('content-length'));
    const totalBytes = Number.isFinite(totalHeader) && totalHeader > 0 ? totalHeader : null;
    if (totalBytes && totalBytes > MAX_ARCHIVE_BYTES) throw new Error('The AboutSecurity archive exceeds the allowed download size.');
    const file = await fs.promises.open(destination, 'wx');
    let receivedBytes = 0;
    try {
      for await (const chunk of response.body) {
        signal.throwIfAborted();
        const buffer = Buffer.from(chunk);
        receivedBytes += buffer.length;
        if (receivedBytes > MAX_ARCHIVE_BYTES) throw new Error('The AboutSecurity archive exceeds the allowed download size.');
        await file.writeFile(buffer);
        const percent = totalBytes ? Math.min(100, Math.floor(receivedBytes * 100 / totalBytes)) : null;
        progress = { stage: 'archive', percent, receivedBytes, totalBytes };
        detail = totalBytes
          ? `Downloading AboutSecurity ${formatBytes(receivedBytes)} / ${formatBytes(totalBytes)}`
          : `Downloading AboutSecurity ${formatBytes(receivedBytes)}`;
      }
      await file.sync();
    } finally { await file.close(); }
    if (totalBytes && receivedBytes !== totalBytes) throw new Error('The AboutSecurity download is incomplete. Please retry.');
    progress = { stage: 'archive', percent: 100, receivedBytes, totalBytes };
  }

  async function deactivate() {
    active = false;
    if (providerDispose) { const dispose = providerDispose; providerDispose = null; dispose(); }
  }

  async function activate() {
    if (active) return;
    if (closed) throw new Error('The plugin has stopped. Restart DSH.');
    if (!runtimeCtx) throw new Error('This DSH instance has not provided the skill service yet. Fully restart the official Desktop app and retry.');
    entries = verifyInstallation();
    const candidates = entries.map(entry => ({
      name: entry.name,
      description: entry.description,
      invocation: entry.invocation,
      source: 'custom',
      provider: PROVIDER,
      resourceBase: { kind: 'directory', path: entry.directory },
      rank: 650,
      path: entry.path,
      locator: entry,
    }));
    providerDispose = runtimeCtx.skills.registerProvider(() => ({
      name: PROVIDER,
      async list() { return candidates; },
      async get(candidate) {
        const entry = candidate.locator;
        const current = fs.readFileSync(entry.path, 'utf8');
        const parsed = parseSkill(current, entry.path);
        return {
          name: entry.name, description: entry.description, invocation: entry.invocation,
          source: 'custom', provider: PROVIDER, path: entry.path,
          resourceBase: { kind: 'directory', path: entry.directory }, content: parsed.content,
        };
      },
    }));
    active = true;
    phase = 'ready';
  }

  async function download() {
    ensureRoot();
    if (fs.existsSync(installDir)) throw new Error('An installation directory already exists. Delete it before downloading again.');
    const signal = operationSignal();
    const stage = path.join(root, '.staging-aboutsecurity-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8));
    fs.mkdirSync(stage);
    writeJson(path.join(stage, MARKER), { owner: OWNER });
    try {
      const archive = path.join(stage, 'aboutsecurity.zip');
      const extracted = path.join(stage, 'extract');
      fs.mkdirSync(extracted);
      await downloadArchive(archive, signal);
      signal.throwIfAborted();
      progress = { stage: 'extracting', percent: null, receivedBytes: null, totalBytes: null };
      detail = 'Download complete. Extracting the skill directory…';
      const tar = options.tarCommand || 'tar';
      await (options.run || run)(tar, ['-xf', archive, '-C', extracted, '--strip-components', '1', '--no-same-owner', '--no-same-permissions', 'AboutSecurity-master/skills'], { cwd: stage, signal });
      signal.throwIfAborted();
      const extractedSkills = path.join(extracted, 'skills');
      const found = scanSkills(extractedSkills);
      if (found.length < 200) throw new Error(`Only ${found.length} AboutSecurity skills were found, fewer than expected. Installation stopped.`);
      fs.rmSync(archive, { force: true });
      writeJson(path.join(extracted, MARKER), { owner: OWNER });
      fs.renameSync(extracted, installDir);
      installed = true;
      entries = found.map(entry => ({ ...entry, path: path.join(installDir, 'skills', path.relative(extractedSkills, entry.path)), directory: path.dirname(path.join(installDir, 'skills', path.relative(extractedSkills, entry.path))) }));
      canCancel = false;
      progress = { stage: 'registering', percent: null, receivedBytes: null, totalBytes: null };
      detail = `Downloaded ${entries.length} skills. Registering…`;
    } finally { if (fs.existsSync(stage)) removeOwned(stage); }
  }

  function start(action, task) {
    if (closed) return { status: 503, body: { ...snapshot(), ok: false, message: 'The plugin has stopped. Please restart.' } };
    if (busy) return { status: 409, body: { ...snapshot(), ok: false, message: 'Processing. Wait for the current operation to finish.' } };
    busy = true; error = null; detail = null; cancelRequested = false;
    operationController = new AbortController();
    progress = action === 'install' ? { stage: 'metadata', percent: null, receivedBytes: null, totalBytes: null } : null;
    canCancel = action === 'install';
    phase = { install: 'installing', enable: 'enabling', disable: 'disabling', delete: 'deleting' }[action];
    operation = Promise.resolve().then(task).catch(cause => {
      if (cancelRequested && !closed) {
        error = null; phase = 'cancelled'; detail = 'Download cancelled. Temporary files have been cleaned up.';
        progress = { ...(progress || {}), stage: 'cancelled' };
        state.enabled = false;
      } else {
        error = messageOf(cause); phase = 'error';
        try { ctx.logger?.warn?.('AboutSecurity skill library: ' + error); } catch { /* optional logger */ }
      }
    }).finally(() => {
      busy = false;
      if (phase !== 'cancelled') detail = null;
      operation = null;
      operationController = null;
      cancelRequested = false;
    });
    return { status: 202, body: snapshot() };
  }

  function action(body) {
    if (!body || Array.isArray(body) || body.id !== CATALOG.id || !['install', 'enable', 'disable', 'delete', 'cancel'].includes(body.action)
      || Object.keys(body).some(key => !['id', 'action'].includes(key))) {
      return { status: 400, body: { ok: false, message: 'Unsupported skill or operation.' } };
    }
    if (body.action === 'cancel') {
      if (!busy || !canCancel || !operationController) return { status: 409, body: { ...snapshot(), ok: false, message: 'Cannot cancel at the current stage.' } };
      cancelRequested = true; canCancel = false; phase = 'cancelling';
      progress = { ...(progress || {}), stage: 'cancelling' };
      detail = 'Stopping the download and cleaning up temporary files…';
      operationController.abort(new Error('Cancelled by user'));
      return { status: 202, body: snapshot() };
    }
    return start(body.action, async () => {
      switch (body.action) {
        case 'install':
          if (!installed) await download();
          canCancel = false;
          state.enabled = true; save(); await activate(); break;
        case 'enable':
          if (!installed) throw new Error('Download and install AboutSecurity first.');
          state.enabled = true; save(); await activate(); break;
        case 'disable':
          state.enabled = false; save(); await deactivate(); phase = installed ? 'disabled' : 'not_installed'; break;
        case 'delete':
          state.enabled = false; save(); await deactivate();
          if (fs.existsSync(installDir)) removeOwned(installDir);
          installed = false; entries = []; phase = 'not_installed'; break;
      }
    });
  }

  ctx.inject(['skills'], scope => {
    runtimeCtx = scope;
    scope.effect(() => async () => { runtimeCtx = null; await deactivate(); }, 'fujiang-aboutsecurity: runtime cleanup');
    if (restored && installed && state.enabled && !active && !busy && !closed) start('enable', activate);
  });
  const restore = async () => {
    try {
      if (!fs.existsSync(root)) return;
      assertOwned(root);
      if (fs.existsSync(stateFile)) state = { enabled: readJson(stateFile).enabled === true };
      if (fs.existsSync(installDir)) {
        assertOwned(installDir);
        installed = true;
        entries = verifyInstallation();
        phase = 'disabled';
        if (state.enabled && runtimeCtx) start('enable', activate);
      }
    } catch (cause) { error = messageOf(cause); phase = 'error'; }
    finally { restored = true; }
  };
  const ready = new Promise(resolve => setImmediate(() => resolve(restore())));
  ctx.effect(() => async () => {
    closed = true; controller.abort();
    if (operation) await operation;
    await deactivate();
  }, 'fujiang-aboutsecurity: manager cleanup');
  return { snapshot, action, ready, settled: async () => { await ready; if (operation) await operation; } };
}
