// The catalog stores sources only. REA is acquired on demand into an owned directory.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';

const OWNER = 'dsh-prompt-custom:skill-library:v1';
const MARKER = '.fujiang-owner.json';
const MCP_VERSION = '0.2.1-rc.5';
const MAX_REA_TARBALL_BYTES = 128 * 1024 * 1024;
const SKILL_NAME = 'fujiang-rea-reverse-engineer-anything';
const SERVER_NAME = 'fujiang_rea';
const CATALOG = Object.freeze({
  id: 'rea', name: 'Reverse Engineering', projectName: 'Reverse Engineer Anything (REA)',
  repositoryUrl: 'https://github.com/morluto/rea',
  installUrl: 'https://registry.npmjs.org/rea-agents/latest',
});
const readJson = file => JSON.parse(fs.readFileSync(file, 'utf8'));
const messageOf = error => String(error?.message || error).slice(0, 1600);
const isInside = (base, file) => {
  const relative = path.relative(base, file);
  return relative !== '' && relative !== '..' && !relative.startsWith('..' + path.sep) && !path.isAbsolute(relative);
};

function run(command, args, { cwd, signal, timeout = 600000 } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd, signal, windowsHide: true, shell: false,
      env: { ...process.env, ELECTRON_RUN_AS_NODE: undefined }, stdio: ['ignore', 'pipe', 'pipe'] });
    let output = '';
    const append = chunk => { output = (output + chunk.toString()).slice(-6000); };
    child.stdout.on('data', append);
    child.stderr.on('data', append);
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; child.kill(); }, timeout);
    let spawnError = null;
    child.on('error', error => { spawnError = error; });
    child.on('close', code => {
      clearTimeout(timer);
      if (timedOut) reject(new Error('Download or installation timed out. Check your network and retry.'));
      else if (spawnError) reject(spawnError);
      else if (code !== 0) reject(new Error(`Installation process exited (${code}): ${output.trim().slice(-1400)}`));
      else resolve(output.trim());
    });
  });
}

async function findNode(signal) {
  const dirs = [path.dirname(process.execPath),
    path.join(process.env.LOCALAPPDATA || '', 'Programs', 'nodejs'),
    path.join(process.env.ProgramFiles || 'C:/Program Files', 'nodejs'),
    path.join(process.env.LOCALAPPDATA || '', 'Programs', 'DeepSeek Harness', 'resources', 'runtime', 'primary-runtime', 'dependencies', 'node', 'bin'),
    ...(process.env.PATH || '').split(path.delimiter)];
  const compatible = [];
  for (const dir of [...new Set(dirs.filter(Boolean))]) {
    const node = path.join(dir, process.platform === 'win32' ? 'node.exe' : 'node');
    if (!fs.existsSync(node)) continue;
    try {
      const version = await run(node, ['--version'], { signal, timeout: 10000 });
      if (!/^v\d+\.\d+\.\d+$/.test(version)) continue;
      const [major, minor, patch] = version.slice(1).split('.').map(Number);
      // REA's published runtime floor; npm --engine-strict checks the selected release too.
      if (!((major === 22 && (minor > 23 || minor === 23 && patch >= 4))
        || (major === 24 && (minor > 22 || minor === 22 && patch >= 1))
        || major > 26 || major === 26 && (minor > 12 || minor === 12 && patch >= 1))) continue;
      const candidates = [path.join(dir, 'node_modules/npm/bin/npm-cli.js'),
        path.join(dir, '../lib/node_modules/npm/bin/npm-cli.js'),
        path.join(process.env.APPDATA || '', 'npm/node_modules/npm/bin/npm-cli.js')];
      const npm = candidates.find(file => fs.existsSync(file));
      if (npm) compatible.push({ node, npm, score: major * 1000000 + minor * 1000 + patch });
    } catch { if (signal?.aborted) throw new Error('Operation stopped.'); }
  }
  if (compatible.length) return compatible.sort((a, b) => b.score - a.score)[0];
  throw new Error('No working Node.js and npm installation was found. Install official Node.js (REA currently requires 22.23.4, 24.22.1, or a newer compatible version).');
}

function writeJson(file, value) {
  const temp = file + '.tmp';
  fs.writeFileSync(temp, JSON.stringify(value, null, 2) + '\n', 'utf8');
  fs.renameSync(temp, file);
}

export function createSkillLibrary(ctx, options = {}) {
  const home = path.resolve(options.home || process.env.DSH_HOME?.trim() || path.join(os.homedir(), '.dsh'));
  const root = path.join(home, 'fujiang-skills');
  const installDir = path.join(root, 'rea');
  const stateFile = path.join(root, 'state.json');
  const controller = new AbortController();
  let state = { enabled: false };
  let installed = false;
  let version = null;
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
  let skillDispose = null;
  let mcpFiber = null;
  let runtimeCtx = null;
  let active = false;
  let restored = false;

  function assertOwned(dir) {
    if (!isInside(home, dir)) throw new Error('The skill directory is outside the area managed by this plugin.');
    if (fs.lstatSync(dir).isSymbolicLink()) throw new Error('The skill directory is a link. Cleanup stopped to protect other installations.');
    const marker = readJson(path.join(dir, MARKER));
    if (marker.owner !== OWNER) throw new Error('This directory does not belong to the plugin. Operation stopped.');
    const realHome = fs.realpathSync(home);
    if (!isInside(realHome, fs.realpathSync(dir))) throw new Error('The actual skill directory location is outside the area managed by this plugin.');
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
    const pkg = readJson(path.join(dir, 'node_modules/rea-agents/package.json'));
    if (pkg.name !== 'rea-agents' || !/^\d+\.\d+\.\d+(?:-[\w.-]+)?$/.test(pkg.version)) throw new Error('REA installation metadata is incomplete. Delete it and download again.');
    for (const file of ['scripts/rea.mjs', 'skills/reverse-engineer-anything/SKILL.md']) {
      if (!fs.statSync(path.join(dir, 'node_modules/rea-agents', file)).isFile()) throw new Error('REA installation files are missing.');
    }
    const require = createRequire(path.join(dir, 'package.json'));
    require.resolve('@deepseek-ai/dsh-mcp-client');
    return pkg.version;
  }
  function removeOwned(dir) {
    assertOwned(root); assertOwned(dir);
    if (path.dirname(dir) !== root) throw new Error('Refusing to clean an unmanaged skill directory.');
    fs.rmSync(dir, { recursive: true, force: true });
  }
  const toolCount = () => {
    try {
      const definitions = runtimeCtx?.tools?.schemas?.() || [];
      return definitions.filter(tool => tool.name?.startsWith(`mcp__${SERVER_NAME}__`)).length;
    } catch { return 0; }
  };
  const snapshot = () => ({ ok: true, skills: [{ ...CATALOG, installed, enabled: active,
    busy, phase, version, message: error || detail, progress: progress && { ...progress }, canCancel,
    tools: active ? toolCount() : 0 }] });

  const operationSignal = () => AbortSignal.any([
    controller.signal, operationController?.signal || new AbortController().signal,
  ]);

  function formatBytes(bytes) {
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  }

  async function downloadTarball(metadata, destination, fetcher, signal) {
    const dist = metadata.dist;
    if (!dist || typeof dist.tarball !== 'string' || typeof dist.integrity !== 'string') {
      throw new Error('The official installation source is missing the package file or integrity information.');
    }
    const url = new URL(dist.tarball);
    if (url.protocol !== 'https:' || url.hostname !== 'registry.npmjs.org'
      || !url.pathname.startsWith(`/rea-agents/-/rea-agents-${metadata.version}.`)) {
      throw new Error('The official installation source returned an unexpected download URL.');
    }
    const response = await fetcher(url.href, {
      signal: AbortSignal.any([signal, AbortSignal.timeout(10 * 60 * 1000)]), redirect: 'error',
    });
    if (!response.ok || !response.body) throw new Error(`REA package download failed (HTTP ${response.status}).`);
    const totalHeader = Number(response.headers?.get?.('content-length'));
    const totalBytes = Number.isFinite(totalHeader) && totalHeader > 0 ? totalHeader : null;
    if (totalBytes && totalBytes > MAX_REA_TARBALL_BYTES) throw new Error('The REA package exceeds the allowed download size.');
    const expectedIntegrity = dist.integrity.split(/\s+/).find(value => value.startsWith('sha512-'));
    if (!expectedIntegrity) throw new Error('The official installation source is missing the SHA-512 integrity hash.');
    const hash = createHash('sha512');
    let receivedBytes = 0;
    const file = await fs.promises.open(destination, 'wx');
    try {
      for await (const chunk of response.body) {
        signal.throwIfAborted();
        const buffer = Buffer.from(chunk);
        await file.writeFile(buffer);
        hash.update(buffer);
        receivedBytes += buffer.length;
        if (receivedBytes > MAX_REA_TARBALL_BYTES) throw new Error('The REA package exceeds the allowed download size.');
        const percent = totalBytes ? Math.min(100, Math.floor(receivedBytes * 100 / totalBytes)) : null;
        progress = { stage: 'package', percent, receivedBytes, totalBytes };
        detail = totalBytes
          ? `Downloading REA package ${formatBytes(receivedBytes)} / ${formatBytes(totalBytes)}`
          : `Downloading REA package ${formatBytes(receivedBytes)}`;
      }
      await file.sync();
    } finally { await file.close(); }
    if (totalBytes && receivedBytes !== totalBytes) throw new Error('The REA package download is incomplete. Please retry.');
    if (hash.digest('base64') !== expectedIntegrity.slice('sha512-'.length)) {
      throw new Error('REA package integrity verification failed. Temporary files have been cleaned up.');
    }
    progress = { stage: 'package', percent: 100, receivedBytes, totalBytes };
  }

  async function deactivate() {
    active = false;
    if (skillDispose) { const dispose = skillDispose; skillDispose = null; dispose(); }
    if (mcpFiber) { const fiber = mcpFiber; mcpFiber = null; await fiber.dispose(); }
  }

  async function activate() {
    if (active) return;
    if (closed) throw new Error('The plugin has stopped. Restart DSH.');
    version = verifyInstallation();
    if (!runtimeCtx) throw new Error('This DSH instance has not provided skill and tool services yet. Fully restart the official Desktop app and retry.');
    const launch = readJson(path.join(installDir, 'launch.json'));
    if (!path.isAbsolute(launch.node) || !fs.existsSync(launch.node)) throw new Error('The Node.js path is no longer valid. Delete the installation, then download and install again.');
    const require = createRequire(path.join(installDir, 'package.json'));
    let mcpClient;
    try { mcpClient = await ctx.get('loader')?.import('@deepseek-ai/dsh-mcp-client'); } catch { /* use the owned fallback */ }
    mcpClient ||= await import(pathToFileURL(require.resolve('@deepseek-ai/dsh-mcp-client')).href);
    const skillDir = path.join(installDir, 'node_modules/rea-agents/skills/reverse-engineer-anything');
    const skillPath = path.join(skillDir, 'SKILL.md');
    const markdown = fs.readFileSync(skillPath, 'utf8');
    const content = markdown.replace(/^\uFEFF?---\r?\n[\s\S]*?\r?\n---(?:\r?\n|$)/, '');
    try {
      mcpFiber = runtimeCtx.plugin(mcpClient, {
        transport: 'stdio', serverName: SERVER_NAME, command: launch.node,
        args: [path.join(installDir, 'node_modules/rea-agents/scripts/rea.mjs'), '--mcp'],
        cwd: installDir, env: { REA_MCP_OUTPUT_SCHEMA_PROFILE: 'off' },
        toolCallTimeoutMs: 60000, failOnStartupError: true, maxInstructionBytes: 32768,
        reconnect: { enabled: true, initialDelayMs: 1000, maxDelayMs: 30000, maxAttempts: 5 },
      });
      await mcpFiber;
      if (closed) throw new Error('The plugin has stopped.');
      if (toolCount() === 0) throw new Error('REA did not register any tools. Retry or download and install again.');
      skillDispose = runtimeCtx.skills.register({
        name: SKILL_NAME, description: 'Use REA to reverse engineer native programs, Electron/JavaScript, packages, firmware, and browser targets.',
        source: 'runtime', provider: 'fujiang-skill-library', path: skillPath, content,
        resourceBase: { kind: 'directory', path: skillDir },
        invocation: { modelInvocable: true, userInvocable: true },
        metadata: { project: 'morluto/rea', version },
      });
      active = true;
      phase = 'ready';
    } catch (error) { await deactivate(); throw error; }
  }

  async function download() {
    ensureRoot();
    if (fs.existsSync(installDir)) throw new Error('An installation directory already exists. Delete it before downloading again.');
    const signal = operationSignal();
    progress = { stage: 'metadata', percent: null, receivedBytes: null, totalBytes: null };
    detail = 'Fetching the official installation source…';
    const fetcher = options.fetch || globalThis.fetch;
    const response = await fetcher(CATALOG.installUrl, { signal: AbortSignal.any([signal, AbortSignal.timeout(30000)]), redirect: 'error' });
    if (!response.ok) throw new Error(`Unable to read the official installation link (HTTP ${response.status}).`);
    const metadataText = await response.text();
    if (metadataText.length > 1024 * 1024) throw new Error('The installation source response is too large.');
    const metadata = JSON.parse(metadataText);
    if (metadata.name !== 'rea-agents' || !/^\d+\.\d+\.\d+(?:-[\w.-]+)?$/.test(metadata.version)) throw new Error('The official installation source returned an invalid version.');
    const launch = await (options.findNode || findNode)(signal);
    const stage = path.join(root, '.staging-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8));
    fs.mkdirSync(stage);
    writeJson(path.join(stage, MARKER), { owner: OWNER });
    writeJson(path.join(stage, 'package.json'), { name: 'fujiang-managed-rea', private: true, version: '1.0.0' });
    try {
      const tarballPath = path.join(stage, 'rea-agents.tgz');
      await downloadTarball(metadata, tarballPath, fetcher, signal);
      progress = { stage: 'dependencies', percent: null, receivedBytes: null, totalBytes: null };
      detail = `REA ${metadata.version} downloaded. Installing dependencies…`;
      await (options.run || run)(launch.node, [launch.npm, 'install', '--ignore-scripts', '--no-audit', '--no-fund',
        '--omit=dev', '--engine-strict', '--registry=https://registry.npmjs.org', '--no-save', '--package-lock=false',
        tarballPath, `@deepseek-ai/dsh-mcp-client@${MCP_VERSION}`], { cwd: stage, signal });
      if (closed) throw new Error('The plugin has stopped.');
      verifyInstallation(stage);
      fs.unlinkSync(tarballPath);
      writeJson(path.join(stage, 'launch.json'), { node: launch.node });
      fs.renameSync(stage, installDir);
      installed = true;
      version = metadata.version;
      canCancel = false;
      progress = { stage: 'registering', percent: null, receivedBytes: null, totalBytes: null };
      detail = 'Download complete. Registering skills and tools…';
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
        try { ctx.logger?.warn?.('REA skill library: ' + error); } catch { /* optional logger */ }
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
    if (!body || Array.isArray(body) || body.id !== 'rea' || !['install', 'enable', 'disable', 'delete', 'cancel'].includes(body.action)
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
          if (!installed) throw new Error('Download and install REA first.');
          state.enabled = true; save(); await activate(); break;
        case 'disable':
          state.enabled = false; save(); await deactivate(); phase = installed ? 'disabled' : 'not_installed'; break;
        case 'delete':
          state.enabled = false; save(); await deactivate();
          if (fs.existsSync(installDir)) removeOwned(installDir);
          installed = false; version = null; phase = 'not_installed'; break;
      }
    });
  }

  // Services are optional for the prompt feature. Their absence is reported by the skill card.
  ctx.inject(['skills', 'tools'], scope => {
    runtimeCtx = scope;
    scope.effect(() => async () => { runtimeCtx = null; await deactivate(); }, 'fujiang-skills: runtime cleanup');
    if (restored && installed && state.enabled && !active && !busy && !closed) start('enable', activate);
  });
  const restore = async () => {
    try {
      if (!fs.existsSync(root)) return;
      assertOwned(root);
      if (fs.existsSync(stateFile)) state = { enabled: readJson(stateFile).enabled === true };
      if (fs.existsSync(installDir)) {
        assertOwned(installDir);
        installed = true; // A broken owned installation must still offer Delete in the UI.
        version = verifyInstallation(); phase = 'disabled';
        if (state.enabled && runtimeCtx) {
          // Cordis finishes injecting dependent services before this delayed restore.
          start('enable', async () => { await activate(); });
        }
      }
    } catch (cause) { error = messageOf(cause); phase = 'error'; }
    finally { restored = true; }
  };
  const ready = new Promise(resolve => setImmediate(() => resolve(restore())));
  ctx.effect(() => async () => {
    closed = true; controller.abort();
    if (operation) await operation;
    await deactivate();
  }, 'fujiang-skills: manager cleanup');
  return { snapshot, action, ready, settled: async () => { await ready; if (operation) await operation; },
    // No prompt file access is performed anywhere in this module.
  };
}
