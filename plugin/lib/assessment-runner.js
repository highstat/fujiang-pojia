import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { digest, managedPath, readBounded, requireText } from './assessment-store.js';

export function loopbackUrl(value, label = 'API URL') {
  const url = new URL(requireText(value, label));
  if (url.protocol !== 'http:' || !['127.0.0.1', '[::1]'].includes(url.hostname) || url.username || url.password || url.search || url.hash) {
    throw new Error(label + ' must use HTTP on a literal loopback address without credentials, query, or fragment.');
  }
  return url;
}

export async function boundedJson(url, init = {}, limit = 4 * 1024 * 1024) {
  const response = await fetch(url, { ...init, redirect: 'error' });
  if (!response.ok) throw new Error('Local API returned HTTP ' + response.status);
  if (!response.body) throw new Error('Local API returned no body.');
  const reader = response.body.getReader();
  const chunks = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > limit) throw new Error('Local API response exceeds the size limit.');
      chunks.push(Buffer.from(value));
    }
  } catch (error) { await reader.cancel(); throw error; }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

export function loadAssessmentConfig(root) {
  let supplied = {};
  try { supplied = JSON.parse(readBounded(managedPath(root, 'config.json'), 128 * 1024).toString('utf8')); }
  catch (error) { if (error.code !== 'ENOENT') throw new Error('Invalid assessment config: ' + error.message); }
  if (!supplied || typeof supplied !== 'object' || Array.isArray(supplied)) throw new Error('Assessment config must be an object.');
  const config = { executionEnabled: false, scope: { urls: [], localRoots: [], templateRoots: [], ruleRoots: [] },
    executables: {}, timeoutMs: 120000, maxOutputBytes: 20 * 1024 * 1024, maxConcurrent: 2,
    rateLimit: 5, zapApiUrl: 'http://127.0.0.1:8080', ...supplied };
  if (typeof config.executionEnabled !== 'boolean') throw new Error('executionEnabled must be boolean.');
  for (const [key, maximum] of Object.entries({ timeoutMs: 3600000, maxOutputBytes: 20 * 1024 * 1024, maxConcurrent: 4, rateLimit: 20 })) {
    if (!Number.isInteger(config[key]) || config[key] < 1 || config[key] > maximum) throw new Error('Invalid assessment limit: ' + key);
  }
  if (!config.scope || typeof config.scope !== 'object' || Array.isArray(config.scope)) throw new Error('scope must be an object.');
  for (const key of ['urls', 'localRoots', 'templateRoots', 'ruleRoots']) {
    config.scope[key] ??= [];
    if (!Array.isArray(config.scope[key]) || config.scope[key].length > 100 || config.scope[key].some(item => typeof item !== 'string' || !item.trim())) {
      throw new Error('Invalid scope list: ' + key);
    }
  }
  if (!config.executables || typeof config.executables !== 'object' || Array.isArray(config.executables)) throw new Error('executables must be an object.');
  loopbackUrl(config.zapApiUrl, 'zapApiUrl');
  return config;
}

export function assertTargetUrl(target, config) {
  const url = new URL(requireText(target, 'target URL', 4000));
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.hash) throw new Error('Expected an HTTP(S) target without credentials or a fragment.');
  const allowed = config.scope.urls.some(value => {
    const base = new URL(value);
    const prefix = base.pathname.replace(/\/$/, '');
    return base.origin === url.origin && (url.pathname === prefix || url.pathname.startsWith(prefix + '/'));
  });
  if (!allowed) throw new Error('Target is outside the configured exact-origin/path scope.');
  return url.href;
}

export function scopedPath(value, roots, label, fileOnly = false) {
  const target = fs.realpathSync(path.resolve(requireText(value, label, 4000)));
  if (!roots.some(root => {
    const relative = path.relative(fs.realpathSync(path.resolve(root)), target);
    return relative === '' || relative !== '..' && !relative.startsWith('..' + path.sep) && !path.isAbsolute(relative);
  })) throw new Error(label + ' is outside its configured local roots.');
  if (fileOnly && !fs.statSync(target).isFile()) throw new Error(label + ' must be one reviewed local file.');
  return target;
}

function executable(name, config) {
  let filename = config.executables[name];
  if (filename !== undefined && (typeof filename !== 'string' || !path.isAbsolute(filename))) throw new Error('Executable overrides must be absolute paths.');
  if (!filename) for (const directory of (process.env.PATH || '').split(path.delimiter)) {
    if (!directory || !path.isAbsolute(directory)) continue;
    const candidate = path.join(directory, name + (process.platform === 'win32' ? '.exe' : ''));
    try { fs.accessSync(candidate, fs.constants.X_OK); filename = candidate; break; } catch {}
  }
  if (!filename) throw new Error(name + ' is not installed or configured; no automatic installation was attempted.');
  filename = fs.realpathSync(filename);
  if (!fs.statSync(filename).isFile()) throw new Error('Executable must be a file.');
  fs.accessSync(filename, fs.constants.X_OK);
  return filename;
}

export function buildAssessmentPlan(request, config, root) {
  const tool = requireText(request.tool, 'tool', 30);
  const campaignId = requireText(request.campaignId, 'campaignId', 120);
  const input = { tool, campaignId, target: requireText(request.target, 'target', 4000) };
  const plan = { input, tool, campaignId, profile: tool === 'zap' ? 'collect-existing-alerts' : 'bounded-scan',
    timeoutMs: config.timeoutMs, maxOutputBytes: config.maxOutputBytes, configDigest: digest(JSON.stringify(config)) };
  if (tool === 'zap') {
    plan.target = input.target = assertTargetUrl(input.target, config);
    plan.apiUrl = loopbackUrl(config.zapApiUrl).origin;
    return plan;
  }
  if (!['nuclei', 'semgrep', 'trivy'].includes(tool)) throw new Error('Supported tools: nuclei, zap, semgrep, trivy.');
  plan.command = executable(tool, config);
  const stat = fs.statSync(plan.command);
  plan.executableIdentity = { size: stat.size, mtimeMs: stat.mtimeMs, ino: String(stat.ino) };
  if (tool === 'nuclei') {
    plan.target = input.target = assertTargetUrl(input.target, config);
    input.templates = scopedPath(request.templates, config.scope.templateRoots, 'templates', true);
    plan.rulesDigest = digest(readBounded(input.templates, 5 * 1024 * 1024));
    if (!root) throw new Error('Assessment home is required for controlled Nuclei configuration.');
    plan.args = ['-config', managedPath(root, 'scanner-config/nuclei.yaml'), '-u', plan.target, '-t', input.templates, '-type', 'http', '-no-interactsh', '-disable-redirects',
      '-rate-limit', String(config.rateLimit), '-concurrency', '1', '-bulk-size', '1', '-retries', '0',
      '-disable-update-check', '-jsonl', '-silent', '-no-color', '-omit-raw', '-omit-template'];
  } else {
    plan.target = input.target = scopedPath(input.target, config.scope.localRoots, 'target');
    plan.cwd = plan.target;
    if (!fs.statSync(plan.target).isDirectory()) throw new Error('Filesystem scan target must be a directory.');
    if (tool === 'semgrep') {
      input.rules = scopedPath(request.rules, config.scope.ruleRoots, 'rules', true);
      plan.rulesDigest = digest(readBounded(input.rules, 5 * 1024 * 1024));
      plan.args = ['scan', '--json', '--metrics', 'off', '--disable-version-check', '--config', input.rules, plan.target];
    } else plan.args = ['fs', '--format', 'json', '--scanners', 'vuln,misconfig', '--skip-db-update', '--skip-java-db-update',
      '--skip-check-update', '--skip-version-check', '--offline-scan', '--quiet', plan.target];
  }
  return plan;
}

export function runBounded(plan, { signal } = {}) {
  if (signal?.aborted) return Promise.reject(new Error('Run cancelled before start.'));
  return new Promise((resolve, reject) => {
    const environment = {};
    for (const key of ['PATH', 'HOME', 'USERPROFILE', 'SystemRoot', 'WINDIR', 'TMP', 'TEMP', 'TMPDIR', 'LANG', 'LC_ALL', 'APPDATA', 'LOCALAPPDATA', 'XDG_CACHE_HOME']) {
      if (process.env[key] !== undefined) environment[key] = process.env[key];
    }
    environment.SEMGREP_SEND_METRICS = 'off';
    const child = spawn(plan.command, plan.args, { cwd: plan.cwd, env: environment, shell: false,
      windowsHide: true, detached: process.platform !== 'win32', stdio: ['ignore', 'pipe', 'pipe'] });
    let reason = null;
    let spawnError = null;
    const stdout = [];
    const stderr = [];
    let bytes = 0;
    function stop(message) {
      reason ||= message;
      if (!child.pid) return;
      if (process.platform === 'win32') {
        const taskkill = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'taskkill.exe');
        const killer = spawn(taskkill, ['/PID', String(child.pid), '/T', '/F'], { windowsHide: true, stdio: 'ignore' });
        killer.on('error', () => child.kill());
      } else {
        try { process.kill(-child.pid, 'SIGKILL'); } catch { child.kill('SIGKILL'); }
      }
    }
    const timer = setTimeout(() => stop('Run timeout reached.'), plan.timeoutMs);
    const abort = () => stop('Run cancelled.');
    signal?.addEventListener('abort', abort, { once: true });
    const append = destination => chunk => {
      bytes += chunk.length;
      if (bytes > plan.maxOutputBytes) { stop('Scanner output limit reached; results are incomplete.'); return; }
      destination.push(Buffer.from(chunk));
    };
    child.stdout.on('data', append(stdout));
    child.stderr.on('data', append(stderr));
    child.on('error', error => { spawnError = error; });
    child.on('close', (exitCode, exitSignal) => {
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
      if (reason || spawnError) { reject(new Error(reason || 'Scanner could not start: ' + spawnError.code)); return; }
      resolve({ exitCode, exitSignal, stdout: Buffer.concat(stdout), stderr: Buffer.concat(stderr) });
    });
  });
}

export async function collectZapAlerts(plan, { signal, apiKey = process.env.FUJIANG_ZAP_API_KEY } = {}) {
  const alerts = [];
  let bytes = 0;
  const requestSignal = signal ? AbortSignal.any([signal, AbortSignal.timeout(plan.timeoutMs)]) : AbortSignal.timeout(plan.timeoutMs);
  for (let start = 0; start <= 10000; start += 500) {
    const url = new URL('/JSON/alert/view/alerts/', plan.apiUrl);
    url.search = new URLSearchParams({ baseurl: plan.target, start: String(start), count: '500' }).toString();
    const result = await boundedJson(url, { signal: requestSignal, headers: apiKey ? { 'X-ZAP-API-Key': apiKey } : {} }, plan.maxOutputBytes);
    if (!Array.isArray(result.alerts)) throw new Error('ZAP did not return an alerts array.');
    bytes += Buffer.byteLength(JSON.stringify(result.alerts));
    if (bytes > plan.maxOutputBytes) throw new Error('ZAP aggregate output limit reached.');
    alerts.push(...result.alerts);
    if (alerts.length > 10000) throw new Error('ZAP alert limit reached; narrow the target before retrying.');
    if (result.alerts.length < 500) {
      const content = Buffer.from(JSON.stringify({ alerts }));
      if (content.length > plan.maxOutputBytes) throw new Error('ZAP output limit reached.');
      return { exitCode: 0, stdout: content, stderr: Buffer.alloc(0) };
    }
  }
  throw new Error('ZAP pagination did not terminate within the limit.');
}
