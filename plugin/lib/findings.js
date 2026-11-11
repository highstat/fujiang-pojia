// Vulnerability report storage: $DSH_HOME/vuln-report/findings.json
//
// Why HTTP instead of ctx.tools.register(): tool registration requires defineTool from
// @deepseek-ai/dsh-tools and its peer dependencies; failed installation breaks the entire page.
// The host already has loopback HTTP routes, so the AI can write findings with one shell command
// (curl/pwsh), with no new dependencies or protocol risks.
//
// The writer (AI) receives: POST /api/dsh-prompt-custom/findings
//   { "action": "upsert", "title": "...", "severity": "critical", "target": "...", ... }
// The tab only reads this file and does not collect evidence, so there is **no** network access here.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const STATUSES = ['open', 'fixed', 'accepted', 'false-positive'];
const MAX_ITEMS = 500;
const TEXT_LIMIT = 8000;

const messageOf = (error) => String(error?.message || error).slice(0, 1600);
const clampText = (value) => (typeof value === 'string' ? value.slice(0, TEXT_LIMIT) : '');
const oneLine = (value, limit = 300) => String(value ?? '').replace(/\s+/g, ' ').trim().slice(0, limit);

function atomicWrite(file, text) {
  const temp = file + '.tmp';
  fs.writeFileSync(temp, text, 'utf8');
  fs.renameSync(temp, file);
}

export function createFindingsStore(ctx, options = {}) {
  const home = path.resolve(options.home || process.env.DSH_HOME?.trim() || path.join(os.homedir(), '.dsh'));
  const root = path.join(home, 'vuln-report');
  const file = path.join(root, 'findings.json');

  let state = { schema: 1, updatedAt: 0, items: [] };
  let lastError = null;

  const normalizeItem = (raw, previous) => {
    const target = oneLine(raw?.target ?? previous?.target ?? '', 300);
    const evidence = clampText(raw?.evidence ?? previous?.evidence ?? '');
    const item = {
      id: oneLine(raw?.id || previous?.id || '', 64) || 'v' + Date.now().toString(36) + Math.random().toString(36).slice(2, 7),
      title: oneLine(raw?.title || previous?.title || 'Untitled vulnerability', 200),
      severity: SEVERITIES.includes(raw?.severity) ? raw.severity : (previous?.severity || 'medium'),
      status: STATUSES.includes(raw?.status) ? raw.status : (previous?.status || 'open'),
      target,
      url: oneLine(raw?.url ?? previous?.url ?? '', 500),
      category: oneLine(raw?.category ?? previous?.category ?? '', 120),
      cve: oneLine(raw?.cve ?? previous?.cve ?? '', 120),
      source: oneLine(raw?.source ?? previous?.source ?? 'ai', 40),
      cvss: Number.isFinite(Number(raw?.cvss ?? previous?.cvss)) ? Math.max(0, Math.min(10, Number(raw?.cvss ?? previous?.cvss))) : null,
      evidence,
      description: clampText(raw?.description ?? previous?.description ?? ''),
      remediation: clampText(raw?.remediation ?? previous?.remediation ?? ''),
      references: clampText(raw?.references ?? previous?.references ?? ''),
      verified: (raw?.verified === true || previous?.verified === true)
        && !!(target && evidence.trim()),
      foundAt: oneLine(raw?.foundAt ?? previous?.foundAt ?? '', 40) || new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    return item;
  };

  function load() {
    try {
      const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
      const items = Array.isArray(parsed?.items) ? parsed.items.filter((x) => x && typeof x === 'object') : [];
      state = { schema: 1, updatedAt: Number(parsed?.updatedAt) || 0, items: items.slice(0, MAX_ITEMS) };
    } catch { /* Missing or corrupt file: empty report. */ }
    return state;
  }

  function save() {
    fs.mkdirSync(root, { recursive: true });
    state.updatedAt = Date.now();
    atomicWrite(file, JSON.stringify(state, null, 2) + '\n');
    return state;
  }

  const stats = () => {
    const out = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: state.items.length, open: 0 };
    for (const item of state.items) {
      if (out[item.severity] === undefined) out[item.severity] = 0;
      out[item.severity] += 1;
      if (item.status === 'open') out.open += 1;
    }
    return out;
  };

  const snapshot = () => ({
    ok: true,
    items: state.items.slice().sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) || String(b.foundAt).localeCompare(String(a.foundAt))),
    stats: stats(),
    updatedAt: state.updatedAt,
    path: file,
    error: lastError,
  });

  function upsert(raw) {
    if (!state.items.length) load();
    const previous = raw?.id ? state.items.find((x) => x.id === raw.id) : undefined;
    const item = normalizeItem(raw || {}, previous);
    if (!previous && item.source === 'ai' && (!item.target || !item.evidence.trim())) {
      throw new Error('AI-added vulnerabilities must include a target and evidence.');
    }
    if (previous) state.items = state.items.map((x) => (x.id === item.id ? item : x));
    else {
      if (state.items.length >= MAX_ITEMS) throw new Error('Report entry limit reached (' + MAX_ITEMS + '). Remove entries first.');
      state.items = [item, ...state.items];
    }
    save();
    return item;
  }

  function remove(id) {
    if (!state.items.length) load();
    const key = oneLine(id, 64);
    const before = state.items.length;
    state.items = state.items.filter((x) => x.id !== key);
    if (state.items.length === before) throw new Error('Record not found: ' + key);
    save();
    return true;
  }

  function clear() {
    state.items = [];
    save();
    return true;
  }

  function setStatus(id, status) {
    if (!STATUSES.includes(status)) throw new Error('Unsupported status: ' + status);
    const key = oneLine(id, 64);
    if (!state.items.length) load();
    if (!state.items.some((item) => item.id === key)) throw new Error('Record not found: ' + key);
    return upsert({ id: key, status });
  }

  /** Markdown report: grouped by severity, with a statistics table and per-entry evidence. */
  function toMarkdown() {
    const s = stats();
    const label = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Informational' };
    const lines = [
      '# Vulnerability Report',
      '',
      '- Generated at: ' + new Date().toISOString(),
      '- Total entries: ' + s.total + ' (Critical ' + s.critical + ' / High ' + s.high + ' / Medium ' + s.medium + ' / Low ' + s.low + ' / Informational ' + s.info + ')',
      '- Open: ' + s.open,
      '',
      '## Summary',
      '',
      '| Severity | Count |',
      '|---|---|',
      '| Critical | ' + s.critical + ' |',
      '| High | ' + s.high + ' |',
      '| Medium | ' + s.medium + ' |',
      '| Low | ' + s.low + ' |',
      '| Informational | ' + s.info + ' |',
      '',
    ];
    for (const severity of SEVERITIES) {
      const group = state.items.filter((x) => x.severity === severity);
      if (!group.length) continue;
      lines.push('## ' + label[severity] + '（' + group.length + '）', '');
      for (const item of group) {
        lines.push('### ' + item.title, '');
        if (item.target || item.url) lines.push('- Target: ' + [item.target, item.url].filter(Boolean).join(' · '));
        if (item.cve) lines.push('- CVE：' + item.cve);
        if (item.category) lines.push('- Category: ' + item.category);
        if (item.cvss !== null) lines.push('- CVSS：' + item.cvss);
        lines.push('- Status: ' + item.status + (item.verified ? ' (verified)' : ' (unverified)'));
        lines.push('- Found at: ' + item.foundAt);
        lines.push('');
        if (item.description) lines.push('**Description**', '', item.description, '');
        if (item.evidence) lines.push('**Evidence**', '', ...item.evidence.split(/\r?\n/).map((line) => '    ' + line), '');
        if (item.remediation) lines.push('**Remediation**', '', item.remediation, '');
        if (item.references) lines.push('**References**', '', item.references, '');
        lines.push('---', '');
      }
    }
    return lines.join('\n');
  }

  load();

  return {
    snapshot,
    upsert,
    remove,
    clear,
    setStatus,
    toMarkdown,
    stats,
    reload: () => { lastError = null; load(); return snapshot(); },
    get path() { return file; },
  };
}
