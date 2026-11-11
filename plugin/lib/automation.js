// Automation orchestration: knowledge base matching index + campaign ledger
//
// Design tradeoffs:
// · Build the matching index fresh from knowledge/*/ frontmatter (ports/product/keywords/cve/severity).
//   Entirely local, no network; reread directories on each query so new content is immediately available.
// · Store the ledger in $DSH_HOME/vuln-report/campaigns.json, with fields deliberately kept human-readable and AI-writable.
// · Native tools are an optional enhancement: skip them entirely if @deepseek-ai/dsh-tools is unavailable.
//   All capabilities remain available over HTTP (this path was verified in 0.10.x).
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import net from 'node:net';
import { domainToASCII } from 'node:url';

const STAGES = ['recon', 'fingerprint', 'match', 'verify', 'exploit', 'lateral', 'report'];
const MAX_CAMPAIGNS = 100;
const FRONTMATTER = /^(?:\uFEFF)?---\r?\n([\s\S]*?)\r?\n---(?:\r?\n|$)/;

const messageOf = (error) => String(error?.message || error).slice(0, 1600);
const clamp = (value, limit) => (typeof value === 'string' ? value.slice(0, limit) : '');

function normalizeHost(value) {
  if (typeof value !== 'string' || !value.trim() || value.length > 200) throw new Error('Invalid asset host.');
  const raw = value.trim().replace(/\.$/, '');
  if (net.isIP(raw)) return raw.toLowerCase();
  const host = domainToASCII(raw).toLowerCase();
  if (!host || host.length > 253 || !host.split('.').every((label) =>
    label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label))) {
    throw new Error('Asset host must be a domain name or IP address.');
  }
  return host;
}

function normalizeScopeEntry(value, allowDomain) {
  if (typeof value !== 'string' || !value.trim()) throw new Error('The authorized scope contains an empty entry.');
  const raw = value.trim();
  if (raw.includes('/')) {
    const parts = raw.split('/');
    const family = net.isIP(parts[0]);
    const prefix = Number(parts[1]);
    if (parts.length !== 2 || !family || !/^\d+$/.test(parts[1]) || prefix > (family === 4 ? 32 : 128)) {
      throw new Error('Invalid CIDR: ' + clamp(raw, 80));
    }
    return parts[0].toLowerCase() + '/' + prefix;
  }
  if (!allowDomain) throw new Error('CIDR ranges must use IP/prefix-length notation.');
  if (raw.startsWith('*.')) return '*.' + normalizeHost(raw.slice(2));
  return normalizeHost(raw);
}

function normalizeScope(raw, previous = {}) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('An authorized scope is required.');
  const result = {};
  for (const key of ['domains', 'cidrs', 'exclude']) {
    const values = raw[key] === undefined ? previous[key] || [] : raw[key];
    if (!Array.isArray(values) || values.length > 50) throw new Error('Authorized scope ' + key + ' must be an array of at most 50 entries.');
    result[key] = values.map((value) => normalizeScopeEntry(value, key !== 'cidrs'));
  }
  // The UI has one scope input; accept CIDRs entered there without broadening domain matching.
  result.cidrs.push(...result.domains.filter((entry) => entry.includes('/')));
  result.domains = result.domains.filter((entry) => !entry.includes('/'));
  result.domains = [...new Set(result.domains)];
  result.cidrs = [...new Set(result.cidrs)];
  result.exclude = [...new Set(result.exclude)];
  if (!result.domains.length && !result.cidrs.length) throw new Error('The authorized scope must include at least one domain, IP, or CIDR.');
  return result;
}

function scopeEntryMatches(host, entry) {
  if (entry.includes('/')) {
    if (!net.isIP(host)) return false;
    const [address, prefix] = entry.split('/');
    const family = net.isIP(address);
    if (net.isIP(host) !== family) return false;
    const block = new net.BlockList();
    block.addSubnet(address, Number(prefix), family === 4 ? 'ipv4' : 'ipv6');
    return block.check(host, family === 4 ? 'ipv4' : 'ipv6');
  }
  if (net.isIP(entry)) {
    if (!net.isIP(host)) return false;
    const block = new net.BlockList();
    const family = net.isIP(entry);
    block.addAddress(entry, family === 4 ? 'ipv4' : 'ipv6');
    return block.check(host, family === 4 ? 'ipv4' : 'ipv6');
  }
  if (net.isIP(host)) return false;
  const domain = entry.startsWith('*.') ? entry.slice(2) : entry;
  return host.endsWith('.' + domain) || (!entry.startsWith('*.') && host === domain);
}

function assertInScope(host, scope) {
  const allowed = [...scope.domains, ...scope.cidrs].some((entry) => scopeEntryMatches(host, entry));
  const excluded = scope.exclude.some((entry) => scopeEntryMatches(host, entry));
  if (!allowed || excluded) throw new Error('Asset is outside the campaign authorized scope: ' + host);
}

function parseFrontmatter(markdown) {
  const match = FRONTMATTER.exec(markdown);
  if (!match) return {};
  const fields = {};
  for (const line of match[1].split(/\r?\n/)) {
    const i = line.indexOf(':');
    if (i <= 0) continue;
    const key = line.slice(0, i).trim();
    if (!/^[a-z][a-z0-9-]*$/.test(key)) continue;
    fields[key] = line.slice(i + 1).trim().replace(/^["']|["']$/g, '');
  }
  return fields;
}

const STOPWORDS = new Set(['gateway','server','service','client','web','http','https','httpd','api','admin','login','default','remote','manager','console','portal','access','open','source','code','test','main','index','config','system','vpn','ssl','tls','ipsec','cloud','security','edge','app','gate','proxy','auth']);
const escapeRe = (w) => w.replace(/[.*+?^\${}()|[\]\\]/g, '\\$&');
/** Whole-word matching: active must not match activemq. */
const hasWord = (hay, word) => new RegExp('(?:^|[^a-z0-9])' + escapeRe(String(word).toLowerCase()) + '(?:$|[^a-z0-9])').test(hay);
const tokens = (value) => String(value || '')
  .toLowerCase()
  .split(/[^a-z0-9.+_/-]+/)
  .filter((t) => t.length >= 2);

/** Build the content index: one record = one vulnerability entry. */
export function createKbIndex(corpusDir) {
  const walkAll = (dir, out = []) => {
    let items = [];
    try { items = fs.readdirSync(dir, { withFileTypes: true }); } catch { return out; }
    for (const item of items) {
      const full = path.join(dir, item.name);
      if (item.isDirectory()) walkAll(full, out);
      else if (item.name.toLowerCase().endsWith('.md')) out.push(full);
    }
    return out;
  };
  function build() {
    const entries = [];
    let categories = [];
    try { categories = fs.readdirSync(corpusDir, { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => d.name); }
    catch { categories = []; }
    for (const category of categories) {
      const dir = path.join(corpusDir, category);
      let files = [];
      try { files = fs.readdirSync(dir).filter((f) => f.endsWith('.md') && f.toLowerCase() !== 'skill.md'); }
      catch { continue; }
      for (const file of files) {
        let text = '';
        try { text = fs.readFileSync(path.join(dir, file), 'utf8'); } catch { continue; }
        const f = parseFrontmatter(text);
        entries.push({
          file, category, path: path.join(dir, file),
          title: f.title || file,
          cve: f.cve || '',
          severity: f.severity || 'medium',
          product: f.product || '',
          versions: f.versions || '',
          entry: f.entry || '',
          ports: String(f.ports || '').split(/[,\s]+/).filter((p) => /^\d+$/.test(p)).map(Number),
          keywordList: tokens(f.keywords),
          rawKeywords: String(f.keywords || '').split(/[,，、\s]+/).map((x) => x.trim()).filter((x) => x.length >= 2),
          text: tokens([f.title, f.product, f.cve, f.keywords, f.entry, f.versions].join(' ')),
        });
      }
    }
    return entries;
  }

  const list = () => build();

  /**
   * Fingerprint → candidate entries. Scoring: port 40, product/title match 30, CVE match 20,
   * keywords 10 each (maximum 20), critical +5. Local ranking only; no network or execution.
   */
  function match(input = {}, limit = 5) {
    const ports = []
      .concat(Array.isArray(input.ports) ? input.ports : [])
      .concat(input.port === undefined ? [] : [input.port])
      .map((p) => Number(p))
      .filter((p) => Number.isFinite(p));
    const haystackTokens = new Set([
      ...tokens(input.banner),
      ...tokens(input.product),
      ...tokens(Object.values(input.headers || {}).join(' ')),
      ...tokens(input.text),
    ]);
    const haystackText = [input.banner, input.product, input.text, ...Object.values(input.headers || {})]
      .filter(Boolean).join(' ').toLowerCase();

    const scored = [];
    for (const item of list()) {
      let score = 0;
      const why = [];
      if (ports.length && item.ports.some((p) => ports.includes(p))) {
        score += 35;
        why.push('Port ' + item.ports.filter((p) => ports.includes(p)).join(','));
      }
      const productTokens = tokens(item.product);
      const productHit = productTokens.some((t) => t.length >= 3 && !STOPWORDS.has(t) && hasWord(haystackText, t));
      if (productHit) { score += 60; why.push('Product ' + item.product); }
      if (item.cve && item.cve !== '\u65e0' && hasWord(haystackText, item.cve)) {
        score += 20; why.push('CVE ' + item.cve);
      }
      const kwHits = item.keywordList.filter((k) => k.length >= 3 && !STOPWORDS.has(k) && hasWord(haystackText, k));
      if (kwHits.length) {
        score += Math.min(16, kwHits.length * 8);
        why.push('Keywords ' + kwHits.slice(0, 4).join('/'));
      }
      const cnHits = (item.rawKeywords || []).filter((k) => /[\u4e00-\u9fa5]/.test(k) && haystackText.includes(k.toLowerCase()));
      if (cnHits.length) {
        // Longer terms are more specific: 2 characters score 8; each additional character adds 2, up to 40.
        const cnScore = cnHits.reduce((sum, k) => sum + 8 + Math.max(0, (k.length - 2) * 2), 0);
        score += Math.min(40, cnScore);
        why.push('Chinese keywords ' + cnHits.slice(0, 3).join('/'));
      }
      const titleHits = item.text.filter((t) => t.length >= 4 && !STOPWORDS.has(t) && haystackTokens.has(t));
      if (!productHit && titleHits.length) {
        score += Math.min(18, titleHits.length * 6);
        why.push('Matches ' + titleHits.slice(0, 3).join('/'));
      }
      if (!score) continue;
      if (item.severity === 'critical') score += 5;
      scored.push({ score, why, item });
    }
    scored.sort((a, b) => b.score - a.score || a.item.file.localeCompare(b.item.file));
    return scored.slice(0, Math.max(1, Math.min(20, Number(limit) || 5))).map((hit) => ({
      file: hit.item.file,
      category: hit.item.category,
      title: hit.item.title,
      cve: hit.item.cve,
      severity: hit.item.severity,
      product: hit.item.product,
      versions: hit.item.versions,
      entry: hit.item.entry,
      ports: hit.item.ports,
      score: hit.score,
      why: hit.why,
    }));
  }

  const size = () => list().length;
  const reset = () => {};
  return { match, size, reset, list };
}

/** Skill index: scan disk directly (249 AboutSecurity entries + knowledge base categories), independent of session catalog injection. */
export function createSkillIndex({ home, knowledgeDir, knowledgeEnabled = () => true, aboutSecurityEnabled = () => true } = {}) {
  const base = path.resolve(home || process.env.DSH_HOME?.trim() || path.join(os.homedir(), '.dsh'));
  const aboutRoot = path.join(base, 'fujiang-skills', 'aboutsecurity', 'skills');
  const fields = (file) => {
    try {
      const text = fs.readFileSync(file, 'utf8');
      const head = /^(?:\uFEFF)?---\r?\n([\s\S]*?)\r?\n---/.exec(text);
      const out = {};
      if (head) {
        for (const line of head[1].split(/\r?\n/)) {
          const i = line.indexOf(':');
          if (i > 0) out[line.slice(0, i).trim()] = line.slice(i + 1).trim().replace(/^["']|["']$/g, '');
        }
      }
      return out;
    } catch { return {}; }
  };

  const walk = (dir, out = []) => {
    let items = [];
    try { items = fs.readdirSync(dir, { withFileTypes: true }); } catch { return out; }
    for (const item of items) {
      const full = path.join(dir, item.name);
      if (item.isDirectory()) walk(full, out);
      else if (item.name.toLowerCase() === 'skill.md') out.push(full);
    }
    return out;
  };

  const walkAll = (dir, out = []) => {
    let items = [];
    try { items = fs.readdirSync(dir, { withFileTypes: true }); } catch { return out; }
    for (const item of items) {
      const full = path.join(dir, item.name);
      if (item.isDirectory()) walkAll(full, out);
      else if (item.name.toLowerCase().endsWith('.md')) out.push(full);
    }
    return out;
  };
  function build() {
    const entries = [];
    for (const file of walk(aboutRoot)) {
      const meta = fields(file);
      const rel = path.relative(aboutRoot, path.dirname(file)).split(path.sep).join('/');
      entries.push({ name: meta.name || rel.split('/').pop(), description: meta.description || '', category: rel.split('/')[0] || 'aboutsecurity', source: 'aboutsecurity', path: file });
    }
    if (knowledgeDir) {
      // Index both categories (SKILL.md) and individual vulnerability entries so the AI can directly find specific PoCs.
      for (const file of walkAll(knowledgeDir)) {
        const base = path.basename(file);
        const meta = fields(file);
        const category = path.basename(path.dirname(file));
        if (base.toLowerCase() === 'skill.md') {
          entries.push({ name: 'kb-' + (meta.name || category).replace(/^kb-/, ''), description: meta.description || '', category, source: 'knowledge', path: file });
          continue;
        }
        const name = base.replace(/\.md$/i, '');
        const summary = [meta.title || '', meta.keywords || '', meta.entry || ''].filter(Boolean).join(' · ');
        entries.push({ name, description: summary.slice(0, 240), category, source: 'knowledge-entry', path: file });
      }
    }
    return entries;
  }

  const list = () => {
    const entries = build();
    let knowledgeOn = false;
    let aboutSecurityOn = false;
    try { knowledgeOn = knowledgeEnabled() === true; } catch { /* Fail closed for bundled knowledge access. */ }
    try { aboutSecurityOn = aboutSecurityEnabled() === true; } catch { /* Fail closed for downloaded skill access. */ }
    return entries.filter((item) => item.source === 'knowledge' || item.source === 'knowledge-entry' ? knowledgeOn
      : item.source === 'aboutsecurity' ? aboutSecurityOn : true);
  };

  function search(query, limit = 8) {
    const q = String(query || '').toLowerCase().trim();
    if (!q) return [];
    const words = q.split(/[^a-z0-9\u4e00-\u9fa5]+/).filter((w) => w.length >= 2);
    const scored = [];
    for (const item of list()) {
      const hay = (item.name + ' ' + item.category + ' ' + item.description).toLowerCase();
      let score = 0;
      if (item.name.toLowerCase() === q) score += 60;
      if (item.name.toLowerCase().includes(q)) score += 40;
      if (item.category.toLowerCase().includes(q)) score += 20;
      for (const w of words) if (hay.includes(w)) score += 10;
      if (!score) continue;
      scored.push({ score, item });
    }
    scored.sort((a, b) => b.score - a.score || a.item.name.localeCompare(b.item.name));
    return scored.slice(0, Math.max(1, Math.min(20, Number(limit) || 8))).map((x) => ({ name: x.item.name, category: x.item.category, source: x.item.source, description: x.item.description.slice(0, 200), path: x.item.path, score: x.score }));
  }

  function read(nameOrPath, maxBytes = 12000) {
    const key = String(nameOrPath || '').trim();
    if (!key) throw new Error('A skill name or path is required.');
    const resolvedKey = path.resolve(key);
    const entries = list();
    const hit = entries.find((x) => x.name === key)
      || entries.find((x) => x.name.toLowerCase() === key.toLowerCase())
      || entries.find((x) => path.resolve(x.path) === resolvedKey);
    if (!hit) throw new Error('Skill not found: ' + key + ' (search with skill_search first)');
    const text = fs.readFileSync(hit.path, 'utf8');
    return { name: hit.name, source: hit.source, path: hit.path, content: text.slice(0, maxBytes), truncated: text.length > maxBytes };
  }

  return { search, read, size: () => list().length, reset: () => {} };
}
/** Campaign ledger: $DSH_HOME/vuln-report/campaigns.json */
export function createCampaignStore(ctx, options = {}) {
  const home = path.resolve(options.home || process.env.DSH_HOME?.trim() || path.join(os.homedir(), '.dsh'));
  const dir = path.join(home, 'vuln-report');
  const file = path.join(dir, 'campaigns.json');

  let state = { schema: 1, updatedAt: 0, items: [] };

  function load() {
    try {
      const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
      state = {
        schema: 1,
        updatedAt: Number(parsed?.updatedAt) || 0,
        items: Array.isArray(parsed?.items) ? parsed.items.slice(0, MAX_CAMPAIGNS) : [],
      };
    } catch { /* Empty ledger. */ }
    return state;
  }

  function save() {
    fs.mkdirSync(dir, { recursive: true });
    state.updatedAt = Date.now();
    const temp = file + '.tmp';
    fs.writeFileSync(temp, JSON.stringify(state, null, 2) + '\n', 'utf8');
    fs.renameSync(temp, file);
    return state;
  }

  const idOf = () => 'c' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);

  function create(raw = {}) {
    if (state.items.length >= MAX_CAMPAIGNS) throw new Error('Campaign limit reached (' + MAX_CAMPAIGNS + ').');
    const campaign = {
      id: idOf(),
      name: clamp(String(raw.name || 'Untitled campaign'), 120),
      stage: STAGES.includes(raw.stage) ? raw.stage : 'recon',
      scope: normalizeScope(raw.scope),
      assets: [],
      steps: [],
      attempts: [],
      note: clamp(String(raw.note || ''), 2000),
      objective: clamp(String(raw.objective || raw.name || ''), 300),
      done: raw.done === true,
      doneNote: '',
      autopilot: raw.autopilot !== false,
      rounds: 0,
      maxRounds: Number.isFinite(Number(raw.maxRounds)) ? Math.max(1, Math.min(30, Number(raw.maxRounds))) : 8,
      lastProgress: -1,
      sessionId: raw.sessionId ? clamp(String(raw.sessionId), 120) : null,
      createdBy: 'ui',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    state.items = [campaign, ...state.items];
    save();
    return campaign;
  }

  function get(id) {
    const campaign = state.items.find((c) => c.id === id);
    if (!campaign) throw new Error('Campaign not found: ' + clamp(String(id), 64));
    return campaign;
  }

  function patch(id, body = {}) {
    const campaign = get(id);
    const name = body.name !== undefined ? clamp(String(body.name), 120) : campaign.name;
    let stage = campaign.stage;
    if (body.stage !== undefined) {
      if (!STAGES.includes(body.stage)) throw new Error('Stage must be one of: ' + STAGES.join(' / '));
      stage = body.stage;
    }
    const note = body.note !== undefined ? clamp(String(body.note), 2000) : campaign.note;
    let scope = campaign.scope;
    if (body.scope !== undefined) {
      const nextScope = normalizeScope(body.scope, campaign.scope);
      for (const asset of campaign.assets) assertInScope(normalizeHost(asset.host), nextScope);
      scope = nextScope;
    }
    const objective = body.objective !== undefined ? clamp(String(body.objective), 300) : campaign.objective;
    const autopilot = body.autopilot !== undefined ? body.autopilot !== false : campaign.autopilot;
    const rounds = Number.isFinite(Number(body.rounds)) ? Math.max(0, Number(body.rounds)) : campaign.rounds;
    const lastProgress = Number.isFinite(Number(body.lastProgress)) ? Number(body.lastProgress) : campaign.lastProgress;
    const done = body.done !== undefined ? body.done === true : campaign.done;
    Object.assign(campaign, { name, stage, note, scope, objective, autopilot, rounds, lastProgress, done });
    campaign.updatedAt = new Date().toISOString();
    save();
    return campaign;
  }

  function validateAsset(id, raw = {}) {
    const campaign = get(id);
    const host = normalizeHost(raw.host);
    assertInScope(host, campaign.scope);
    return host;
  }

  function upsertAsset(id, raw = {}) {
    const campaign = get(id);
    const host = validateAsset(id, raw);
    const port = Number.isFinite(Number(raw.port)) ? Number(raw.port) : null;
    const existing = campaign.assets.find((a) => a.host === host && a.port === port);
    const asset = existing || { host, port, fingerprint: '', status: 'new', kbHits: [], note: '', firstSeenAt: new Date().toISOString() };
    if (raw.fingerprint !== undefined) asset.fingerprint = clamp(String(raw.fingerprint), 300);
    if (raw.status !== undefined) asset.status = clamp(String(raw.status), 40);
    if (raw.note !== undefined) asset.note = clamp(String(raw.note), 500);
    if (Array.isArray(raw.kbHits)) asset.kbHits = raw.kbHits.map((k) => clamp(String(k), 120)).slice(0, 20);
    asset.lastSeenAt = new Date().toISOString();
    if (!existing) campaign.assets.push(asset);
    campaign.updatedAt = asset.lastSeenAt;
    save();
    return asset;
  }

  function addStep(id, raw = {}) {
    const campaign = get(id);
    const step = {
      id: 's' + (campaign.steps.length + 1) + '-' + Math.random().toString(36).slice(2, 5),
      stage: STAGES.includes(raw.stage) ? raw.stage : campaign.stage,
      action: clamp(String(raw.cmd || raw.command || (raw.action && raw.action !== 'step' ? raw.action : '')), 500),
      result: clamp(String(raw.result || ''), 4000),
      at: new Date().toISOString(),
    };
    campaign.steps.push(step);
    if (campaign.steps.length > 200) campaign.steps = campaign.steps.slice(-200);
    campaign.updatedAt = step.at;
    save();
    return step;
  }

  function addAttempt(id, raw = {}) {
    const campaign = get(id);
    const attempt = {
      id: 'a' + (campaign.attempts.length + 1),
      asset: clamp(String(raw.asset || ''), 220),
      kb: clamp(String(raw.kb || ''), 120),
      payload: clamp(String(raw.payload || ''), 800),
      outcome: clamp(String(raw.outcome || ''), 120),
      at: new Date().toISOString(),
    };
    campaign.attempts.push(attempt);
    if (campaign.attempts.length > 300) campaign.attempts = campaign.attempts.slice(-300);
    campaign.updatedAt = attempt.at;
    save();
    return attempt;
  }

  /** Bind to a session (only one campaign runs per session). */
  function bind(id, sessionId) {
    const campaign = get(id);
    const session = clamp(String(sessionId || ''), 120);
    if (!session) throw new Error('bind requires sessionId.');
    for (const other of state.items) if (other.id !== id && other.sessionId === session) other.sessionId = null;
    campaign.sessionId = session;
    campaign.updatedAt = new Date().toISOString();
    save();
    return campaign;
  }

  /** Mark the objective as achieved (call after human or model confirmation). */
  function markDone(id, note) {
    const campaign = get(id);
    campaign.done = true;
    campaign.doneNote = clamp(String(note || ''), 500);
    campaign.updatedAt = new Date().toISOString();
    save();
    return campaign;
  }

  /** Advance one stage, stopping at report; return from/to. */
  function advance(id) {
    const campaign = get(id);
    const from = campaign.stage;
    const index = STAGES.indexOf(from);
    const to = index < 0 || index >= STAGES.length - 1 ? campaign.stage : STAGES[index + 1];
    campaign.stage = to;
    campaign.updatedAt = new Date().toISOString();
    save();
    return { campaign, from, to, changed: from !== to };
  }
  function unbind(id) {
    const campaign = get(id);
    campaign.sessionId = null;
    campaign.updatedAt = new Date().toISOString();
    save();
    return campaign;
  }

  /** Session → campaign (at most one per session). */
  const forSession = (sessionId) => state.items.find((c) => c.sessionId && c.sessionId === sessionId) || null;
  function remove(id) {
    const before = state.items.length;
    state.items = state.items.filter((c) => c.id !== id);
    if (state.items.length === before) throw new Error('Campaign not found: ' + clamp(String(id), 64));
    save();
    return true;
  }

  /** Objective progress: stages contribute 0–60%, assets/attempts/hits 0–40%. Coarse guidance for the model only. */
  function progressOf(campaign) {
    const stageIndex = Math.max(0, STAGES.indexOf(campaign.stage));
    const stagePart = (stageIndex / (STAGES.length - 1)) * 60;
    const assetsPart = Math.min(10, campaign.assets.length * 4);
    const attemptsPart = Math.min(10, campaign.attempts.length * 3);
    const hitPart = Math.min(20, campaign.attempts.filter((a) => /hit|success|ok|\u547d\u4e2d/i.test(String(a.outcome || ''))).length * 10);
    return Math.round(Math.min(100, stagePart + assetsPart + attemptsPart + hitPart));
  }

  /** Derive completion criteria from objective when doneCriteria is not explicitly provided. */
  function criteriaOf(campaign) {
    if (Array.isArray(campaign.doneCriteria) && campaign.doneCriteria.length) return campaign.doneCriteria;
    const o = String(campaign.objective || campaign.name || '');
    const out = ['A verified finding provides evidence that the objective has been achieved'];
    if (/\u540e\u53f0|\u7ba1\u7406\u5458|admin|\u7ba1\u7406\u7aef/i.test(o)) out.push('An administrator session can access backend endpoints (returning backend data rather than 401/403)');
    if (/\u6570\u636e|\u4f1a\u5458|\u62d6\u5e93|\u5bfc\u51fa/i.test(o)) out.push('Business data belonging to another account can be read (a redacted sample is sufficient)');
    if (/shell|rce|\u547d\u4ee4\u6267\u884c|\u670d\u52a1\u5668/i.test(o)) out.push('A command can be executed on the target and its output retrieved');
    return out;
  }

  /** Suggest next steps: stage, pending assets, and matching entries (caller supplies kbIndex when needed). */
  function nextStep(id, kbIndex) {
    const campaign = get(id);
    const index = STAGES.indexOf(campaign.stage);
    const pending = campaign.assets.filter((a) => a.status === 'new' || a.status === 'fingerprinted');
    const suggestions = [];
    if (!campaign.assets.length) suggestions.push({ kind: 'recon', text: 'No assets in the ledger yet: probe live hosts and ports within scope, then write host/port to assets.' });
    if (pending.length && kbIndex) {
      for (const asset of pending.slice(0, 5)) {
        const hits = kbIndex.match({ port: asset.port, text: asset.fingerprint }, 3);
        if (hits.length) suggestions.push({ kind: 'match', asset: asset.host + (asset.port ? ':' + asset.port : ''), text: 'Fingerprint-based candidates: ' + hits.map((h) => h.cve + ' ' + h.title).join(' / '), hits: hits.map((h) => h.file) });
      }
    }
    const nextStage = index < 0 || index >= STAGES.length - 1 ? campaign.stage : STAGES[index + 1];
    const progress = progressOf(campaign);
    const stalled = progress <= campaign.lastProgress && (campaign.rounds || 0) >= 2 && !campaign.done;
    const tried = new Set(campaign.attempts.map((a) => String(a.kb || '') + '|'));
    const nextActions = [];
    for (const sug of suggestions) {
      for (const hit of (sug.hits || [])) {
        if (tried.has(hit + '|')) continue;
        nextActions.push({ action: 'verify', kb: hit, asset: sug.asset, text: 'Perform minimal validation using the PoC in ' + hit + ' (prefer read-only checks)' });
      }
    }
    if (!nextActions.length && pending.length) nextActions.push({ action: 'fingerprint', text: 'Add fingerprints for pending assets (banner/response headers/JS paths), then call kb_match' });
    if (stalled) nextActions.unshift({ action: 'pivot', text: 'No progress for two consecutive rounds: change entry points (subdomain/origin server/backend/API documentation) or candidate entries; do not repeat the same payload' });
    return {
      campaignId: campaign.id,
      objective: campaign.objective || campaign.name,
      done: campaign.done === true,
      doneCriteria: criteriaOf(campaign),
      progress,
      stalled,
      rounds: campaign.rounds || 0,
      maxRounds: campaign.maxRounds || 8,
      stage: campaign.stage,
      nextStage,
      assets: campaign.assets.length,
      pending: pending.length,
      steps: campaign.steps.length,
      attempts: campaign.attempts.length,
      instructions: STAGE_STEPS[campaign.stage] || [],
      nextActions: nextActions.slice(0, 3),
      suggestions,
    };
  }

    const STAGE_STEPS = {
      recon: ['Enumerate live hosts and ports (nmap/fscan/httpx)', 'Write host/port/fingerprint to asset', 'campaign_upsert(advance=true) to enter the fingerprinting stage'],
      fingerprint: ['Identify services and versions (banner/response headers/page characteristics)', 'kb_match(port,banner) to retrieve candidate entries', 'campaign_upsert(advance=true) to enter the matching stage'],
      match: ['Select a critical/high entry from kb_match results', 'Use skill to load the corresponding kb-* category and read the PoC', 'campaign_upsert(advance=true) to enter the validation stage'],
      verify: ['Perform minimal validation against the entry criteria (read-only, low frequency)', 'Hit → finding_upsert; no hit → change candidate', 'campaign_upsert(command,result,advance=true)'],
      exploit: ['Exploit according to the PoC and preserve evidence', 'Hit → finding_upsert(severity,evidence)', 'campaign_upsert(advance=true)'],
      lateral: ['Use obtained credentials for lateral movement (within scope only)', 'Update status for each asset', 'campaign_upsert(advance=true)'],
      report: ['Export findings.md', 'Check each piece of evidence and reproduction steps', 'Wrap up: do not advance stages further']
    };
  const snapshot = () => ({ ok: true, updatedAt: state.updatedAt, items: state.items, stages: STAGES, path: file });
  const list = () => ({ ok: true, updatedAt: state.updatedAt, stages: STAGES, items: state.items.map((c) => ({ id: c.id, name: c.name, stage: c.stage, sessionId: c.sessionId || null, assets: c.assets.length, steps: c.steps.length, updatedAt: c.updatedAt })) });

  load();
  return { snapshot, list, create, get, patch, validateAsset, upsertAsset, addStep, addAttempt, remove, nextStep, bind, unbind, advance, markDone, progressOf, criteriaOf, forSession, reload: () => { load(); return snapshot(); }, get path() { return file; } };
}

/**
 * Optionally register capabilities as native tools. If @deepseek-ai/dsh-tools is unavailable,
 * return { ok:false, reason } so the caller stays HTTP-only without throwing or affecting plugin startup.
 */
export async function registerAutomationTools(ctx, { kbIndex, campaigns, findings, skillIndex }) {
  let toolsModule = null;
  try {
    const loader = typeof ctx.get === 'function' ? ctx.get('loader') : undefined;
    toolsModule = loader && typeof loader.import === 'function'
      ? await loader.import('@deepseek-ai/dsh-tools')
      : await import('@deepseek-ai/dsh-tools');
  } catch (error) {
    return { ok: false, reason: 'dsh-tools unavailable: ' + messageOf(error) };
  }
  const defineTool = toolsModule?.defineTool;
  if (typeof defineTool !== 'function') return { ok: false, reason: 'dsh-tools does not export defineTool' };

  const registered = [];
  const schema = (properties) => ({ type: 'object', additionalProperties: false, properties });
  const text = (value) => ({ type: 'string', required: true, description: value });

  try {
    const fiber = ctx.inject(['tools'], (scope) => {
      if (!scope?.tools || typeof scope.tools.register !== 'function') return;
      const defs = [
        {
          name: 'kb_match',
          description: 'Match candidate entries by port/fingerprint in the local CVE/PoC knowledge base (no network). Returns file/cve/severity/entry and match reasons.',
          parameters: { port: { type: 'number', description: 'Port number' }, banner: text('Service fingerprint or banner'), product: { type: 'string', description: 'Product name' } },
          output: { schema: schema({ hits: { type: 'array', required: true, items: { type: 'object', additionalProperties: true } } }), render: (args, value) => [{ type: 'text', text: JSON.stringify(value).slice(0, 4000) }] },
          execute: async (args) => ({ hits: kbIndex.match({ port: args.port, banner: args.banner, product: args.product }, 5) }),
        },
        {
          name: 'campaign_upsert',
          description: 'Update the ledger of a user-created campaign: write assets and advance stages. Does not create campaigns.',
          parameters: { campaignId: text('Campaign ID (must first be created by the user)'), stage: { type: 'string', description: 'recon|fingerprint|match|verify|exploit|lateral|report' }, host: { type: 'string', description: 'Asset host' }, port: { type: 'number', description: 'Asset port' }, fingerprint: { type: 'string', description: 'Fingerprint' }, command: { type: 'string', description: 'Command executed in this step (recorded in steps)' }, sessionId: { type: 'string', description: 'Bind the campaign to this session (usually specified by the user)' }, result: { type: 'string', description: 'Conclusion of this step (recorded in steps)' }, status: { type: 'string', description: 'Asset status: new|fingerprinted|verified|exploited|blocked' }, advance: { type: 'boolean', description: 'Set true to advance one stage (recon→…→report)' }, done: { type: 'boolean', description: 'Set true when the objective is achieved (stops automatic continuation)' }, autopilot: { type: 'boolean', description: 'Set false to disable automatic continuation' }, objective: { type: 'string', description: 'Campaign objective (one sentence, used for completion criteria)' } },
          output: { schema: schema({ campaign: { type: 'object', required: true, additionalProperties: true }, stage: { type: 'object', additionalProperties: true } }), render: (args, value) => [{ type: 'text', text: JSON.stringify(value).slice(0, 4000) }] },
          execute: async (args) => {
            if (!args.campaignId) throw new Error('Only the user can create campaigns in the plugin panel. Record updates under an existing campaignId.');
            if (args.stage && !STAGES.includes(args.stage)) throw new Error('Stage must be one of: ' + STAGES.join(' / '));
            let campaign = campaigns.get(args.campaignId);
            if (args.host) campaigns.validateAsset(campaign.id, { host: args.host });
            if (args.host) campaigns.upsertAsset(campaign.id, { host: args.host, port: args.port, fingerprint: args.fingerprint, status: args.status });
            if (args.stage) campaign = campaigns.patch(campaign.id, { stage: args.stage });
            if (args.objective !== undefined) campaign = campaigns.patch(campaign.id, { objective: args.objective });
            if (args.done === true) campaign = campaigns.markDone(campaign.id, args.result || '');
            if (args.command || args.result) campaigns.addStep(campaign.id, { stage: args.stage || campaign.stage, cmd: args.command, result: args.result });
            if (args.sessionId) campaign = campaigns.bind(campaign.id, args.sessionId);
            let moved = null;
            if (args.advance === true) { const res = campaigns.advance(campaign.id); campaign = res.campaign; moved = { from: res.from, to: res.to, changed: res.changed }; }
            return moved ? { campaign: campaigns.get(campaign.id), stage: moved } : { campaign: campaigns.get(campaign.id) };
          },
        },
        {
          name: 'finding_upsert',
          description: 'Write a confirmed vulnerability to the vulnerability report (equivalent to POST /findings).',
          parameters: { title: text('Vulnerability title'), severity: text('critical|high|medium|low|info'), target: { type: 'string', description: 'Target' }, evidence: { type: 'string', description: 'Evidence' }, remediation: { type: 'string', description: 'Remediation recommendations' }, verified: { type: 'boolean', description: 'Whether it has been verified' } },
          output: { schema: schema({ item: { type: 'object', required: true, additionalProperties: true } }), render: (args, value) => [{ type: 'text', text: JSON.stringify(value).slice(0, 4000) }] },
          execute: async (args) => ({ item: findings.upsert({ title: args.title, severity: args.severity, target: args.target, evidence: args.evidence, remediation: args.remediation, verified: args.verified, source: 'ai' }) }),
        },
        {
          name: 'skill_search',
          description: 'Search the local skill library by keyword (AboutSecurity methodology + knowledge base categories), independently of the session catalog. Returns name/category/source/path.',
          parameters: { query: text('Keywords, e.g. sqli / ad / privilege / deserialization'), limit: { type: 'number', description: 'Number of results (default 8)' } },
          output: { schema: schema({ hits: { type: 'array', required: true, items: { type: 'object', additionalProperties: true } } }), render: (args, value) => [{ type: 'text', text: JSON.stringify(value).slice(0, 4000) }] },
          execute: async (args) => ({ hits: skillIndex.search(args.query, args.limit) }),
        },
        {
          name: 'skill_read',
          description: 'Read a skill SKILL.md body (find its name or path with skill_search first).',
          parameters: { name: text('Skill name or absolute path'), maxBytes: { type: 'number', description: 'Maximum characters to return (default 12000)' } },
          output: { schema: schema({ name: { type: 'string', required: true }, path: { type: 'string', required: true }, content: { type: 'string', required: true }, source: { type: 'string' }, truncated: { type: 'boolean' } }), render: (args, value) => [{ type: 'text', text: String(value.content || '').slice(0, 4000) }] },
          execute: async (args) => skillIndex.read(args.name, args.maxBytes),
        },        {
          name: 'pipeline_next',
          description: 'Return the suggested next campaign stage, pending assets, and candidate vulnerability entries.',
          parameters: { campaignId: text('Campaign ID') },
          output: { schema: schema({ next: { type: 'object', required: true, additionalProperties: true } }), render: (args, value) => [{ type: 'text', text: JSON.stringify(value).slice(0, 4000) }] },
          execute: async (args) => ({ next: campaigns.nextStep(args.campaignId, kbIndex) }),
        },
      ];
      for (const def of defs) {
        try { scope.tools.register(defineTool(def)); registered.push(def.name); }
        catch (error) { ctx.logger?.warn?.('[dsh-prompt-custom] Tool registration failed ' + def.name + ': ' + messageOf(error)); }
      }
    });
    await fiber;
  } catch (error) {
    return { ok: false, reason: 'tools service unavailable: ' + messageOf(error), registered };
  }
  return { ok: registered.length > 0, registered };
}
