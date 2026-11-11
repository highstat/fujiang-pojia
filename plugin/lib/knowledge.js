// dsh-prompt-custom — knowledge base (bundled CVE / PoC content)
//
// Unlike skills.js (REA, downloaded on demand) and aboutsecurity.js (downloaded on demand),
// this content **ships with the plugin**: markdown under plugin/knowledge/ belongs to the plugin.
// No downloads, extraction, npm, or network access; the only disk operation is reading/writing
// a boolean toggle in $DSH_HOME/fujiang-skills/knowledge-state.json.
//
// Why register multiple category skills instead of one large skill:
//   The model sees each skill's name+description in the <available_skills> catalog;
//   its body is injected only when invoked. Categories let each description direct the model
//   precisely (Java deserialization / edge devices / Exchange+AD / Windows+AD / CMS / local
//   privilege escalation / cloud and containers), saving context and finding the right entry
//   in a single "what vulnerability is this?" query.
//
// The single source of truth for the content protocol is SKILL.md frontmatter in each category directory:
//   ---
//   name: kb-java-deser
//   description: ...
//   ---
// get() reads the body fresh, so content edits need no host restart (the next list/get picks them up).
// Only toggling and adding/removing categories require a restart.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';

const OWNER = 'dsh-prompt-custom:skill-library:v1';
const MARKER = '.fujiang-owner.json';
const PROVIDER = 'fujiang-knowledge';
const VERSION = '1.3.1'

/** Same directory ownership marker as skills.js / aboutsecurity.js (same root and owner). */
const CATALOG = Object.freeze({
  id: 'knowledge',
  name: 'Knowledge Base',
  projectName: 'CVE / PoC Vulnerability Knowledge Base',
  license: 'Bundled with the plugin; local only',
});

const moduleDir = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_CORPUS = path.join(moduleDir, '..', 'knowledge');

/** Category directory → skill name; names must use lowercase and hyphens (core skill-name constraint). */
const CATEGORIES = Object.freeze([
  { dir: 'java-deser', fallback: 'kb-java-deser' },
  { dir: 'java-web', fallback: 'kb-java-web' },
  { dir: 'edge-device', fallback: 'kb-edge-device' },
  { dir: 'exchange-ad', fallback: 'kb-exchange-ad' },
  { dir: 'web-cms', fallback: 'kb-web-cms' },
  { dir: 'linux-priv', fallback: 'kb-linux-priv' },
  { dir: 'cloud-container', fallback: 'kb-cloud-container' },
  { dir: 'gray-market', fallback: 'kb-gray-market' },
  { dir: 'triage', fallback: 'kb-triage' },
]);

const messageOf = (error) => String(error?.message || error).slice(0, 1600);
const isInside = (base, file) => {
  const relative = path.relative(base, file);
  return relative !== '' && relative !== '..' && !relative.startsWith('..' + path.sep) && !path.isAbsolute(relative);
};
const readJson = (file) => JSON.parse(fs.readFileSync(file, 'utf8'));

function writeJson(file, value) {
  const temp = file + '.tmp';
  fs.writeFileSync(temp, JSON.stringify(value, null, 2) + '\n', 'utf8');
  fs.renameSync(temp, file);
}

/** Parse only flat key: value frontmatter enclosed in `---`; do not interpret values as YAML. */
const FRONTMATTER = /^(?:\uFEFF)?---\r?\n([\s\S]*?)\r?\n---(?:\r?\n|$)/;

function unquote(value) {
  const text = value.trim();
  if (text.startsWith('"') && text.endsWith('"') && text.length > 1) {
    try { return JSON.parse(text); } catch { return text.slice(1, -1); }
  }
  if (text.startsWith("'") && text.endsWith("'") && text.length > 1) return text.slice(1, -1);
  return text;
}

function parseFrontmatter(markdown) {
  const match = FRONTMATTER.exec(markdown);
  if (!match) return { fields: {}, body: markdown };
  const fields = {};
  for (const line of match[1].split(/\r?\n/)) {
    const split = line.indexOf(':');
    if (split <= 0) continue;
    const key = line.slice(0, split).trim();
    if (!/^[a-z][a-z0-9-]*$/.test(key)) continue;
    fields[key] = unquote(line.slice(split + 1));
  }
  return { fields, body: markdown.slice(match[0].length) };
}

export function createKnowledgeLibrary(ctx, options = {}) {
  const home = path.resolve(options.home || process.env.DSH_HOME?.trim() || path.join(os.homedir(), '.dsh'));
  const root = path.join(home, 'fujiang-skills');
  const stateFile = path.join(root, 'knowledge-state.json');
  const corpus = path.resolve(options.corpus || DEFAULT_CORPUS);

  // Enabled by default: bundled local files need no network or downloads and are immediately readable by the model.
  let state = { enabled: true };
  let active = false;
  let phase = 'disabled';
  let error = null;
  let busy = false;
  let closed = false;
  let providerDispose = null;
  let runtimeCtx = null;
  let restored = false;
  let cache = null;

  function assertOwned(dir) {
    if (!isInside(home, dir)) throw new Error('The skill directory is outside the area managed by this plugin.');
    if (fs.lstatSync(dir).isSymbolicLink()) throw new Error('The skill directory is a link. Operation stopped to protect other installations.');
    if (readJson(path.join(dir, MARKER)).owner !== OWNER) throw new Error('This directory does not belong to the plugin. Operation stopped.');
  }
  function ensureRoot() {
    fs.mkdirSync(home, { recursive: true });
    if (fs.existsSync(root)) assertOwned(root);
    else {
      fs.mkdirSync(root);
      writeJson(path.join(root, MARKER), { owner: OWNER });
    }
  }
  function save() { ensureRoot(); writeJson(stateFile, { schema: 1, enabled: state.enabled === true }); }

  /** Read a category: SKILL.md frontmatter defines its skill name and description; its unmodified body becomes content. */
  function readCategory(spec) {
    const dir = path.join(corpus, spec.dir);
    if (!isInside(corpus, dir)) throw new Error('Category directory is out of bounds: ' + spec.dir);
    const file = path.join(dir, 'SKILL.md');
    const markdown = fs.readFileSync(file, 'utf8');
    const { fields, body } = parseFrontmatter(markdown);
    const name = fields.name || spec.fallback;
    if (!/^[a-z0-9][a-z0-9-]{0,63}$/.test(name)) throw new Error('Invalid knowledge base skill name: ' + name);
    const entries = fs.readdirSync(dir)
      .filter((item) => item.endsWith('.md') && item.toLowerCase() !== 'skill.md')
      .sort();
    return {
      dir, file, name,
      description: String(fields.description || name).replace(/\s+/g, ' ').trim().slice(0, 1200),
      body,
      entries,
    };
  }

  function categories() {
    if (cache) return cache;
    const list = [];
    for (const spec of CATEGORIES) {
      try { list.push(readCategory(spec)); }
      catch (cause) {
        if (fs.existsSync(path.join(corpus, spec.dir))) error = messageOf(cause);
      }
    }
    cache = list;
    return cache;
  }

  const entryCount = () => categories().reduce((total, item) => total + item.entries.length, 0);

  /** Settings category catalog: category titles + per-item title/severity/entry (read only from frontmatter). */
  const catalog = () => categories().map((item) => {
    let title = item.name;
    try {
      const match = /^#\s+(.+)$/m.exec(fs.readFileSync(item.file, 'utf8'));
      if (match) title = match[1].trim();
    } catch { /* Fall back to the skill name if unreadable. */ }
    const entries = item.entries.map((file) => {
      try {
        const { fields } = parseFrontmatter(fs.readFileSync(path.join(item.dir, file), 'utf8'));
        return { file, title: fields.title || file, severity: fields.severity || '-', entry: fields.entry || '' };
      } catch { return { file, title: file, severity: '-', entry: '' }; }
    });
    return { name: item.name, title, count: entries.length, entries };
  });

  const snapshot = () => {
    let skillCount = 0;
    let entries = 0;
    try { skillCount = categories().length; entries = entryCount(); }
    catch (cause) { error = messageOf(cause); }
    return {
      ok: true,
      skills: [{
        ...CATALOG,
        installed: true,
        enabled: active,
        busy,
        phase,
        version: VERSION,
        skillCount,
        registered: active,
        entries,
        tools: 0,
        canCancel: false,
        progress: null,
        message: error || (skillCount ? null : 'Knowledge base content is missing. Reinstall the plugin.'),
      }],
    };
  };

  function deactivate() {
    active = false;
    if (providerDispose) { const dispose = providerDispose; providerDispose = null; dispose(); }
    phase = state.enabled ? 'disabled' : 'disabled';
  }

  /** Register a read-only provider: list() supplies the catalog; get() reads bodies fresh, making content edits visible immediately. */
  function activate() {
    if (active) return;
    if (closed) throw new Error('The plugin has stopped. Restart DSH.');
    if (!runtimeCtx) throw new Error('This DSH instance has not provided the skill service yet. Fully restart the official Desktop app and retry.');
    cache = null;                       // Each toggle rereads categories and descriptions.
    const list = categories();
    if (!list.length) throw new Error('Knowledge base content is missing. Reinstall the plugin.');
    providerDispose = runtimeCtx.skills.registerProvider(() => ({
      name: PROVIDER,
      async list() {
        return list.map((item) => ({
          name: item.name,
          description: item.description,
          invocation: { modelInvocable: true, userInvocable: true },
          source: 'custom',
          provider: PROVIDER,
          path: item.file,
          resourceBase: { kind: 'directory', path: item.dir },
          rank: 700,
          locator: item,
          metadata: { knowledge: true, entries: item.entries.length, version: VERSION },
        }));
      },
      async get(candidate) {
        const item = candidate?.locator || list.find((entry) => entry.name === candidate?.name);
        if (!item) throw new Error('This knowledge base entry is no longer valid. Toggle the knowledge base off and on again.');
        const markdown = fs.readFileSync(item.file, 'utf8');
        const { body } = parseFrontmatter(markdown);
        // Read the entry list **fresh every time**: newly added md files appear on the next call without toggling.
        let entries = item.entries;
        try {
          entries = fs.readdirSync(item.dir)
            .filter((file) => file.endsWith('.md') && file.toLowerCase() !== 'skill.md')
            .sort();
        } catch { /* If the directory disappears, fall back to the list from registration. */ }
        const index = entries.map((file) => '- `' + file + '`').join('\n');
        const content = [body.trim(), '', '---', '',
          'Content directory: `' + item.dir + '`',
          '',
          'Individual entry details (fingerprints / prerequisites / PoC / exploitation steps / remediation) are in the same directory; read them directly with the read tool:',
          '',
          index || '(No entries in this category yet)',
        ].join('\n');
        return {
          name: item.name,
          description: item.description,
          invocation: { modelInvocable: true, userInvocable: true },
          source: 'custom',
          provider: PROVIDER,
          path: item.file,
          resourceBase: { kind: 'directory', path: item.dir },
          content,
        };
      },
    }));
    active = true;
    phase = 'ready';
    error = null;
  }

  function start(action, task) {
    if (closed) return { status: 503, body: { ...snapshot(), ok: false, message: 'The plugin has stopped. Please restart.' } };
    if (busy) return { status: 409, body: { ...snapshot(), ok: false, message: 'Processing. Wait for the current operation to finish.' } };
    busy = true; error = null;
    phase = { enable: 'enabling', disable: 'disabling' }[action] || phase;
    Promise.resolve().then(task).catch((cause) => {
      error = messageOf(cause);
      phase = 'error';
      try { ctx.logger?.warn?.('Knowledge base: ' + error); } catch { /* optional logger */ }
    }).finally(() => {
      busy = false;
      if (phase !== 'error') phase = active ? 'ready' : 'disabled';
    });
    return { status: 202, body: snapshot() };
  }

  function action(body) {
    if (!body || Array.isArray(body) || body.id !== CATALOG.id
      || !['enable', 'disable'].includes(body.action)
      || Object.keys(body).some((key) => !['id', 'action'].includes(key))) {
      return { status: 400, body: { ok: false, message: 'Unsupported knowledge base operation.' } };
    }
    return start(body.action, async () => {
      if (body.action === 'enable') {
        state.enabled = true; save(); activate();
      } else {
        state.enabled = false; save(); deactivate();
      }
    });
  }

  ctx.inject(['skills'], (scope) => {
    runtimeCtx = scope;
    scope.effect(() => async () => { runtimeCtx = null; deactivate(); }, 'fujiang-knowledge: runtime cleanup');
    if (restored && state.enabled && !active && !busy && !closed) start('enable', async () => { activate(); });
  });

  const restore = async () => {
    try {
      if (fs.existsSync(stateFile)) {
        const saved = readJson(stateFile);
        state = { enabled: saved?.enabled !== false };
      }
      if (!categories().length) { error = 'Knowledge base content is missing. Reinstall the plugin.'; phase = 'error'; return; }
      phase = 'disabled';
      if (state.enabled && runtimeCtx) start('enable', async () => { activate(); });
    } catch (cause) {
      error = messageOf(cause);
      phase = 'error';
    } finally {
      restored = true;
    }
  };
  const ready = new Promise((resolve) => setImmediate(() => resolve(restore())));

  ctx.effect(() => async () => {
    closed = true;
    deactivate();
  }, 'fujiang-knowledge: manager cleanup');

  const listForTest = async () => categories();
  return { listForTest, snapshot, action, catalog, ready, settled: async () => { await ready; }, resetCache: () => { cache = null; } };
}
