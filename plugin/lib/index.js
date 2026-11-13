// dsh-prompt-custom (standalone port) — host side
//
// ── 0.3.0 fix: injection scope (the cause of previous silent failures) ──
// The kernel SystemPrompt section registry is layered (@deepseek-ai/dsh-scope ScopedLayers):
// one global layer plus a scoped layer per agent. During assembly, merge() lays out the global layer,
// then Map.set overrides same-name sections from distant to near scopes (dsh-scope/lib/index.js:177-181). Duplicate checks apply within a layer only.
//
// Correctly replacing the official persona means registering the same section name in a nearer scope.
//   ✗ Registering on the plugin's root ctx: SystemPrompt's constructor already occupies that layer, so it throws.
//       prompt section "deployment:persona-prefix" is already registered
//       (for a per-agent override, register through that agent's `agent.ctx` instead)
//     Older versions caught this exception in the logger and returned only applied:null over HTTP:
//     the switch appeared on and saving appeared successful, but no prompt was injected.
//   ✓ Registering on agent.ctx: the agent layer shadows the global persona, so replacement takes effect.
//
// This version follows the official host-plugin example (dsh-file-reference-local/lib/index.js:339-372):
//   agent.ctx.inject(['systemPrompt'], scope => scope.systemPrompt.section(...))
//   + ctx.get('agents').list() covers existing agents; agent/created adds new ones; agent/disposed cleans up.
// Use agent.ctx.inject(...), not agent.ctx.systemPrompt: createScope() produces a scoped fiber without inject,
// so services cannot be read directly; derive a child fiber with inject, as in the official example.
//
// Section text is a function, reevaluated at every assembly step (dsh-system-prompt/lib/index.js:342).
// Editing text therefore needs no registration refresh and takes effect next step; only enablement or
// append↔replace changes require registration again (section names differ: dsh:custom-prompt vs deployment:persona-prefix).
//
// ── 0.3.0 additional fix: make silent failures visible ──
// /config now returns armed / injected / lastError, so settings show the actual state,
// not an unconditional Saved message. Injection errors propagate the original kernel error to the UI.
//
// ── 0.4.0 addition: prompt cards (multiple saved prompts and one-click switching) ──
// Configuration adds a cards array, each item { id, name, text }, intentionally in the same file
// as enabled/mode/text. GET reads, non-destructive merges, unknown-key warnings, and protocol mismatch
// protection share one path, without a second persistence location. Card text becomes live.text only when used;
// before that it participates in neither injection nor variable scanning. Once activated, existing warnings cover it.
//
// Protocol 2→3: with a new UI and old host (page refreshed without restarting), the old normalize
// silently drops POST cards—the exact failure to avoid: the UI says Saved while data disappears.
// Protocol 3 lets the new UI detect the mismatch, disable cards, and explain why.
// Protocol 3→4 adds an enablement-only composer toggle route, without exposing prompt text to that control.
//
// Another fix: accept POST cards only when it is an array. A non-array from a client bug or manual request
// must not clear existing cards; strip the field and preserve the current data, following non-destructive persistence.
//
// Configuration: $DSH_HOME/prompt-custom.json; reads and writes use the plugin's webServer routes.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { createSkillLibrary } from './skills.js';
import { createAboutSecuritySkillLibrary } from './aboutsecurity.js';
import { createKnowledgeLibrary } from './knowledge.js';
import { createContext7Bridge, TOOL_USE_POLICY } from './tool-integrations.js';
import { createFindingsStore } from './findings.js';
import { createKbIndex, createCampaignStore, createSkillIndex, registerAutomationTools } from './automation.js';
import { fileURLToPath } from 'node:url';
import { createAssessmentService } from './assessment.js';
import { assessmentHarnessTools, invokeAssessmentTool } from './assessment-tools.js';

export const name = 'dsh-prompt-custom';
export const inject = ['systemPrompt', 'webServer'];

const SECTION_CUSTOM = 'dsh:custom-prompt';
// The official fixed greeting is separate from the deployment persona and must be overridden by its own section name.
const SECTION_HARNESS_IDENTITY = 'harness:identity';
// Replacement requires the kernel's exact section name; another name merely appends (dsh-system-prompt/lib/index.js:49-57).
const SECTION_PERSONA_PREFIX = 'deployment:persona-prefix';
const SECTION_PERSONA_SUFFIX = 'deployment:persona-suffix';
// Kernel SECTION_ORDERS fallback, used only when getSectionOrder is unavailable.
const ORDER_PERSONA_PREFIX = 0;
const ORDER_PERSONA_SUFFIX = 10200;
const ORDER_HARNESS_IDENTITY = -1000;
const CONFIG_ROUTE = '/api/dsh-prompt-custom/config';
const PREVIEW_ROUTE = '/api/dsh-prompt-custom/preview';
const TOGGLE_ROUTE = '/api/dsh-prompt-custom/toggle';
const KNOWLEDGE_ROUTE = '/api/dsh-prompt-custom/knowledge';
const FINDINGS_ROUTE = '/api/dsh-prompt-custom/findings';
const FINDINGS_MD_ROUTE = '/api/dsh-prompt-custom/findings.md';
const MATCH_ROUTE = '/api/dsh-prompt-custom/match';
const CAMPAIGNS_ROUTE = '/api/dsh-prompt-custom/campaigns';
// HTTP protocol version checked by the client: host code changes only after restarting Node,
// while a page refresh loads the new client bundle. The UI must clearly explain this mismatch.
// 2→3 (0.4.0): config added cards; 3→4 adds the prompt-free toggle route.
const API_PROTO = 11;
const PLUGIN_VERSION = '0.20.12';

function configPath() {
  const home = process.env.DSH_HOME && String(process.env.DSH_HOME).trim()
    ? String(process.env.DSH_HOME).trim()
    : path.join(os.homedir(), '.dsh');
  return path.join(home, 'prompt-custom.json');
}

function readFileConfig() {
  try {
    const parsed = JSON.parse(fs.readFileSync(configPath(), 'utf8'));
    // Must be a plain non-array object. Arrays also satisfy typeof === 'object'; without exclusion,
    // they would spread as {"0":..,"1":..}:
    //   · normalize() would create spurious 0/1 fields
    //   · detectUnknownConfigKeys() would falsely report "0"/"1" as unknown configuration keys
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null;
  } catch { return null; }
}

/**
 * Write configuration: overwrite only fields owned by this plugin; preserve other on-disk keys (non-destructive persistence).
 *
 * Another plugin version may have written this file, for example adding a prefix field.
 * If an older version rewrites the entire file with only its three fields, newer settings are irreversibly lost.
 * This is the same class of failure as the earlier silent failure: data disappears without any UI explanation.
 * unknownConfigKeys reports unfamiliar keys to the UI, but saving itself must never remove them.
 */
function writeFileConfig(cfg) {
  const file = configPath();
  fs.mkdirSync(path.dirname(file), { recursive: true });
  let base = {};
  try {
    const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (raw && typeof raw === 'object' && !Array.isArray(raw)) base = raw;
  } catch { /* Missing or corrupt file: start with an empty object */ }
  const out = { ...base, ...cfg };
  fs.writeFileSync(file, JSON.stringify(out, null, 2) + '\n', 'utf8');
  return file;
}

// Prompt-card limits and field specifications (client CARDS_MAX and CARD_ID must match).
const MAX_CARDS = 50;
const CARD_NAME_MAX = 60;
const CARD_ID = /^[A-Za-z0-9_-]{1,64}$/;

/** Same shape as client newCardId(); host fallback adds an ID when a manually edited file omits one. */
function makeCardId() {
  return 'c' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

/**
 * Sanitize cards. Non-arrays always become [] (not null).
 * Callers must first check whether the body contains cards; strip the field if it is a non-array
 * so merging preserves existing data. A non-array reaching this function can only mean no cards on disk (cold start),
 * where [] correctly means no cards yet.
 *
 * Per-card sanitization: discard non-objects or items with empty name and text; truncate names; replace missing/invalid IDs.
 * MAX_CARDS truncates excess cards (the client applies the same limit, so normal interaction cannot exceed it).
 * Oversized hand-edited files display truncated cards on GET and persist the truncated array on save; this is explicit here.
 */
function sanitizeCards(input) {
  if (!Array.isArray(input)) return [];
  const out = [];
  for (const raw of input) {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) continue;
    const text = typeof raw.text === 'string' ? raw.text : '';
    let name = typeof raw.name === 'string' ? raw.name.trim() : '';
    if (name.length > CARD_NAME_MAX) name = name.slice(0, CARD_NAME_MAX);
    if (!name && !text) continue;
    const id = typeof raw.id === 'string' && CARD_ID.test(raw.id) ? raw.id : makeCardId();
    out.push({ id, name: name || 'Untitled card', text });
    if (out.length >= MAX_CARDS) break;
  }
  return out;
}

function normalize(input) {
  const src = input && typeof input === 'object' ? input : {};
  return {
    enabled: src.enabled === true,
    mode: src.mode === 'replace' ? 'replace' : 'append',
    text: typeof src.text === 'string' ? src.text : '',
    cards: sanitizeCards(src.cards)
  };
}

function isLoopback(req) {
  const ra = (req.socket && req.socket.remoteAddress) || '';
  return ra === '127.0.0.1' || ra === '::1' || ra === '::ffff:127.0.0.1';
}

function sendJson(res, status, body) {
  const data = Buffer.from(JSON.stringify(body), 'utf8');
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'content-length': String(data.length)
  });
  res.end(data);
}

function readBody(req, limit = 256 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) { reject(new Error('payload too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}); }
      catch { reject(new Error('invalid JSON body')); }
    });
    req.on('error', reject);
  });
}

// Kernel variable syntax (dsh-system-prompt/lib/index.js:58-61).
const VAR_GROUP = /^\{\{([^{}]*)\}\}/;
const VAR_NAME = /^[a-z][a-z0-9_]*$/;

/** Create a new variable-scan result. */
function newSink() { return { missing: new Set(), malformed: new Set() }; }

/**
 * Scan without replacing: find references the kernel would consider unknown or malformed variables.
 * Kernel renderPrompt throws on unknown variables, failing the entire round.
 * A typo such as {{modell}} would therefore break every model step without an explanation on the page.
 * Expose the problem as a visible settings warning.
 */
function scanVariables(text, known, sink) {
  if (typeof text !== 'string' || !text.includes('{{')) return;
  let last = 0;
  for (let open = text.indexOf('{{'); open >= 0; open = text.indexOf('{{', last)) {
    const group = VAR_GROUP.exec(text.slice(open));
    if (group === null) { last = open + 2; continue; }
    const name = group[0].slice(2, -2);
    if (!VAR_NAME.test(name)) sink.malformed.add(name);
    else if (!known.has(name)) sink.missing.add(name);
    last = open + group[0].length;
  }
}

/**
 * Preview interpolation replaces known variables with actual values and preserves unknown/malformed ones unchanged,
 * unlike strict kernel assembly. Record scan results in sink for the UI.
 */
function interpolateText(text, variables, sink) {
  if (typeof text !== 'string') return '';
  if (!text.includes('{{')) return text;
  let out = '';
  let last = 0;
  for (let open = text.indexOf('{{'); open >= 0; open = text.indexOf('{{', last)) {
    const group = VAR_GROUP.exec(text.slice(open));
    if (group === null) { out += text.slice(last, open + 2); last = open + 2; continue; }
    const name = group[0].slice(2, -2);
    const known = VAR_NAME.test(name);
    const value = known && Object.hasOwn(variables, name) ? variables[name] : undefined;
    if (known && value !== undefined) {
      out += text.slice(last, open) + String(value);
    } else {
      if (known) sink.missing.add(name); else sink.malformed.add(name);
      out += text.slice(last, open + group[0].length);
    }
    last = open + group[0].length;
  }
  return out + text.slice(last);
}

/** Render assembled output as preview text, including variable substitution. */
function renderSections(assembly, sink) {
  const secs = (assembly && assembly.sections) || [];
  const vars = (assembly && assembly.variables) || {};
  return secs
    .filter(Boolean)
    .map((s) => {
      const raw = typeof s.text === 'string' ? s.text : String((s && s.text) || '');
      return s.interpolate === false ? raw : interpolateText(raw, vars, sink);
    })
    .filter((t) => t && t.trim())
    .join('\n\n');
}

/** Return section names only. assemble() sections contain { name, text, interpolate? }, without order
 * (dsh-system-prompt/lib/index.js:339-344). order requires getSectionOrder('CONSTANT_NAME'),
 * whereas s.name is a section name (such as "deployment:persona-prefix"), not a constant name.
 * Do not return order: the older order: undefined field was permanently meaningless. */
function sectionNames(assembly) {
  return ((assembly && assembly.sections) || [])
    .filter(Boolean)
    .map((s) => ({ name: s.name }));
}

/**
 * Configuration fields recognized by this version. Other keys indicate a file written by another version.
 *
 * Explicit detection is required as the schema evolves (for example, splitting text into prefix/suffix):
 * code unable to understand an older text field could silently discard the user's active prompt.
 * This plugin already suffered a silent failure (see the opening comments); do not repeat the same class of mistake.
 */
const KNOWN_CONFIG_KEYS = new Set(['enabled', 'mode', 'text', 'cards']);

export function apply(ctx, config) {
  const context7 = createContext7Bridge(ctx);
  const reaSkillLibrary = createSkillLibrary(ctx);
  const aboutSecurityLibrary = createAboutSecuritySkillLibrary(ctx);
  // Knowledge base: bundled corpus (plugin/knowledge/), no download or network access; enabled by default.
  const knowledgeLibrary = createKnowledgeLibrary(ctx);
  // Vulnerability report: stored at DSH_HOME/vuln-report/findings.json; AI writes through loopback HTTP.
  const findings = createFindingsStore(ctx);
  // Automation: local matching index (knowledge/ frontmatter) and task ledger.
  const corpusDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'knowledge');
  const kbIndex = createKbIndex(corpusDir);
  const knowledgeEnabled = () => knowledgeLibrary.snapshot().skills[0]?.enabled === true;
  const assessment = createAssessmentService({ corpusDir, knowledgeEnabled });
  ctx.effect(() => () => assessment.dispose(), 'dsh-prompt-custom: assessment cleanup');
  const availableKbIndex = {
    size: () => knowledgeEnabled() ? kbIndex.size() : 0,
    match: (...args) => knowledgeEnabled() ? kbIndex.match(...args) : [],
  };
  const campaigns = createCampaignStore(ctx);
  const aboutSecurityEnabled = () => aboutSecurityLibrary.snapshot().skills[0]?.enabled === true;
  const skillIndex = createSkillIndex({ knowledgeDir: corpusDir, knowledgeEnabled, aboutSecurityEnabled });
  const skillLibrary = {
    ready: Promise.all([reaSkillLibrary.ready, aboutSecurityLibrary.ready, knowledgeLibrary.ready]),
    snapshot: () => ({ ok: true, skills: [
      ...knowledgeLibrary.snapshot().skills,
      ...reaSkillLibrary.snapshot().skills,
      ...aboutSecurityLibrary.snapshot().skills,
    ] }),
    action: body => {
      const id = body?.id;
      if (id === 'knowledge') return knowledgeLibrary.action(body);
      if (id === 'aboutsecurity') return aboutSecurityLibrary.action(body);
      return reaSkillLibrary.action(body);
    },
  };
  const log = (msg) => { try { ctx.logger?.info?.(msg); } catch { console.log(msg); } };
  const warn = (msg) => { try { ctx.logger?.warn?.(msg); } catch { console.warn(msg); } };

  let live = normalize({ ...(config || {}), ...(readFileConfig() || {}) });
  let lastError = null;                 // Original text of the latest kernel injection error; null = no error
  const entries = new Map();            // agent -> { shape: 'off'|'append'|'replace', fiber }
  let lastAgent = null;                 // Selects a scope for /preview

  /** Injection shape for the current configuration; 'off' means no custom sections should exist. */
  const desiredShape = () => {
    if (!live.enabled || !String(live.text || '').trim()) return 'off';
    return live.mode === 'replace' ? 'replace' : 'append';
  };

  /**
   * Section text is a function reevaluated on every kernel assembly (dsh-system-prompt/lib/index.js:342),
   * so text changes take effect next step without registering again.
   *
   * Do not check whether the shape/switch still matches here: failed checks would return an empty string,
   * which in replace mode would erase the entire official persona (worse than retaining old text for one step).
   * install registration refreshes ensure consistency between shape and switch (aligned on POST and GET).
   *
   * textShadow covers the transition when text is cleared: desiredShape becomes 'off',
   * but the registered replace section is removed in a later microtask. An intervening assembly
   * could erase the official persona with an empty string (empty-persona frames caught by E4/E6). Retain the last nonempty text
   * until the section is disposed and the official persona is restored, preventing an empty-persona window.
   * In steady state, textShadow is inert: empty text means no registered section and no call to currentText.
   */
  let textShadow = String(live.text || '');
  const currentText = () => {
    const text = String(live.text || '');
    if (text.trim()) textShadow = text;
    return textShadow;
  };

  const orderOf = (sp, key, fallback) => {
    try {
      const v = typeof sp.getSectionOrder === 'function' ? sp.getSectionOrder(key) : undefined;
      return Number.isFinite(v) ? v : fallback;
    } catch { return fallback; }
  };

  // Serialize install/uninstall: agent/created (serial and awaited by the kernel) can race settings saves.
  // Interleaving could leave partial registration or register twice for one agent, triggering duplicate-name protection.
  //
  // This queue never rejects. It is attached to the agent/created listener; kernel serial dispatch
  // would propagate a listener rejection and prevent session creation. The plugin must never cause that.
  // Downgrade every failure to lastError for display in settings.
  let queue = Promise.resolve();
  const serialize = (fn) => {
    const next = queue.then(fn, fn).catch((error) => {
      lastError = String((error && error.message) || error);
      warn('[dsh-prompt-custom] Installation queue error (handled): ' + lastError);
    });
    queue = next;
    return next;
  };

  const disposeEntry = async (agent) => {
    const entry = entries.get(agent);
    if (!entry) return;
    entries.delete(agent);
    if (lastAgent === agent) lastAgent = null;
    if (!entry.fiber) return;
    try { await entry.fiber.dispose(); } catch { /* Agent scope is usually already disposed */ }
  };

  /**
   * Install or remove custom sections in one agent's scope.
   * Callers serialize access (install / reinstallAll already hold the lock).
   */
  const installInner = async (agent) => {
    if (!agent || !agent.ctx || typeof agent.ctx.inject !== 'function') return;
    const shape = desiredShape();
    const entry = entries.get(agent);
    if (entry && entry.shape === shape) return;      // Same shape: the text function picks up changes itself
    if (entry) await disposeEntry(agent);
    if (shape === 'off') { entries.set(agent, { shape: 'off', fiber: null }); return; }

    let fiber = null;
    try {
      fiber = agent.ctx.inject(['systemPrompt'], (scope) => {
        try {
          const sp = scope.systemPrompt;
          // Remove the official fixed greeting only in the agent layer where the custom prompt is active.
          // Do not modify user text. Disabling/clearing disposes this fiber and restores official defaults.
          sp.section({
            name: SECTION_HARNESS_IDENTITY,
            order: orderOf(sp, 'HARNESS_IDENTITY', ORDER_HARNESS_IDENTITY),
            text: ''
          });
          if (shape === 'replace') {
            // Replacement requires the same name; suffix must explicitly have an empty section or the global suffix remains active
            // because merge only overrides names present in the layer.
            sp.section({
              name: SECTION_PERSONA_PREFIX,
              order: orderOf(sp, 'DEPLOYMENT_PERSONA_PREFIX', ORDER_PERSONA_PREFIX),
              text: currentText
            });
            sp.section({
              name: SECTION_PERSONA_SUFFIX,
              order: orderOf(sp, 'DEPLOYMENT_PERSONA_SUFFIX', ORDER_PERSONA_SUFFIX),
              text: ''
            });
          } else {
            sp.section({
              name: SECTION_CUSTOM,
              order: orderOf(sp, 'DEPLOYMENT_PERSONA_SUFFIX', ORDER_PERSONA_SUFFIX) + 1,
              text: currentText
            });
          }
          sp.section({
            name: 'fujiang:tool-use',
            order: orderOf(sp, 'DEPLOYMENT_PERSONA_SUFFIX', ORDER_PERSONA_SUFFIX) + 2,
            text: TOOL_USE_POLICY
          });
          lastError = null;
        } catch (error) {
          lastError = String((error && error.message) || error);
          warn('[dsh-prompt-custom] Injection failed (agent ' + (agent.id || '?') + '): ' + lastError);
        }
      });
      await fiber;                                   // Wait for loading before reporting accurate status
      entries.set(agent, { shape, fiber });
      lastAgent = agent;
      log('[dsh-prompt-custom] Injected into agent ' + (agent.id || '?') + ': mode=' + shape);
    } catch (error) {
      lastError = String((error && error.message) || error);
      warn('[dsh-prompt-custom] Agent-scope registration failed: ' + lastError);
      try { await fiber?.dispose?.(); } catch { /* ignore */ }
      entries.set(agent, { shape: 'off', fiber: null });
    }
  };

  const install = (agent) => serialize(() => installInner(agent));

  /** Refresh all known agents' injection shapes to match the updated configuration. */
  const reinstallAll = () => serialize(async () => {
    for (const agent of [...entries.keys()]) await installInner(agent);
  });

  /** Live-session list (read-only; no injection or wakeups). */
  const liveAgents = () => {
    try {
      const agents = typeof ctx.get === 'function' ? ctx.get('agents') : undefined;
      return agents && typeof agents.list === 'function' ? (agents.list() || []) : [];
    } catch { return []; }
  };

  // ---- Automatic continuation: advance until objectives are met, done, or the round limit ----
  const autopilotTimers = new Map();

  const autopilotMessage = (campaign, next) => [
    'Continue task "' + (campaign.objective || campaign.name) + '" (' + campaign.id + ').',
    '- Current stage: ' + next.stage + ' | Progress: ' + next.progress + '% | Round ' + next.rounds + '/' + next.maxRounds,
    '- Completion criteria: ' + next.doneCriteria.join('; '),
    next.stalled ? '- Repeated lack of progress: change entry point/candidate; do not repeat the same payload.' : '',
    '- Required this round: ' + (next.nextActions.length ? next.nextActions.map((a) => a.text).join('; ') : next.instructions.join('; ')),
    '- Immediately record successful checks with finding_upsert and progress with campaign_upsert(advance=true); record unsuccessful attempts and exclusion reasons too.',
    '- Call campaign_upsert(done=true) when completion criteria are met; do not continue idling.'
  ].filter(Boolean).join('\n');

  const autopilotTick = (id) => {
    let campaign;
    try { campaign = campaigns.get(id); } catch (error) { return { ticked: false, reason: String((error && error.message) || error) }; }
    if (campaign.done === true) return { ticked: false, reason: 'done' };
    if (campaign.autopilot === false) return { ticked: false, reason: 'autopilot-off' };
    if ((campaign.rounds || 0) >= (campaign.maxRounds || 8)) return { ticked: false, reason: 'max-rounds' };
    const agent = liveAgents().find((a) => a.id === campaign.sessionId);
    if (!agent) return { ticked: false, reason: 'no-agent' };
    const next = campaigns.nextStep(campaign.id, availableKbIndex);
    const moved = campaigns.patch(campaign.id, { rounds: (campaign.rounds || 0) + 1, lastProgress: next.progress });
    const msg = autopilotMessage(moved, next);
    const llm = llmModule;
    const createUserMessage = llm && llm.createUserMessage;
    const message = typeof createUserMessage === 'function'
      ? createUserMessage({ content: [{ type: 'text', text: msg }], source: { kind: 'user' } })
      : { role: 'user', content: [{ type: 'text', text: msg }], source: { kind: 'user' }, id: 'ap' + Date.now().toString(36) };
    try {
      Promise.resolve(agent.followup(message)).catch(() => {});
      return { ticked: true, round: moved.rounds, progress: next.progress };
    } catch (error) {
      return { ticked: false, reason: String((error && error.message) || error) };
    }
  };

  const scheduleAutopilot = (id, delay = 20000) => {
    if (autopilotTimers.has(id)) return;
    const timer = setTimeout(() => {
      autopilotTimers.delete(id);
      const result = autopilotTick(id);
      if (result.ticked) scheduleAutopilot(id, delay);
    }, delay);
    if (timer.unref) timer.unref();
    autopilotTimers.set(id, timer);
  };

  const stopAutopilot = (id) => {
    const timer = autopilotTimers.get(id);
    if (timer) { clearTimeout(timer); autopilotTimers.delete(id); }
  };

  // ---- Automatic start: construct real user messages with the kernel factory, not bare objects ----
  let llmModule;
  const loadLlm = async () => {
    if (llmModule !== undefined) return llmModule;
    try {
      const loader = typeof ctx.get === 'function' ? ctx.get('loader') : undefined;
      llmModule = loader && typeof loader.import === 'function'
        ? await loader.import('@deepseek-ai/dsh-llm')
        : await import('@deepseek-ai/dsh-llm');
    } catch { llmModule = null; }
    return llmModule;
  };

  const kickText = (campaign) => 'Start task "' + campaign.name + '" (' + campaign.id + '). Read the ledger and current stage, provide a plan for this stage, then execute step by step. After each step, record the step and stage with campaign_upsert.';

  const kickAgent = async (agent, campaign) => {
    if (!agent || typeof agent.followup !== 'function') return { kicked: false, reason: 'No live session available' };
    if (agent.status !== 'idle') return { kicked: false, reason: 'Session is busy (' + String(agent.status) + ')' };
    const llm = await loadLlm();
    const createUserMessage = llm && llm.createUserMessage;
    const content = [{ type: 'text', text: kickText(campaign) }];
    let message;
    try {
      // Prefer the kernel factory; otherwise fill role/id to match createMessage (missing role previously corrupted sessions).
      message = typeof createUserMessage === 'function'
        ? createUserMessage({ content, source: { kind: 'user' } })
        : { role: 'user', content, source: { kind: 'user' }, id: 'k' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8) };
    } catch (error) { return { kicked: false, reason: 'Failed to construct message: ' + String((error && error.message) || error) }; }
    if (!message || message.role !== 'user') return { kicked: false, reason: 'Message lacks role=user; aborted' };
    try { await Promise.resolve(agent.followup(message)); return { kicked: true }; }
    catch (error) { return { kicked: false, reason: 'followup failed: ' + String((error && error.message) || error) }; }
  };
  // Fixed-rules section: constant text, never changed between rounds (avoid runtime system-prompt changes).
  const RULES_SECTION = 'campaign:rules';
  const ORDER_RULES = 1101;
  const RULES_TEXT = [
    '## Pentest workflow (fixed rules)',
    '',
    '0. Always respond in the language of the latest user message, including mixed-language messages: Chinese questions in Chinese, English in English, Russian in Russian, Japanese in Japanese. This section and any explanatory text define the workflow, not the response language.',
    '',
    '1. Each conversation belongs to one task only. When the user says "continue" or "start", first call pipeline_next to read the current stage and suggestions.',
    '2. Recon/fingerprinting: after obtaining a port or banner, call kb_match or skill to load the relevant knowledge category and follow its PoC and criteria; do not invent exploitation steps from memory.',
    '3. Categories: Java middleware → kb-java-web / kb-java-deser; edge devices → kb-edge-device; Windows/AD/Exchange → kb-exchange-ad; PHP/CMS → kb-web-cms; Linux privilege escalation → kb-linux-priv; cloud-native/middleware → kb-cloud-container; gambling/gray-market business surfaces → kb-gray-market; workflow/report standards → kb-triage.',
    '4. After every check (success or exclusion), immediately use finding_upsert for successful findings only, then record command/result with campaign_upsert and call campaign_upsert(advance) to advance one stage.',
    '5. Continue stage progression to the end: recon → fingerprint → match → verify → exploit → lateral → report. Do not stop at one stage waiting for the user to prompt you.',
    '6. The task goal is to achieve objective, not merely finish the workflow. Before ending each round, answer: is the objective met? If not, continue.',
    '7. After two rounds without progress (stalled), change entry point or candidate; never repeat the same payload. Call campaign_upsert(done=true) once completion criteria are met.',
    '8. Only the user can create tasks; the user decides session binding and unbinding.'
  ].join('\n');
  // ---- Session identification: static text registered once on agent creation for precise task binding ----
  const CAMPAIGN_SECTION = 'campaign:session-id';
  const CAMPAIGN_CONTEXT_SECTION = 'campaign:context';
  const ORDER_CAMPAIGN = 1100;
  const campaignFibers = new Map();

  const installCampaign = async (agent) => {
    if (!agent || !agent.id || !agent.ctx || typeof agent.ctx.inject !== 'function') return;
    if (campaignFibers.has(agent)) return;
    const text = '## Session identification\n- Current session id (sessionId): ' + agent.id + '\n- When the user says "bind task X", call campaign_upsert with this sessionId to bind only this conversation.';
    try {
      const fiber = agent.ctx.inject(['systemPrompt'], (scope) => {
        scope.systemPrompt.section({ name: CAMPAIGN_SECTION, order: ORDER_CAMPAIGN, text });
        if (agent.__withRules) scope.systemPrompt.section({ name: RULES_SECTION, order: ORDER_RULES, text: RULES_TEXT });
        scope.systemPrompt.section({
          name: CAMPAIGN_CONTEXT_SECTION,
          order: ORDER_RULES + 1,
          text: () => {
            const campaign = campaigns.forSession(agent.id);
            if (!campaign) return '';
            const next = campaigns.nextStep(campaign.id, availableKbIndex);
            return [
          'Objective: ' + (campaign.objective || campaign.name),
          'Progress: ' + next.progress + '%' + (next.stalled ? ' (stalled; change direction)' : ''),
          'Completion criteria: ' + next.doneCriteria.join('; '),
              '## Currently bound pentest task',
              '- Task: ' + campaign.name + ' (' + campaign.id + ')',
              '- Stage: ' + campaign.stage,
              '- Authorized domains: ' + campaign.scope.domains.join(', '),
              '- Authorized CIDRs: ' + campaign.scope.cidrs.join(', '),
              '- Exclusions: ' + campaign.scope.exclude.join(', '),
              '- Recorded assets: ' + campaign.assets.length,
              '- Next step: ' + next.instructions.join('; '),
              '- Work only on targets within the authorized scope above; use kb_match and skill_search/skill_read to verify candidates, record evidence with finding_upsert, and track progress with campaign_upsert.',
            ].join('\n');
          },
        });
      });
      await fiber;
      campaignFibers.set(agent, fiber);
    } catch (error) {
      warn('[dsh-prompt-custom] Session-identification injection failed: ' + ((error && error.message) || error));
    }
  };

  const disposeCampaign = (agent) => {
    const fiber = campaignFibers.get(agent);
    if (!fiber) return;
    campaignFibers.delete(agent);
    try { const pending = fiber.dispose?.(); if (pending && pending.catch) pending.catch(() => {}); } catch { /* ignore */ }
  };
  // ---- Lifecycle ----
  // Include existing agents (usually empty when applying the host plugin; useful for HMR / later enablement).
  try {
    const agents = typeof ctx.get === 'function' ? ctx.get('agents') : undefined;
    const list = agents && typeof agents.list === 'function' ? agents.list() : [];
      for (const agent of list || []) {
        agent.__withRules = true;
        install(agent); installCampaign(agent);
      }
  } catch (error) {
    warn('[dsh-prompt-custom] Failed to include existing agents (ignored): ' + ((error && error.message) || error));
  }

  // agent/created is serial and awaited: sections installed here participate in the agent's first assembly.
  // Listener errors prevent session creation (kernel semantics), so always catch them and record lastError.
  ctx.on('agent/created', async ({ agent } = {}) => {
    if (!agent) return;
    lastAgent = agent;
    if (!entries.has(agent)) entries.set(agent, { shape: 'off', fiber: null });
    agent.__withRules = true;
    await install(agent);
    await installCampaign(agent);
  });

  ctx.on('agent/disposed', ({ agent } = {}) => {
    if (!agent) return;
    disposeCampaign(agent);
    const entry = entries.get(agent);
    if (!entry) return;
    entries.delete(agent);
    if (lastAgent === agent) lastAgent = null;
    // Sections belong to the agent-scope fiber and are disposed with the agent; only remove records here.
    // Deliberately do not await dispose: the agent scope is already being torn down; a stalled dispose
    // would block the serial queue above and prevent installation for every subsequent agent.
    try {
      const p = entry.fiber?.dispose?.();
      if (p && typeof p.catch === 'function') p.catch(() => {});
    } catch { /* ignore */ }
  });

  const setConfig = async (next) => {
    live = normalize({ ...live, ...next });
    try { writeFileConfig(live); }
    catch (error) { warn('[dsh-prompt-custom] Persistence failed: ' + ((error && error.message) || error)); }
    await reinstallAll();
    return live;
  };

  /** Actual settings status: armed=config ready, injected=number of live injected agents, lastError=original kernel error. */
  const status = () => {
    let injected = 0;
    for (const entry of entries.values()) if (entry.shape !== 'off') injected++;
    return {
      // Protocol version: the client can update before the host if only the page is refreshed.
      // The page reloads index.html and obtains a new client bundle, while host Node plugin code
      // stays unchanged until restart. The client uses this field to detect mismatches and provide actionable guidance;
      // otherwise users would see an empty preview without knowing what happened.
      proto: API_PROTO,
      armed: desiredShape() !== 'off',
      agents: entries.size,
      injected,
      lastError,
      toolIntegrations: { context7: context7.snapshot(), rea: reaSkillLibrary.snapshot().skills[0] },
      // Keys not recognized by this version (schema-evolution protection; see opening comments)
      unknownConfigKeys: detectUnknownConfigKeys(),
      path: configPath()
    };
  };

  // Variable warnings must also be available on /config, not only /preview:
  // unknown variables make kernel renderPrompt throw, failing every model step.
  // Show this risk as soon as settings opens, not only after the user requests a preview.
  // Known variable names always come from actual assembled kernel variables, never a hardcoded list (avoids false warnings).
  let knownVarNames = null;
  const refreshKnownVars = async () => {
    try {
      const assembly = await ctx.systemPrompt.assemble({});
      knownVarNames = new Set(Object.keys((assembly && assembly.variables) || {}));
    } catch { /* Keep the previous set; an omitted warning is better than a false positive */ }
    return knownVarNames;
  };
  const variableWarnings = () => {
    const sink = newSink();
    if (knownVarNames) {
      // Scan every field carrying prompt text. If text is split into multiple fields later,
      // include all of them or unknown-variable warnings will miss some references and assembly will fail each step.
      // Cards from 0.4.0 are excluded: card text is not injected before activation,
      // then becomes live.text and is naturally covered by this scan.
      for (const key of ['text']) {
        try { scanVariables(String(live[key] || ''), knownVarNames, sink); } catch { /* ignore */ }
      }
    }
    return { unknownVariables: [...sink.missing], malformedVariables: [...sink.malformed] };
  };

  /**
   * Unknown configuration keys mean the file was written by another plugin version.
   * Not returning them would turn schema evolution into another silent failure.
   */
  const detectUnknownConfigKeys = () => {
    try {
      const raw = readFileConfig();
      return raw ? Object.keys(raw).filter((k) => !KNOWN_CONFIG_KEYS.has(k)) : [];
    } catch { return []; }
  };

  // ---- HTTP routes (loopback restricted) ----
  let automationTools = { ok: false, pending: true };
  ctx.inject(['webServer'], (webCtx) => {
    const route = (p, handler) => {
      webCtx.effect(
        () => webCtx.webServer.register({ kind: 'exact', path: p, handler }),
        'dsh-prompt-custom: route ' + p
      );
    };

    route('/api/dsh-prompt-custom/skills', async (req, res) => {
      if (!isLoopback(req)) { res.writeHead(403); res.end('forbidden'); return; }
      // Browsers must use the local UI; reject cross-site mutation requests.
      if (req.method === 'POST' && req.headers?.origin) {
        try {
          const origin = new URL(req.headers.origin);
          if (origin.host !== req.headers.host || !['http:', 'https:'].includes(origin.protocol)) {
            sendJson(res, 403, { ok: false, message: 'forbidden origin' }); return;
          }
        } catch { sendJson(res, 403, { ok: false, message: 'invalid origin' }); return; }
      }
      await skillLibrary.ready;
      if (req.method === 'GET' || req.method === 'HEAD') { sendJson(res, 200, skillLibrary.snapshot()); return; }
      if (req.method === 'POST') {
        try {
          const result = skillLibrary.action(await readBody(req, 1024));
          sendJson(res, result.status, result.body);
        } catch (error) { sendJson(res, 400, { ok: false, message: String(error?.message || error) }); }
        return;
      }
      res.writeHead(405, { allow: 'GET, HEAD, POST' }); res.end();
    });

    route(TOGGLE_ROUTE, async (req, res) => {
      if (!isLoopback(req)) { res.writeHead(403); res.end('forbidden'); return; }
      if (req.method === 'GET' || req.method === 'HEAD') {
        const fromDisk = readFileConfig();
        if (fromDisk) live = normalize({ ...live, ...fromDisk });
        await reinstallAll();
        sendJson(res, 200, { ok: true, enabled: live.enabled });
        return;
      }
      if (req.method === 'POST') {
        try {
          const body = await readBody(req, 1024);
          if (!body || typeof body !== 'object' || Array.isArray(body) || typeof body.enabled !== 'boolean') {
            sendJson(res, 400, { ok: false, message: 'enabled must be a boolean' });
            return;
          }
          const fromDisk = readFileConfig();
          if (fromDisk) live = normalize({ ...live, ...fromDisk });
          const saved = await setConfig({ enabled: body.enabled });
          sendJson(res, 200, { ok: true, enabled: saved.enabled });
        } catch (error) {
          sendJson(res, 400, { ok: false, message: String((error && error.message) || error) });
        }
        return;
      }
      res.writeHead(405, { allow: 'GET, HEAD, POST' });
      res.end();
    });

    // Live sessions: selects the conversation to bind a task to
    route("/api/dsh-prompt-custom/sessions", async (req, res) => {
      if (!isLoopback(req)) { res.writeHead(403); res.end("forbidden"); return; }
      if (req.method !== "GET" && req.method !== "HEAD") { res.writeHead(405, { allow: "GET, HEAD" }); res.end(); return; }
      try {
        const sessions = liveAgents().filter((agent) => agent && agent.id).map((agent) => {
          // Best-effort title: location varies by kernel version; if unavailable, let the frontend display an ID suffix.
          const probes = [agent.title, agent.session && agent.session.title, agent.session && agent.session.meta && agent.session.meta.title, agent.options && agent.options.title];
          const title = probes.find((x) => typeof x === 'string' && x.trim().length > 0) || '';
          return { id: agent.id, title, status: typeof agent.status === 'string' ? agent.status : '' };
        });
        sendJson(res, 200, { ok: true, proto: API_PROTO, sessions });
      } catch (error) {
        sendJson(res, 500, { ok: false, message: String((error && error.message) || error) });
      }
    });

    // Self-check: expose every link in the chain determining whether AI can see the knowledge base
    route("/api/dsh-prompt-custom/diagnostics", async (req, res) => {
      if (!isLoopback(req)) { res.writeHead(403); res.end("forbidden"); return; }
      if (req.method !== "GET" && req.method !== "HEAD") { res.writeHead(405, { allow: "GET, HEAD" }); res.end(); return; }
      const report = { ok: true, proto: API_PROTO, version: PLUGIN_VERSION };
      try {
        const catalog = knowledgeLibrary.catalog();
        const snap = knowledgeLibrary.snapshot();
        const provider = snap.skills && snap.skills[0] ? snap.skills[0] : {};
        let listed = null;
        try { listed = typeof knowledgeLibrary.listForTest === "function" ? (await knowledgeLibrary.listForTest()).length : null; } catch { listed = "error"; }
        report.knowledge = {
          corpusPath: knowledgeLibrary.corpusPath || corpusDir,
          entries: catalog.reduce((sum, item) => sum + item.count, 0),
          categories: catalog.length,
          enabled: provider.enabled === true,
          providerRegistered: provider.registered === true,
          providerEntries: listed,
          phase: provider.phase || null,
          message: provider.message || null,
        };
      } catch (error) {
        report.knowledge = { error: String((error && error.message) || error) };
      }
      try {
        report.skillsService = typeof (ctx.get && ctx.get("skills")) === "object" || typeof (ctx.get && ctx.get("skills")) === "function" ? "present" : "missing";
      } catch { report.skillsService = "unknown"; }
      // Skill libraries (AboutSecurity / REA): installation and registered-skill counts
      try {
        const libs = [];
        for (const lib of [reaSkillLibrary, aboutSecurityLibrary]) {
          if (!lib || typeof lib.snapshot !== "function") continue;
          const one = lib.snapshot();
          const item = one && one.skills && one.skills[0] ? one.skills[0] : null;
          if (!item) continue;
          libs.push({ id: item.id || null, installed: item.installed === true, enabled: item.enabled === true, phase: item.phase || null, skillCount: typeof item.skillCount === "number" ? item.skillCount : null, message: item.message || null });
        }
        report.skillLibraries = libs;
      } catch (error) { report.skillLibraries = [{ error: String((error && error.message) || error) }]; }
      try { report.agents = liveAgents().length; } catch { report.agents = 0; }
      try { report.campaigns = campaigns.list().items.length; } catch { report.campaigns = 0; }
      try { report.findings = findings.snapshot().items.length; } catch { report.findings = 0; }
      report.automationTools = automationTools;
      report.tail = { version: PLUGIN_VERSION, proto: API_PROTO, dsh: process.versions && process.versions.node ? "node " + process.versions.node : "node" };
      sendJson(res, 200, report);
    });

    // Called when the disclaimer is declined: reply first, then close all of Harness.
    route("/api/dsh-prompt-custom/shutdown", async (req, res) => {
      if (!isLoopback(req)) { res.writeHead(403); res.end("forbidden"); return; }
      if (req.method !== "POST") { res.writeHead(405, { allow: "POST" }); res.end(); return; }
      const origin = req.headers?.origin;
      if (origin) {
        try {
          const parsed = new URL(origin);
          if (parsed.host !== req.headers.host || !["http:", "https:"].includes(parsed.protocol)) {
            sendJson(res, 403, { ok: false, message: "forbidden origin" });
            return;
          }
        } catch { sendJson(res, 403, { ok: false, message: "invalid origin" }); return; }
      }
      sendJson(res, 200, { ok: true, message: "shutting down" });
      log("[dsh-prompt-custom] User declined the disclaimer; closing Harness");
      setTimeout(() => { try { process.exit(0); } catch { } }, 500);
    });
    // Fingerprint → knowledge-base candidates (local index, no network)
    route('/api/dsh-prompt-custom/assessment', async (req, res) => {
      if (!isLoopback(req)) { res.writeHead(403); res.end('forbidden'); return; }
      if (req.method !== 'POST') { res.writeHead(405, { allow: 'POST' }); res.end(); return; }
      try {
        const host = new URL('http://' + req.headers?.host);
        if (!['127.0.0.1', '[::1]', 'localhost'].includes(host.hostname)) throw new Error('Assessment API requires a loopback Host.');
        if (req.headers?.['sec-fetch-site'] === 'cross-site') throw new Error('Cross-site requests are forbidden.');
        if (req.headers?.origin && new URL(req.headers.origin).origin !== host.origin) throw new Error('Assessment API requires same-origin requests.');
      } catch (error) { sendJson(res, 403, { ok: false, message: error.message }); return; }
      try {
        const body = await readBody(req, 128 * 1024);
        const result = await invokeAssessmentTool(assessment, body?.tool, body?.arguments ?? {});
        sendJson(res, 200, { ok: true, proto: API_PROTO, result });
      } catch (error) { sendJson(res, 400, { ok: false, message: String(error.message || error) }); }
    });
    route(MATCH_ROUTE, async (req, res) => {
      if (!isLoopback(req)) { res.writeHead(403); res.end('forbidden'); return; }
      if (req.method !== 'POST') { res.writeHead(405, { allow: 'POST' }); res.end(); return; }
      try {
        const body = await readBody(req, 64 * 1024);
        sendJson(res, 200, { ok: true, proto: API_PROTO, enabled: knowledgeEnabled(), indexSize: availableKbIndex.size(), hits: availableKbIndex.match(body || {}, body && body.limit) });
      } catch (error) {
        sendJson(res, 400, { ok: false, message: String((error && error.message) || error) });
      }
    });

    // Task ledger: GET list / GET ?id= details / POST actions
    route(CAMPAIGNS_ROUTE, async (req, res) => {
      if (!isLoopback(req)) { res.writeHead(403); res.end('forbidden'); return; }
      if (req.method === 'GET' || req.method === 'HEAD') {
        try {
          const url = new URL(req.url || '/', 'http://127.0.0.1');
          const id = url.searchParams.get('id');
          const sid = url.searchParams.get('sessionId');
          if (sid && !id) {
            const bound = campaigns.forSession(sid);
            sendJson(res, 200, { ok: true, proto: API_PROTO, sessionId: sid, campaign: bound, ...campaigns.list() });
            return;
          }
          if (id) {
            const campaign = campaigns.get(id);
            sendJson(res, 200, { ok: true, proto: API_PROTO, campaign, next: campaigns.nextStep(id, availableKbIndex), stages: ['recon', 'fingerprint', 'match', 'verify', 'exploit', 'lateral', 'report'] });
            return;
          }
          sendJson(res, 200, { proto: API_PROTO, ...campaigns.list() });
        } catch (error) {
          sendJson(res, 400, { ok: false, message: String((error && error.message) || error) });
        }
        return;
      }
      if (req.method === 'POST') {
        try {
          const body = await readBody(req, 256 * 1024);
          const action = String((body && body.action) || 'create');
          // Only users can create tasks through the panel: same-origin browser fetch includes sec-fetch-site; scripts/tools do not by default.
          if (action === 'create') {
            const site = String((req.headers && req.headers['sec-fetch-site']) || '');
            const ui = String((req.headers && req.headers['x-dsh-ui']) || '');
            const origin = String((req.headers && req.headers.origin) || '');
            let sameOrigin = false;
            if (origin) {
              try { sameOrigin = new URL(origin).host === String((req.headers && req.headers.host) || ''); } catch { sameOrigin = false; }
            }
            if (site !== 'same-origin' && site !== 'none' && ui !== '1' && !sameOrigin) {
              sendJson(res, 403, { ok: false, message: 'Only the user can create tasks in the plugin panel; AI can only record progress in existing tasks.' });
              return;
            }
          }
          let result;
          let kick = { kicked: false };
          if (action === "create") {
            result = campaigns.create(body || {});
            const agents = liveAgents().filter((a) => a && a.id);
            const target = body.sessionId ? agents.find((a) => a.id === body.sessionId) : (agents.length === 1 ? agents[0] : null);
            if (target) {
              result = campaigns.bind(result.id, target.id);
              kick = await kickAgent(target, result);
              if (kick && kick.kicked) scheduleAutopilot(result.id);
            } else if (agents.length > 1) {
              kick = { kicked: false, reason: "Multiple conversations are online; click Start AI to choose one" };
            }
          }
          else if (action === 'patch') result = campaigns.patch(body.id, body || {});
          else if (action === 'asset') result = campaigns.upsertAsset(body.id, body || {});
          else if (action === 'step') result = campaigns.addStep(body.id, body || {});
          else if (action === 'attempt') result = campaigns.addAttempt(body.id, body || {});
          else if (action === 'delete') { campaigns.remove(body.id); sendJson(res, 200, { ok: true, proto: API_PROTO, ...campaigns.list() }); return; }
          else if (action === "advance") {
            const moved = campaigns.advance(body.id);
            sendJson(res, 200, { ok: true, proto: API_PROTO, item: moved.campaign, stage: { from: moved.from, to: moved.to, changed: moved.changed }, ...campaigns.list() });
            return;
          }
          else if (action === "done") {
            const campaign = campaigns.markDone(body.id, body.note || '');
            stopAutopilot(campaign.id);
            sendJson(res, 200, { ok: true, proto: API_PROTO, item: campaign, ...campaigns.list() });
            return;
          }
          else if (action === "autopilot") {
            const campaign = campaigns.patch(body.id, { autopilot: body.on !== false });
            if (campaign.autopilot && !campaign.done) scheduleAutopilot(campaign.id);
            else stopAutopilot(campaign.id);
            sendJson(res, 200, { ok: true, proto: API_PROTO, item: campaign, autopilot: campaign.autopilot });
            return;
          }
          else if (action === "tick") {
            const tick = autopilotTick(body.id);
            if (tick.ticked) scheduleAutopilot(body.id);
            sendJson(res, 200, { ok: true, proto: API_PROTO, tick });
            return;
          }
          else if (action === "next") { sendJson(res, 200, { ok: true, proto: API_PROTO, next: campaigns.nextStep(body.id, availableKbIndex) }); return; }
          else if (action === "bind") {
            const explicit = String(body.sessionId || '');
            if (!explicit) { sendJson(res, 400, { ok: false, message: "Binding requires an explicit sessionId: say 'bind task X' in that conversation, or leave only one conversation open." }); return; }
            const bound = campaigns.bind(body.id, explicit);
            const agent = liveAgents().find((a) => a.id === bound.sessionId);
            kick = agent ? await kickAgent(agent, bound) : { kicked: false, reason: "That session is offline" };
            if (bound.autopilot !== false && !bound.done) scheduleAutopilot(bound.id);
            sendJson(res, 200, { ok: true, proto: API_PROTO, item: bound, kicked: kick.kicked, kickReason: kick.reason, ...campaigns.list() });
            return;
          }
          else if (action === "unbind") {
            const campaign = campaigns.unbind(body.id);
            sendJson(res, 200, { ok: true, proto: API_PROTO, item: campaign, ...campaigns.list() });
            return;
          }
          else if (action === "kick") {
            const campaign = campaigns.get(body.id);
            const agent = liveAgents().find((a) => a.id === campaign.sessionId);
            const kicked = agent ? await kickAgent(agent, campaign) : { kicked: false, reason: "Task is not bound to an online session" };
            if (kicked && kicked.kicked) scheduleAutopilot(campaign.id);
            sendJson(res, 200, { ok: true, proto: API_PROTO, kicked: kicked.kicked, kickReason: kicked.reason, item: campaign });
            return;
          }
          else { sendJson(res, 400, { ok: false, message: 'Unsupported action: ' + action }); return; }
          sendJson(res, 200, { ok: true, proto: API_PROTO, item: result, kicked: kick.kicked, kickReason: kick.reason, ...campaigns.list() });
        } catch (error) {
          sendJson(res, 400, { ok: false, message: String((error && error.message) || error) });
        }
        return;
      }
      res.writeHead(405, { allow: 'GET, HEAD, POST' });
      res.end();
    });

    // Vulnerability report: GET read, POST write (upsert / delete / clear / status), Markdown export.
    route(FINDINGS_ROUTE, async (req, res) => {
      if (!isLoopback(req)) { res.writeHead(403); res.end('forbidden'); return; }
      if (req.method === 'GET' || req.method === 'HEAD') {
        sendJson(res, 200, { proto: API_PROTO, ...findings.reload() });
        return;
      }
      if (req.method === 'POST') {
        try {
          const body = await readBody(req, 512 * 1024);
          const action = body && typeof body.action === 'string' ? body.action : 'upsert';
          if (action === 'upsert') findings.upsert(body);
          else if (action === 'delete') findings.remove(body.id);
          else if (action === 'clear') findings.clear();
          else if (action === 'status') findings.setStatus(body.id, body.status);
          else { sendJson(res, 400, { ok: false, message: 'Unsupported action: ' + action }); return; }
          sendJson(res, 200, { proto: API_PROTO, ...findings.snapshot() });
        } catch (error) {
          sendJson(res, 400, { ok: false, message: String((error && error.message) || error) });
        }
        return;
      }
      res.writeHead(405, { allow: 'GET, HEAD, POST' });
      res.end();
    });

    route(FINDINGS_MD_ROUTE, async (req, res) => {
      if (!isLoopback(req)) { res.writeHead(403); res.end('forbidden'); return; }
      if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405, { allow: 'GET, HEAD' }); res.end(); return; }
      try {
        const data = Buffer.from(findings.toMarkdown(), 'utf8');
        res.writeHead(200, {
          'content-type': 'text/markdown; charset=utf-8',
          'content-disposition': 'attachment; filename="vuln-report.md"',
          'cache-control': 'no-store',
          'content-length': String(data.length)
        });
        res.end(data);
      } catch (error) {
        sendJson(res, 500, { ok: false, message: String((error && error.message) || error) });
      }
    });

    // Knowledge-base tab: read-only catalog (categories + entry title/severity/entry), plus enabled state.
    route(KNOWLEDGE_ROUTE, async (req, res) => {
      if (!isLoopback(req)) { res.writeHead(403); res.end('forbidden'); return; }
      if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405, { allow: 'GET, HEAD' }); res.end(); return; }
      try {
        const all = knowledgeLibrary.catalog();
        const knowledge = knowledgeLibrary.snapshot().skills[0] || {};
        const enabled = knowledge.enabled === true;
        const available = all.reduce((sum, item) => sum + item.count, 0);
        const categories = enabled ? all : [];
        sendJson(res, 200, {
          ok: true,
          proto: API_PROTO,
          total: enabled ? available : 0,
          available,
          categories,
          enabled,
          busy: knowledge.busy === true,
          phase: knowledge.phase || null,
          version: knowledge.version || null,
          message: knowledge.message || null
        });
      } catch (error) {
        sendJson(res, 500, { ok: false, message: String((error && error.message) || error) });
      }
    });

    route(CONFIG_ROUTE, async (req, res) => {
      if (!isLoopback(req)) { res.writeHead(403); res.end('forbidden'); return; }
      if (req.method === 'GET' || req.method === 'HEAD') {
        // Reread from disk to maintain consistency across windows.
        // Updating live alone is insufficient: if disk changes outside this instance's POST handler
        // (manual edits or another process sharing $DSH_HOME), registered scoped sections retain the old shape,
        // creating contradictions such as armed:false with injected:1, or even erasing the official persona.
        // Align the injection shape after rereading (installInner returns early when unchanged).
        const fromDisk = readFileConfig();
        if (fromDisk) live = normalize({ ...live, ...fromDisk });
        await refreshKnownVars();
        await reinstallAll();
        sendJson(res, 200, { ok: true, config: live, ...status(), ...variableWarnings() });
        return;
      }
      if (req.method === 'POST') {
        try {
          // 2 MB limit: main text plus up to 50 cards. The default 256 KB is too small for a card collection.
          const body = await readBody(req, 2 * 1024 * 1024);
          // Partial updates: update only fields present in body (setConfig merges with live).
          // Accept cards only as an array; strip non-arrays from buggy clients, manual requests, or old clients.
          // Never clear existing cards on disk; preserve non-destructive persistence semantics.
          const patch = body && typeof body === 'object' && !Array.isArray(body) ? { ...body } : {};
          if ('cards' in patch && !Array.isArray(patch.cards)) delete patch.cards;
          const saved = await setConfig(patch);
          await refreshKnownVars();
          sendJson(res, 200, { ok: true, config: saved, ...status(), ...variableWarnings() });
        } catch (error) {
          sendJson(res, 400, { ok: false, message: String((error && error.message) || error) });
        }
        return;
      }
      res.writeHead(405, { allow: 'GET, HEAD, POST' });
      res.end();
    });

    // Two preview types with distinct semantics:
    //   official  = assemble({}), without agent-injected custom sections: the official prompt,
    //               for comparing and writing replacement content (the button's original purpose).
    //   effective = assemble({agent, scope: agent}), the full text actually seen by the model this step;
    //               replace mode shows that the official persona is truly shadowed.
    // Older versions returned only effective as text, so Official prompt preview showed user content; fixed.
    route(PREVIEW_ROUTE, async (req, res) => {
      if (!isLoopback(req)) { res.writeHead(403); res.end('forbidden'); return; }
      if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405, { allow: 'GET, HEAD' }); res.end(); return; }
      let agent = lastAgent && entries.has(lastAgent) ? lastAgent : null;
      if (!agent) { for (const a of entries.keys()) { agent = a; break; } }
      try {
        const sink = newSink();
        const officialAssembly = await ctx.systemPrompt.assemble({});
        const official = renderSections(officialAssembly, sink);
        let effective = official;
        let sections = sectionNames(officialAssembly);
        if (agent) {
          const scopedAssembly = await ctx.systemPrompt.assemble({ agent, scope: agent });
          effective = renderSections(scopedAssembly, sink);
          sections = sectionNames(scopedAssembly);
        }
        // Separately scan user-written text: it is injected as a function; incorrect variables fail every assembly step.
        await refreshKnownVars();
        sendJson(res, 200, {
          ok: true,
          official,
          effective,
          // Compatibility: text always means official (the old client button meant Official prompt).
          text: official,
          scoped: !!agent,
          agentId: agent ? (agent.id || null) : null,
          sections,
          ...variableWarnings(),
          ...status()
        });
      } catch (error) {
        sendJson(res, 500, { ok: false, message: String((error && error.message) || error) });
      }
    });
  });
  // Native tools are an optional enhancement: silently fall back to HTTP if dsh-tools is unavailable.
  registerAutomationTools(ctx, { kbIndex: availableKbIndex, campaigns, findings, skillIndex, advancedTools: assessmentHarnessTools(assessment) }).then((result) => {
    automationTools = result;
    if (result.ok) log('[dsh-prompt-custom] Registered native tools: ' + result.registered.join(', '));
    else warn('[dsh-prompt-custom] Native tools disabled (HTTP remains available): ' + result.reason);
  }).catch((error) => {
    automationTools = { ok: false, reason: String((error && error.message) || error) };
    warn('[dsh-prompt-custom] Native tool registration error: ' + automationTools.reason);
  });
}
