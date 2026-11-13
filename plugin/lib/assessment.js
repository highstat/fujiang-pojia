import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { assessmentHome, atomicFile, createAssessmentStore, digest, identifier, managedPath, readBounded, requireText, timestamp } from './assessment-store.js';
import { canonicalAsset, findingIdentity, parseScannerReport, SCANNERS, SEVERITIES } from './assessment-reports.js';
import { buildAssessmentPlan, collectZapAlerts, loadAssessmentConfig, runBounded, assertTargetUrl } from './assessment-runner.js';
import { investigationGraph } from './assessment-graph.js';
import { createKnowledgeSearch } from './knowledge-search.js';

const defaultCorpus = fileURLToPath(new URL('../knowledge/', import.meta.url));
const campaign = value => requireText(value, 'campaignId', 120);
const optionalText = (value, label, limit = 8000) => value === undefined || value === '' ? '' : requireText(value, label, limit);
const failure = error => String(error?.message || error).slice(0, 2000);
const active = new Set(['queued', 'running']);

function page(items, input) {
  const offset = input.offset ?? 0;
  const limit = input.limit ?? 50;
  if (!Number.isInteger(offset) || offset < 0 || !Number.isInteger(limit) || limit < 1 || limit > 200) throw new Error('Use an integer offset >= 0 and limit between 1 and 200.');
  return { total: items.length, offset, items: items.slice(offset, offset + limit), nextOffset: offset + limit < items.length ? offset + limit : null };
}

export function createAssessmentService(options = {}) {
  const store = createAssessmentStore(options.directory || assessmentHome());
  const jobs = new Map();
  const search = createKnowledgeSearch({ directory: store.root, corpusDir: options.corpusDir || defaultCorpus,
    provider: options.provider, embedding: options.embedding || {
      model: process.env.FUJIANG_EMBEDDING_MODEL, url: process.env.FUJIANG_EMBEDDING_URL || 'http://127.0.0.1:11434',
    } });
  let disposed = false;
  let running = 0;
  const pending = [];

  function importReport(input) {
    const campaignId = campaign(input.campaignId);
    const tool = requireText(input.tool, 'tool', 30);
    if (input.file === undefined && input.content === undefined) throw new Error('A report file or report content is required.');
    const content = input.file ? readBounded(requireText(input.file, 'report file', 4000)) : Buffer.from(input.content ?? '');
    if (content.length > 20 * 1024 * 1024) throw new Error('Report exceeds 20 MiB.');
    const asset = input.asset ? canonicalAsset(input.asset) : undefined;
    const component = optionalText(input.component, 'component', 500);
    const version = optionalText(input.version, 'version', 200);
    const parsed = parseScannerReport(tool, content, { asset });
    const config = input.enforceScope ? loadAssessmentConfig(store.root) : null;
    const observations = parsed.observations.map(item => {
      if (config && ['nuclei', 'zap'].includes(tool)) assertTargetUrl(item.asset, config);
      return { ...item, component: item.component || component, version: item.version || version };
    });
    const report = store.artifact(content);
    const receiptId = identifier('import', campaignId, tool, report.sha256, asset, component, version);
    return store.update(state => {
      if (state.imports[receiptId]) return { ...state.imports[receiptId], duplicate: true };
      const findingIds = new Set();
      for (const observation of observations) {
        const id = findingIdentity(campaignId, observation);
        findingIds.add(id);
        let finding = state.findings[id];
        if (!finding) {
          finding = state.findings[id] = { id, campaignId, asset: observation.asset, component: observation.component,
            version: observation.version, location: observation.location, parameter: observation.parameter,
            title: observation.title, cves: observation.cves, severity: observation.severity,
            status: 'open', verified: false, createdAt: timestamp(), observations: [] };
        }
        const observationId = identifier('observation', tool, report.sha256, observation.pointer);
        if (!finding.observations.some(item => item.id === observationId)) {
          if (finding.observations.length >= 200) throw new Error('Finding observation limit reached; archive before importing more evidence.');
          finding.observations.push({ ...observation, id: observationId, report, importedAt: timestamp() });
        }
        if (SEVERITIES.indexOf(observation.severity) > SEVERITIES.indexOf(finding.severity)) finding.severity = observation.severity;
        finding.updatedAt = timestamp();
      }
      const ids = [...findingIds];
      const receipt = { id: receiptId, campaignId, tool, report, observations: observations.length,
        findingCount: ids.length, findingIds: ids.slice(0, 100), truncated: ids.length > 100,
        warnings: parsed.warnings, importedAt: timestamp() };
      state.imports[receiptId] = receipt;
      return { ...receipt, duplicate: false };
    });
  }

  function review(input) {
    const id = requireText(input.id, 'finding ID', 100);
    const campaignId = campaign(input.campaignId);
    if (!['open', 'fixed', 'accepted', 'false-positive'].includes(input.status)) throw new Error('Invalid review status.');
    if (typeof input.verified !== 'boolean') throw new Error('Review must explicitly set verified to true or false.');
    const note = requireText(input.note, 'review note', 8000);
    const evidence = optionalText(input.evidence, 'review evidence', 16000);
    if (input.verified && !evidence) throw new Error('Verified findings require explicit review evidence.');
    return store.update(state => {
      const finding = state.findings[id];
      if (!finding || finding.campaignId !== campaignId) throw new Error('Finding not found in this campaign.');
      finding.status = input.status;
      finding.verified = input.verified;
      finding.review = { note, evidence, reviewedAt: timestamp() };
      finding.updatedAt = timestamp();
      return finding;
    });
  }

  function inventoryUpsert(input) {
    const campaignId = campaign(input.campaignId);
    const asset = canonicalAsset(input.asset);
    const component = requireText(input.component, 'component', 500);
    const version = optionalText(input.version, 'version', 200);
    const evidence = requireText(input.evidence, 'inventory evidence', 16000);
    const id = identifier('inventory', campaignId, asset, component, version);
    return store.update(state => state.inventory[id] = { id, campaignId, asset, component, version, evidence, updatedAt: timestamp() });
  }

  function plan(input) {
    const recipe = buildAssessmentPlan(input, loadAssessmentConfig(store.root), store.root);
    const id = 'plan_' + randomUUID();
    return store.update(state => state.runs[id] = { id, kind: 'plan', status: 'planned', campaignId: recipe.campaignId,
      recipe, recipeHash: digest(JSON.stringify(recipe)), createdAt: timestamp() });
  }

  function validatedPlan(planId) {
    const saved = store.read().runs[requireText(planId, 'planId', 100)];
    if (saved?.kind !== 'plan') throw new Error('Assessment plan not found.');
    const config = loadAssessmentConfig(store.root);
    if (!config.executionEnabled) throw new Error('Execution is disabled. The operator must enable it in assessment config.json after reviewing scope.');
    const recipe = buildAssessmentPlan(saved.recipe.input, config, store.root);
    if (digest(JSON.stringify(recipe)) !== saved.recipeHash || JSON.stringify(recipe) !== JSON.stringify(saved.recipe)) {
      throw new Error('Plan is stale or modified; regenerate it after reviewing the current configuration and rules.');
    }
    return { recipe, config };
  }

  function lease(maximum) {
    for (let slot = 0; slot < maximum; slot++) {
      const filename = managedPath(store.root, 'execution-' + slot + '.lock');
      try {
        const descriptor = fs.openSync(filename, 'wx', 0o600);
        try { fs.writeFileSync(descriptor, JSON.stringify({ pid: process.pid, startedAt: timestamp() })); }
        finally { fs.closeSync(descriptor); }
        return () => fs.unlinkSync(filename);
      } catch (error) { if (error.code !== 'EEXIST') throw error; }
    }
    throw new Error('All cross-session execution slots are occupied. Retry later; inspect lock PIDs after a crash, never remove live locks.');
  }

  function patchRun(id, update) {
    return store.update(state => Object.assign(state.runs[id], update, { updatedAt: timestamp() }));
  }

  function pump() {
    if (disposed) return;
    const maximum = loadAssessmentConfig(store.root).maxConcurrent;
    while (running < maximum && pending.length) {
      const job = pending.shift();
      running++;
      Promise.resolve().then(async () => {
        job.controller.signal.throwIfAborted();
        patchRun(job.id, { status: 'running', startedAt: timestamp() });
        return job.work(job.controller.signal);
      }).then(result => patchRun(job.id, { status: 'completed', result, finishedAt: timestamp() }),
        error => patchRun(job.id, { status: job.controller.signal.aborted ? 'cancelled' : 'failed', error: failure(error), finishedAt: timestamp() }))
        .then(job.resolve, job.reject).finally(() => { running--; jobs.delete(job.id); try { pump(); } catch {} }).catch(() => {});
    }
  }

  function enqueue(record, work) {
    if (disposed) throw new Error('Assessment service is closed.');
    if (jobs.size >= 20) throw new Error('Assessment queue is full.');
    loadAssessmentConfig(store.root);
    store.update(state => { state.runs[record.id] = { ...record, pid: process.pid, status: 'queued', createdAt: timestamp() }; });
    const controller = new AbortController();
    let resolve;
    let reject;
    const promise = new Promise((done, failed) => { resolve = done; reject = failed; });
    promise.catch(() => {});
    const job = { id: record.id, controller, work, promise, resolve, reject };
    jobs.set(record.id, job);
    pending.push(job);
    pump();
    return { id: record.id, status: 'queued' };
  }

  function start(input) {
    validatedPlan(input.planId);
    const id = 'run_' + randomUUID();
    return enqueue({ id, kind: 'scan', planId: input.planId }, async signal => {
      const { recipe, config } = validatedPlan(input.planId);
      const release = lease(config.maxConcurrent);
      try {
        if (recipe.tool === 'nuclei') atomicFile(managedPath(store.root, 'scanner-config/nuclei.yaml'), '{}\n');
        const result = recipe.tool === 'zap' ? await collectZapAlerts(recipe, { signal }) : await runBounded(recipe, { signal });
        const stdout = store.artifact(result.stdout);
        const stderr = store.artifact(result.stderr);
        patchRun(id, { exitCode: result.exitCode, exitSignal: result.exitSignal || null, stdout, stderr });
        if (result.exitCode !== 0 || result.exitSignal) throw new Error('Scanner failed; output was preserved but the run is not a clean assessment.');
        const receipt = importReport({ campaignId: recipe.campaignId, tool: recipe.tool, content: result.stdout,
          asset: recipe.target, enforceScope: true });
        if (receipt.warnings.length) throw new Error('Scanner coverage is incomplete; candidate findings were imported. ' + receipt.warnings.join(' '));
        return receipt;
      } finally { release(); }
    });
  }

  function status(input) {
    const run = store.read().runs[requireText(input.id, 'run ID', 100)];
    if (!run) throw new Error('Run or plan not found.');
    if (active.has(run.status) && !jobs.has(run.id)) {
      let alive = true;
      try { process.kill(run.pid, 0); } catch (error) { alive = error.code !== 'ESRCH'; }
      return { ...run, ...(alive ? { note: 'Owned by another service instance; no automatic resume or cancellation.' }
        : { status: 'interrupted', note: 'Owner exited; no automatic replay. Inspect execution locks before a new run.' }) };
    }
    return run;
  }

  function cancel(input) {
    const job = jobs.get(requireText(input.id, 'run ID', 100));
    if (!job) throw new Error('Only runs owned by this live service instance can be cancelled.');
    job.controller.abort();
    return { id: job.id, cancellationRequested: true };
  }

  return {
    directory: store.root, importReport, review, inventoryUpsert, plan, start, status, cancel,
    capabilities() { return { tools: SCANNERS, executionEnabled: loadAssessmentConfig(store.root).executionEnabled,
      zapMode: 'collect-existing-alerts-only', storage: store.root, semanticModelConfigured: search.modelConfigured,
      readiness: 'Planning validates installed executables and reviewed rules; no scanner or model is installed automatically.' }; },
    findings(input) { const campaignId = campaign(input.campaignId); return page(Object.values(store.read().findings).filter(item => item.campaignId === campaignId), input); },
    graph(input) { return investigationGraph(store.read(), input); },
    async search(input) {
      if (options.knowledgeEnabled && !options.knowledgeEnabled()) throw new Error('Knowledge library is disabled.');
      return search.search(input);
    },
    index() {
      if (options.knowledgeEnabled && !options.knowledgeEnabled()) throw new Error('Knowledge library is disabled.');
      return enqueue({ id: 'index_' + randomUUID(), kind: 'index' }, signal => search.buildIndex({ signal }));
    },
    async settled(id) { await jobs.get(id)?.promise; return status({ id }); },
    async dispose() {
      disposed = true;
      for (const job of jobs.values()) job.controller.abort();
      for (const job of pending.splice(0)) {
        try { job.resolve(patchRun(job.id, { status: 'cancelled', finishedAt: timestamp() })); }
        catch (error) { job.reject(error); }
        jobs.delete(job.id);
      }
      await Promise.allSettled([...jobs.values()].map(job => job.promise));
    },
  };
}
