import path from 'node:path';
import { createKbIndex } from './automation.js';
import { parseKnowledgeDocument } from './knowledge-schema.js';
import { atomicFile, createAssessmentStore, digest, managedPath, readBounded, requireText, timestamp } from './assessment-store.js';
import { boundedJson, loopbackUrl } from './assessment-runner.js';
import { versionApplicability } from './knowledge-versions.js';

const RECIPE = 1;
const stopwords = new Set(['the', 'and', 'for', 'with', 'from', 'this', 'that', 'how', 'what', 'are', 'was', 'can', 'into', 'using', 'have', 'has', 'not', 'but']);
const tokens = value => (String(value).normalize('NFKC').toLowerCase().match(/[\p{L}\p{N}]+(?:[._-][\p{L}\p{N}]+)*/gu) || [])
  .filter(token => token.length > 1 && !stopwords.has(token)).slice(0, 50000);

function vectors(values, count) {
  if (!Array.isArray(values) || values.length !== count) throw new Error('Embedding result count mismatch.');
  const dimension = values[0]?.length;
  if (!Number.isInteger(dimension) || dimension < 1 || dimension > 8192) throw new Error('Invalid embedding dimensions.');
  return values.map(vector => {
    if (!Array.isArray(vector) || vector.length !== dimension || vector.some(value => typeof value !== 'number' || !Number.isFinite(value))) throw new Error('Invalid embedding vector.');
    const norm = Math.sqrt(vector.reduce((sum, value) => sum + value * value, 0));
    if (!Number.isFinite(norm) || !norm) throw new Error('Embedding vector has no finite magnitude.');
    return vector.map(value => value / norm);
  });
}

export function createLocalEmbeddings({ model, url = 'http://127.0.0.1:11434', timeoutMs = 30000 } = {}) {
  if (!model) return null;
  model = requireText(model, 'embedding model', 200);
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120000) throw new Error('Embedding timeout must be between 1 and 120000 ms.');
  const base = loopbackUrl(url, 'embedding URL');
  if (base.pathname !== '/') throw new Error('Embedding URL must be a loopback origin, not a custom path.');
  const request = (route, init, signal) => boundedJson(new URL(route, base), { ...init,
    signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)]) : AbortSignal.timeout(timeoutMs) });
  return {
    async metadata(signal) {
      const result = await request('/api/tags', {}, signal);
      const item = result.models?.find(item => [model, model + ':latest'].includes(item.name) || [model, model + ':latest'].includes(item.model));
      if (!item?.digest || typeof item.digest !== 'string') throw new Error('Embedding model is not installed locally; no model was downloaded.');
      return { provider: 'ollama', url: base.origin, model: item.name || item.model, digest: item.digest, recipe: RECIPE };
    },
    async embed(input, signal) {
      const result = await request('/api/embed', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ model, input, truncate: false }) }, signal);
      return vectors(result.embeddings, input.length);
    },
  };
}

export function createKnowledgeSearch({ corpusDir, directory, provider, embedding, index = createKbIndex(corpusDir) }) {
  const store = createAssessmentStore(directory);
  const embedder = provider === undefined ? createLocalEmbeddings(embedding) : provider;
  const cacheFile = () => managedPath(store.root, 'embeddings.json');
  function documents() {
    return index.list().map(item => {
      const content = readBounded(item.path, 1024 * 1024).toString('utf8');
      const { fields, body } = parseKnowledgeDocument(content);
      const lexical = [item.title, item.title, item.title, item.product, item.product, item.cve, item.cve, fields.keywords, body].join(' ');
      const terms = tokens(lexical);
      const counts = new Map();
      for (const term of terms) counts.set(term, (counts.get(term) || 0) + 1);
      return { ...item, fields, body, counts, length: terms.length, sha256: digest(content),
        embeddingText: [item.title, item.product, item.cve, fields.keywords, body].join('\n').slice(0, 6000) };
    });
  }
  function affectedRecords() {
    try {
      const data = JSON.parse(readBounded(path.join(corpusDir, 'affected-versions.json')).toString('utf8'));
      if (data.schema !== 1 || !Array.isArray(data.records)) throw new Error('Invalid affected-version dataset.');
      return new Map(data.records.map(item => [item.cve, item]));
    } catch (error) { if (error.code === 'ENOENT') return new Map(); throw error; }
  }
  function readCache() {
    try { return JSON.parse(readBounded(cacheFile(), 64 * 1024 * 1024).toString('utf8')); }
    catch (error) { if (error.code === 'ENOENT') return null; throw new Error('Embedding cache is unreadable; rebuild it explicitly.'); }
  }
  async function buildIndex({ signal, progress = () => {} } = {}) {
    if (!embedder) throw new Error('Configure a local embedding model before indexing; no model is installed automatically.');
    const docs = documents();
    const metadata = await embedder.metadata(signal);
    let old;
    try { old = readCache(); } catch { old = null; }
    const reusable = old?.schema === 1 && JSON.stringify(old.metadata) === JSON.stringify(metadata)
      && Array.isArray(old.documents) ? new Map(old.documents.map(item => [item.id + ':' + item.sha256, item.vector])) : new Map();
    const entries = [];
    const missing = [];
    for (const item of docs) {
      const cached = reusable.get(item.id + ':' + item.sha256);
      if (cached) {
        try { entries.push({ id: item.id, sha256: item.sha256, vector: vectors([cached], 1)[0] }); }
        catch { missing.push(item); }
      } else missing.push(item);
    }
    for (let start = 0; start < missing.length; start += 8) {
      signal?.throwIfAborted();
      const batch = missing.slice(start, start + 8);
      const result = vectors(await embedder.embed(batch.map(item => item.embeddingText), signal), batch.length);
      batch.forEach((item, offset) => entries.push({ id: item.id, sha256: item.sha256, vector: result[offset] }));
      progress({ completed: entries.length, total: docs.length });
    }
    if (JSON.stringify(await embedder.metadata(signal)) !== JSON.stringify(metadata)) throw new Error('Embedding model changed during indexing; retry with a stable model.');
    if (entries.length && entries.some(item => item.vector.length !== entries[0].vector.length)) throw new Error('Embedding dimensions changed during indexing.');
    const cache = { schema: 1, metadata, updatedAt: timestamp(), documents: entries };
    const content = JSON.stringify(cache) + '\n';
    if (Buffer.byteLength(content) > 64 * 1024 * 1024) throw new Error('Embedding cache exceeds its size limit.');
    store.update(() => atomicFile(cacheFile(), content));
    return { indexed: entries.length, reused: docs.length - missing.length, metadata, updatedAt: cache.updatedAt };
  }
  async function search(input, { signal } = {}) {
    const query = requireText(input?.query, 'search query', 2000);
    const docs = documents();
    const filters = input.filters || {};
    if (!filters || typeof filters !== 'object' || Array.isArray(filters)) throw new Error('filters must be an object.');
    for (const key of Object.keys(filters)) if (!['category', 'kind', 'severity', 'product', 'version', 'configuration', 'cve', 'kev'].includes(key)) throw new Error('Unknown search filter: ' + key);
    if (filters.kev !== undefined && typeof filters.kev !== 'boolean') throw new Error('kev filter must be boolean.');
    for (const key of ['category', 'kind', 'severity', 'product', 'version', 'cve']) if (filters[key] !== undefined) requireText(filters[key], key + ' filter', 500);
    if (filters.configuration !== undefined && (!Array.isArray(filters.configuration) || filters.configuration.length > 20
      || filters.configuration.some(value => typeof value !== 'string' || !value.trim() || value.length > 200))) throw new Error('configuration must be an array of at most 20 bounded text conditions.');
    const records = filters.version ? affectedRecords() : new Map();
    const applicable = new Map();
    const candidates = docs.filter(item => {
      for (const key of ['category', 'kind', 'severity']) if (filters[key] && item[key] !== filters[key]) return false;
      if (filters.kev !== undefined && item.kev !== filters.kev) return false;
      if (filters.cve && ![item.cve, ...item.relatedCves].includes(String(filters.cve).toUpperCase())) return false;
      if (filters.product && !String(item.product).toLowerCase().includes(String(filters.product).toLowerCase())) return false;
      if (filters.configuration) {
        const conditions = Array.isArray(filters.configuration) ? filters.configuration : [filters.configuration];
        const haystack = (item.product + '\n' + item.body).toLowerCase();
        if (!conditions.every(condition => typeof condition === 'string' && condition.length > 0 && haystack.includes(condition.toLowerCase()))) return false;
      }
      const status = versionApplicability(records.get(item.cve), filters.version, filters.product);
      applicable.set(item.id, status);
      return status.status !== 'not-affected';
    });
    const queryTokens = [...new Set(tokens(query))].slice(0, 100);
    const averageLength = docs.reduce((sum, item) => sum + item.length, 0) / (docs.length || 1);
    const frequency = new Map(queryTokens.map(term => [term, docs.filter(item => item.counts.has(term)).length]));
    const lexical = candidates.map(item => {
      let score = 0;
      for (const term of queryTokens) {
        const count = item.counts.get(term) || 0;
        if (!count) continue;
        const inverse = Math.log(1 + (docs.length - frequency.get(term) + 0.5) / (frequency.get(term) + 0.5));
        score += inverse * (count * 2.2) / (count + 1.2 * (0.25 + 0.75 * item.length / (averageLength || 1)));
      }
      return { item, score };
    }).filter(item => item.score > 0).sort((first, second) => second.score - first.score || first.item.id.localeCompare(second.item.id));
    let semantic = { status: embedder ? 'index_required' : 'disabled', reason: embedder
      ? 'Build the local embedding index with knowledge_index before semantic search.' : 'No local embedding model is configured; results are lexical only.' };
    let neighbors = [];
    if (embedder) try {
      const cache = readCache();
      const metadata = await embedder.metadata(signal);
      if (cache?.schema === 1 && JSON.stringify(cache.metadata) === JSON.stringify(metadata) && Array.isArray(cache.documents)) {
        const cached = new Map(cache.documents.map(item => [item.id + ':' + item.sha256, item.vector]));
        if (docs.every(item => cached.has(item.id + ':' + item.sha256))) {
          const queryVector = vectors(await embedder.embed([query], signal), 1)[0];
          neighbors = candidates.map(item => {
            const vector = vectors([cached.get(item.id + ':' + item.sha256)], 1)[0];
            if (vector.length !== queryVector.length) throw new Error('Embedding model dimensions do not match the index.');
            return { item, score: Math.max(-1, Math.min(1, vector.reduce((sum, value, offset) => sum + value * queryVector[offset], 0))) };
          }).filter(item => item.score > 0).sort((first, second) => second.score - first.score || first.item.id.localeCompare(second.item.id));
          if (JSON.stringify(await embedder.metadata(signal)) !== JSON.stringify(metadata)) throw new Error('Embedding model changed during search.');
          semantic = { status: 'ready', model: metadata.model, digest: metadata.digest };
        } else semantic = { status: 'index_stale', reason: 'Corpus content changed; rebuild the embedding index. No stale vectors were used.' };
      }
    } catch {
      signal?.throwIfAborted();
      neighbors = [];
      semantic = { status: 'unavailable', reason: 'Local embeddings or their cache are unavailable or invalid; results are lexical only.' };
    }
    const combined = new Map();
    for (const [channel, ranking] of [['lexical', lexical], ['semantic', neighbors]]) ranking.slice(0, 100).forEach((hit, rank) => {
      const previous = combined.get(hit.item.id) || { item: hit.item, score: 0, reasons: [], channels: {} };
      previous.score += 1 / (60 + rank + 1);
      previous.channels[channel] = hit.score;
      previous.reasons.push(channel === 'lexical' ? 'BM25 full-text match' : 'Local model cosine similarity');
      combined.set(hit.item.id, previous);
    });
    const ranked = [...combined.values()].map(hit => ({ ...hit,
      score: hit.score * (1 + (hit.item.kev === true ? 0.1 : 0) + (hit.item.epss || 0) * 0.05) }))
      .sort((first, second) => second.score - first.score || first.item.id.localeCompare(second.item.id));
    const limit = Math.max(1, Math.min(50, Number(input.limit) || 10));
    return { mode: semantic.status === 'ready' ? 'hybrid' : 'lexical', semantic, corpusSize: docs.length,
      eligible: candidates.length, totalHits: ranked.length, truncated: ranked.length > limit,
      hits: ranked.slice(0, limit).map(({ item, score, reasons, channels }) => ({ id: item.id, title: item.title,
        file: item.category + '/' + item.file, category: item.category, kind: item.kind, cve: item.cve,
        product: item.product, versions: item.versions, severity: item.severity, verified: item.verified,
        kev: item.kev, epss: item.epss, epssDate: item.fields['epss-date'] || null,
        applicability: applicable.get(item.id), configurationCheck: filters.configuration ? 'text-filter-only' : 'not-assessed',
        score, channels, reasons, excerpt: item.body.replace(/\s+/g, ' ').slice(0, 350) })) };
  }
  return { search, buildIndex, modelConfigured: Boolean(embedder) };
}
