import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { isDate, knowledgeFiles, parseKnowledgeDocument, serializeKnowledgeDocument,
  validateKnowledgeCorpus } from '../plugin/lib/knowledge-schema.js';
import { corpusRoot, printPatch } from './normalize-knowledge.mjs';

export const KEV_SOURCE = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
export const EPSS_SOURCE = 'https://api.first.org/data/v1/epss';

async function fetchJson(url, fetcher) {
  const response = await fetcher(url, { signal: AbortSignal.timeout(25000), headers: { Accept: 'application/json' } });
  if (!response.ok) throw new Error('Metadata request failed: HTTP ' + response.status + ' from ' + new URL(url).hostname);
  return response.json();
}

function probability(value) {
  if (!['string', 'number'].includes(typeof value) || String(value).trim() === '') throw new Error('Invalid probability');
  const number = Number(value);
  if (!Number.isFinite(number) || number < 0 || number > 1) throw new Error('Probability must be in [0,1]');
  return number;
}

export async function enrichMetadata(records, { fetcher = fetch, today = new Date().toISOString().slice(0, 10) } = {}) {
  if (!isDate(today)) throw new Error('Invalid retrieval date');
  const cves = [...new Set(records.map((record) => record.cve).filter(Boolean))].sort();
  if (cves.some((cve) => !/^CVE-\d{4}-\d{4,}$/.test(cve))) throw new Error('Invalid CVE identifier');
  if (!cves.length) return records.map((record) => ({ ...record }));
  const feed = await fetchJson(KEV_SOURCE, fetcher);
  if (!Array.isArray(feed.vulnerabilities) || feed.count !== feed.vulnerabilities.length
    || typeof feed.catalogVersion !== 'string' || !isDate(feed.dateReleased?.slice(0, 10))
    || feed.dateReleased.slice(0, 10) > today) throw new Error('Invalid CISA KEV catalog');
  const kev = new Map();
  for (const record of feed.vulnerabilities) {
    if (!/^CVE-\d{4}-\d{4,}$/.test(record.cveID) || !isDate(record.dateAdded) || record.dateAdded > today || kev.has(record.cveID)) throw new Error('Invalid or duplicate KEV record');
    kev.set(record.cveID, record);
  }
  const epss = new Map();
  for (let offset = 0; offset < cves.length; offset += 100) {
    const batch = cves.slice(offset, offset + 100);
    const url = EPSS_SOURCE + '?cve=' + batch.join(',') + '&limit=100';
    const response = await fetchJson(url, fetcher);
    if (response.status !== 'OK' || !Array.isArray(response.data)
      || Number(response.total) !== response.data.length || Number(response.offset) !== 0) throw new Error('Invalid or incomplete FIRST EPSS response');
    for (const record of response.data) {
      if (!batch.includes(record.cve) || epss.has(record.cve) || !isDate(record.date) || record.date > today) throw new Error('Invalid or duplicate EPSS record');
      epss.set(record.cve, { score: probability(record.epss), percentile: probability(record.percentile), date: record.date });
    }
  }
  return records.map((record) => {
    if (!record.cve) return { ...record };
    const match = kev.get(record.cve);
    const score = epss.get(record.cve);
    const cwes = Array.isArray(match?.cwes) ? match.cwes.filter((cwe) => /^CWE-\d+$/.test(cwe)) : [];
    return {
      ...record,
      cwe: cwes.length ? [...new Set(cwes)].join(', ') : record.cwe,
      kev: Boolean(match),
      'kev-date': match?.dateAdded || null,
      'kev-source': KEV_SOURCE,
      epss: score?.score ?? null,
      'epss-percentile': score?.percentile ?? null,
      'epss-date': score?.date || null,
      'epss-source': score ? EPSS_SOURCE : null,
      'enrichment-updated': today,
    };
  });
}

export async function enrichmentChanges(root = corpusRoot, options = {}) {
  const errors = validateKnowledgeCorpus(root);
  if (errors.length) throw new Error('Validate the corpus before enrichment:\n' + errors.join('\n'));
  const files = knowledgeFiles(root).map((item) => {
    const original = fs.readFileSync(item.path, 'utf8');
    return { ...item, original, ...parseKnowledgeDocument(original) };
  });
  const enriched = await enrichMetadata(files.map((file) => file.fields), options);
  return files.flatMap((file, index) => {
    const content = serializeKnowledgeDocument(enriched[index], file.body,
      file.original.includes('\r\n') ? '\r\n' : '\n', file.original.startsWith('\uFEFF') ? '\uFEFF' : '');
    return content === file.original ? [] : [{ path: file.path, original: file.original, content }];
  });
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  try {
    const arguments_ = process.argv.slice(2);
    if (arguments_.length > 1 || (arguments_.length && arguments_[0] !== '--patch')) throw new Error('Usage: node scripts/enrich-knowledge.mjs [--patch]');
    const changes = await enrichmentChanges();
    if (arguments_[0] === '--patch' && changes.length) printPatch(changes);
    else console.log('Metadata updates available for ' + changes.length + ' entries. No files changed. Use --patch to review a patch.');
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
