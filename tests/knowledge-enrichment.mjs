import assert from 'node:assert/strict';
import test from 'node:test';
import { enrichMetadata, KEV_SOURCE, EPSS_SOURCE } from '../scripts/enrich-knowledge.mjs';

const today = '2026-11-13';
const source = { cve: 'CVE-2024-23897', verified: false, cwe: null, 'patch-date': null, 'vendor-advisory': null };
const kev = { catalogVersion: '2026.11.12', dateReleased: '2026-11-12T10:00:00Z', count: 1,
  vulnerabilities: [{ cveID: source.cve, dateAdded: '2024-08-19', cwes: ['CWE-27'], dueDate: '2024-09-09' }] };
const epss = { status: 'OK', total: 1, offset: 0, data: [{ cve: source.cve, epss: '0.42', percentile: '0.9', date: '2026-11-12' }] };

function fetcher({ kevFeed = kev, epssFeed = epss, status = 200 } = {}) {
  return async (url) => ({ ok: status === 200, status, json: async () => structuredClone(url === KEV_SOURCE ? kevFeed : epssFeed) });
}

test('enrichment records official sources and dates without claiming laboratory verification or patch dates', async () => {
  const [result] = await enrichMetadata([source], { fetcher: fetcher(), today });
  assert.equal(result.kev, true);
  assert.equal(result['kev-date'], '2024-08-19');
  assert.equal(result['kev-source'], KEV_SOURCE);
  assert.equal(result.epss, 0.42);
  assert.equal(result['epss-percentile'], 0.9);
  assert.equal(result['epss-date'], '2026-11-12');
  assert.equal(result['epss-source'], EPSS_SOURCE);
  assert.equal(result['enrichment-updated'], today);
  assert.equal(result.verified, false);
  assert.equal(result.cwe, 'CWE-27');
  assert.equal(result['patch-date'], null);
  assert.equal(result['vendor-advisory'], null);
  assert.deepEqual(source, { cve: 'CVE-2024-23897', verified: false, cwe: null, 'patch-date': null, 'vendor-advisory': null });
});

test('missing EPSS stays unknown and absence from KEV means not listed, never verified safe', async () => {
  const [result] = await enrichMetadata([source], { today, fetcher: fetcher({ kevFeed: { ...kev, count: 0, vulnerabilities: [] }, epssFeed: { status: 'OK', total: 0, offset: 0, data: [] } }) });
  assert.equal(result.kev, false);
  assert.equal(result['kev-date'], null);
  assert.equal(result.epss, null);
  assert.equal(result['epss-date'], null);
  assert.equal(result.verified, false);
});

test('non-CVE entries do not trigger requests and retain original fields', async () => {
  const record = { cve: null, kind: 'workflow', verified: false };
  const results = await enrichMetadata([record], { today, fetcher: () => { throw new Error('Network forbidden'); } });
  assert.deepEqual(results, [record]);
});

test('malformed, duplicated, truncated, or failed responses cannot generate enrichment patches', async () => {
  const badEpss = [
    { ...epss, total: 2 }, { ...epss, offset: 1 }, { ...epss, status: 'ERROR' },
    { ...epss, total: 2, data: [epss.data[0], epss.data[0]] },
    ...[{ epss: '' }, { epss: 'NaN' }, { epss: 1.01 }, { percentile: -1 }, { date: '2026-02-30' }, { date: '2026-11-14' }, { cve: 'CVE-2000-0001' }]
      .map((change) => ({ ...epss, data: [{ ...epss.data[0], ...change }] })),
  ];
  for (const epssFeed of badEpss) await assert.rejects(enrichMetadata([source], { today, fetcher: fetcher({ epssFeed }) }));
  for (const kevFeed of [{}, { ...kev, count: 2 }, { ...kev, count: 2, vulnerabilities: [...kev.vulnerabilities, ...kev.vulnerabilities] }]) {
    await assert.rejects(enrichMetadata([source], { today, fetcher: fetcher({ kevFeed }) }));
  }
  await assert.rejects(enrichMetadata([source], { today, fetcher: fetcher({ status: 503 }) }), /HTTP 503/);
});

test('EPSS requests deduplicate CVEs and use bounded batches', async () => {
  const records = Array.from({ length: 105 }, (_, index) => ({ cve: 'CVE-2026-' + (10000 + index), cwe: null }));
  const batches = [];
  const mock = async (url) => {
    if (url === KEV_SOURCE) return { ok: true, json: async () => kev };
    const requested = new URL(url).searchParams.get('cve').split(',');
    batches.push(requested);
    return { ok: true, json: async () => ({ status: 'OK', total: 0, offset: 0, data: [] }) };
  };
  await enrichMetadata([...records, records[0]], { today, fetcher: mock });
  assert.deepEqual(batches.map((batch) => batch.length), [100, 5]);
});
