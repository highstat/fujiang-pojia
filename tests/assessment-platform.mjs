import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { createAssessmentService } from '../plugin/lib/assessment.js';
import { createAssessmentStore, digest, readBounded } from '../plugin/lib/assessment-store.js';
import { parseScannerReport, canonicalAsset, findingIdentity } from '../plugin/lib/assessment-reports.js';
import { assertTargetUrl, buildAssessmentPlan, collectZapAlerts, loadAssessmentConfig, loopbackUrl, runBounded, scopedPath } from '../plugin/lib/assessment-runner.js';
import { graphDot } from '../plugin/lib/assessment-graph.js';
import { assessmentHarnessTools, assessmentTools, invokeAssessmentTool } from '../plugin/lib/assessment-tools.js';
import { registerAutomationTools } from '../plugin/lib/automation.js';

const root = fileURLToPath(new URL('../', import.meta.url));
const cli = path.join(root, 'scripts/assessment.mjs');
const cve = 'CVE-2024-12345';
const target = 'https://target.example.test/app';
const nuclei = (overrides = {}) => ({ 'template-id': 'fixture-rule', 'matched-at': target,
  info: { name: 'Fixture finding', severity: 'high', classification: { 'cve-id': [cve] }, remediation: 'Apply vendor patch' }, ...overrides });
const zap = (overrides = {}) => ({ pluginId: '10001', alert: 'Fixture finding', url: target, risk: 'High', reference: cve, evidence: 'fixture response', ...overrides });

function directory(context) {
  const location = fs.mkdtempSync(path.join(os.tmpdir(), 'fujiang-assessment-'));
  context.after(() => fs.rmSync(location, { recursive: true, force: true }));
  return fs.realpathSync(location);
}
function service(context, home = directory(context), options = {}) {
  const assessment = createAssessmentService({ directory: home, ...options });
  context.after(() => assessment.dispose());
  return assessment;
}
function config(home, overrides = {}) {
  const value = { executionEnabled: false, scope: { urls: [target], localRoots: [home], templateRoots: [home], ruleRoots: [home] },
    executables: { nuclei: process.execPath, semgrep: process.execPath, trivy: process.execPath }, ...overrides };
  fs.writeFileSync(path.join(home, 'config.json'), JSON.stringify(value));
  return loadAssessmentConfig(home);
}
async function server(context, handler) {
  const instance = http.createServer(handler);
  instance.listen(0, '127.0.0.1');
  await once(instance, 'listening');
  context.after(() => { instance.closeAllConnections(); return new Promise(resolve => instance.close(resolve)); });
  return 'http://127.0.0.1:' + instance.address().port;
}
const json = (response, data) => { response.setHeader('Content-Type', 'application/json'); response.end(JSON.stringify(data)); };

test('all four report formats normalize without inventing verification', () => {
  const first = parseScannerReport('nuclei', JSON.stringify(nuclei()));
  assert.equal(first.observations[0].severity, 'high');
  assert.deepEqual(first.observations[0].cves, [cve]);
  assert.equal(parseScannerReport('zap', JSON.stringify({ alerts: [zap()] })).observations[0].severity, 'high');
  const classic = parseScannerReport('zap', JSON.stringify({ site: [{ '@name': target, alerts: [{ pluginid: '1', name: 'Fixture', riskcode: '2',
    instances: [{ uri: target + '/one', param: 'id' }, { uri: target + '/two' }] }] }] }));
  assert.equal(classic.observations.length, 2);
  assert.equal(classic.observations[0].severity, 'medium');
  const semgrep = parseScannerReport('semgrep', JSON.stringify({ results: [{ check_id: 'fixture', path: 'src/app.js', start: { line: 7 },
    extra: { message: 'Fixture', severity: 'ERROR', lines: 'fixture code', metadata: { cve } } }], errors: [{ message: 'coverage gap' }] }), { asset: '/repo' });
  assert.equal(semgrep.observations[0].location, 'src/app.js:7');
  assert.equal(semgrep.observations[0].severity, 'high');
  assert.equal(semgrep.warnings.length, 1);
  const trivy = parseScannerReport('trivy', JSON.stringify({ Results: [{ Target: 'package-lock.json', Vulnerabilities: [{ VulnerabilityID: cve,
    PkgName: 'fixture', InstalledVersion: '1.0', FixedVersion: '1.1', Severity: 'CRITICAL' }],
    Misconfigurations: [{ ID: 'AVD-1', Title: 'Config', Severity: 'LOW', Status: 'FAIL' }, { ID: 'AVD-2', Status: 'PASS' }], Secrets: [{}] }] }));
  assert.equal(trivy.observations.length, 2);
  assert.equal(trivy.observations[0].component, 'fixture');
  assert.match(trivy.observations[0].remediation, /1\.1/);
  assert.match(trivy.warnings[0], /Secret findings are not imported/);
  for (const report of [first, classic, semgrep, trivy]) for (const observation of report.observations) assert.equal(observation.verified, undefined);
});

test('malformed reports fail and explicit empty formats remain valid', () => {
  for (const tool of ['zap', 'semgrep', 'trivy']) for (const invalid of ['[]', '{}', '{bad']) assert.throws(() => parseScannerReport(tool, invalid));
  assert.throws(() => parseScannerReport('nuclei', '{}'), /Invalid Nuclei/);
  assert.throws(() => parseScannerReport('nuclei', '{bad'), /line 1/);
  assert.throws(() => parseScannerReport('other', '{}'), /Unsupported scanner/);
  assert.equal(parseScannerReport('nuclei', '').observations.length, 0);
  assert.equal(parseScannerReport('semgrep', '{"results":[]}').observations.length, 0);
  assert.equal(parseScannerReport('trivy', '{"Results":[]}').observations.length, 0);
  assert.equal(parseScannerReport('zap', '{"alerts":[]}').observations.length, 0);
});

test('dedup keys preserve campaigns, components, versions, parameters and CVE sets', () => {
  assert.equal(canonicalAsset(target + '?token=secret&id=1#fragment'), target + '?id=&token=');
  assert.throws(() => canonicalAsset('https://user:secret@example.test/'), /credentials/);
  const observation = parseScannerReport('nuclei', JSON.stringify(nuclei())).observations[0];
  const id = findingIdentity('one', observation);
  for (const change of [{ component: 'other' }, { version: '2' }, { location: 'src:3' }, { parameter: 'id' }, { cves: [cve, 'CVE-2024-99999'] }]) {
    assert.notEqual(findingIdentity('one', { ...observation, ...change }), id);
  }
  assert.notEqual(findingIdentity('two', observation), id);
  assert.equal(findingIdentity('one', { ...observation, tool: 'zap', rule: 'other' }), id);
  assert.notEqual(findingIdentity('one', { ...observation, cves: [], tool: 'zap' }), findingIdentity('one', { ...observation, cves: [] }));
});

test('imports persist provenance, deduplicate across scanners, and preserve explicit reviews', context => {
  const assessment = service(context);
  const input = { campaignId: 'lab', tool: 'nuclei', content: JSON.stringify(nuclei()) };
  const receipt = assessment.importReport(input);
  assert.equal(receipt.findingCount, 1);
  assert.equal(assessment.importReport(input).duplicate, true);
  assessment.importReport({ campaignId: 'lab', tool: 'zap', content: JSON.stringify({ alerts: [zap()] }) });
  let finding = assessment.findings({ campaignId: 'lab' }).items[0];
  assert.equal(finding.observations.length, 2);
  assert.equal(finding.verified, false);
  assert.throws(() => assessment.review({ campaignId: 'lab', id: finding.id, status: 'open', verified: true, note: 'review' }), /require explicit review evidence/);
  assessment.review({ campaignId: 'lab', id: finding.id, status: 'accepted', verified: true, note: 'Fixture review', evidence: 'Local reproduction ticket 42' });
  assessment.importReport({ ...input, content: JSON.stringify(nuclei({ timestamp: 'changed scanner timestamp' })) });
  finding = assessment.findings({ campaignId: 'lab' }).items[0];
  assert.equal(finding.verified, true);
  assert.equal(finding.status, 'accepted');
  assert.equal(finding.observations.length, 3);
  assessment.review({ campaignId: 'lab', id: finding.id, status: 'false-positive', verified: false, note: 'Review revoked' });
  const restarted = service(context, assessment.directory);
  assert.equal(restarted.findings({ campaignId: 'lab' }).items[0].verified, false);
  const report = finding.observations[0].report;
  assert.equal(digest(readBounded(path.join(assessment.directory, report.path))), report.sha256);
  if (process.platform !== 'win32') assert.equal(fs.statSync(path.join(assessment.directory, report.path)).mode & 0o777, 0o600);
  assert.throws(() => assessment.importReport({ ...input, content: JSON.stringify(nuclei()) + '\n{}' }));
  assert.equal(restarted.findings({ campaignId: 'lab' }).total, 1);
  assert.throws(() => assessment.findings({ campaignId: 'lab', limit: 1000 }), /limit/);
});

test('graph is stable across restart, campaign isolated, searchable and path-queryable', context => {
  const assessment = service(context);
  assessment.importReport({ campaignId: 'one', tool: 'nuclei', component: 'Fixture', version: '1.0', content: JSON.stringify(nuclei()) });
  assessment.importReport({ campaignId: 'two', tool: 'nuclei', content: JSON.stringify(nuclei()) });
  assessment.inventoryUpsert({ campaignId: 'one', asset: target, component: 'Fixture', version: '1.0', evidence: 'manifest checksum' });
  const graph = assessment.graph({ campaignId: 'one' });
  assert.deepEqual(service(context, assessment.directory).graph({ campaignId: 'one' }), graph);
  for (const type of ['campaign', 'asset', 'component', 'version', 'cve', 'finding', 'evidence', 'remediation']) assert.ok(graph.nodes.some(node => node.type === type), type);
  const other = assessment.graph({ campaignId: 'two' });
  assert.equal(other.nodes.some(node => graph.nodes.some(first => first.id === node.id)), false);
  assert.equal(other.nodes.some(node => node.type === 'version'), false);
  const from = graph.nodes.find(node => node.type === 'asset').id;
  const to = graph.nodes.find(node => node.type === 'cve').id;
  const route = assessment.graph({ campaignId: 'one', from, to });
  assert.equal(route.path[0], from);
  assert.equal(route.path.at(-1), to);
  assert.equal(route.path.length, 5);
  assert.throws(() => assessment.graph({ campaignId: 'two', from, to }), /must exist in this campaign/);
  assert.equal(assessment.graph({ campaignId: 'one', limit: 1 }).truncated, true);
  assert.ok(assessment.graph({ campaignId: 'one', query: cve }).nodes.some(node => node.type === 'finding'));
  assert.match(graphDot(graph), /^digraph investigation/);
});

test('store refuses corruption, locks, symlinks, and oversized files without replacing evidence', context => {
  const home = directory(context);
  const store = createAssessmentStore(home);
  store.update(state => { state.inventory.fixture = { id: 'fixture' }; });
  assert.ok(createAssessmentStore(home).read().inventory.fixture);
  fs.writeFileSync(path.join(home, 'write.lock'), '{}');
  assert.throws(() => store.update(() => {}), /locked/);
  fs.unlinkSync(path.join(home, 'write.lock'));
  fs.writeFileSync(path.join(home, 'investigations.json'), '{corrupt');
  assert.throws(() => store.update(() => {}), /preserve it/);
  assert.equal(fs.readFileSync(path.join(home, 'investigations.json'), 'utf8'), '{corrupt');
  assert.equal(fs.existsSync(path.join(home, 'write.lock')), false);
  const tiny = path.join(home, 'tiny');
  fs.writeFileSync(tiny, '12345');
  assert.throws(() => readBounded(tiny, 4), /size limit/);
  if (process.platform !== 'win32') {
    fs.unlinkSync(path.join(home, 'investigations.json'));
    fs.symlinkSync(tiny, path.join(home, 'investigations.json'));
    assert.throws(() => store.read(), /symbolic link/);
  }
});

test('plans enforce exact URL scope, canonical local roots, reviewed files and default-off execution', context => {
  const home = directory(context);
  const rules = path.join(home, 'rules.yaml');
  fs.writeFileSync(rules, 'rules: []');
  const settings = config(home);
  assert.equal(assertTargetUrl(target + '/child', settings), target + '/child');
  for (const url of [target + '-other', 'https://other.example.test/app', target + '/../outside', 'https://user:pass@target.example.test/app']) assert.throws(() => assertTargetUrl(url, settings));
  for (const url of ['https://127.0.0.1', 'http://localhost:8080', 'http://127.0.0.1/?key=secret']) assert.throws(() => loopbackUrl(url));
  assert.equal(scopedPath(rules, [home], 'rules', true), rules);
  assert.throws(() => scopedPath(os.homedir(), [home], 'target'), /outside/);
  if (process.platform !== 'win32') {
    fs.symlinkSync(os.homedir(), path.join(home, 'escape'));
    assert.throws(() => scopedPath(path.join(home, 'escape'), [home], 'target'), /outside/);
  }
  const plan = buildAssessmentPlan({ tool: 'nuclei', campaignId: 'lab', target, templates: rules }, settings, home);
  assert.ok(plan.args.includes('-no-interactsh'));
  assert.ok(plan.args.includes('-disable-redirects'));
  assert.equal(plan.args[0], '-config');
  assert.ok(plan.args.includes(path.join(home, 'scanner-config/nuclei.yaml')));
  const semgrep = buildAssessmentPlan({ tool: 'semgrep', campaignId: 'lab', target: home, rules }, settings, home);
  assert.deepEqual(semgrep.args.slice(0, 6), ['scan', '--json', '--metrics', 'off', '--disable-version-check', '--config']);
  const trivy = buildAssessmentPlan({ tool: 'trivy', campaignId: 'lab', target: home }, settings, home);
  assert.ok(trivy.args.includes('--offline-scan'));
  assert.ok(trivy.args.includes('--skip-db-update'));
  const assessment = service(context, home);
  const saved = assessment.plan({ tool: 'zap', campaignId: 'lab', target });
  assert.throws(() => assessment.start({ planId: saved.id }), /Execution is disabled/);
});

test('bounded subprocess runner handles success, nonzero exits, caps, timeout and cancellation with Node fixtures only', async () => {
  const plan = { command: process.execPath, args: ['-e', 'process.stdout.write("fixture");process.stderr.write("notice")'], timeoutMs: 5000, maxOutputBytes: 1024 };
  const result = await runBounded(plan);
  assert.equal(result.stdout.toString(), 'fixture');
  assert.equal(result.stderr.toString(), 'notice');
  assert.equal((await runBounded({ ...plan, args: ['-e', 'process.exit(7)'] })).exitCode, 7);
  await assert.rejects(runBounded({ ...plan, args: ['-e', 'process.stdout.write("x".repeat(10000))'] }), /output limit/);
  await assert.rejects(runBounded({ ...plan, args: ['-e', 'setInterval(()=>{},1000)'], timeoutMs: 60 }), /timeout/);
  const controller = new AbortController();
  const cancelled = runBounded({ ...plan, args: ['-e', 'setInterval(()=>{},1000)'] }, { signal: controller.signal });
  controller.abort();
  await assert.rejects(cancelled, /cancelled/);
  const envResult = await runBounded({ ...plan, args: ['-e', 'process.stdout.write(String(process.env.FUJIANG_ZAP_API_KEY))'] });
  assert.equal(envResult.stdout.toString(), 'undefined');
});

test('ZAP collector pages local alerts and puts authentication only in headers', async context => {
  const pages = [];
  const url = await server(context, (request, response) => {
    const parsed = new URL(request.url, 'http://127.0.0.1');
    assert.equal(request.headers['x-zap-api-key'], 'fixture-key');
    assert.equal(request.url.includes('fixture-key'), false);
    pages.push(parsed.searchParams.get('start'));
    json(response, { alerts: parsed.searchParams.get('start') === '0' ? Array.from({ length: 500 }, () => zap()) : [] });
  });
  const result = await collectZapAlerts({ apiUrl: url, target, timeoutMs: 3000, maxOutputBytes: 1024 * 1024 }, { apiKey: 'fixture-key' });
  assert.deepEqual(pages, ['0', '500']);
  assert.equal(JSON.parse(result.stdout).alerts.length, 500);
});

test('engine executes only a fresh saved plan and preserves candidate evidence without sending target traffic', async context => {
  const url = await server(context, (request, response) => json(response, { alerts: [zap()] }));
  const home = directory(context);
  config(home, { executionEnabled: true, zapApiUrl: url });
  const assessment = service(context, home);
  const saved = assessment.plan({ tool: 'zap', campaignId: 'lab', target });
  const job = assessment.start({ planId: saved.id });
  const result = await assessment.settled(job.id);
  assert.equal(result.status, 'completed', result.error);
  assert.equal(result.result.findingCount, 1);
  assert.equal(assessment.findings({ campaignId: 'lab' }).items[0].verified, false);
  config(home, { executionEnabled: true, zapApiUrl: url, rateLimit: 3 });
  assert.throws(() => assessment.start({ planId: saved.id }), /stale or modified/);
  const fresh = assessment.plan({ tool: 'zap', campaignId: 'lab', target });
  createAssessmentStore(home).update(state => { state.runs[fresh.id].recipe.target = 'https://other.example.test/'; });
  assert.throws(() => assessment.start({ planId: fresh.id }), /stale or modified/);
});

test('out-of-scope ZAP observations fail the run without importing a partial report', async context => {
  const url = await server(context, (request, response) => json(response, { alerts: [zap(), zap({ url: 'https://other.example.test/' })] }));
  const home = directory(context);
  config(home, { executionEnabled: true, zapApiUrl: url });
  const assessment = service(context, home);
  const saved = assessment.plan({ tool: 'zap', campaignId: 'lab', target });
  const result = await assessment.settled(assessment.start({ planId: saved.id }).id);
  assert.equal(result.status, 'failed');
  assert.match(result.error, /outside/);
  assert.ok(result.stdout.sha256);
  assert.equal(assessment.findings({ campaignId: 'lab' }).total, 0);
});

test('execution slots are cross-session and cancellation stops queued local jobs', async context => {
  const url = await server(context, (request, response) => { setTimeout(() => json(response, { alerts: [] }), 100); });
  const home = directory(context);
  config(home, { executionEnabled: true, zapApiUrl: url, maxConcurrent: 1 });
  const assessment = service(context, home);
  const saved = assessment.plan({ tool: 'zap', campaignId: 'lab', target });
  fs.writeFileSync(path.join(home, 'execution-0.lock'), JSON.stringify({ pid: process.pid }));
  const blocked = await assessment.settled(assessment.start({ planId: saved.id }).id);
  assert.equal(blocked.status, 'failed');
  assert.match(blocked.error, /slots are occupied/);
  fs.unlinkSync(path.join(home, 'execution-0.lock'));
  const first = assessment.start({ planId: saved.id });
  const second = assessment.start({ planId: saved.id });
  assessment.cancel({ id: second.id });
  assert.equal((await assessment.settled(first.id)).status, 'completed');
  assert.equal((await assessment.settled(second.id)).status, 'cancelled');
  assert.equal(fs.existsSync(path.join(home, 'execution-0.lock')), false);
});

test('MCP protocol exposes actual shared tools and explicit errors without scanners or models', context => {
  const home = directory(context);
  const requests = [
    { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18' } },
    { jsonrpc: '2.0', method: 'notifications/initialized' },
    { jsonrpc: '2.0', id: 2, method: 'tools/list' },
    { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'assessment_capabilities', arguments: {} } },
    { jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'kb_search', arguments: { query: 7 } } },
    { jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'unknown' } },
  ];
  const result = spawnSync(process.execPath, [cli, 'mcp', '--home', home], { encoding: 'utf8', timeout: 10000,
    env: { ...process.env, FUJIANG_EMBEDDING_MODEL: '' }, input: requests.map(item => JSON.stringify(item)).join('\n') + '\n' });
  assert.equal(result.status, 0, result.stderr);
  const replies = result.stdout.trim().split('\n').map(line => JSON.parse(line));
  assert.equal(replies.length, 5);
  assert.equal(replies[0].result.protocolVersion, '2025-06-18');
  assert.ok(replies[1].result.tools.some(tool => tool.name === 'investigation_graph'));
  assert.equal(JSON.parse(replies[2].result.content[0].text).executionEnabled, false);
  assert.equal(replies[3].result.isError, true);
  assert.equal(replies[4].error.code, -32602);
});

test('native Harness descriptors and tool input validation use the same assessment engine', async context => {
  const assessment = service(context);
  const registered = [];
  const ctx = { get() { return { import: async () => ({ defineTool: value => value }) }; },
    inject(dependencies, callback) { callback({ tools: { register: value => registered.push(value) } }); return Promise.resolve(); } };
  const result = await registerAutomationTools(ctx, { advancedTools: assessmentHarnessTools(assessment) });
  assert.equal(result.ok, true);
  assert.equal(result.registered.length, 6 + assessmentTools(assessment).length);
  const tool = registered.find(item => item.name === 'assessment_plan');
  assert.equal(tool.parameters.target.required, true);
  assert.equal((await registered.find(item => item.name === 'assessment_capabilities').execute({})).executionEnabled, false);
  await assert.rejects(invokeAssessmentTool(assessment, 'kb_search', { query: 'fixture', command: 'arbitrary' }), /Unknown argument/);
  await assert.rejects(invokeAssessmentTool(assessment, 'assessment_findings', { campaignId: 'lab', limit: 1.5 }), /integer bounds/);
});

test('OpenCode tools installation contains a self-contained offline assessment runtime', context => {
  const home = directory(context);
  const result = spawnSync(process.execPath, [path.join(root, 'scripts/install.mjs'), 'opencode', '--config-dir', home, '--with-tools'], { encoding: 'utf8', timeout: 30000 });
  assert.equal(result.status, 0, result.stderr);
  const settings = JSON.parse(fs.readFileSync(path.join(home, 'opencode.json'), 'utf8'));
  const command = settings.mcp.servers.fujiang_assessment.command;
  assert.equal(command[0], process.execPath);
  assert.ok(fs.existsSync(path.join(home, 'fujiang-runtime/plugin/knowledge/affected-versions.json')));
  const search = spawnSync(command[0], [command[1], 'search', '--home', path.join(home, 'data'), '--json', '{"query":"triage","limit":1}'], {
    encoding: 'utf8', timeout: 10000, env: { ...process.env, FUJIANG_EMBEDDING_MODEL: '' },
  });
  assert.equal(search.status, 0, search.stderr);
  assert.equal(JSON.parse(search.stdout).corpusSize, 300);
});
