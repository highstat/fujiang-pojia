#!/usr/bin/env node
import path from 'node:path';
import { createAssessmentService } from '../plugin/lib/assessment.js';
import { invokeAssessmentTool } from '../plugin/lib/assessment-tools.js';
import { serveAssessmentMcp } from '../plugin/lib/assessment-mcp.js';
import { graphDot } from '../plugin/lib/assessment-graph.js';
import { readBounded } from '../plugin/lib/assessment-store.js';

const aliases = { capabilities: 'assessment_capabilities', plan: 'assessment_plan', run: 'assessment_run', status: 'assessment_status',
  cancel: 'assessment_cancel', import: 'assessment_import', findings: 'assessment_findings', review: 'assessment_review',
  inventory: 'inventory_upsert', graph: 'investigation_graph', search: 'kb_search', index: 'knowledge_index' };
let service;
try {
  const argv = process.argv.slice(2);
  const command = argv.shift();
  const flags = {};
  while (argv.length) {
    const flag = argv.shift();
    if (!['--home', '--request', '--json', '--wait', '--execute', '--dot'].includes(flag) || Object.hasOwn(flags, flag)) throw new Error('Unknown or repeated option: ' + flag);
    flags[flag] = ['--wait', '--execute', '--dot'].includes(flag) ? true : argv.shift();
    if (flags[flag] === undefined || typeof flags[flag] === 'string' && flags[flag].startsWith('--')) throw new Error('Missing value for ' + flag);
  }
  if (command !== 'mcp' && !aliases[command]) throw new Error('Usage: node scripts/assessment.mjs <' + Object.keys(aliases).join('|') + '|mcp> [--home PATH] [--request JSON_FILE | --json JSON] [--wait] [--execute] [--dot]');
  if (flags['--request'] && flags['--json']) throw new Error('Use either --request or --json.');
  if (command === 'run' && !flags['--execute']) throw new Error('CLI runs require --execute in addition to operator-enabled config.');
  const args = JSON.parse(flags['--request'] ? readBounded(path.resolve(flags['--request']), 1024 * 1024).toString('utf8') : flags['--json'] || '{}');
  service = createAssessmentService({ directory: flags['--home'] ? path.resolve(flags['--home']) : undefined });
  const shutdown = () => { void service.dispose().then(() => process.exit(130), () => process.exit(1)); };
  process.once('SIGINT', shutdown);
  process.once('SIGTERM', shutdown);
  if (command === 'mcp') await serveAssessmentMcp(service);
  else {
    let result = await invokeAssessmentTool(service, aliases[command], args);
    if (['run', 'index'].includes(command)) result = await service.settled(result.id);
    process.stdout.write(flags['--dot'] && command === 'graph' ? graphDot(result) : JSON.stringify(result, null, 2) + '\n');
    if (['failed', 'cancelled', 'interrupted'].includes(result.status)) process.exitCode = 1;
  }
} catch (error) { process.stderr.write('Assessment: ' + error.message + '\n'); process.exitCode = 1; }
finally { await service?.dispose(); }
