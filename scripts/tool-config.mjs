import fs from 'node:fs';
import path from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { CONTEXT7_URL, REA_VERSION } from '../plugin/lib/tool-integrations.js';

function object(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(label + ' must be an object.');
  return value;
}

export function openCodeToolEntry(root, environment = process.env) {
  if (fs.existsSync(path.join(root, 'opencode.jsonc'))) {
    throw new Error('--with-tools does not rewrite JSONC. Merge the MCP example from docs/tool-integrations.md manually, or use a separate --project directory.');
  }
  const destination = path.join(root, 'opencode.json');
  if (fs.existsSync(destination) && fs.lstatSync(destination).isSymbolicLink()) {
    throw new Error('Refusing to read a symbolic-link MCP configuration.');
  }
  let existing = {};
  if (fs.existsSync(destination)) {
    try { existing = object(JSON.parse(fs.readFileSync(destination, 'utf8')), 'OpenCode configuration'); }
    catch { throw new Error('OpenCode configuration must be a valid JSON object; no files were changed.'); }
  }
  const mcp = object(existing.mcp ?? {}, 'mcp');
  const servers = object(mcp.servers ?? {}, 'mcp.servers');
  const requested = {
    fujiang_context7: {
      type: 'remote', url: CONTEXT7_URL, oauth: false,
      ...(environment.CONTEXT7_API_KEY?.trim() ? { headers: { Authorization: 'Bearer {env:CONTEXT7_API_KEY}' } } : {}),
    },
    fujiang_rea: {
      type: 'local', command: ['npx', '-y', 'rea-agents@' + REA_VERSION, '--mcp'],
      environment: { REA_MCP_OUTPUT_SCHEMA_PROFILE: 'off' },
      timeout: { startup: 120000, execution: 60000 },
    },
    fujiang_assessment: {
      type: 'local', command: [process.execPath, path.resolve(root, 'fujiang-runtime/scripts/assessment.mjs'), 'mcp'],
      timeout: { startup: 30000, execution: 120000 },
    },
  };
  for (const [name, configuration] of Object.entries(requested)) {
    if (Object.hasOwn(mcp, name) || Object.hasOwn(servers, name) && !isDeepStrictEqual(servers[name], configuration)) {
      throw new Error('MCP server name conflicts with an existing configuration: ' + name + '. No files were changed.');
    }
  }
  return { destination, content: JSON.stringify({ ...existing, mcp: { ...mcp, servers: { ...servers, ...requested } } }, null, 2) + '\n' };
}
