const text = (description, maxLength = 4000) => ({ type: 'string', description, minLength: 1, maxLength });
const campaignId = text('Persistent investigation namespace; use the existing campaign ID when linking a Harness campaign.', 120);
const integer = (maximum, minimum = 1) => ({ type: 'integer', minimum, maximum });
const object = (properties, required = []) => ({ type: 'object', properties, required, additionalProperties: false });

export function assessmentTools(service) {
  const definition = (name, description, properties, required, method) => ({ name, description,
    inputSchema: object(properties, required), execute: args => service[method](args) });
  return [
    definition('assessment_capabilities', 'Inspect assessment capabilities and execution gate without starting scanners.', {}, [], 'capabilities'),
    definition('assessment_plan', 'Prepare a bounded scanner plan using operator-controlled scope and reviewed local rules. Does not run it.', {
      campaignId, tool: { type: 'string', enum: ['nuclei', 'zap', 'semgrep', 'trivy'] }, target: text('Allowed URL or local directory'),
      templates: text('One reviewed local Nuclei template file'), rules: text('One reviewed local Semgrep rule file'),
    }, ['campaignId', 'tool', 'target'], 'plan'),
    definition('assessment_run', 'Queue a saved plan. Requires operator-enabled execution. Returns immediately; poll assessment_status. ZAP collects existing alerts only.', {
      planId: text('Saved plan ID', 100),
    }, ['planId'], 'start'),
    definition('assessment_status', 'Read persisted run/plan status; interrupted runs are not automatically replayed.', { id: text('Run or plan ID', 100) }, ['id'], 'status'),
    definition('assessment_cancel', 'Cancel a queued/running job owned by this live service instance.', { id: text('Run ID', 100) }, ['id'], 'cancel'),
    definition('assessment_import', 'Import an existing scanner JSON/JSONL report, preserve evidence, and deduplicate candidates. Does not scan or verify findings.', {
      campaignId, tool: { type: 'string', enum: ['nuclei', 'zap', 'semgrep', 'trivy'] }, file: text('Absolute path to a local JSON/JSONL report'),
      asset: text('Asset context for filesystem reports'), component: text('Known component when missing from scanner output', 500),
      version: text('Observed version when missing from scanner output', 200),
    }, ['campaignId', 'tool', 'file'], 'importReport'),
    definition('assessment_findings', 'List normalized findings and scanner evidence within one investigation.', {
      campaignId, offset: integer(20000, 0), limit: integer(200),
    }, ['campaignId'], 'findings'),
    definition('assessment_review', 'Record an explicit evidence-backed operator review. Reimports never silently promote candidates to verified.', {
      campaignId, id: text('Finding ID', 100), status: { type: 'string', enum: ['open', 'fixed', 'accepted', 'false-positive'] },
      verified: { type: 'boolean' }, note: text('Review rationale', 8000), evidence: text('Verification evidence, required when verified is true', 16000),
    }, ['campaignId', 'id', 'status', 'verified', 'note'], 'review'),
    definition('inventory_upsert', 'Persist an observed asset/component/version with provenance; no fingerprint is treated as a confirmed vulnerability.', {
      campaignId, asset: text('Asset'), component: text('Observed component', 500), version: text('Observed version', 200), evidence: text('Inventory evidence', 16000),
    }, ['campaignId', 'asset', 'component', 'evidence'], 'inventoryUpsert'),
    definition('investigation_graph', 'Query the persistent investigation graph, one-hop text neighborhoods, or shortest paths between node IDs.', {
      campaignId, query: text('Node label/type query', 500), from: text('Start node ID', 100), to: text('End node ID', 100),
      direction: { type: 'string', enum: ['out', 'both'] }, limit: integer(500),
    }, ['campaignId'], 'graph'),
    definition('kb_search', 'Search full document bodies using BM25 plus optional local embeddings. Returns actual semantic status and conservative CNA version applicability.', {
      query: text('Search terms or natural-language question', 2000), limit: integer(50), filters: object({
        category: text('Exact category', 100), kind: text('Exact entry kind', 100), severity: text('Exact severity', 30),
        cve: text('Exact CVE', 40), product: text('Product; exact CNA name for version evaluation', 500), version: text('Observed version', 200),
        configuration: { type: 'array', maxItems: 20, items: text('Required configuration text; not live attestation', 200) }, kev: { type: 'boolean' },
      }),
    }, ['query'], 'search'),
    definition('knowledge_index', 'Queue embeddings for the local corpus using an already installed local Ollama model. No model downloads; semantic indexing is explicit.', {}, [], 'index'),
  ];
}

export function validateToolInput(schema, value, label = 'arguments') {
  if (schema.type === 'object') {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(label + ' must be an object.');
    for (const key of schema.required || []) if (value[key] === undefined) throw new Error(label + '.' + key + ' is required.');
    for (const [key, item] of Object.entries(value)) {
      if (!Object.hasOwn(schema.properties, key)) throw new Error('Unknown argument: ' + label + '.' + key);
      validateToolInput(schema.properties[key], item, label + '.' + key);
    }
  } else if (schema.type === 'array') {
    if (!Array.isArray(value) || value.length > schema.maxItems) throw new Error(label + ' exceeds array bounds.');
    for (const item of value) validateToolInput(schema.items, item, label);
  } else if (schema.type === 'string') {
    if (typeof value !== 'string' || (schema.minLength && !value.trim()) || value.length > (schema.maxLength ?? 4000)) throw new Error(label + ' must be a bounded non-empty string.');
  } else if (schema.type === 'boolean') {
    if (typeof value !== 'boolean') throw new Error(label + ' must be boolean.');
  } else if (schema.type === 'integer') {
    if (!Number.isInteger(value) || value < schema.minimum || value > schema.maximum) throw new Error(label + ' is outside integer bounds.');
  }
  if (schema.enum && !schema.enum.includes(value)) throw new Error('Unsupported value for ' + label);
}

export async function invokeAssessmentTool(service, name, args = {}) {
  const tool = assessmentTools(service).find(item => item.name === name);
  if (!tool) throw new Error('Unknown assessment tool: ' + name);
  validateToolInput(tool.inputSchema, args);
  return tool.execute(args);
}

function harnessSchema(schema) {
  if (schema.type !== 'object') return schema;
  const result = { ...schema, properties: Object.fromEntries(Object.entries(schema.properties).map(([key, value]) => [key,
    { ...harnessSchema(value), ...((schema.required || []).includes(key) ? { required: true } : {}) }])) };
  delete result.required;
  return result;
}

export function assessmentHarnessTools(service) {
  return assessmentTools(service).map(tool => ({ name: tool.name, description: tool.description,
    parameters: harnessSchema(tool.inputSchema).properties,
    output: { schema: { type: 'object', additionalProperties: true }, render: (args, result) => [{ type: 'text', text: JSON.stringify(result).slice(0, 16000) }] },
    execute: args => invokeAssessmentTool(service, tool.name, args),
  }));
}
