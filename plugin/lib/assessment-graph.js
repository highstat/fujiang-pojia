import { identifier, requireText } from './assessment-store.js';

export function investigationGraph(state, options) {
  const campaignId = requireText(options?.campaignId, 'campaignId', 120);
  const nodes = new Map();
  const edges = new Map();
  function node(type, key, label, data = {}) {
    const id = identifier(type, campaignId, key);
    if (!nodes.has(id)) nodes.set(id, { id, type, label: String(label).slice(0, 500), campaignId, data });
    return id;
  }
  function edge(from, to, type) {
    const id = identifier('edge', from, to, type);
    edges.set(id, { id, from, to, type });
  }
  const root = node('campaign', campaignId, campaignId);
  function inventory(asset, component, version) {
    const assetId = node('asset', asset, asset);
    edge(root, assetId, 'includes');
    let previous = assetId;
    if (component) {
      const componentId = node('component', [asset, component], component);
      edge(previous, componentId, 'has_component');
      previous = componentId;
      if (version) {
        const versionId = node('version', [asset, component, version], version, { component });
        edge(previous, versionId, 'has_observed_version');
        previous = versionId;
      }
    }
    return previous;
  }
  for (const item of Object.values(state.inventory).filter(item => item.campaignId === campaignId)) {
    const last = inventory(item.asset, item.component, item.version);
    if (item.evidence) {
      const evidence = node('evidence', ['inventory', item.id], 'Inventory evidence', { note: item.evidence, source: 'operator' });
      edge(last, evidence, 'supported_by');
    }
  }
  for (const finding of Object.values(state.findings).filter(item => item.campaignId === campaignId)) {
    const last = inventory(finding.asset, finding.component, finding.version);
    const findingId = node('finding', finding.id, finding.title, { findingId: finding.id, severity: finding.severity,
      status: finding.status, verified: finding.verified, location: finding.location, parameter: finding.parameter });
    edge(last, findingId, finding.verified ? 'has_reviewed_finding' : 'has_candidate');
    for (const cve of finding.cves) edge(findingId, node('cve', cve, cve), 'scanner_references');
    for (const observation of finding.observations) {
      const evidence = node('evidence', observation.id, observation.tool + ': ' + observation.rule,
        { sha256: observation.report.sha256, path: observation.report.path,
          observationIndex: observation.pointer, parserVersion: 1, tool: observation.tool });
      edge(findingId, evidence, 'reported_by');
      if (observation.remediation) {
        const remediation = node('remediation', [finding.id, observation.remediation], observation.remediation,
          { text: observation.remediation, source: observation.tool });
        edge(evidence, remediation, 'suggests_remediation');
        edge(findingId, remediation, 'has_proposed_remediation');
      }
    }
    if (finding.review?.evidence) edge(findingId, node('evidence', ['review', finding.id], 'Review evidence', finding.review), 'reviewed_with');
  }
  const allEdges = [...edges.values()];
  let selected;
  let pathResult = null;
  if (options.from || options.to) {
    if (!nodes.has(options.from) || !nodes.has(options.to)) throw new Error('Both graph node IDs must exist in this campaign.');
    const adjacency = new Map();
    for (const item of allEdges) {
      if (!adjacency.has(item.from)) adjacency.set(item.from, []);
      adjacency.get(item.from).push(item.to);
      if (options.direction !== 'out') {
        if (!adjacency.has(item.to)) adjacency.set(item.to, []);
        adjacency.get(item.to).push(item.from);
      }
    }
    const parents = new Map([[options.from, null]]);
    const queue = [options.from];
    for (let index = 0; index < queue.length && !parents.has(options.to); index++) {
      if (queue.length > 50000) throw new Error('Graph traversal limit reached; narrow the campaign.');
      for (const next of adjacency.get(queue[index]) || []) if (!parents.has(next)) { parents.set(next, queue[index]); queue.push(next); }
    }
    pathResult = [];
    if (parents.has(options.to)) for (let current = options.to; current !== null; current = parents.get(current)) pathResult.unshift(current);
    selected = pathResult.map(id => nodes.get(id));
  } else if (options.query) {
    const query = requireText(options.query, 'graph query', 500).toLowerCase();
    const ids = new Set([...nodes.values()].filter(item => (item.type + ' ' + item.label).toLowerCase().includes(query)).map(item => item.id));
    const seeds = new Set(ids);
    for (const item of allEdges) if (seeds.has(item.from) || seeds.has(item.to)) { ids.add(item.from); ids.add(item.to); }
    selected = [...nodes.values()].filter(item => ids.has(item.id));
  } else selected = [...nodes.values()];
  const limit = Math.max(1, Math.min(500, Number(options.limit) || 150));
  const matchedNodes = selected.length;
  selected = selected.slice(0, limit);
  const selectedIds = new Set(selected.map(item => item.id));
  return { campaignId, nodes: selected, edges: allEdges.filter(item => selectedIds.has(item.from) && selectedIds.has(item.to)),
    totalNodes: nodes.size, totalEdges: edges.size, matchedNodes, truncated: matchedNodes > limit,
    ...(pathResult ? { path: pathResult, pathTruncated: pathResult.length > limit } : {}) };
}

export function graphDot(graph) {
  return ['digraph investigation {', ...graph.nodes.map(node => '  ' + JSON.stringify(node.id) + ' [label=' + JSON.stringify(node.type + ': ' + node.label) + '];'),
    ...graph.edges.map(edge => '  ' + JSON.stringify(edge.from) + ' -> ' + JSON.stringify(edge.to) + ' [label=' + JSON.stringify(edge.type) + '];'), '}'].join('\n') + '\n';
}
