import { identifier, requireText } from './assessment-store.js';

export const SCANNERS = Object.freeze(['nuclei', 'zap', 'semgrep', 'trivy']);
export const SEVERITIES = Object.freeze(['info', 'low', 'medium', 'high', 'critical']);
const text = (value, limit = 8000) => String(value ?? '').slice(0, limit);
const list = value => value === undefined || value === null ? [] : Array.isArray(value) ? value : [value];
const cves = value => [...new Set((JSON.stringify(value) || '').toUpperCase().match(/CVE-\d{4}-\d{4,}/g) || [])].sort();
const severity = value => ({ information: 'info', informational: 'info', warning: 'medium', error: 'high', note: 'info', unknown: 'info' }[String(value).toLowerCase()]
  || (SEVERITIES.includes(String(value).toLowerCase()) ? String(value).toLowerCase() : 'info'));

export function canonicalAsset(value) {
  const target = requireText(value, 'asset', 4000);
  if (/^https?:\/\//i.test(target)) {
    const url = new URL(target);
    if (url.username || url.password) throw new Error('Targets must not contain embedded credentials.');
    url.hash = '';
    const keys = [...new Set(url.searchParams.keys())].sort();
    url.search = '';
    for (const key of keys) url.searchParams.append(key, '');
    return url.href;
  }
  return target.replace(/\\/g, '/');
}

function record(tool, raw, index, options) {
  const common = { tool, pointer: index, component: '', version: '', location: '', parameter: '', cves: [],
    references: [], remediation: '', evidence: '', description: '', severity: 'info' };
  let item;
  if (tool === 'nuclei') {
    if (!raw || typeof raw !== 'object' || !raw.info || !raw['template-id']) throw new Error('Invalid Nuclei JSONL record.');
    item = { rule: raw['template-id'], title: raw.info.name, asset: raw['matched-at'] || raw.host || options.asset,
      severity: raw.info.severity, cves: cves(raw.info.classification?.['cve-id'] || raw['template-id']),
      description: raw.info.description, remediation: raw.info.remediation,
      references: list(raw.info.reference), evidence: list(raw['extracted-results']).join('\n') };
  } else if (tool === 'zap') {
    item = { rule: raw.pluginId || raw.pluginid || raw.alertRef || raw.alertref, title: raw.alert || raw.name,
      asset: raw.url || raw.uri || options.asset, parameter: raw.param, severity: ['info', 'low', 'medium', 'high'][Number(raw.riskcode ?? raw.risk)] || raw.riskdesc?.split(' ')[0] || raw.risk,
      cves: cves([raw.cve, raw.reference]), description: raw.desc || raw.description, remediation: raw.solution,
      references: list(raw.reference), evidence: raw.evidence || raw.attack };
  } else if (tool === 'semgrep') {
    if (!raw.check_id || !raw.path || !raw.extra) throw new Error('Invalid Semgrep result.');
    item = { rule: raw.check_id, title: raw.extra.message || raw.check_id, asset: options.asset || 'source:' + raw.path,
      location: raw.path + ':' + (raw.start?.line || 1), severity: raw.extra.severity,
      cves: cves(raw.extra.metadata?.cve), description: raw.extra.message,
      references: list(raw.extra.metadata?.references), remediation: raw.extra.fix || raw.extra.metadata?.remediation,
      evidence: raw.extra.lines || raw.extra.message };
  } else {
    item = { rule: raw.VulnerabilityID || raw.ID || raw.AVDID, title: raw.Title || raw.VulnerabilityID || raw.ID,
      asset: options.asset || 'artifact:' + raw._target, component: raw.PkgName || raw._type || '',
      version: raw.InstalledVersion || '', location: raw.PkgPath || raw._target,
      severity: raw.Severity, cves: cves(raw.VulnerabilityID), description: raw.Description,
      references: list(raw.References).concat(raw.PrimaryURL || []),
      remediation: raw.FixedVersion ? 'Upgrade to a supported fixed version: ' + raw.FixedVersion : raw.Resolution,
      evidence: raw.Message || [raw.PkgName, raw.InstalledVersion, raw.Status].filter(Boolean).join(' ') };
  }
  const result = { ...common, ...item };
  result.rule = requireText(String(result.rule || ''), 'scanner rule', 500);
  result.title = text(result.title || result.rule, 500);
  result.asset = canonicalAsset(result.asset);
  result.severity = severity(result.severity);
  result.references = [...new Set(result.references.map(value => text(value, 2000)))].slice(0, 40);
  for (const key of ['component', 'version', 'location', 'parameter', 'description', 'remediation', 'evidence']) result[key] = text(result[key]);
  return result;
}

export function parseScannerReport(tool, content, options = {}) {
  if (!SCANNERS.includes(tool)) throw new Error('Unsupported scanner: ' + tool);
  const textContent = Buffer.isBuffer(content) ? content.toString('utf8') : String(content);
  let records;
  const warnings = [];
  if (tool === 'nuclei') {
    records = textContent.trim() ? textContent.trim().split(/\r?\n/).map((line, index) => {
      try { return JSON.parse(line); } catch { throw new Error('Invalid Nuclei JSONL at line ' + (index + 1)); }
    }) : [];
  } else {
    let report;
    try { report = JSON.parse(textContent); } catch { throw new Error('Invalid scanner JSON report.'); }
    if (!report || typeof report !== 'object' || Array.isArray(report)) throw new Error('Expected a scanner report object.');
    if (tool === 'semgrep') {
      if (!Array.isArray(report.results)) throw new Error('Semgrep report must include results.');
      records = report.results;
      if (report.errors?.length) warnings.push('Semgrep reported ' + report.errors.length + ' errors; coverage is incomplete.');
    } else if (tool === 'trivy') {
      if (!Array.isArray(report.Results)) throw new Error('Trivy report must include Results.');
      records = report.Results.flatMap(result => {
        if (!result || typeof result !== 'object') throw new Error('Invalid Trivy result.');
        const configurations = list(result.Misconfigurations).filter(item => item.Status === undefined || String(item.Status).toUpperCase() === 'FAIL');
        return [...list(result.Vulnerabilities), ...configurations].map(item => ({ ...item, _target: result.Target, _type: result.Type }));
      });
      if (report.Results.some(result => result.Secrets?.length)) warnings.push('Secret findings are not imported by this connector; keep the original report private.');
    } else if (Array.isArray(report.alerts)) records = report.alerts;
    else if (Array.isArray(report.site)) records = report.site.flatMap(site => list(site.alerts).flatMap(alert => {
      const instances = list(alert.instances);
      return (instances.length ? instances : [{}]).map(instance => ({ ...alert, ...instance,
        url: instance.uri || instance.url || site['@name'] }));
    }));
    else throw new Error('ZAP report must include alerts or site.');
  }
  if (records.length > 10000) throw new Error('Report contains more than 10000 observations; split it before import.');
  return { observations: records.map((raw, index) => record(tool, raw, index, options)), warnings };
}

export function findingIdentity(campaignId, observation) {
  return identifier('f', campaignId, observation.asset, observation.component, observation.version,
    observation.location, observation.parameter,
    observation.cves.length ? observation.cves : [observation.tool, observation.rule]);
}
