import fs from 'node:fs';
import path from 'node:path';

export const KNOWLEDGE_CATEGORIES = Object.freeze([
  'java-deser', 'java-web', 'edge-device', 'exchange-ad', 'web-cms',
  'linux-priv', 'cloud-container', 'gray-market', 'triage', 'red-team', 'blue-team',
]);
export const WORKFLOW_CATEGORIES = Object.freeze(['triage', 'red-team', 'blue-team']);
export const KNOWLEDGE_VERSION = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;
export const ENTRY_HEADINGS = Object.freeze([
  'Fingerprinting', 'Prerequisites', 'PoC', 'Exploitation Steps', 'Remediation and Mitigation', 'References',
]);
export const ENTRY_KINDS = Object.freeze(['cve', 'implementation', 'configuration', 'business-logic', 'workflow']);
export const ENTRY_FIELDS = Object.freeze([
  'id', 'title', 'kind', 'cve', 'related-cves', 'cve-note', 'severity', 'cvss', 'severity-basis', 'severity-note',
  'product', 'versions', 'ports', 'keywords', 'entry', 'verified', 'verified-on', 'verification-evidence',
  'source-url', 'vendor-advisory', 'cwe', 'patch-date', 'sources',
  'kev', 'kev-date', 'kev-source', 'epss', 'epss-percentile', 'epss-date', 'epss-source', 'enrichment-updated',
]);
const FRONTMATTER = /^(?:\uFEFF)?---\r?\n([\s\S]*?)\r?\n---(?:\r?\n|$)/;
const CVE = /^CVE-\d{4}-\d{4,}$/;

function parseScalar(value) {
  const text = value.trim();
  if (text.startsWith('"')) return JSON.parse(text);
  if (text.startsWith("'") && text.endsWith("'")) return text.slice(1, -1).replaceAll("''", "'");
  if (/^[\[{]/.test(text) || ['|', '>'].includes(text)) throw new Error('Nested or multiline frontmatter values are not supported');
  if (text === 'null' || text === '~') return null;
  if (text === 'true') return true;
  if (text === 'false') return false;
  if (/^-?\d+(?:\.\d+)?$/.test(text)) return Number(text);
  return text;
}

export function parseKnowledgeDocument(markdown) {
  const match = FRONTMATTER.exec(markdown);
  if (!match) return { fields: {}, body: markdown, hasFrontmatter: false };
  const fields = {};
  for (const line of match[1].split(/\r?\n/)) {
    if (!line.trim() || line.trimStart().startsWith('#')) continue;
    const field = /^([a-z][a-z0-9-]*):\s*(.*)$/.exec(line);
    if (!field) throw new Error('Expected flat frontmatter key: value, got: ' + line);
    if (Object.hasOwn(fields, field[1])) throw new Error('Duplicate frontmatter field: ' + field[1]);
    fields[field[1]] = parseScalar(field[2]);
  }
  return { fields, body: markdown.slice(match[0].length), hasFrontmatter: true };
}

export function serializeKnowledgeDocument(fields, body, eol = '\n', bom = '') {
  const header = Object.entries(fields).map(([key, value]) => key + ': ' + JSON.stringify(value)).join(eol);
  return bom + '---' + eol + header + eol + '---' + eol + body;
}

export function knowledgeFiles(root) {
  return KNOWLEDGE_CATEGORIES.flatMap((category) => fs.readdirSync(path.join(root, category), { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith('.md') && entry.name.toLowerCase() !== 'skill.md')
    .map((entry) => ({ category, file: entry.name, path: path.join(root, category, entry.name) })))
    .sort((left, right) => left.path.localeCompare(right.path));
}

export function outsideFences(markdown, transform) {
  let fence = null;
  return markdown.split(/(?<=\n)/).map((line) => {
    const marker = /^\s{0,3}(`{3,}|~{3,})/.exec(line);
    if (marker) {
      if (!fence) fence = marker[1];
      else if (marker[1][0] === fence[0] && marker[1].length >= fence.length
        && /^\s{0,3}(?:`{3,}|~{3,})[ \t]*\r?\n?$/.test(line)) fence = null;
      return line;
    }
    return fence ? line : transform(line);
  }).join('');
}

export function documentHeadings(body) {
  const headings = [];
  outsideFences(body, (line) => {
    const match = /^##\s+(.+?)\s*\r?\n?$/.exec(line);
    if (match) headings.push(match[1]);
    return line;
  });
  return headings;
}

export function severityForScore(score) {
  return score >= 9 ? 'critical' : score >= 7 ? 'high' : score >= 4 ? 'medium' : score > 0 ? 'low' : 'info';
}

export function isDate(value) {
  return typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value)
    && !Number.isNaN(Date.parse(value)) && new Date(value).toISOString().slice(0, 10) === value;
}

export function isHttpsUrl(value) {
  try { const url = new URL(value); return url.protocol === 'https:' && !url.username && !url.password; }
  catch { return false; }
}

export function validateKnowledgeEntry(markdown, filename, category) {
  const errors = [];
  let document;
  try { document = parseKnowledgeDocument(markdown); }
  catch (error) { return [error.message]; }
  const { fields, body, hasFrontmatter } = document;
  if (!hasFrontmatter) errors.push('Missing frontmatter');
  for (const key of ENTRY_FIELDS) if (!Object.hasOwn(fields, key)) errors.push('Missing field: ' + key);
  for (const key of Object.keys(fields)) if (!ENTRY_FIELDS.includes(key)) errors.push('Unknown field: ' + key);
  if (fields.id !== path.basename(filename, '.md')) errors.push('id must match the filename');
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(fields.id || '')) errors.push('Invalid id');
  for (const key of ['title', 'product', 'versions', 'ports', 'keywords', 'entry', 'sources']) {
    if (typeof fields[key] !== 'string' || !fields[key].trim()) errors.push('Expected nonempty string: ' + key);
  }
  if (!ENTRY_KINDS.includes(fields.kind)) errors.push('Invalid kind');
  if (fields.cve !== null && !CVE.test(fields.cve)) errors.push('cve must be one CVE ID or null');
  if ((fields.kind === 'cve') !== (fields.cve !== null)) errors.push('kind=cve requires a CVE, other kinds require null');
  if (fields['related-cves'] !== null && (typeof fields['related-cves'] !== 'string'
    || !fields['related-cves'].split(/,\s*/).every((value) => CVE.test(value) && value !== fields.cve))) {
    errors.push('Invalid related-cves');
  }
  if (!['critical', 'high', 'medium', 'low', 'info'].includes(fields.severity)) errors.push('Invalid severity');
  if (typeof fields.cvss !== 'number' || !Number.isFinite(fields.cvss) || fields.cvss < 0 || fields.cvss > 10) errors.push('Invalid cvss');
  if (!['cvss', 'editorial'].includes(fields['severity-basis'])) errors.push('Invalid severity-basis');
  if (fields.severity !== severityForScore(fields.cvss)
    && (fields['severity-basis'] !== 'editorial' || !fields['severity-note'])) errors.push('Severity/CVSS mismatch requires an editorial explanation');
  if (fields['severity-basis'] === 'cvss' && fields.severity !== severityForScore(fields.cvss)) errors.push('CVSS-based severity must match cvss');
  if (WORKFLOW_CATEGORIES.includes(category) !== (fields.kind === 'workflow')) errors.push('Workflow entries belong in triage, red-team, or blue-team');
  if (fields.kind === 'workflow' && (fields.cvss !== 0 || fields.severity !== 'info')) errors.push('Workflow severity must be info with cvss=0');
  if (typeof fields.verified !== 'boolean') errors.push('verified must be boolean');
  if (fields.verified && (!isDate(fields['verified-on']) || !fields['verification-evidence'])) errors.push('Verified entries require a date and laboratory evidence');
  if (!fields.verified && (fields['verified-on'] !== null || fields['verification-evidence'] !== null)) errors.push('Unverified entries must not claim laboratory verification');
  for (const key of ['cve-note', 'severity-note', 'verification-evidence', 'cwe']) {
    if (fields[key] !== null && (typeof fields[key] !== 'string' || !fields[key].trim())) errors.push('Expected nullable string: ' + key);
  }
  if (fields.cwe !== null && !/^CWE-\d+(?:,\s*CWE-\d+)*$/.test(fields.cwe)) errors.push('Invalid CWE identifiers');
  for (const key of ['source-url', 'vendor-advisory', 'kev-source', 'epss-source']) {
    if (fields[key] !== null && !isHttpsUrl(fields[key])) errors.push('Expected HTTPS URL: ' + key);
  }
  for (const key of ['verified-on', 'patch-date', 'kev-date', 'epss-date', 'enrichment-updated']) {
    if (fields[key] !== null && !isDate(fields[key])) errors.push('Invalid date: ' + key);
  }
  if (fields.kev !== null && typeof fields.kev !== 'boolean') errors.push('kev must be boolean or null');
  if (fields.kev !== null && (!fields['kev-source'] || !fields['enrichment-updated'])) errors.push('KEV status requires source and retrieval date');
  if (fields.kev === null && (fields['kev-source'] !== null || fields['kev-date'] !== null)) errors.push('Unknown KEV status must not claim source data');
  if (fields.kev === true && !fields['kev-date']) errors.push('Positive KEV status requires dateAdded');
  if (fields.kev !== true && fields['kev-date'] !== null) errors.push('Only positive KEV status has dateAdded');
  for (const key of ['epss', 'epss-percentile']) {
    if (fields[key] !== null && (typeof fields[key] !== 'number' || !Number.isFinite(fields[key]) || fields[key] < 0 || fields[key] > 1)) errors.push('Expected probability in [0,1]: ' + key);
  }
  if (fields.epss !== null && (!fields['epss-date'] || !fields['epss-source'] || fields['epss-percentile'] === null || !fields['enrichment-updated'])) errors.push('EPSS requires percentile, score date, source, and retrieval date');
  if (fields.epss === null && ['epss-date', 'epss-source', 'epss-percentile'].some((key) => fields[key] !== null)) errors.push('Unknown EPSS must have null score metadata');
  if (fields.cve === null && ['kev', 'kev-date', 'kev-source', 'epss', 'epss-percentile', 'epss-date', 'epss-source', 'enrichment-updated'].some((key) => fields[key] !== null)) errors.push('Non-CVE entries must not have CVE enrichment');
  if (fields.kind !== 'workflow' && JSON.stringify(documentHeadings(body)) !== JSON.stringify(ENTRY_HEADINGS)) errors.push('Non-workflow sections must follow the six canonical headings');
  let fence = null;
  for (const line of body.split(/\r?\n/)) {
    const marker = /^\s{0,3}(`{3,}|~{3,})/.exec(line);
    if (!marker) continue;
    if (!fence) fence = marker[1];
    else if (marker[1][0] === fence[0] && marker[1].length >= fence.length
      && /^\s{0,3}(?:`{3,}|~{3,})[ \t]*$/.test(line)) fence = null;
  }
  if (fence) errors.push('Unclosed code fence');
  if (/\p{Script=Han}/u.test(markdown)) errors.push('Untranslated Han characters');
  return errors;
}

export function validateKnowledgeCorpus(root) {
  const errors = [];
  const ids = new Set();
  let entries;
  try { entries = knowledgeFiles(root); }
  catch (error) { return [error.message]; }
  for (const item of entries) {
    const markdown = fs.readFileSync(item.path, 'utf8');
    errors.push(...validateKnowledgeEntry(markdown, item.file, item.category).map((error) => item.category + '/' + item.file + ': ' + error));
    try {
      const { fields } = parseKnowledgeDocument(markdown);
      if (ids.has(fields.id)) errors.push('Duplicate entry id: ' + fields.id);
      ids.add(fields.id);
      item.fields = fields;
    } catch { continue; }
  }
  for (const category of KNOWLEDGE_CATEGORIES) {
    const file = path.join(root, category, 'SKILL.md');
    try {
      const { fields, body, hasFrontmatter } = parseKnowledgeDocument(fs.readFileSync(file, 'utf8'));
      if (!hasFrontmatter || fields.name !== 'kb-' + category || typeof fields.description !== 'string' || !fields.description.trim()) errors.push(category + ': Invalid skill metadata');
      if (/\(\d+\s+entries\)/i.test(fields.description || '')) errors.push(category + ': Do not hardcode entry counts in skill descriptions');
      const members = entries.filter((entry) => entry.category === category);
      const count = /^# .*\((\d+) entries\)\s*$/im.exec(body);
      if (!count || Number(count[1]) !== members.length) errors.push(category + ': Wrong category heading count');
      if (!body.includes('| File | Vulnerability | Severity | Entry Point |')) errors.push(category + ': Noncanonical table header');
      const references = [];
      outsideFences(body, (line) => {
        const filename = /^\|\s*`([^`]+\.md)`\s*\|/.exec(line)?.[1];
        if (!filename) return line;
        references.push(filename);
        const entry = members.find((item) => item.file === filename);
        if (!entry) { errors.push(category + ': Broken entry reference: ' + filename); return line; }
        const cells = line.split(/(?<!\\)\|/).map((cell) => cell.trim());
        if (cells[3] !== entry.fields?.severity || cells[4] !== entry.fields?.entry?.replaceAll('|', '\\|')) errors.push(category + ': Stale table metadata for ' + filename);
        return line;
      });
      if (new Set(references).size !== references.length) errors.push(category + ': Duplicate table references');
      for (const member of members) if (!references.includes(member.file)) errors.push(category + ': Missing table reference: ' + member.file);
    } catch (error) { errors.push(category + ': ' + error.message); }
  }
  return errors;
}
