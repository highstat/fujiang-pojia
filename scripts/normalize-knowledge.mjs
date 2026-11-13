import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { ENTRY_FIELDS, KNOWLEDGE_CATEGORIES, WORKFLOW_CATEGORIES, knowledgeFiles, outsideFences,
  parseKnowledgeDocument, serializeKnowledgeDocument, severityForScore } from '../plugin/lib/knowledge-schema.js';

export const corpusRoot = fileURLToPath(new URL('../plugin/knowledge/', import.meta.url));
const entryPoints = {
  'cve-2021-29441-nacos': 'Nacos HTTP authentication and configuration API',
  'cve-2024-40711-veeam-rce': 'Veeam Backup & Replication network service',
  'docker-api-2375': 'Docker Remote API on TCP 2375 or 2376',
  'redis-unauth': 'Redis network service without authentication',
  'cve-2018-13379-fortinet-fortios': 'FortiOS SSL VPN web portal',
  'cve-2019-19781-citrix-path-traversal': 'Citrix ADC or Gateway web interface',
  'cve-2021-22986-f5-icontrol': 'BIG-IP iControl REST management API',
  'cve-2022-1388-f5-icontrol': 'BIG-IP iControl REST management API',
  'cve-2023-46805-2024-21887-ivanti': 'Ivanti Connect Secure or Policy Secure web interface',
  'cve-2024-3400-panos-globalprotect': 'PAN-OS GlobalProtect portal or gateway',
  'adcs-esc1-esc8': 'AD CS certificate enrollment and web enrollment services',
  'cve-2017-0144-eternalblue': 'Windows SMBv1 service on TCP 445',
  'cve-2020-1472-zerologon': 'Domain controller Netlogon RPC service',
  'cve-2021-26855-proxylogon': 'Exchange HTTPS frontend and proxy endpoints',
  'cve-2021-34473-proxyshell': 'Exchange HTTPS Autodiscover and backend services',
  'cve-2021-34527-printnightmare': 'Windows Print Spooler RPC service',
  'cve-2021-42287-nopac': 'Active Directory account management and Kerberos',
  'api-idor-bola': 'API endpoints accepting user-controlled object identifiers',
  'jwt-none-and-weak-key': 'JWT authentication and signing-key validation',
  'object-storage-datastore-exposure': 'Public object storage or exposed datastore services',
  'payment-notify-forgery': 'Payment-provider notification and callback endpoints',
  'repo-config-backup-leak': 'Public repository metadata, configuration, and backup files',
  'ruoyi-admin-unauth': 'RuoYi administration and monitoring web endpoints',
  'sms-bomb-and-enum': 'SMS verification-code and account lookup endpoints',
  'spring-actuator-exposure': 'Spring Boot Actuator management endpoints',
  'upload-getshell': 'Application file-upload and uploaded-file serving endpoints',
  'cve-2017-10271-weblogic-wls-wsat': 'WebLogic WLS-WSAT HTTP web service',
  'cve-2017-5638-struts2-s2-045': 'Struts2 multipart request handling',
  'cve-2021-44228-log4shell': 'Application inputs logged by vulnerable Log4j2',
  'cve-2022-22965-spring4shell': 'Spring MVC request parameter binding',
  'cve-2022-25845-fastjson-autotype': 'Fastjson JSON deserialization input',
  'cve-2019-17558-solr-velocity': 'Solr HTTP configuration and template handling',
  'cve-2022-26134-confluence-ognl': 'Confluence HTTP request handling',
  'cve-2023-22527-confluence-ssti': 'Confluence template-rendering endpoints',
  'cve-2023-42793-teamcity-auth-bypass': 'TeamCity HTTP administration and REST API',
  'cve-2024-23897-jenkins-file-read': 'Jenkins CLI over HTTP or the dedicated CLI port',
  'cve-2021-3156-baron-samedit': 'Local sudo/sudoedit command-line processing',
  'cve-2021-4034-pwnkit': 'Local pkexec executable',
  'cve-2022-0847-dirtypipe': 'Local Linux pipe and page-cache operations',
  'cve-2023-0386-overlayfs': 'Local Linux OverlayFS and user namespace operations',
  'cve-2024-1086-nftables': 'Local Linux nftables and user namespace operations',
  'fingerprint-workflow': 'Asset fingerprinting and version-identification workflow',
  'report-template': 'Vulnerability reporting and retesting workflow',
  'safe-verification': 'Authorization, minimal verification, and evidence collection',
  'cve-2018-7600-drupalgeddon2': 'Drupal Form API request handling',
  'cve-2019-11043-phpfpm-underflow': 'Nginx-to-PHP-FPM PATH_INFO handling',
  'cve-2019-16759-vbulletin': 'vBulletin widget configuration endpoint',
  'cve-2024-4577-phpcgi-windows': 'Windows PHP-CGI HTTP argument handling',
  'thinkphp5-rce': 'ThinkPHP 5.x routing and method handling',
};

export function normalizeBody(body) {
  return outsideFences(body, (line) => {
    line = line.replace(/(?<=\S) (?=\r?\n?$)/, '');
    const match = /^## (.+?)(\r?\n|$)$/.exec(line);
    if (!match) return line;
    const [heading, eol] = [match[1], match[2]];
    if (/^fingerprints?(?:ing)?$/i.test(heading)) return '## Fingerprinting' + eol;
    if (/^exploitation steps$/i.test(heading)) return '## Exploitation Steps' + eol;
    if (/^remediation and mitigation/i.test(heading)) return '## Remediation and Mitigation' + eol
      + (/\(/.test(heading) ? eol + '### ' + heading + eol : '');
    if (/^version check /i.test(heading)) return '### ' + heading + eol;
    if (/^PoC \(/.test(heading)) return '## PoC' + eol + eol + '### ' + heading + eol;
    return line;
  });
}

export function normalizeEntry(markdown, filename, category) {
  const { fields: original, body } = parseKnowledgeDocument(markdown);
  const id = path.basename(filename, '.md');
  const matches = String(original.cve || '').match(/CVE-\d{4}-\d{4,}/g) || [];
  const cve = /^CVE-/.test(original.cve || '') ? matches[0] : null;
  const kind = WORKFLOW_CATEGORIES.includes(category) ? 'workflow' : cve ? 'cve'
    : /business|feature abuse/i.test(original.cve || '') ? 'business-logic'
      : /config|deployment/i.test(original.cve || '') ? 'configuration' : 'implementation';
  const fields = { ...original };
  fields.id = original.id || id;
  fields.kind = original.kind || kind;
  fields.cve = cve;
  fields['related-cves'] ??= cve && matches.length > 1 ? [...new Set(matches.slice(1))].join(', ') : null;
  fields['cve-note'] ??= original.cve !== cve ? original.cve : null;
  fields.versions = String(fields.versions || '-');
  fields.ports = String(fields.ports || 'Any');
  fields.entry ||= entryPoints[id];
  if (!fields.entry) throw new Error('Add a reviewed entry point for ' + filename);
  if (['cve-2024-23897-jenkins-file-read', 'cve-2020-12812-fortios-2fa-case-bypass'].includes(id)) fields.severity = severityForScore(fields.cvss);
  const mismatch = fields.severity !== severityForScore(fields.cvss);
  fields['severity-basis'] ||= mismatch ? 'editorial' : 'cvss';
  fields['severity-note'] ??= mismatch ? 'Legacy editorial severity retained; the stored CVSS score maps to '
    + severityForScore(fields.cvss) + '. No vendor classification or laboratory verification is implied.' : null;
  fields['source-url'] ??= cve ? 'https://nvd.nist.gov/vuln/detail/' + cve : null;
  for (const key of ENTRY_FIELDS) if (!Object.hasOwn(fields, key)) fields[key] = null;
  const ordered = Object.fromEntries(ENTRY_FIELDS.map((key) => [key, fields[key]]));
  for (const key of Object.keys(original)) if (!ENTRY_FIELDS.includes(key)) throw new Error('Unknown metadata field: ' + key);
  return serializeKnowledgeDocument(ordered, fields.kind === 'workflow' ? body : normalizeBody(body),
    markdown.includes('\r\n') ? '\r\n' : '\n', markdown.startsWith('\uFEFF') ? '\uFEFF' : '');
}

function normalizeSkill(markdown, entries) {
  const { fields, body } = parseKnowledgeDocument(markdown);
  fields.description = fields.description.replace(/\s*\(\d+\s+entries\)/gi, '');
  let updated = outsideFences(body, (line) => {
    if (/^# /.test(line)) return line.replace(/\(\d+\s+entries\)/i, '(' + entries.length + ' entries)');
    if (/^\| File \|/.test(line)) return line.replace(/Entry(?: point| Point)?\s*\|/, 'Entry Point |');
    const file = /^\|\s*`([^`]+\.md)`\s*\|/.exec(line)?.[1];
    const entry = entries.find((item) => item.file === file);
    if (!entry) return line;
    const cells = line.split('|');
    if (cells.length !== 6) throw new Error('Unsupported category table row: ' + line);
    cells[3] = ' ' + entry.fields.severity + ' ';
    cells[4] = ' ' + entry.fields.entry.replaceAll('|', '\\|') + ' ';
    return cells.join('|');
  });
  return serializeKnowledgeDocument(fields, updated, markdown.includes('\r\n') ? '\r\n' : '\n', markdown.startsWith('\uFEFF') ? '\uFEFF' : '');
}

export function normalizationChanges(root = corpusRoot) {
  const changes = [];
  const entries = knowledgeFiles(root).map((item) => {
    const original = fs.readFileSync(item.path, 'utf8');
    const content = normalizeEntry(original, item.file, item.category);
    if (content !== original) changes.push({ path: item.path, original, content });
    return { ...item, fields: parseKnowledgeDocument(content).fields };
  });
  for (const category of KNOWLEDGE_CATEGORIES) {
    const filename = path.join(root, category, 'SKILL.md');
    const original = fs.readFileSync(filename, 'utf8');
    const content = normalizeSkill(original, entries.filter((item) => item.category === category));
    if (content !== original) changes.push({ path: filename, original, content });
  }
  return changes;
}

export function printPatch(changes) {
  console.log('*** Begin Patch');
  for (const change of changes) {
    console.log('*** Update File: ' + change.path);
    console.log('@@');
    for (const line of change.original.replace(/\n$/, '').split('\n')) console.log('-' + line);
    for (const line of change.content.replace(/\n$/, '').split('\n')) console.log('+' + line);
  }
  console.log('*** End Patch');
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  try {
    const arguments_ = process.argv.slice(2);
    if (arguments_.length !== 1 || !['--check', '--patch'].includes(arguments_[0])) throw new Error('Usage: node scripts/normalize-knowledge.mjs --check | --patch');
    const changes = normalizationChanges();
    if (arguments_[0] === '--patch' && changes.length) printPatch(changes);
    else if (changes.length) { console.error('Normalization needed: ' + changes.map((item) => item.path).join(', ')); process.exitCode = 1; }
    else console.error('Knowledge normalization is up to date.');
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
