function versionParts(value) {
  const match = String(value).match(/^v?(\d+(?:\.\d+){0,3})(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/);
  if (!match) return null;
  const core = match[1].split('.').map(Number);
  const prerelease = match[2]?.split('.') || [];
  if (core.some(part => !Number.isSafeInteger(part)) || prerelease.some(part => /^\d+$/.test(part) && !Number.isSafeInteger(Number(part)))) return null;
  return { core, prerelease };
}

export function compareVersions(left, right) {
  const first = versionParts(left);
  const second = versionParts(right);
  if (!first || !second) return null;
  for (let index = 0; index < Math.max(first.core.length, second.core.length); index++) {
    const difference = (first.core[index] || 0) - (second.core[index] || 0);
    if (difference) return Math.sign(difference);
  }
  if (!first.prerelease.length || !second.prerelease.length) return first.prerelease.length ? -1 : second.prerelease.length ? 1 : 0;
  for (let index = 0; index < Math.max(first.prerelease.length, second.prerelease.length); index++) {
    const firstPart = first.prerelease[index];
    const secondPart = second.prerelease[index];
    if (firstPart === undefined || secondPart === undefined) return firstPart === undefined ? -1 : 1;
    if (firstPart === secondPart) continue;
    const firstNumeric = /^\d+$/.test(firstPart);
    const secondNumeric = /^\d+$/.test(secondPart);
    if (firstNumeric && secondNumeric) return Math.sign(Number(firstPart) - Number(secondPart));
    if (firstNumeric !== secondNumeric) return firstNumeric ? -1 : 1;
    return firstPart < secondPart ? -1 : 1;
  }
  return 0;
}

function rowStatus(row, version) {
  if (row.versionType && row.versionType !== 'semver') return { status: 'unknown', understood: false };
  const exact = String(row.version) === String(version);
  let included = exact;
  const upper = row.lessThan ?? row.lessThanOrEqual;
  if (upper !== undefined) {
    const lowerComparison = row.version === '*' ? 1 : compareVersions(version, row.version);
    const upperComparison = compareVersions(version, upper);
    if (lowerComparison === null || upperComparison === null) return { status: 'unknown', understood: false };
    included = lowerComparison >= 0 && (row.lessThan !== undefined ? upperComparison < 0 : upperComparison <= 0);
  } else if (row.version === '*') included = true;
  else if (compareVersions(version, row.version) === null && !exact) return { status: 'unknown', understood: false };
  else included ||= compareVersions(version, row.version) === 0;
  if (!included) return { status: null, understood: true };
  let status = row.status || 'unknown';
  if (row.changes !== undefined && !Array.isArray(row.changes)) return { status: 'unknown', understood: false };
  const changes = [...(row.changes || [])];
  if (changes.some(change => compareVersions(version, change.at) === null)) return { status: 'unknown', understood: false };
  changes.sort((first, second) => compareVersions(first.at, second.at));
  for (const change of changes) if (compareVersions(version, change.at) >= 0) status = change.status;
  return { status, understood: true };
}

export function versionApplicability(record, version, product) {
  if (!version || !record?.affected?.length) return { status: 'unknown', reason: 'No structured version evidence for this entry.' };
  if (!product) return { status: 'unknown', reason: 'An exact CNA product name is required to interpret product-specific ranges.' };
  const normalize = value => String(value).toLowerCase().replace(/[^\p{L}\p{N}]/gu, '');
  const affected = record.affected.filter(item => normalize(item.product) === normalize(product));
  if (!affected.length) return { status: 'unknown', reason: 'Product does not exactly match a structured CNA product; no range was guessed.' };
  const statuses = affected.map(item => {
    const rows = (item.versions || []).map(row => rowStatus(row, version));
    const matching = rows.filter(row => row.status !== null);
    if (matching.some(row => !row.understood)) return 'unknown';
    const unique = [...new Set(matching.map(row => row.status))];
    return unique.length === 1 ? unique[0] : unique.length > 1 ? 'unknown' : item.defaultStatus || 'unknown';
  });
  const status = statuses.includes('affected') ? 'affected' : statuses.every(item => item === 'unaffected') ? 'not-affected' : 'unknown';
  return { status, reason: 'Structured CNA range comparison; configuration prerequisites and live verification remain separate.',
    source: record.source, recordUpdated: record.recordUpdated, product, version };
}
