import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';

export const digest = value => createHash('sha256').update(value).digest('hex');
export const identifier = (type, ...parts) => type + '_' + digest(JSON.stringify(parts)).slice(0, 24);
export const timestamp = () => new Date().toISOString();
export const assessmentHome = () => path.resolve(process.env.FUJIANG_ASSESSMENT_HOME
  || path.join(process.env.DSH_HOME?.trim() || path.join(os.homedir(), '.dsh'), 'assessment'));

export function requireText(value, label, limit = 2000) {
  if (typeof value !== 'string' || !value.trim() || value.length > limit || /\x00/.test(value)) {
    throw new Error(label + ' must be a non-empty string of at most ' + limit + ' characters.');
  }
  return value.trim();
}

export function readBounded(filename, limit = 20 * 1024 * 1024) {
  const descriptor = fs.openSync(filename, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const stat = fs.fstatSync(descriptor);
    if (!stat.isFile() || stat.size > limit) throw new Error('Expected a regular file within the size limit: ' + filename);
    const buffer = Buffer.alloc(stat.size + 1);
    let length = 0;
    while (length < buffer.length) {
      const count = fs.readSync(descriptor, buffer, length, buffer.length - length, null);
      if (!count) break;
      length += count;
    }
    if (length > stat.size) throw new Error('File changed while reading; retry with a stable report.');
    return buffer.subarray(0, length);
  } finally { fs.closeSync(descriptor); }
}

export function managedPath(root, relative) {
  const filename = path.resolve(root, relative);
  const inside = path.relative(root, filename);
  if (!inside || inside === '..' || inside.startsWith('..' + path.sep) || path.isAbsolute(inside)) {
    throw new Error('Managed paths must stay inside the assessment directory.');
  }
  let current = root;
  for (const segment of ['', ...inside.split(path.sep)]) {
    current = path.join(current, segment);
    try { if (fs.lstatSync(current).isSymbolicLink()) throw new Error('Refusing a managed-path symbolic link: ' + current); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  return filename;
}

export function atomicFile(filename, content) {
  fs.mkdirSync(path.dirname(filename), { recursive: true, mode: 0o700 });
  const temporary = filename + '.' + randomUUID() + '.tmp';
  let descriptor;
  try {
    descriptor = fs.openSync(temporary, 'wx', 0o600);
    fs.writeFileSync(descriptor, content);
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = undefined;
    fs.renameSync(temporary, filename);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    try { fs.unlinkSync(temporary); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
}

const initialState = () => ({ schema: 1, updatedAt: null, findings: {}, runs: {}, inventory: {}, imports: {} });

export function createAssessmentStore(directory = assessmentHome()) {
  const root = path.resolve(directory);
  const filename = () => managedPath(root, 'investigations.json');
  function read() {
    let state;
    try { state = JSON.parse(readBounded(filename(), 64 * 1024 * 1024).toString('utf8')); }
    catch (error) { if (error.code === 'ENOENT') return initialState(); throw new Error('Assessment store cannot be read; preserve it before repair: ' + error.message); }
    if (state?.schema !== 1 || !['findings', 'runs', 'inventory', 'imports'].every(key => state[key]
      && typeof state[key] === 'object' && !Array.isArray(state[key]))) throw new Error('Unsupported or corrupt assessment store; no data was replaced.');
    return state;
  }
  function update(callback) {
    managedPath(root, 'write.lock');
    fs.mkdirSync(root, { recursive: true, mode: 0o700 });
    const lock = managedPath(root, 'write.lock');
    let descriptor;
    try { descriptor = fs.openSync(lock, 'wx', 0o600); }
    catch (error) { if (error.code === 'EEXIST') throw new Error('Assessment store is locked. Retry; after a crash inspect write.lock and its PID before removing it.'); throw error; }
    try {
      fs.writeFileSync(descriptor, JSON.stringify({ pid: process.pid, startedAt: timestamp() }));
      const state = read();
      const result = callback(state);
      if (result && typeof result.then === 'function') throw new Error('Store transactions must be synchronous.');
      if (Object.keys(state.findings).length > 20000 || Object.keys(state.runs).length > 20000) throw new Error('Assessment store capacity reached; archive this investigation before continuing.');
      state.updatedAt = timestamp();
      const content = JSON.stringify(state, null, 2) + '\n';
      if (Buffer.byteLength(content) > 64 * 1024 * 1024) throw new Error('Assessment store size limit reached; no update was saved.');
      atomicFile(filename(), content);
      return result;
    } finally { fs.closeSync(descriptor); fs.unlinkSync(lock); }
  }
  function artifact(content) {
    const hash = digest(content);
    const relative = path.join('evidence', hash + '.report');
    const file = managedPath(root, relative);
    try {
      if (digest(readBounded(file)) !== hash) throw new Error('Existing evidence hash mismatch; preserve it before repair.');
    } catch (error) { if (error.code !== 'ENOENT') throw error; atomicFile(file, content); }
    return { sha256: hash, path: relative, bytes: Buffer.byteLength(content) };
  }
  return { root, read, update, artifact };
}
