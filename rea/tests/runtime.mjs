import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import test from 'node:test';

const source = filename => fs.readFileSync(new URL('../scripts/frida/' + filename, import.meta.url), 'utf8');

function fixture({ timing = false } = {}) {
  const attached = new Map();
  const context = {
    console: { log() {} }, ptr: value => value,
    Process: { platform: 'windows', pointerSize: 8, findModuleByName: () => ({ findExportByName: name => name }) },
    Interceptor: { attach(name, callbacks) { attached.set(name, callbacks); return { detach() {} }; } },
  };
  const script = timing ? source('bypass-anti-debug.js').replace('const timingHooksEnabled = false;', 'const timingHooksEnabled = true;') : source('bypass-anti-debug.js');
  vm.runInNewContext(script, context);
  return attached;
}

test('debugger hooks preserve API success and write exact out-parameter widths', () => {
  const attached = fixture();
  const writes = [];
  const output = { isNull: () => false, writeU32: value => writes.push(['u32', value]), writePointer: value => writes.push(['pointer', value]) };
  const invoke = (informationClass, length = 8) => {
    const callbacks = attached.get('NtQueryInformationProcess');
    const state = {};
    callbacks.onEnter.call(state, [null, { toInt32: () => informationClass }, output, { toInt32: () => length }]);
    callbacks.onLeave.call(state, { toInt32: () => 0 });
  };
  invoke(7);
  invoke(31);
  invoke(1);
  invoke(7, 4);
  assert.deepEqual(writes, [['pointer', 0], ['u32', 1]]);
  const remote = attached.get('CheckRemoteDebuggerPresent');
  const state = {};
  remote.onEnter.call(state, [null, output]);
  remote.onLeave.call(state, { toInt32: () => 1 });
  assert.deepEqual(writes.at(-1), ['u32', 0]);
  assert.equal(attached.has('GetTickCount'), false);
  assert.equal(attached.has('QueryPerformanceCounter'), false);
});

test('optional performance-counter hook writes only eight bytes and advances monotonically', () => {
  const callbacks = fixture({ timing: true }).get('QueryPerformanceCounter');
  const values = [];
  const output = { isNull: () => false, writeU64: value => values.push(value) };
  const state = {};
  callbacks.onEnter.call(state, [output]);
  callbacks.onLeave.call(state, { toInt32: () => 1 });
  callbacks.onLeave.call(state, { toInt32: () => 1 });
  assert.deepEqual(values, [1001, 1002]);
});

test('Objective-C helper uses the queue API and attaches to a native implementation pointer', () => {
  let attached;
  const queue = {};
  const context = { console: { log() {} }, Process: { findModuleByName: () => null, attachModuleObserver() {} },
    ObjC: { available: true, mainQueue: queue, classes: { Fixture: { '- isValid': { implementation: 'native-address' } } },
      schedule(selected, callback) { assert.equal(selected, queue); callback(); } },
    Interceptor: { attach(address, callbacks) { assert.equal(address, 'native-address'); attached = callbacks; return {}; } },
  };
  vm.runInNewContext(source('force-license.js') + '\nforceObjcBool("Fixture", "isValid");', context);
  let result;
  attached.onLeave({ replace(value) { result = value; } });
  assert.equal(result, 1);
});
