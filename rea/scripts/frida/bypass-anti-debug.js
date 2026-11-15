'use strict';

const hooks = [];
const timingHooksEnabled = false;

function attachExport(moduleName, exportName, callbacks) {
  const module = Process.findModuleByName(moduleName);
  const target = module === null ? null : module.findExportByName(exportName);
  if (target === null) return false;
  hooks.push(Interceptor.attach(target, callbacks));
  return true;
}

if (Process.platform === 'windows') {
  attachExport('kernel32.dll', 'IsDebuggerPresent', {
    onLeave(result) { result.replace(0); }
  });
  attachExport('kernel32.dll', 'CheckRemoteDebuggerPresent', {
    onEnter(args) { this.output = args[1]; },
    onLeave(result) {
      if (result.toInt32() !== 0 && !this.output.isNull()) this.output.writeU32(0);
    }
  });
  attachExport('ntdll.dll', 'NtQueryInformationProcess', {
    onEnter(args) {
      this.informationClass = args[1].toInt32();
      this.output = args[2];
      this.length = args[3].toInt32();
    },
    onLeave(result) {
      if (result.toInt32() !== 0 || this.output.isNull()) return;
      if ([7, 30].includes(this.informationClass) && this.length >= Process.pointerSize) this.output.writePointer(ptr(0));
      if (this.informationClass === 31 && this.length >= 4) this.output.writeU32(1);
    }
  });
  if (timingHooksEnabled) {
    let ticks = 1000;
    attachExport('kernel32.dll', 'QueryPerformanceCounter', {
      onEnter(args) { this.output = args[0]; },
      onLeave(result) {
        if (result.toInt32() !== 0 && !this.output.isNull()) this.output.writeU64(++ticks);
      }
    });
  }
}

console.log('[bypass] installed ' + hooks.length + ' scoped Windows observation hooks; clock rewriting is opt-in. Select platform-specific checks before adding hooks.');
