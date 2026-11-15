/**
 * Force a licence decision to "valid" by hooking the function that makes it.
 *
 * Frida 17 notes:
 *   - Use Process.getModuleByName(...).getExportByName(...); the static
 *     Module.findExportByName is gone.
 *   - The Objective-C, Java and Swift bridges are separate packages in 17.x.
 *     Bundle them with frida-compile: npx frida-compile hook.js -o hook.out.js
 *
 * Usage:
 *   frida -U -f com.vendor.app -l force-license.js
 *   frida -n AppName -l force-license.js
 *
 * Adjust MODULE / FUNCTION to the target. Every NativeCallback is stored in a
 * live array: a collected callback is freed and the next call jumps into
 * freed memory.
 */

'use strict';

const hooks = [];

// ---------------------------------------------------------------- native ----

/**
 * Force a native function that returns a boolean to return true.
 * Replace the module and function names with the ones from the target.
 */
function forceNativeBool(moduleName, functionName) {
  const module = Process.findModuleByName(moduleName);
  if (module === null) {
    console.log('[hook] module not loaded: ' + moduleName);
    return false;
  }
  const target = module.findExportByName(functionName);
  if (target === null) {
    console.log('[hook] export not found: ' + functionName + ' in ' + moduleName);
    return false;
  }

  Interceptor.attach(target, {
    onEnter(args) {
      this.backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress)
        .join('\n    ');
    },
    onLeave(retval) {
      const original = retval.toInt32();
      if (original === 0) {
        console.log('[hook] ' + functionName + ' returned 0 -> forced to 1');
        console.log('    called from:\n    ' + this.backtrace);
      }
      retval.replace(1);
    }
  });

  console.log('[hook] attached to ' + moduleName + '!' + functionName);
  return true;
}

/**
 * Hook a native function that returns a pointer / handle and replace the
 * pointer with one allocated by us, carrying the value we want.
 */
function replaceReturnValue(moduleName, functionName, replacementValue) {
  const module = Process.findModuleByName(moduleName);
  if (module === null) return false;
  const target = module.findExportByName(functionName);
  if (target === null) return false;

  Interceptor.attach(target, {
    onLeave(retval) {
      retval.replace(ptr(replacementValue));
    }
  });
  console.log('[hook] ' + functionName + ' return replaced with ' + replacementValue);
  return true;
}

/**
 * Log the arguments and the result of a function without changing anything.
 * Use it to identify which overload or which argument carries the licence.
 */
function traceNative(moduleName, functionName, argumentCount) {
  const module = Process.findModuleByName(moduleName);
  if (module === null) return false;
  const target = module.findExportByName(functionName);
  if (target === null) return false;

  const names = [];
  for (let i = 0; i < argumentCount; i++) names.push('arg' + i);

  Interceptor.attach(target, {
    onEnter(args) {
      this.args = [];
      for (let i = 0; i < argumentCount; i++) this.args.push(args[i].toString());
    },
    onLeave(retval) {
      console.log(
        '[trace] ' + functionName + '(' + this.args.join(', ') +
        ') = ' + retval.toString()
      );
    }
  });
  return true;
}

/**
 * Hook a module that has not been loaded yet.
 */
function onModuleLoaded(moduleName, callback) {
  const existing = Process.findModuleByName(moduleName);
  if (existing !== null) {
    callback(existing);
    return;
  }
  Process.attachModuleObserver({
    onAdded(module) {
      if (module.name === moduleName) callback(module);
    }
  });
}

// ------------------------------------------------------------------ ObjC ----

function forceObjcBool(className, selectorName) {
  if (typeof ObjC === 'undefined' || !ObjC.available) {
    console.log('[hook] the Objective-C bridge is not available. ' +
                'Install frida-objc-bridge and bundle with frida-compile.');
    return false;
  }
  ObjC.schedule(ObjC.mainQueue, function () {
    try {
      const klass = ObjC.classes[className];
      if (klass === undefined) {
        console.log('[hook] class not found: ' + className);
        return;
      }
      const method = klass['- ' + selectorName];
      if (method === undefined) {
        console.log('[hook] selector not found: -' + selectorName);
        return;
      }
      hooks.push(Interceptor.attach(method.implementation, {
        onLeave(result) { result.replace(1); }
      }));
      console.log('[hook] attached to -[' + className + ' ' + selectorName + ']');
    } catch (error) {
      console.log('[hook] ObjC hook failed: ' + error);
    }
  });
  return true;
}

// ------------------------------------------------------------------ Java ----

function forceJavaBool(className, methodName) {
  if (typeof Java === 'undefined') {
    console.log('[hook] the Java bridge is not available. ' +
                'Install frida-java-bridge and bundle with frida-compile.');
    return false;
  }
  Java.perform(function () {
    try {
      const klass = Java.use(className);
      const method = klass[methodName];
      if (method === undefined) {
        console.log('[hook] method not found: ' + className + '.' + methodName);
        return;
      }
      method.implementation = function () {
        console.log('[hook] ' + className + '.' + methodName + '() -> true');
        return true;
      };
      console.log('[hook] attached to ' + className + '.' + methodName);
    } catch (error) {
      console.log('[hook] Java hook failed: ' + error);
    }
  });
  return true;
}

// --------------------------------------------------------------- helpers ----

/**
 * Read a C string argument safely.
 */
function readCString(pointer) {
  if (pointer === null || pointer.isNull()) return null;
  try {
    return pointer.readCString();
  } catch (error) {
    return null;
  }
}

/**
 * Dump a buffer as hex.
 */
function dumpBuffer(pointer, length) {
  if (pointer === null || pointer.isNull()) return '<null>';
  return hexdump(pointer, { length: Math.min(length, 256) });
}

// ------------------------------------------------------------- entrypoint ---

// Native licence check:
onModuleLoaded('liblicense.so', function (module) {
  forceNativeBool('liblicense.so', 'is_licensed');
});

// Objective-C entitlement check:
// forceObjcBool('LicenseManager', 'isLicensed');

// Java entitlement check:
// forceJavaBool('com.vendor.LicenseManager', 'isValid');

console.log('[hook] ready');
