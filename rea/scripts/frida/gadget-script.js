/**
 * Frida Gadget script for Android: an autonomous agent that runs inside the
 * app with no host attached.
 *
 * Build it with the bridge bundled, because Frida 17 no longer ships the
 * Java bridge inside the runtime:
 *
 *   npm install frida-java-bridge frida-compile
 *   npx frida-compile gadget.js -o gadget.script.js
 *
 * Deploy it next to the Gadget library inside the APK:
 *
 *   lib/arm64-v8a/libgadget.so
 *   lib/arm64-v8a/libgadget.config.json   {"interaction":{"type":"script","path":"libgadget.script.js"}}
 *   lib/arm64-v8a/libgadget.script.js
 *
 * The script must never throw: an exception in the Gadget script aborts the
 * agent and the app continues unmodified.
 */

'use strict';

function safe(label, work) {
  try {
    work();
  } catch (error) {
    console.log('[gadget] ' + label + ' failed: ' + error);
  }
}

function hookJavaBool(className, methodName) {
  safe('java hook ' + className + '.' + methodName, function () {
    const klass = Java.use(className);
    const method = klass[methodName];
    method.implementation = function () {
      return true;
    };
    console.log('[gadget] hooked ' + className + '.' + methodName);
  });
}

function hookJavaVoid(className, methodName) {
  safe('java hook ' + className + '.' + methodName, function () {
    const klass = Java.use(className);
    const method = klass[methodName];
    method.implementation = function () {
      console.log('[gadget] suppressed ' + className + '.' + methodName);
    };
    console.log('[gadget] hooked ' + className + '.' + methodName);
  });
}

function hookNativeBool(moduleName, functionName) {
  safe('native hook ' + moduleName + '!' + functionName, function () {
    const module = Process.findModuleByName(moduleName);
    if (module === null) return;
    const target = module.findExportByName(functionName);
    if (target === null) return;
    Interceptor.attach(target, {
      onLeave(retval) {
        retval.replace(1);
      }
    });
    console.log('[gadget] hooked ' + moduleName + '!' + functionName);
  });
}

if (typeof Java === 'undefined') {
  throw new Error('The autonomous Gadget script requires a bundled frida-java-bridge. Compile the script before deployment.');
}
Java.perform(function () {
  console.log('[gadget] agent started');

  // Java layer
  hookJavaBool('com.vendor.LicenseManager', 'isValid');
  hookJavaBool('com.vendor.LicenseManager', 'isLicensed');
  hookJavaBool('com.vendor.Premium', 'isUnlocked');
  hookJavaVoid('com.vendor.LicenseManager', 'showExpiredDialog');

  // Native layer, when it is loaded later
  Process.attachModuleObserver({
    onAdded(module) {
      if (module.name === 'liblicense.so') {
        hookNativeBool('liblicense.so', 'Java_com_vendor_LicenseManager_isValid');
      }
    }
  });
});
