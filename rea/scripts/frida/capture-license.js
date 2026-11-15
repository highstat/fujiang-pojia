/**
 * Capture licence material as it flows through the target.
 *
 * Frida 17 notes:
 *   - Process.getModuleByName(...).getExportByName(...) replaces the removed
 *     static Module.findExportByName.
 *   - The bridges are separate packages in 17.x; bundle with frida-compile.
 *
 * Usage:
 *   frida -U -f com.vendor.app -l capture-license.js
 */

'use strict';

const hooks = [];

/**
 * Log every argument of a function, plus the result.
 */
function trace(moduleName, functionName, argumentCount) {
  const module = Process.findModuleByName(moduleName);
  if (module === null) {
    console.log('[capture] module not loaded: ' + moduleName);
    return;
  }
  const target = module.findExportByName(functionName);
  if (target === null) {
    console.log('[capture] export not found: ' + functionName);
    return;
  }

  Interceptor.attach(target, {
    onEnter(args) {
      this.values = [];
      for (let i = 0; i < argumentCount; i++) {
        this.values.push(args[i].toString());
      }
      this.stack = Thread.backtrace(this.context, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress)
        .slice(0, 8)
        .join('\n    ');
    },
    onLeave(retval) {
      console.log(
        '[capture] ' + functionName + '(' + this.values.join(', ') + ')' +
        '\n    = ' + retval.toString() +
        '\n    from:\n    ' + this.stack
      );
    }
  });
  console.log('[capture] tracing ' + moduleName + '!' + functionName);
}

/**
 * Dump a buffer passed as the first argument, with the length as the second.
 */
function captureBuffer(moduleName, functionName, lengthArgumentIndex) {
  const module = Process.findModuleByName(moduleName);
  if (module === null) return;
  const target = module.findExportByName(functionName);
  if (target === null) return;

  const lengthIndex = lengthArgumentIndex === undefined ? 1 : lengthArgumentIndex;

  Interceptor.attach(target, {
    onEnter(args) {
      const pointer = args[0];
      const length = args[lengthIndex].toInt32();
      if (pointer.isNull() || length <= 0) return;
      console.log(
        '[capture] ' + functionName + ' buffer (' + length + ' bytes):\n' +
        hexdump(pointer, { length: Math.min(length, 512) })
      );
    }
  });
  console.log('[capture] capturing buffer at ' + moduleName + '!' + functionName);
}

/**
 * Print the key and IV passed to a CommonCrypto or OpenSSL decrypt call.
 */
function captureKey(moduleName, functionName, keyIndex, keyLengthIndex, ivIndex) {
  const module = Process.findModuleByName(moduleName);
  if (module === null) return;
  const target = module.findExportByName(functionName);
  if (target === null) return;

  Interceptor.attach(target, {
    onEnter(args) {
      const key = args[keyIndex === undefined ? 3 : keyIndex];
      const keyLength = args[keyLengthIndex === undefined ? 4 : keyLengthIndex].toInt32();
      const iv = args[ivIndex === undefined ? 5 : ivIndex];
      if (!key.isNull() && keyLength > 0) {
        console.log('[capture] key: ' + hexdump(key, { length: Math.min(keyLength, 256) }));
      }
      if (!iv.isNull()) {
        console.log('[capture] iv : ' + hexdump(iv, { length: 16 }));
      }
    }
  });
  console.log('[capture] capturing key at ' + moduleName + '!' + functionName);
}

/**
 * Read a string argument that is known to be UTF-8.
 */
function captureString(moduleName, functionName, argumentIndex) {
  const module = Process.findModuleByName(moduleName);
  if (module === null) return;
  const target = module.findExportByName(functionName);
  if (target === null) return;

  const index = argumentIndex === undefined ? 0 : argumentIndex;
  Interceptor.attach(target, {
    onEnter(args) {
      const pointer = args[index];
      if (pointer.isNull()) return;
      try {
        console.log('[capture] ' + functionName + ' string: ' + pointer.readUtf8String(512));
      } catch (error) {
        console.log('[capture] ' + functionName + ' string is not UTF-8');
      }
    }
  });
}

// ------------------------------------------------------------------ apply ---

// Trace a licence validation routine:
// trace('liblicense.so', 'validate_license', 2);

// Capture a licence blob:
// captureBuffer('liblicense.so', 'load_license_blob', 1);

// Capture a CommonCrypto key:
// captureKey('libcommonCrypto.dylib', 'CCCryptorCreate', 3, 4, 5);

// Capture an OpenSSL decryption key:
// EVP_DecryptInit_ex has no key-length argument; do not use captureKey without a cipher-specific adapter.

// Capture the serial as it is entered:
// captureString('liblicense.so', 'set_serial', 0);

console.log('[capture] ready');
