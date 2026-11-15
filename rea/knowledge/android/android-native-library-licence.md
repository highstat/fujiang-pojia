---
id: "android-native-library-licence"
title: "Android native library licence checks"
domain: "android"
kind: "technique"
platforms: "android"
arch: "x86-64, arm, arm64"
difficulty: "advanced"
tools: "r2, rabin2, readelf, nm, strings, Frida, Frida Gadget, zipalign, apksigner"
verified: false
updated: "2026-11-15"
summary: "Find the shared object that carries a licence decision, identify its JNI entry point, patch the return value in machine code or force it at runtime with Frida, and put the modified library back into a signed APK."
---

## Summary

Some apps do not decide the licence in the DEX. They load `liblicence.so` through
`System.loadLibrary("licence")` and call a native method whose return value is the answer.
The decision then lives in an ELF shared object inside `lib/<abi>/`, which is both harder to
read and harder to patch than smali, but has the advantage that the check is usually a single
function with a single return.

This entry covers locating the library and the JNI symbol, patching the function to return
`1`, replacing the `.so` inside the APK without breaking alignment, and hooking the function
at runtime with Frida 17 either through `frida-server` on a rooted device or through Frida
Gadget inside the APK on a stock device.

## Recognition

Signals that the decision is native:

- A `static { System.loadLibrary("..."); }` block in the application class:
  `grep -rn "loadLibrary" app_decoded/smali*/ | head`.
- A `native` method declaration in the DEX with no body:
  `grep -rn "\.method.*native.*isLicen" app_decoded/smali*/ | head`.
- A `.so` in the APK whose exported symbols use the `Java_<package>_<class>_<method>` mangling:

  ```bash
  unzip -Z1 app.apk | grep '^lib/'
  # lib/arm64-v8a/liblicence.so
  # lib/armeabi-v7a/liblicence.so
  # lib/x86_64/liblicence.so
  ```

- A Java class that only wraps one native call, e.g. `LicenseManager.isLicensed()` whose
  entire body is `return nativeIsLicensed(ctx);`.
- Logcat messages that come from the native side: `libc: Fatal signal 11` after the licence
  dialog, or a `__android_log_print` line with the tag `License`.

## Method

### 1. Extract the library

```bash
cd /path/to/work
mkdir -p libs && cd libs
unzip -o ../app.apk 'lib/*' -d .
ls -l lib/arm64-v8a/
```

Always work on the ABI slice that matches the device under test. The same package ships
different code per ABI and the licence check is not always identical across slices.

### 2. Locate the decision function

Four independent views; use them together, because a single name is rarely enough.

```bash
cd /path/to/work/libs
# exported and dynamic symbols
readelf -sW lib/arm64-v8a/liblicence.so | grep -i 'licen\|valid\|regist'
nm -D lib/arm64-v8a/liblicence.so 2>/dev/null | grep -i 'licen\|valid'

# radare2: symbols, then strings, then cross-references
r2 -qc 'is~licen' lib/arm64-v8a/liblicence.so
r2 -qc 'iz~licen' lib/arm64-v8a/liblicence.so
r2 -qc 'axt @@ sym.*Licen*' lib/arm64-v8a/liblicence.so

# plain strings
strings -a lib/arm64-v8a/liblicence.so | grep -i 'licen\|expired\|invalid key'
```

Useful strings that pin the decision: `license expired`, `invalid signature`, `trial days
left`, `evaluation only`, `ERR_LICENSE_013`, `https://vendor.example/api/activate`.

### 3. Identify the JNI entry point

JNI symbols are mangled mechanically:

| Java | C symbol |
| --- | --- |
| `com.vendor.app.LicenseManager.isLicensed` | `Java_com_vendor_app_LicenseManager_isLicensed` |
| `com.vendor.app.LicenseManager.isLicensed` (package with `_`) | `Java_com_vendor_1app_LicenseManager_isLicensed` |
| `com.vendor.app.LicenseManager.check(String)` | `Java_com_vendor_app_LicenseManager_check__Ljava_lang_String_2` |

The rules: `_` in a Java name becomes `_1`; `;` becomes `_2`; `[` becomes `_3`; `/` becomes
`_`; overloads get `__` followed by the mangled parameter types. A long symbol is also
registered dynamically through `RegisterNatives` in `JNI_OnLoad`, in which case no
`Java_*` symbol exists:

```bash
cd /path/to/work/libs
r2 -qc 'is~JNI_OnLoad' lib/arm64-v8a/liblicence.so
r2 -qc 'pdf @ sym.JNI_OnLoad' lib/arm64-v8a/liblicence.so
```

`RegisterNatives` takes an array of `{name, signature, functionPointer}`. When the
registration is dynamic, find the method name string in the binary and take its
cross-reference:

```bash
r2 -qc 'iz~isLicensed; axt @@ str.*isLicensed' lib/arm64-v8a/liblicence.so
```

### 4. Patch the function

The check almost always ends in a boolean return. The cheapest patch replaces the first
instructions of the function with a constant `1` and a return.

For ARM64 (the common case on modern devices), the two instructions are:

```text
mov w0, #1      ->  20 00 80 52
ret             ->  c0 03 5f d6
```

So the patched function prologue is six bytes:

```text
20 00 80 52 c0 03 5f d6
```

`mov w0, #1` sets `w0` to `1`, which is `jboolean` true (`JNI_TRUE`). `ret` returns.

Other encodings for the same idea:

| Arch | Instruction | Bytes |
| --- | --- | --- |
| arm64 | `mov w0, #1` | `20 00 80 52` |
| arm64 | `mov w0, #0` | `00 00 80 52` |
| arm64 | `mov x0, #1` | `20 00 80 d2` |
| arm64 | `ret` | `c0 03 5f d6` |
| armv7 | `mov r0, #1` | `01 00 a0 e3` |
| armv7 | `bx lr` | `1e ff 2f e1` |
| x86_64 | `mov eax, 1` | `b8 01 00 00 00` |
| x86_64 | `ret` | `c3` |

Rather than blind-patching the prologue, look at what the function actually does. A common
shape is:

```asm
; arm64
cmp  w0, #0
b.eq 0x...            ; early return 0
...
mov  w0, #1
ret
```

In that case patching the conditional branch is the smaller change. `b.eq` with a 4-byte
displacement encodes as `20 00 00 54`; `b.ne` with the same displacement is `21 00 00 54`
(the difference is the condition field in the lowest byte: EQ = `0`, NE = `1`).

Find the file offset of the instruction. radare2 works in virtual addresses; convert to file
offset with the section table:

```bash
cd /path/to/work/libs
rabin2 -S lib/arm64-v8a/liblicence.so | grep -E '\.text|Name'
# 0x00001238 0x00001238 0x00001800 0x00000040 0x00000000 0x00 0x0 .text
# paddr      vaddr      vsize     size      vaddr2   perm ...
```

`file_offset = vaddr - section.vaddr + section.paddr`. With `vaddr` from
`r2 -qc 'is~Java_com_vendor_app_LicenseManager_isLicensed'`:

```bash
r2 -qc 's sym.Java_com_vendor_app_LicenseManager_isLicensed; pd 12' lib/arm64-v8a/liblicence.so
```

Apply the patch with LIEF 1.0.0, which handles the segment layout:

```python
# patch_licence.py — run with: python3 patch_licence.py
import lief

BIN = "lib/arm64-v8a/liblicence.so"
TARGET = "Java_com_vendor_app_LicenseManager_isLicensed"
PATCH = bytes.fromhex("20008052c0035fd6")   # mov w0, #1 ; ret

binary = lief.parse(BIN)
symbol = binary.get_dynamic_symbol(TARGET).value
segment = next(s for s in binary.segments if s.virtual_address <= symbol < s.virtual_address + s.virtual_size)
offset = symbol - segment.virtual_address + segment.file_offset

data = bytearray(open(BIN, "rb").read())
data[offset:offset + len(PATCH)] = PATCH
open(BIN, "wb").write(bytes(data))
print(f"patched {TARGET} at vaddr 0x{symbol:x} file offset 0x{offset:x}")
```

A hex-editor alternative when the offsets are already known:

```bash
printf '\x20\x00\x80\x52\xc0\x03\x5f\xd6' | dd of=lib/arm64-v8a/liblicence.so \
  bs=1 seek=$((0x3a40)) conv=notrunc
```

### 5. Put the library back into the APK

The `.so` must stay **uncompressed and page-aligned** when the app sets
`android:extractNativeLibs="false"` in the manifest (the default for apps built against API
23+). A compressed library forces extraction and also breaks the page-alignment requirement.

```bash
cd /path/to/work
cp app_original.apk build/app_patched.apk

# remove the old entry, then add the patched one stored (not deflated)
zip -d build/app_patched.apk "lib/arm64-v8a/liblicence.so"
zip -X -0 build/app_patched.apk "lib/arm64-v8a/liblicence.so"

# align, then sign
zipalign -P 16 -f 4 build/app_patched.apk build/app_aligned.apk
apksigner sign \
  --ks debug.keystore \
  --ks-key-alias androiddebugkey \
  --ks-pass pass:android \
  --key-pass pass:android \
  --out build/app_signed.apk \
  build/app_aligned.apk
apksigner verify --verbose --print-certs build/app_signed.apk
```

Repeat for every ABI the APK carries: `lib/armeabi-v7a/`, `lib/arm64-v8a/`, `lib/x86_64/`.

With apktool the equivalent is to leave the library in `unknown/lib/<abi>/` and add it to
`apktool.yml` so it is stored uncompressed:

```yaml
doNotCompress:
  - resources.arsc
  - lib/arm64-v8a/liblicence.so
```

Then `apktool b app_decoded -o build/app_built.apk` and continue with `zipalign` and
`apksigner`.

### 6. Force the value at runtime with Frida

Runtime hooking is faster than a rebuild and survives the signing problems above. Frida 17
removed the static `Module.findExportByName`; use the module instance API.

#### 6a. Rooted device with frida-server

```bash
# on the workstation
adb push frida-server-17.26.0-android-arm64 /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
adb shell su -c "/data/local/tmp/frida-server -l 0.0.0.0:27042 &"
adb forward tcp:27042 tcp:27042
frida -U -f com.vendor.app -l hook_licence.js
```

Frida 16 and later resume a spawned process automatically; the old `--no-pause` flag was
removed in 17. If the app must be resumed manually, put `%resume` at the top of the script.

#### 6b. Stock device with Frida Gadget

Copy the Gadget into the APK and load it from the application class:

```bash
cd /path/to/work
cp frida-gadget-17.26.0-android-arm64.so app_decoded/lib/arm64-v8a/libfrida-gadget.so
cp frida-gadget-17.26.0-android-arm64.so app_decoded/lib/x86_64/libfrida-gadget.so
```

The Gadget reads its configuration from a file next to the library, with the extension
replaced by `.config.json`. For a library named `libfrida-gadget.so` that is
`lib/arm64-v8a/libfrida-gadget.config.json` and `lib/x86_64/libfrida-gadget.config.json`:

```json
{
  "interaction": {
    "type": "script",
    "path": "assets/agent.js",
    "on_change": "reload"
  },
  "runtime": "qjs",
  "teardown": "minimal"
}
```

- `interaction.type: "script"` makes the Gadget autonomous: it loads the script at startup
  with no host attached, which is the only workable mode on a device without `frida-server`.
- `path` is resolved relative to the application bundle. `assets/agent.js` is the usual
  placement; put the file in `app_decoded/assets/agent.js`.
- If the library is renamed to `libgadget.so`, the configuration file must be renamed to
  `libgadget.config.json` to match.

Load the Gadget by adding a `System.loadLibrary("frida-gadget")` call to the `<clinit>` of the
application class named in the manifest (`android:name` attribute of the `<application>` tag),
then rebuild:

```bash
cd /path/to/work
apktool b app_decoded -o build/app_built.apk
zipalign -P 16 -f 4 build/app_built.apk build/app_aligned.apk
apksigner sign --ks debug.keystore --ks-key-alias androiddebugkey \
  --ks-pass pass:android --key-pass pass:android \
  --out build/app_signed.apk build/app_aligned.apk
adb install -r build/app_signed.apk
```

The Gadget must match the device ABI: `arm64` for a modern ARM device, `x86_64` for an
emulator.

#### 6c. The hook script

```js
// hook_licence.js — Frida 17.x, frida-server or Gadget
'use strict';

const LIB = 'liblicence.so';
const SYMBOL = 'Java_com_vendor_app_LicenseManager_isLicensed';

function findModule(name) {
  for (const m of Process.enumerateModules()) {
    if (m.name === name || m.path.endsWith('/' + name)) {
      return m;
    }
  }
  return null;
}

function hook() {
  const mod = findModule(LIB);
  if (mod === null) {
    console.log('[-] ' + LIB + ' not loaded yet, waiting');
    return false;
  }
  let fn;
  try {
    fn = mod.getExportByName(SYMBOL);
  } catch (e) {
    console.log('[-] ' + SYMBOL + ' not exported: ' + e.message);
    return false;
  }
  if (fn.isNull()) {
    console.log('[-] ' + SYMBOL + ' is null');
    return false;
  }
  Interceptor.replace(fn, new NativeCallback(function (env, obj) {
    console.log('[+] ' + SYMBOL + ' forced to true');
    return 1;                     // JNI_TRUE
  }, 'int', ['pointer', 'pointer']));
  console.log('[+] hooked ' + SYMBOL + ' at ' + fn);
  return true;
}

if (!hook()) {
  // The library is loaded by System.loadLibrary later than this script runs.
  Process.attachModuleObserver({
    onAdded(module) {
      if (module.name === LIB) {
        console.log('[+] ' + LIB + ' loaded, hooking now');
        hook();
      }
    }
  });
}
```

Notes on the script:

- The JNI signature of a static method is `(JNIEnv*, jclass)`; of an instance method it is
  `(JNIEnv*, jobject)`. Both are two pointers, so the argument list does not change; only the
  meaning of the second argument differs.
- `Interceptor.replace` replaces the function for the whole process, including calls made
  from other threads.
- The return value must be an integer; `1` is `JNI_TRUE`.
- If the library registers its methods dynamically with `RegisterNatives`, there is no
  exported symbol. Hook `RegisterNatives` instead and patch the `functionPointer` in the
  array it receives, or hook the Java-side method with the Java bridge (see
  [`play-billing-entitlement-faking.md`](play-billing-entitlement-faking.md)).

## Variations

### Interposing the helper instead of the entry point

If the licence function is short and calls a helper such as `validate_key`, hooking the
helper covers every caller:

```js
const mod = Process.getModuleByName('liblicence.so');
const helper = mod.getExportByName('validate_key');
Interceptor.replace(helper, new NativeCallback(function (key) {
  console.log('[+] validate_key -> 1');
  return 1;
}, 'int', ['pointer']));
```

### Hooking the Java layer from the same script

With the `frida-java-bridge` installed and bundled through `frida-compile` (Frida 17 does not
ship the bridges inside the runtime), the same process can be hooked at the Java level, which
also covers `RegisterNatives` cases:

```js
// agent.ts — compile with: npx frida-compile agent.ts -o agent.js
import Java from 'frida-java-bridge';

Java.perform(() => {
  const Manager = Java.use('com.vendor.app.LicenseManager');
  Manager.isLicensed.implementation = function () {
    console.log('[+] LicenseManager.isLicensed -> true');
    return true;
  };
});
```

### Patching a stripped library

When symbols are stripped, `nm` and `readelf -s` show nothing. Reconstruct the candidates
from the strings and the call graph:

```bash
r2 -qc 'aaa; afl~Java_' lib/arm64-v8a/liblicence.so
r2 -qc 'iz~isLicen; axt @@ str.*isLicen' lib/arm64-v8a/liblicence.so
```

`afl` lists the functions radare2 discovered; the JNI entry points are the exported ones that
take two pointer arguments and return an int.

### Thumb and ARM32 slices

On `armeabi-v7a`, the entry point symbol has the low bit set (Thumb mode). Clear the low bit
before computing the file offset, and expect `mov r0, #1` (`01 00 a0 e3`) plus `bx lr`
(`1e ff 2f e1`).

### x86_64 slices

Emulators and Chromebooks use `lib/x86_64/`. `mov eax, 1` is `b8 01 00 00 00` and `ret` is
`c3`. The System V return register is `rax`, so `eax` is the 32-bit sub-register and the
boolean lands in the low byte as expected.

### Runtime patching without a rebuilt APK

`Memory.patchCode` can write the patched bytes into the live mapping:

```js
const mod = Process.getModuleByName('liblicence.so');
const fn = mod.getExportByName('Java_com_vendor_app_LicenseManager_isLicensed');
const PATCH = new Uint8Array([0x20, 0x00, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6]);
Memory.patchCode(fn, PATCH.length, code => {
  code.writeByteArray(PATCH);
});
console.log('[+] patched in memory');
```

This is ephemeral: it dies with the process and is not a patch.

## Verification

1. Static check. Disassemble the patched function and confirm the new instructions:

   ```bash
   r2 -qc 's sym.Java_com_vendor_app_LicenseManager_isLicensed; pd 4' lib/arm64-v8a/liblicence.so
   ```

   Expected: `mov w0, 1` then `ret`.
2. Container check. `zipalign -c -v 4 build/app_signed.apk` reports
   `Verification succesful`, and `unzip -lv build/app_signed.apk 'lib/*/liblicence.so'` shows
   the `Stored` method, not `Defl:N`.
3. Signature check. `apksigner verify --verbose --print-certs build/app_signed.apk` prints
   `Verifies` with v2 and v3 enabled.
4. Runtime check. Launch the app, confirm the licensed UI, and confirm the native log line
   no longer appears (`adb logcat | grep -i license`).
5. Negative test. Reinstall the original APK and confirm the native check runs again and the
   app refuses. Then reinstall the patched build and confirm the licence feature is unlocked.
   If the app caches the entitlement, clear it with `adb shell pm clear com.vendor.app`
   before the negative test so a cached success cannot masquerade as a patch.

## Pitfalls

- **Patching the wrong ABI slice.** The device runs the slice for its ABI. Patching
  `lib/x86_64` and testing on an ARM phone changes nothing.
- **Patching the symbol address without the ELF mapping.** The symbol value is a virtual
  address; writing at that offset in the file corrupts the wrong bytes. Convert through the
  segment table (`file_offset = vaddr - segment.virtual_address + segment.file_offset`).
- **A stripped library has no `Java_*` symbol.** Look for the dynamically registered methods
  instead.
- **Compressing the `.so` on the way back in.** `zip` with default deflate breaks
  `android:extractNativeLibs="false"` builds. Use `zip -X -0`.
- **Aligning after signing.** The v2/v3 signature covers the file; realigning invalidates it.
  Align, then sign.
- **The native code re-checks its own integrity.** Some libraries hash their own text segment
  at startup and refuse to run when it changes. Expect a crash or an immediate "tampered"
  message after patching.
- **The decision is not in the native library.** Many apps validate the licence on the
  server; the native call only returns a cached answer. See
  [`play-billing-entitlement-faking.md`](play-billing-entitlement-faking.md).
- **Frida Gadget breaks the app start-up.** A Gadget configuration with a wrong `path` makes
  the app hang on the splash screen. The Gadget log goes to `adb logcat -s Frida`.
- **`Process.codeSigningPolicy`.** On a platform where signing is mandatory, `Interceptor`
  and in-memory modification are refused. Check `Process.codeSigningPolicy` before relying on
  them.
- **The Frida bridge is missing.** Frida 17 no longer bundles `Java`/`ObjC`/`Swift`; a script
  that uses `Java.perform` throws `TypeError: undefined is not an object (evaluating
  'Java.perform')`. Install `frida-java-bridge` and bundle it with `frida-compile`.

## References

- Frida 17.x JavaScript API: <https://frida.re/docs/javascript-api/>
- Frida Gadget configuration: <https://frida.re/docs/gadget/>
- Frida bridges (separate packages since 17.0.0): <https://frida.re/docs/bridges/>
- Android NDK, "JNI tips" and the JNI naming convention:
  <https://developer.android.com/ndk/guides/jni-tip>
- Android "Package native code" and `extractNativeLibs`:
  <https://developer.android.com/guide/topics/manifest/application-element>
- LIEF 1.0.0 ELF documentation: <https://lief.re/doc/latest/formats/elf.html>
- radare2 6.2.6 release: <https://github.com/radareorg/radare2/releases>
- Sibling entries: [`apk-decode-rebuild-sign.md`](apk-decode-rebuild-sign.md),
  [`dex-smali-licence-patching.md`](dex-smali-licence-patching.md),
  [`play-billing-entitlement-faking.md`](play-billing-entitlement-faking.md)
