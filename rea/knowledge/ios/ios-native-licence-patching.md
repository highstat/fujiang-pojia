---
id: "ios-native-licence-patching"
title: "iOS native licence patching"
domain: "ios"
kind: "technique"
platforms: "ios"
arch: "arm64"
difficulty: "advanced"
tools: "r2, rabin2, otool, nm, class-dump, strings, LIEF, Frida, codesign"
verified: false
updated: "2026-11-15"
summary: "Locate the Objective-C method or C function that returns an iOS entitlement, patch its arm64 boolean return in the Mach-O, and force it at runtime with Frida while keeping the code signature valid."
---

## Summary

An iOS licence gate is usually an Objective-C method that returns a `BOOL`. The compiler
generates a handful of arm64 instructions, and the value comes back in `w0` through
`objc_msgSend`. Patching the constant that is loaded into `w0` changes the answer for every
caller, including the ones the app never takes itself.

The patch is four bytes in `__TEXT`, which means the code signature no longer matches and
the binary has to be re-signed. Runtime hooking with Frida avoids the re-signing entirely
and is the right first step while the offset is still being established.

## Recognition

### Mach-O layout

- iOS binaries are Mach-O, arm64 (and arm64e for the hardened slice). 32-bit arm is dead.
- `otool -l App | head -40` shows the load commands: `LC_SEGMENT_64 __TEXT` with
  `vmaddr 0x100000000` and `fileoff 0`, `__DATA` and `__DATA_CONST`, `__LINKEDIT`.
- `__TEXT` holds the code and the read-only data: `__text`, `__cstring`, `__objc_methname`,
  `__objc_classname`, `__swift5_*`.
- `__DATA` holds `__objc_classlist`, `__objc_protolist`, `__objc_const`, `__const`.
- `__objc_methname` holds the selector strings: `isLicensed`, `licenseKey`, `validate`.
- `LC_LOAD_DYLIB` lists the frameworks the binary links against.

### The gate

- A class named after the domain — `LicenseManager`, `LicenceController`, `SubscriptionManager`,
  `EntitlementService` — with a selector named after the decision: `isLicensed`,
  `hasValidLicense`, `isActivated`, `isPremium`, `checkLicense`.
- The method returns `BOOL`, so its implementation is tiny: a compare, a branch, a constant
  into `w0`, and `ret`.
- A JavaScript- or configuration-driven gate reads a key from a dictionary or a JSON file in
  `Library/Application Support/` or the app container.

### Artefacts that confirm the gate

- A string in `__cstring`: `license expired`, `Subscription inactive`, `ERR_LICENSE_013`,
  `https://vendor.example/api/validate`.
- A key in `NSUserDefaults`: `license_valid`, `premium`, `entitlement`.
- A file in the container: `Library/Application Support/license.json`,
  `Library/Caches/license.plist`.
- `NSLog` output on failure: `[-[LicenseManager isLicensed] license rejected]`.

## Method

### 1. Locate the class and the selector

```bash
cd /path/to/work
class-dump -H App.app/App | grep -A6 'LicenseManager'
```

`class-dump` prints the interface with the method list. Without class-dump:

```bash
otool -oV App.app/App | grep -B4 -A12 'isLicensed'
nm -m App.app/App | grep -i 'licens'
strings -a App.app/App | grep -n 'isLicensed'
r2 -qc 'ic~Licens' App.app/App
r2 -qc 'ic~Licens' App.app/App
```

The radare2 command `ic` lists the Objective-C classes and methods; `ic~Licens` filters on
the licence-related names. `rabin2 -cc App.app/App` gives the same list in JSON.

`otool -oV` prints the implementation address of each method:

```text
0000000100001234  -[LicenseManager isLicensed]
```

### 2. Disassemble the method

```bash
cd /path/to/work
r2 -qc 's 0x100001234; pd 12' App.app/App
otool -tvV App.app/App | grep -A12 'isLicensed'
```

The typical arm64 body:

```asm
100001234:  adrp x1, 0x100003000
100001238:  add  x1, x1, 0x1a0        ; "license expired"
10000123c:  mov  w0, #0
100001240:  ret
```

and the checked variant:

```asm
100001234:  bl   _objc_retainAutoreleasedReturnValue
100001238:  cbz  x0, 0x100001250
10000123c:  ldrb  w0, [x0, #0x10]      ; the entitlement flag
100001240:  ret
100001244:  mov  w0, #0
100001248:  ret
```

### 3. Patch the return value

The boolean is materialised with `mov w0, #0` or `mov w0, #1`:

| Instruction | Bytes | Notes |
| --- | --- | --- |
| `mov w0, #0` | `00 00 80 52` | false |
| `mov w0, #1` | `20 00 80 52` | true |
| `mov x0, #0` | `00 00 80 d2` | pointer-sized variant |
| `mov x0, #1` | `20 00 80 d2` | pointer-sized variant |
| `ret` | `c0 03 5f d6` | return |
| `cbz x0, +8` | `20 00 00 34` | conditional branch, 32-bit register |
| `cbnz x0, +8` | `20 00 00 35` | the opposite branch |
| `b.eq +8` | `20 00 00 54` | conditional branch |
| `b.ne +8` | `21 00 00 54` | the opposite branch |

To force the licensed answer, replace `00 00 80 52` with `20 00 80 52` at the offset of
`mov w0, #0`:

```text
offset 0x1238:  00 00 80 52   ->   20 00 80 52      mov w0, #0  ->  mov w0, #1
```

The `b.eq` / `b.ne` pair differs only in the lowest byte of the 32-bit word (the condition
field: EQ = `0`, NE = `1`). To flip the branch, change `20` to `21` in the little-endian
encoding.

For a branch that selects between two return values, flipping the condition is the smaller
edit than replacing the constant.

### 4. Compute the file offset

The address from `otool -oV` is a virtual address. The file offset is:

```text
file_offset = vmaddr - segment.vmaddr + segment.fileoff
```

For `__TEXT` the segment is `vmaddr 0x100000000`, `fileoff 0`, so the file offset of
`0x100001234` is `0x1234`:

```bash
otool -l App.app/App | grep -A6 'segname __TEXT'
```

Write the bytes:

```bash
cd /path/to/work
printf '\x20\x00\x80\x52' | dd of=App.app/App bs=1 seek=$((0x1234)) conv=notrunc
```

Or with LIEF 1.0.0, which also handles the fat-binary slice selection:

```python
# patch_licence.py — python3 patch_licence.py
import lief

PATH = "App.app/App"
VADDR = 0x100001234
PATCH = list(bytes.fromhex("20008052"))   # mov w0, #1

fat = lief.MachO.parse(PATH)
for binary in fat:
    binary.patch_address(VADDR, PATCH)
fat.write(PATH)
```

`patch_address` exists on the Mach-O surface in LIEF 1.0.0. It patches the file content at
the offset that backs the given virtual address.

### 5. Re-sign

Any edit to `__TEXT` invalidates the code signature: `LC_CODE_SIGNATURE` points at a
signature blob in `__LINKEDIT` that covers the whole file.

```bash
cd /path/to/work
codesign --remove-signature App.app/App
rm -rf App.app/_CodeSignature
codesign --force --sign - --timestamp=none --entitlements entitlements.plist App.app/App
codesign --verify --verbose=4 App.app/App
```

The full bundle-level sequence, including the nested frameworks, is in
[`ipa-repack-and-resign.md`](ipa-repack-and-resign.md).

### 6. Force the value at runtime with Frida

Runtime hooking avoids the offset work and the re-signing. Frida 17 removed the static
`Module.findExportByName`; use the module instance API.

```js
// hook_licence.js — Frida 17.x on iOS
'use strict';

const APP = 'App';

function findModule(name) {
  for (const m of Process.enumerateModules()) {
    if (m.name === name || m.path.endsWith('/' + name)) {
      return m;
    }
  }
  return null;
}

const mod = findModule(APP);
if (mod === null) {
  console.log('[-] ' + APP + ' not found');
} else {
  console.log('[+] ' + APP + ' at ' + mod.base);
}
```

#### Objective-C level

The Objective-C bridge replaces a method by assigning its implementation. The replacement
runs in place of the original and receives `this` and the arguments:

```js
'use strict';

if (typeof ObjC === 'undefined') {
  console.log('[-] the Objective-C bridge is not bundled in this build');
} else {
  ObjC.schedule(function () {
    const LicenseManager = ObjC.classes.LicenseManager;
    if (LicenseManager === undefined) {
      console.log('[-] LicenseManager class not found');
      return;
    }
    const sel = '-isLicensed';
    if (!LicenseManager[sel]) {
      console.log('[-] -[LicenseManager isLicensed] not found');
      return;
    }
    LicenseManager[sel].implementation = function () {
      console.log('[+] -[LicenseManager isLicensed] forced to true');
      return true;
    };
    console.log('[+] hooked -[LicenseManager isLicensed]');
  });
}
```

Inside the replacement, the original implementation stays reachable as
`this.isLicensed_()` (the selector with colons replaced by underscores), which is how a
partial override is written:

```js
LicenseManager['-isLicensed'].implementation = function () {
  const original = this.isLicensed_();
  console.log('[+] original returned ' + original + ', forcing true');
  return true;
};
```

Frida 17 no longer bundles the Objective-C bridge either. Install `frida-objc-bridge` and
bundle it with `frida-compile`:

```bash
npm install frida-objc-bridge
npx frida-compile agent.ts -o agent.js
frida -U -f com.vendor.app -l agent.js
```

#### Native level

When the decision is a C function, replace the exported symbol:

```js
'use strict';

const APP = 'App';
const SYMBOL = '_license_is_valid';

function findModule(name) {
  for (const m of Process.enumerateModules()) {
    if (m.name === name || m.path.endsWith('/' + name)) {
      return m;
    }
  }
  return null;
}

const mod = findModule(APP);
if (mod === null) {
  console.log('[-] ' + APP + ' not found');
} else {
  let fn;
  try {
    fn = mod.getExportByName(SYMBOL);
  } catch (e) {
    console.log('[-] ' + SYMBOL + ' not exported: ' + e.message);
  }
  if (fn !== undefined && !fn.isNull()) {
    Interceptor.replace(fn, new NativeCallback(function () {
      console.log('[+] ' + SYMBOL + ' forced to 1');
      return 1;
    }, 'int', []));
    console.log('[+] hooked ' + SYMBOL + ' at ' + fn);
  }
}
```

`Interceptor.replace` replaces the function for the whole process, including calls from
other threads and from inside `objc_msgSend` senders.

#### Hooking the message dispatch

To observe every call to the selector, without replacing it:

```js
ObjC.schedule(function () {
  const LicenseManager = ObjC.classes.LicenseManager;
  const method = LicenseManager['-isLicensed'];
  const original = method.implementation;
  Interceptor.attach(original, {
    onLeave(retval) {
      console.log('[+] -[LicenseManager isLicensed] returned ' + retval);
    }
  });
});
```

## Variations

### arm64e and pointer authentication

- The arm64e slice adds pointer authentication (`pacib`, `autib`) around pointer returns and
  some function pointers.
- Ordinary `BOOL` returns are unaffected: `w0` holds an integer, not a pointer, and no
  signing instruction applies to it. Patching `mov w0, #0` to `mov w0, #1` behaves the same
  in an arm64e slice.
- The arm64e slice has its own file offset inside a fat binary. A patch applied at the arm64
  offset does not touch the arm64e code, and the two slices diverge at every offset. Patch
  both, or the device may load the slice that was not patched.
- `__TEXT_EXEC` in the arm64e slice may be a separate segment with its own permissions; the
  offset arithmetic in step 4 uses the segment that contains the address, which is not
  necessarily `__TEXT`.

### Swift code

A Swift `var isLicensed: Bool` or a computed property compiles to a getter with the same
shape. The selector name is mangled (`s5App10LicenseMgmtB6isLicensedSbvg`); find it with
`nm -m App | grep -i licens` or `r2 -qc 'ic~licens' App`. Swift's `bool` return is also in
`w0`, so the same four-byte patch applies.

### Stripped binaries

With `STRIP_INSTALLED_PRODUCT = YES` the symbols are gone but the Objective-C metadata is
not: `ic` in radare2 and `otool -oV` still list the classes and methods, because the
Objective-C runtime looks them up through `__objc_classlist`. The implementation address is
still available from the metadata.

### Encrypted binaries

The App Store binary is encrypted; the method bodies are not readable on disk. Decrypt it
first — see [`fairplay-decrypted-binary-handling.md`](fairplay-decrypted-binary-handling.md).

### One gate, many call sites

The same decision is often consulted from the UI, from a background queue and from a
notification handler. Patching the method covers all of them; patching a call site covers
one.

### Swift/ObjC interop trampolines

When a Swift class is exposed to Objective-C, the Swift implementation calls into a
trampoline. The `mov w0, #1` must go into the Swift implementation, not into the
`__objc_stubs` trampoline, or the trampoline will overwrite the return value.

## Verification

1. Disassembly check. After patching, re-read the instruction:

   ```bash
   r2 -qc 's 0x100001234; pd 6' App.app/App
   ```

   Expected: `mov w0, 1` instead of `mov w0, 0`.

2. Signature check. `codesign --verify --verbose=4 App.app/App` must succeed after
   re-signing; a patched but unsigned binary fails with `code object is not signed at all`.
3. Runtime check. Launch the app and confirm the licensed UI. If the method returns a
   `BOOL`, the gate changes from a locked screen to the entitled screen.
4. Hook check. With the Frida script attached, the log line
   `[+] -[LicenseManager isLicensed] forced to true` proves the method was reached, and the
   absence of the original implementation's log line proves the replacement took effect.
5. Negative test. Reinstall the unmodified binary and confirm the gate returns. Then clear
   the app's cached state (`rm -rf` the app container on a jailbroken device, or uninstall
   and reinstall) and confirm the patched build still passes. A patch that only survives
   because a licence flag was cached is not a patch.

## Pitfalls

- **Patching without re-signing.** `__TEXT` is covered by the code signature. The app is
  killed at launch with `Killed: 9` and a `dyld` message about a corrupt or invalid code
  signature.
- **Virtual address used as a file offset.** `0x100001234` is not `0x1234`. Compute
  `file_offset = vmaddr - segment.vmaddr + segment.fileoff`.
- **Only one fat slice patched.** The device picks the arm64e slice on arm64e hardware. Patch
  both, or check which slice the device actually loaded:
  `vmmap <pid> | grep App`.
- **The wrong `mov`.** `mov w0, #1` also appears in unrelated methods. Confirm the offset
  belongs to the target method by disassembling from the method's implementation address.
- **The return value is not in `w0`.** A method returning an `NSNumber` or an enum returns a
  pointer or a wider value; the patch bytes differ. Read the return type from the class dump.
- **The gate is server-side.** A patched client flag does not unlock a server response.
- **The bridge is missing.** Frida 17 does not bundle `ObjC`; the script throws
  `TypeError: undefined is not an object (evaluating 'ObjC.schedule')`. Install
  `frida-objc-bridge` and bundle it with `frida-compile`.
- **Entitlements lost on re-signing.** Without `--entitlements`, the app loses keychain
  access and push. See [`ipa-repack-and-resign.md`](ipa-repack-and-resign.md).
- **The method is called before the hook is installed.** Attaching to a running process is
  too late for a check that runs during launch. Spawn with
  `frida -U -f com.vendor.app -l agent.js` or inject the Gadget.
- **Anti-tamper.** Apps that verify their own `__TEXT` hash detect the patch immediately.

## References

- Apple, "Mach-O Programming Topics" (segments, sections, load commands):
  <https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/MachOOverview.html>
- Apple, "Dynamic Linking":
  <https://developer.apple.com/library/archive/documentation/DeveloperTools/Conceptual/DynamicLibraries/100-Articles/DynamicLibraries.html>
- ARM Architecture Reference Manual, A64 instruction encodings:
  <https://developer.arm.com/documentation/ddi0487/latest>
- LIEF 1.0.0 Mach-O documentation: <https://lief.re/doc/latest/formats/macho.html>
- Frida 17.x JavaScript API: <https://frida.re/docs/javascript-api/>
- Frida bridges: <https://frida.re/docs/bridges/>
- `class-dump`: <https://github.com/nickhutchinson/ClassDump>
- Sibling entries: [`ipa-repack-and-resign.md`](ipa-repack-and-resign.md),
  [`fairplay-decrypted-binary-handling.md`](fairplay-decrypted-binary-handling.md),
  [`jailbreak-detection-bypass.md`](jailbreak-detection-bypass.md)
