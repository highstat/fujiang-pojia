---
id: "hardened-runtime-and-library-validation"
title: "Hardened runtime and library validation"
domain: "macos"
kind: "technique"
platforms: "macos"
arch: "x86-64, arm64"
difficulty: "advanced"
tools: "codesign,otool,optool,frida,security"
verified: false
updated: "2026-11-15"
summary: "Explains how the hardened runtime and library validation block dynamic library injection into a signed macOS app, and gives the three workable routes — entitlement re-sign, DYLD_INSERT_LIBRARIES on a non-hardened build, and an added LC_LOAD_DYLIB — with the exact codesign invocations and confirmation steps."
---

## Summary

The hardened runtime is the switch that decides whether a dynamic library can be loaded into a
signed app. This entry explains what library validation and the `DYLD_*` restrictions actually
enforce, then gives the three routes that remain open: re-signing with
`com.apple.security.cs.disable-library-validation`, using `DYLD_INSERT_LIBRARIES` where it is still
honoured, and adding an `LC_LOAD_DYLIB` to the executable itself. Reach for it when
`DYLD_INSERT_LIBRARIES` is silently ignored and the injected library never loads.

## Recognition

- `codesign -dvvv Foo.app` shows `flags=0x10000(runtime)`; the `runtime` flag is the hardened
  runtime.
- `codesign -d --entitlements - Foo.app` shows **no**
  `com.apple.security.cs.disable-library-validation` key. Its absence is what enforces validation.
- `DYLD_INSERT_LIBRARIES=/path/lib.dylib ./Foo` starts normally and the library's constructor never
  runs; `DYLD_PRINT_LIBRARIES=1 ./Foo` prints the loaded libraries and the injected one is absent.
- `log stream --predicate 'eventMessage CONTAINS "DYLD"'` shows
  `dyld[pid:123]: DYLD_INSERT_LIBRARIES ignored because the program uses the hardened runtime`.
- `otool -l Foo` has no `LC_LOAD_DYLIB` entry pointing outside the bundle, and no `LC_RPATH` that
  includes a writable directory.
- A setuid binary under `AT_SECURE` (`getauxval(AT_SECURE) != 0`) drops every `DYLD_*` variable.
- On a SIP-protected system, `/usr/bin/sipconfig` reports `System Integrity Protection status:
  enabled`, and `/System/Library/*` binaries ignore `DYLD_*` regardless of the entitlements.

## Method

### 1. Establish the current enforcement state

```bash
cd /path/to/Foo.app
codesign -dvvv Contents/MacOS/Foo 2>&1 | grep -E 'flags=|Identifier=|TeamIdentifier='
codesign -d --entitlements - Contents/MacOS/Foo 2>&1
otool -l Contents/MacOS/Foo | grep -A4 LC_CODE_SIGNATURE
```

Record three facts: the `flags=` value, the presence or absence of
`com.apple.security.cs.disable-library-validation`, and whether the process runs under SIP or
`AT_SECURE`.

### 2. Route (a): re-sign with library validation disabled

This is the general route. It works on hardened and non-hardened builds and does not depend on
`DYLD_*` surviving.

Write the entitlement file:

```bash
cat > /tmp/disable-libval.plist <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>com.apple.security.cs.disable-library-validation</key>
  <true/>
  <key>com.apple.security.cs.allow-dyld-environment-variables</key>
  <true/>
  <key>com.apple.security.cs.allow-unsigned-executable-memory</key>
  <true/>
</dict>
</plist>
PLIST
plutil -lint /tmp/disable-libval.plist
```

Expected: `OK`.

Strip the hardened-runtime flag while keeping the other entitlements. Two equivalent routes:

```bash
# Route A1: preserve entitlements and requirements, drop the runtime flag by
# simply not passing --options runtime.
codesign --force --sign - \
  --preserve-metadata=entitlements,requirements,flags \
  --entitlements /tmp/disable-libval.plist \
  --timestamp=none \
  Foo.app
```

```bash
# Route A2: strip the runtime flag explicitly with ldid / optool before signing.
optool uninstall -s Foo.app          # removes the existing signature
codesign --force --sign - \
  --entitlements /tmp/disable-libval.plist \
  --timestamp=none \
  Foo.app
```

`--preserve-metadata=entitlements,requirements,flags` copies the original entitlements, the
designated requirement and the original flags. Because `--options runtime` is absent from the
command line, the hardened runtime is not re-enabled, so the `runtime` flag disappears from the new
CodeDirectory while the preserved entitlements merge with the supplied file.

Confirm both halves:

```bash
codesign -dvvv Foo.app 2>&1 | grep -E 'flags='
codesign -d --entitlements - Foo.app 2>&1
otool -l Contents/MacOS/Foo | grep -A4 LC_CODE_SIGNATURE
```

Expected: `flags=0x0(adhoc)` with no `runtime` flag, the entitlements XML containing
`com.apple.security.cs.disable-library-validation` set to `true`, and the `LC_CODE_SIGNATURE`
`datasize` changed because the blob was rewritten.

If the app is not a bundle but a bare Mach-O, sign that file directly:

```bash
codesign --force --sign - --entitlements /tmp/disable-libval.plist --timestamp=none ./Foo
```

### 3. Route (b): DYLD_INSERT_LIBRARIES on a non-hardened build

Where the hardened runtime is off and the binary is not `AT_SECURE`, the variable is honoured:

```bash
DYLD_INSERT_LIBRARIES=$PWD/libhook.dylib ./Foo
```

Confirm the injection actually happened:

```bash
DYLD_PRINT_LIBRARIES=1 DYLD_INSERT_LIBRARIES=$PWD/libhook.dylib ./Foo 2>&1 | grep -i libhook
```

Expected: `/path/to/libhook.dylib` appears in the printed library list.

If it does not appear, the variable was stripped. The reason is visible in the unified log:

```bash
log stream --style compact --predicate 'eventMessage CONTAINS[c] "DYLD"' &
DYLD_INSERT_LIBRARIES=$PWD/libhook.dylib ./Foo
```

Expected messages:

- `DYLD_INSERT_LIBRARIES ignored because the program uses the hardened runtime`
- `DYLD_INSERT_LIBRARIES ignored because the program is setuid`
- `DYLD_INSERT_LIBRARIES ignored because the program is protected by SIP`

The SIP case can be confirmed with:

```bash
/usr/bin/csrutil status
```

### 4. Route (c): add an LC_LOAD_DYLIB to the executable

This removes the dependency on the environment entirely. The load command is inserted into the
Mach-O and the binary is re-signed.

```bash
cd /path/to/Foo.app
optool install -c load -p "@executable_path/../Frameworks/libhook.dylib" Contents/MacOS/Foo
codesign --force --sign - --entitlements /tmp/disable-libval.plist --timestamp=none Contents/MacOS/Foo
codesign --force --sign - --timestamp=none Foo.app
```

Verify the load command landed:

```bash
otool -L Contents/MacOS/Foo | grep -i libhook
```

Expected: `Contents/MacOS/libhook.dylib (compatibility version 1.0.0, current version 1.0.0)`.

`optool` also removes the existing signature in the same pass, so the re-sign order is mandatory.
The dylib must be reachable through an existing `LC_RPATH` or through `@executable_path`. Confirm
the path resolves:

```bash
otool -l Contents/MacOS/Foo | grep -A2 LC_RPATH
```

A relative path such as `@loader_path/../Frameworks/libhook.dylib` resolves relative to the
executable that loads it; `@executable_path` resolves relative to the main executable.

### 5. Confirm the injected library loads

```bash
DYLD_PRINT_LIBRARIES=1 ./Contents/MacOS/Foo 2>&1 | grep -i libhook
```

Expected: the library path appears, and the library's constructor output appears on stdout or
stderr. A constructor is the cheapest positive test:

```c
#include <stdio.h>
__attribute__((constructor)) static void announce(void) {
    fprintf(stderr, "libhook: loaded at %p\n", (void *)announce);
}
```

Compile and place it where the load command points:

```bash
clang -dynamiclib -o /tmp/libhook.dylib libhook.c
mkdir -p Foo.app/Contents/Frameworks
cp /tmp/libhook.dylib Foo.app/Contents/Frameworks/libhook.dylib
```

### 6. The Frida path

Frida 17.x injects into a process through the same machinery, so the same rules apply. Attach to a
running process:

```javascript
// attach.js — Frida 17.x, instance-side module API
const mod = Process.mainModule;
mod.ensureInitialized();
const target = mod.getExportByName('strcmp');
Interceptor.attach(target, {
  onEnter(args) { this.original = args[0].readCString(); },
  onLeave(retval) { retval.replace(0); }
});
```

```bash
frida -f /path/to/Foo.app/Contents/MacOS/Foo -l attach.js
```

`Process.codeSigningPolicy` reports `optional` when the agent believes code signing is not
enforced. For a hardened, library-validated app the agent attaches but hooks on unsigned pages may
fail; the hardened-runtime route (a) is the prerequisite for reliable in-process modification.

## Variations

- **Same-team injection.** Library validation accepts a library signed by the same team identifier
  as the host, so re-signing only the injected library with the vendor's identity is enough — but
  that identity is not available without the vendor's certificate.
- **Developer-signed target.** An app signed for development locally is usually not hardened and
  not notarized; route (b) works out of the box.
- **XPC and helpers.** A hardened restriction on the main executable does not automatically apply
  to an XPC service that has its own signature. Each nested component carries its own entitlements
  and must be re-signed separately; see `codesign-and-entitlements.md`.
- **SIP-protected binaries.** `/System/Library/` and `/usr/libexec/` binaries are protected by SIP
  and ignore `DYLD_*` regardless of entitlements. Copying the binary to a writable location and
  removing its signature produces a runnable copy, but the copy then lacks the platform's
  entitlements.
- **`AT_SECURE` binaries.** setuid and setgid binaries run in secure-execution mode and the dynamic
  linker ignores `LD_*`/`DYLD_*` entirely.
- **Intel vs ARM64.** The hardening rules are identical; only the injected library needs to match
  the slice (`lipo -thin arm64` / `lipo -thin x86_64`).

## Verification

Positive — library validation is off and the runtime flag is gone:

```bash
codesign -dvvv Foo.app 2>&1 | grep -E 'flags='
codesign -d --entitlements - Foo.app 2>&1 | grep -A1 'disable-library-validation'
otool -l Contents/MacOS/Foo | grep -A4 LC_CODE_SIGNATURE
```

Expected: `flags=0x0(adhoc)` (no `runtime`), `disable-library-validation` present with `true`,
and a rewritten `LC_CODE_SIGNATURE` block.

Positive — the injected library is loaded:

```bash
DYLD_PRINT_LIBRARIES=1 ./Contents/MacOS/Foo 2>&1 | grep -c libhook
```

Expected: `1` or more.

Negative — the check is really gone, not merely cached. Delete all licence state and re-run:

```bash
rm -f ~/Library/Application\ Support/Foo/licence.json ~/Library/Preferences/com.vendor.Foo.plist
DYLD_PRINT_LIBRARIES=1 ./Contents/MacOS/Foo 2>&1 | grep -i libhook
```

Expected: the library still loads with the licence state removed. A patch that only survives while
a cache file exists is not a patch.

Negative — the signature is genuinely valid after the surgery:

```bash
codesign -v --deep --strict --verbose=4 Foo.app ; echo "exit=$?"
spctl -a -vv Foo.app
```

Expected: `exit=0`; `spctl` prints `rejected (the code is valid but not signed by a recognized
authority)`, which is expected for an ad-hoc signature and does not block local launch. Remove the
quarantine attribute if Gatekeeper intervenes:

```bash
xattr -d com.apple.quarantine Foo.app
```

## Pitfalls

- The `runtime` flag and the `disable-library-validation` entitlement are independent. Removing the
  entitlement alone does not turn the hardened runtime off, and removing the runtime flag alone
  still leaves library validation on for the signed library set.
- `codesign --preserve-metadata=entitlements` alone does not merge the new entitlement file; the
  supplied `--entitlements` file replaces the preserved set unless the preserved keys are
  duplicated in it.
- A `DYLD_INSERT_LIBRARIES` that "does not work" on a third-party app is nearly always a hardened
  runtime, not a broken library. Check `flags=` before touching the code.
- `DYLD_PRINT_LIBRARIES` prints to stderr; redirect `2>&1` or the check looks empty.
- `optool install -c load` shifts the file offset of the code signature and everything after it.
  The binary must be re-signed, and the `LC_LOAD_DYLIB` must not exceed the header padding, or
  `optool` reports `invalid argument`.
- A `LC_LOAD_DYLIB` pointing at a path outside the bundle breaks the moment the app is moved.
  Use `@executable_path` or `@loader_path` relative paths.
- Adding a load command to a universal binary must be done on each slice, or `lipo` reports
  `fat file has a different architecture`.
- Re-signing strips the notarization ticket. `spctl` still accepts the app locally but distribution
  through Gatekeeper fails; `xcrun stapler validate` reports `does not have a ticket stapled to it`.
- `frida -f` on a hardened app fails with `Failed to enumerate processes` or `unable to attach`
  when the target is `AT_SECURE` or SIP-protected.

## References

- Apple, *Hardened Runtime* and *Technical Note TN2206: macOS Code Signing In Depth*
- Apple, *The dyld dynamic linker* and *Code Signing Guide* — entitlement semantics
- `man 1 codesign`, `man 1 optool` upstream README (aferrero2707/optool)
- `man 2 getauxval` for `AT_SECURE`
- `man 8 csrutil` and `man 1 sysctl` for SIP state
- Sibling entries: `codesign-and-entitlements.md`, `app-bundle-analysis.md`,
  `mas-receipt-validation.md`
