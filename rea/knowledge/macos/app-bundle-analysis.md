---
id: "app-bundle-analysis"
title: "macOS app bundle analysis"
domain: "macos"
kind: "technique"
platforms: "macos"
arch: "x86-64, arm64"
difficulty: "intermediate"
tools: "codesign,otool,lipo,plutil,strings,nm,r2"
verified: false
updated: "2026-11-15"
summary: "Tears a Foo.app bundle into executable, metadata, resources and signature parts, then walks the path from a user-visible licence error string to the function that raises it."
---

## Summary

A macOS `.app` is a directory tree with a fixed contract, not an opaque file. This entry gives that
layout, the commands that read each part without launching the app, and the string-to-cross-reference
path that ends at the licence decision point. Reach for it as the first step on any macOS target: it
fixes the executable, the architecture, the signature state and the localisation resources before a
single byte is inspected.

## Recognition

- `file Foo.app` reports a directory. `Contents/` holds `MacOS/`, `Resources/`, `Frameworks/`,
  `PlugIns/`, `Info.plist`, `PkgInfo`, and optionally `_MASReceipt/` and `embedded.provisionprofile`.
- `Contents/MacOS/<CFBundleExecutable>` is the Mach-O. Nothing else belongs in `Contents/MacOS/`.
- `Contents/Info.plist` is a binary or XML property list. `plutil -lint Contents/Info.plist` prints
  `OK` or an `NSPOSIXErrorDomain` error.
- `Contents/_MASReceipt/receipt` present means a Mac App Store build.
- `Contents/embedded.provisionprofile` present means a Developer ID-signed build distributed outside
  the store.
- `Contents/Resources/*.lproj/` (`en.lproj`, `de.lproj`, `zh_CN.lproj`) holds `Localizable.strings`.
- The licence refusal is frequently a *localised* string, so the on-screen text changes with the
  system locale while the compiled English string stays constant inside the binary.

## Method

### 1. Survey the bundle tree

```bash
cd /path/to/Foo.app
find . -maxdepth 3 -print | sed 's|^\./||' | sort
```

Expected: `Contents/MacOS/Foo`, `Contents/Info.plist`, `Contents/Resources/...`, and empty or
populated `Contents/Frameworks/` and `Contents/PlugIns/`. An empty `Frameworks/` means the app is
not using a vendored framework; a populated one means the licence logic may live inside a framework
binary rather than in the main executable.

### 2. Read the metadata

```bash
plutil -p Contents/Info.plist
```

```bash
plutil -convert json -o - Contents/Info.plist | python3 -c "
import json, sys
d = json.load(sys.stdin)
keys = ('CFBundleExecutable', 'CFBundleIdentifier', 'CFBundleShortVersionString',
        'CFBundleVersion', 'LSMinimumSystemVersion', 'NSHumanReadableCopyright',
        'LSApplicationCategoryType')
for k in keys:
    print(f'{k} = {d.get(k)!r}')
"
```

Interpretation of the keys that matter:

| Key | Meaning for the licence work |
| --- | --- |
| `CFBundleExecutable` | File name of the Mach-O inside `Contents/MacOS`. Never assume it equals the `.app` name. |
| `CFBundleIdentifier` | Reverse-DNS identifier. It appears verbatim in the designated requirement, so a re-signed copy must keep or deliberately change it. |
| `LSMinimumSystemVersion` | Deployment floor, e.g. `11.0`. Older floor means more legacy code paths, possibly a non-hardened fallback. |
| `NSHumanReadableCopyright` | Vendor line. A store build typically names Apple Inc. or the App Store legal entity. |
| `LSEnvironment` | Environment variables the launcher exports, including `DYLD_*` overrides the vendor ships. |
| `SUFeedURL` | Sparkle update feed. A licence server or activation endpoint is often the same host. |

A store build is confirmed by the presence of `Contents/_MASReceipt/receipt`, not by the copyright
string alone.

### 3. Read the load commands

```bash
otool -L Contents/MacOS/Foo
```

Each line is a `LC_LOAD_DYLIB` entry: the install name recorded in the binary. Three forms matter:
`/usr/lib/libSystem.B.dylib` (system), `@rpath/../Frameworks/Foo.framework/Versions/A/Foo`
(resolved through `LC_RPATH`), and `@executable_path/../Frameworks/...`. A non-system install name
that is not inside the bundle points at an injected or third-party dependency.

```bash
otool -l Contents/MacOS/Foo | grep -A2 LC_RPATH
```

```bash
otool -l Contents/MacOS/Foo | grep -A5 'segname __RESTRICT'
```

The `__RESTRICT,__restrict` section carries the path the kernel uses to launch the process under
`/usr/libexec/rosetta/runtime` for translated processes, and the restricted-environment marker for
protected processes. Its presence tells whether the binary is translated or sandbox-restricted.

### 4. Read the signature and the entitlements

```bash
codesign -dvvv Contents/MacOS/Foo 2>&1
codesign -d --entitlements - Contents/MacOS/Foo 2>&1
codesign --verify --deep --strict --verbose=4 Foo.app
```

`codesign -d` writes to stderr. Without `2>&1` the terminal shows nothing and the step looks
broken. Look at `Identifier=`, `TeamIdentifier=`, `Flags=0x2(0x10000) Runtime` (the hardened
runtime), `Authority=` (chain) and `Sealed Resources version=2 rules=...`.

### 5. Establish the architecture set

```bash
lipo -info Contents/MacOS/Foo
lipo -archs Contents/MacOS/Foo
lipo -thin arm64 -output /tmp/Foo.arm64 Contents/MacOS/Foo
```

`lipo -info` prints `Non-fat file: ... is architecture: arm64` for a thin build and
`Architectures in the fat file: Foo are: x86_64 arm64` for a universal build. A universal build needs
both slices patched, or the patch is only visible on one architecture.

### 6. Use the localisation files to recover the error text

```bash
find Contents/Resources -name 'Localizable.strings' -print | sort
plutil -p Contents/Resources/en.lproj/Localizable.strings | grep -i -n 'licen'
plutil -p Contents/Resources/de.lproj/Localizable.strings | grep -i -n 'licen'
```

The *key* is usually identical across locales while the *value* is translated. That key is the
reliable anchor for the code path, because SwiftUI `LocalizedStringKey` and `NSLocalizedString` both
resolve the key at runtime, while the English value never reaches the binary.

Two candidate anchors result:

- the localisation key, e.g. `license_error_title`, which is present in the binary as a string
  literal used with `NSLocalizedString`;
- the English value, e.g. `Your licence is not valid.`, present only when the app embeds the value
  inline or compiles a `.strings` file into `__cstring`.

Check both:

```bash
strings -a -t x Contents/MacOS/Foo | grep -iE 'licen|trial|expire|activ|serial|regist|subscription|purchas'
```

`strings -t x` prints the file offset in hex, which is what later feeds `r2` seeks.

### 7. Locate the licence gate

Pass A — plain symbols:

```bash
nm -nm Contents/MacOS/Foo 2>/dev/null | grep -iE 'licen|valid|verif|receipt|trial'
```

Pass B — Objective-C class list and method names:

```bash
otool -oV Contents/MacOS/Foo | grep -E '^\s+name |baseMethods' | grep -iE 'licen|valid|receipt|trial'
```

`otool -oV` prints the whole `__objc_classlist`, `__objc_catlist` and method name sections. Expect
class names in the `LicenseManager`, `LicenseValidator`, `SubscriptionManager`, `ReceiptValidator`
family. A stripped release build has no C symbols, but the Objective-C class list and the
`__objc_methname` section survive because they are runtime data.

Pass C — Swift demangling:

```bash
nm -nm Contents/MacOS/Foo 2>/dev/null | swift-demangle | grep -iE 'license|validat|entitle' | head -40
```

`swift-demangle` ships with the Xcode command line tools. If it is missing, `xcrun swift-demangle`
also resolves.

Pass D — radare2 cross-reference:

```bash
r2 -qc 'aaa; iz~licen' Contents/MacOS/Foo
r2 -qc 'aaa; axt @@ str.*' Contents/MacOS/Foo
```

The first command lists candidate strings with their virtual addresses and the flag name each string
received in the string table. The second prints the code addresses that reference any string flag.
Then read the referencing function:

```bash
r2 -qc 'aaa; s 0xADDR; pdf' Contents/MacOS/Foo
```

Expected result: a function such as `-[LicenseManager validateLicenseKey:]` or
`LicenseValidator.validate(receipt:)` whose body loads the string constant and calls a validation
routine, followed by a conditional branch that selects the refusal path.

### 8. Record the anchors

Write down, before touching bytes: bundle identifier, executable path, architecture set, the exact
licence error string and its file offset, the candidate function and its address, and the original
bytes at the decision point. Without the original bytes there is no rollback.

## Variations

- **Store build vs Developer ID build.** The store build carries `Contents/_MASReceipt/receipt` and
  the launch-time receipt check; see `mas-receipt-validation.md`. The Developer ID build carries
  `Contents/embedded.provisionprofile` and, usually, a hardened runtime; see
  `codesign-and-entitlements.md` and `hardened-runtime-and-library-validation.md`.
- **Universal vs thin.** `lipo -thin` per architecture, then repeat every patch on each slice.
  A universal binary also has two `LC_CODE_SIGNATURE` blobs, one per slice.
- **Rosetta-only apps.** A binary with `arm64` but a sibling `Contents/MacOS/Foo` Intel slice
  launched through Rosetta shows the `__RESTRICT,__restrict` section pointing at
  `/usr/libexec/rosetta/runtime`.
- **Vendored framework licences.** If `otool -L` lists a framework that is not part of the OS, the
  licence manager may live inside that framework binary. Enumerate and repeat the string sweep on
  every framework binary:

```bash
find Contents/Frameworks -type f -perm -u+x -print0 | xargs -0 -n1 sh -c \
  'echo "== $0"; strings -a "$0" | grep -icE "licen|licence"'
```

- **Electron app bundles.** The real payload is `Contents/Resources/app.asar`; see
  `../electron-js/asar-extract-repack.md` and `../electron-js/electron-licence-flow.md`.
- **SwiftUI vs AppKit.** SwiftUI renders the refusal inside a view hierarchy with no separate
  dialog class, so the Objective-C class list may be empty of licence names and the localisation key
  becomes the only anchor.
- **Non-macOS analogues.** The same "read the metadata, find the string, take the cross-reference"
  flow applies to the Android `apk` and the Windows `.exe` resource sections, but the container
  contract differs and none of the tools in this entry apply.

## Verification

Positive checks on the untouched bundle:

```bash
cd /path/to/Foo.app
plutil -lint Contents/Info.plist                    # -> OK
codesign --verify --deep --strict --verbose=4 .   # -> no output, exit status 0
lipo -info Contents/MacOS/Foo                      # -> architecture list
otool -L Contents/MacOS/Foo | tail -n +2 | while read -r line; do :; done  # all install names print
```

Negative test on a scratch copy, proving the signature actually covers the resources:

```bash
cd /tmp && cp -R /path/to/Foo.app Foo.broken.app
printf '\x00' | dd of=Foo.broken.app/Contents/MacOS/Foo bs=1 seek=4096 count=1 conv=notrunc
codesign --verify --deep --strict --verbose=4 Foo.broken.app 2>&1 | head -5
```

Expected: `a sealed resource is missing or invalid` or `code object is not signed at all`. That
failure is the proof that the signature is real and that a subsequent patch requires a re-sign.

The licence gate itself must be demonstrated, not assumed: set a breakpoint at the candidate
function address in `lldb` and confirm the error string address appears on the stack when the
dialog is shown.

```bash
lldb -- Contents/MacOS/Foo
# (lldb) b *0xADDR
# (lldb) run
# (lldb) x/s $x0        # confirm the string constant
```

## Pitfalls

- `codesign -d` writes to stderr; without `2>&1` the output appears to be missing.
- `codesign --verify --deep` also verifies nested code. A single modified framework produces the
  failure report, not the main executable, which sends the analysis down the wrong path.
- `otool -oV` output runs to thousands of lines. Pipe it or the terminal loses the class list.
- `nm` on a stripped release build prints `no symbols`. The Objective-C class list and the
  `__objc_methname` section still exist.
- `strings` without `-a` skips some segments; `strings -a` scans everything but also matches noise
  inside the code signature blob. Filter by the offset range of `__text`/`__cstring` from
  `otool -l` when it matters.
- The English value from `en.lproj` may never appear in the binary. When the app loads
  `Localizable.strings` at runtime, the key is the anchor and the value is not searchable.
- `CFBundleExecutable` is not necessarily the app name; `Foo.app` may ship `Contents/MacOS/FooHelper`.
- Editing any file inside the bundle invalidates the seal. The app will refuse to launch with
  `killed: 9` until it is re-signed; see `codesign-and-entitlements.md`.
- `plutil -p` on a binary plist prints Python-style output, not JSON. Use
  `plutil -convert json -o -` before piping into a JSON parser.

## References

- Apple, *Code Signing Guide* and *Plist Format Documentation* (developer.apple.com documentation set)
- Apple, *Technical Note TN2206: macOS Code Signing In Depth*
- `man 1 codesign`, `man 1 otool`, `man 1 lipo`, `man 1 plutil`
- `man 5 plist` for the property list key set
- radare2 6.2.6 documentation for `iz`, `izz`, `axt` and `@@ str.*` iteration
- Sibling entries: `codesign-and-entitlements.md`, `hardened-runtime-and-library-validation.md`,
  `mas-receipt-validation.md`, `../electron-js/asar-extract-repack.md`
