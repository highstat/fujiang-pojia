# Playbook: macOS app bundle licence bypass

**Target**: a macOS application in `Foo.app` form whose features are gated by a licence check.
**Outcome**: the patched bundle launches, the feature works, and the code signature is valid
enough for the app to run.

## 0. Preparation

```sh
mkdir -p work && cd work
cp -R "/path/to/Foo.app" Foo.app
find Foo.app -type f -exec shasum -a 256 {} \; | tee hashes.txt
plutil -p Foo.app/Contents/Info.plist | head -40
codesign -dvvv --entitlements - Foo.app 2>&1 | tee sig-before.txt
lipo -info Foo.app/Contents/MacOS/Foo
```

Record: the bundle identifier, the executable path, the architecture (universal or single
slice), the current signature flags and entitlements.

## 1. Locate the check

```sh
otool -L Foo.app/Contents/MacOS/Foo
otool -oV Foo.app/Contents/MacOS/Foo | grep -iA 12 'License\|Subscription\|Pro'
nm -m Foo.app/Contents/MacOS/Foo | grep -i licen
r2 -q -c 'izz~licen' Foo.app/Contents/MacOS/Foo
```

Also check the localised strings — the user-visible error often lives in
`Contents/Resources/en.lproj/Localizable.strings`:

```sh
grep -ril licen Foo.app/Contents/Resources/
plutil -p Foo.app/Contents/Resources/en.lproj/Localizable.strings | grep -i licen
```

The `__objc_methname` section holds selector names, so `-isLicensed` shows up there even in a
stripped binary.

## 2. Classify

| Shape | Route |
| --- | --- |
| ObjC method returning `BOOL` | patch the method or its caller |
| Swift function | patch the mangled Swift symbol's body |
| C function returning `int`/`bool` | patch the return value |
| Receipt validation | see `knowledge/macos/mas-receipt-validation.md` |
| Server-side entitlement | protocol route |

## 3. Patch

### ObjC `BOOL` method, arm64

```
00 00 80 52 C0 03 5F D6      mov w0, #0 ; ret   (false)
20 00 80 52 C0 03 5F D6      mov w0, #1 ; ret   (true)
```

### Conditional branch, arm64

`B.cond` — condition in bits [3:0] of the first byte:

```
40 00 00 54   b.eq +0x08   ->   41 00 00 54   b.ne +0x08
```

### x86_64 slice

Use the x86 encodings: `0F 85` ↔ `0F 84` for near jumps, `B0 01 C3` for a true return.

### Universal binary

Patch every slice that can run, or thin the binary first:

```sh
lipo Foo.app/Contents/MacOS/Foo -thin arm64 -output Foo.arm64
# patch, then
lipo -create Foo.arm64 Foo.x86_64 -output Foo.app/Contents/MacOS/Foo
```

A patch that only covers arm64 is invisible when the app runs under Rosetta.

## 4. Re-sign

The signature is invalid after the edit, and the kernel kills the process. Re-sign the whole
bundle, deepest code first:

```sh
# preserve the original entitlements
codesign -d --entitlements :- Foo.app > entitlements.plist 2>/dev/null

rm -rf Foo.app/Contents/_CodeSignature

# nested frameworks, plugins and XPC services first
find Foo.app/Contents/Frameworks Foo.app/Contents/PlugIns Foo.app/Contents/XPCServices \
     -name '*.framework' -o -name '*.appex' -o -name '*.xpc' 2>/dev/null |
while read -r item; do
  codesign --force --sign - "$item"
done

# then the main executable
codesign --force --sign - Foo.app/Contents/MacOS/Foo

# then the bundle
codesign --force --sign - --entitlements entitlements.plist Foo.app

codesign -v --deep --strict --verbose=2 Foo.app
```

If the app requires the hardened runtime, keep it but add the capability needed for your
injection route:

```xml
<key>com.apple.security.cs.disable-library-validation</key>
<true/>
```

Preserve metadata instead of re-deriving it when possible:

```sh
codesign --force --sign - \
         --preserve-metadata=entitlements,requirements,flags,runtime \
         Foo.app
```

Note: `--preserve-metadata` keeps the original `runtime` flag, which keeps library validation
enabled. Drop `runtime` from the list when you need `DYLD_INSERT_LIBRARIES` to work.

## 5. Verify

```sh
codesign -v --deep --strict Foo.app && echo "signature ok"
spctl -a -vv Foo.app            # may report a rejected source for an ad-hoc signature; that is expected
./Foo.app/Contents/MacOS/Foo
```

Then:

1. Reproduce the operation that was locked.
2. Quit the app fully, clear `~/Library/Caches/<bundleid>` and
   `~/Library/Preferences/<bundleid>.plist`, relaunch, and repeat.
3. Confirm the patched code is what runs — check the bytes at the function address in a debugger
   attached to the running process.

## 6. If the app will not start

| Symptom | Cause | Fix |
| --- | --- | --- |
| Killed at launch, `code signature invalid` | not re-signed, or nested code signed after the bundle | re-sign in the correct order |
| `dyld: Symbol not found` | a framework was signed or modified after being referenced | re-sign nested code, then the bundle |
| `Library Validation failed` | the hardened runtime with library validation on | add the `disable-library-validation` entitlement and re-sign |
| `DYLD_INSERT_LIBRARIES` ignored | hardened runtime or a platform binary | re-sign with the entitlement, or use `optool` load-command injection |
| The patch has no effect | a different slice is running | check `lipo -info` and `arch` |
| The app runs but crashes later | the patch broke an invariant — e.g. a licence array that must have entries | patch the state, not only the boolean |

## Deliverable

`Foo.app`, the re-signing command sequence, the patch manifest with the Mach-O offsets, and the
verification output.
