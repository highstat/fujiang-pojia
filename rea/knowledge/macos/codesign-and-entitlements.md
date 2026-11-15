---
id: "codesign-and-entitlements"
title: "Code signing and entitlements"
domain: "macos"
kind: "technique"
platforms: "macos"
arch: "x86-64, arm64"
difficulty: "intermediate"
tools: "codesign,otool,security,spctl"
verified: false
updated: "2026-11-15"
summary: "Explains where the code signature lives in a Mach-O and in a bundle, how ad-hoc and hardened-runtime signatures are produced, how designated requirements bind a signature to an identifier, and the nested-first order for re-signing a bundle that still passes verification."
---

## Summary

Every executable on macOS carries a code signature, and every app bundle carries a *resource
envelope* on top of it. Modifying either one breaks the seal and the loader refuses the file. This
entry explains the storage layout, the meaning of the hardened-runtime flag and the entitlement
set, the role of the designated requirement, and the exact command sequence for re-signing a bundle
so that `codesign --verify` and `spctl` still accept it. Reach for it whenever bytes have been
changed and the app will not start.

## Recognition

- The Mach-O contains a `LC_CODE_SIGNATURE` load command pointing at a signature blob; `otool -l`
  shows `cmd LC_CODE_SIGNATURE`, `cmdsize 16`, `dataoff 0x...`, `datasize 0x...`.
- The bundle contains `Contents/_CodeSignature/CodeResources`, a plist listing every sealed file
  with its SHA-256 digest.
- `codesign -dvvv` reports `CodeDirectory v=20500 size=... flags=0x10000(runtime) hashes=...+...`
  when the hardened runtime is on, and `flags=0x0(adhoc)` for an ad-hoc signature.
- `codesign -d --entitlements -` prints the XML plist of entitlements; an empty `<dict/>` means no
  special entitlements are claimed.
- A signature that was tampered with reports `code object is not signed at all` or
  `a sealed resource is missing or invalid` under `codesign --verify`.
- `spctl -a -vv` returns `rejected (the code is valid but not signed by a recognized authority)`
  for ad-hoc signatures and `accepted, source=Notarized Developer ID` for store-distributed builds.

## Method

### 1. Locate the signature blobs

```bash
cd /path/to/Foo.app
otool -l Contents/MacOS/Foo | grep -A4 LC_CODE_SIGNATURE
```

The load command carries `dataoff` (file offset of the blob) and `datasize` (its length). The blob
itself is a `CSMAGIC_EMBEDDED_SIGNATURE` (`0xfade0cc0`) superblob containing a `CodeDirectory`
(`0xfade0c02`), optionally a `CMS` signature (`0xfade0b01`) and a set of `CodeDirectory` blobs with
alternate hashes (`0xfade0c01`).

```bash
python3 - <<'PY'
import struct, sys
p = "Contents/MacOS/Foo"
blob = open(p, "rb").read()
magic, length = struct.unpack_from(">II", blob, 0)
print(f"superblob magic=0x{magic:08x} length={length}")
off = 12
while off + 8 <= length:
    idx, sub_magic, sub_len = struct.unpack_from(">III", blob, off)
    print(f"  blob[{idx}] magic=0x{sub_magic:08x} len={sub_len} offset=0x{off:x}")
    off += sub_len
PY
```

Expected: the first entry has magic `0xfade0c02` (`CodeDirectory`); a Developer ID build adds a
`0xfade0b01` (`CMS`) blob.

The bundle-level envelope is separate:

```bash
plutil -p Contents/_CodeSignature/CodeResources | head -40
```

It contains `files2` with one entry per sealed file, each holding a `hash2` dict of
`sha256` digests. The digests cover the *contents* of `Contents/MacOS/Foo` and every resource file,
which is why editing any file inside the bundle invalidates the seal.

### 2. Inspect the current signature

```bash
codesign -dvvv Contents/MacOS/Foo 2>&1
codesign -d --entitlements - Contents/MacOS/Foo 2>&1
codesign --verify --deep --strict --verbose=4 Foo.app
```

The `flags=` field decodes as follows: `0x1` adhoc, `0x2` hard (unsigned, kill on failure),
`0x100` kill, `0x10000` runtime (hardened runtime), `0x20000` library validation is present unless
the `com.apple.security.cs.disable-library-validation` entitlement says otherwise.

### 3. Produce an ad-hoc signature

```bash
cd /path/to/Foo.app
codesign --force --sign - --timestamp=none Contents/MacOS/Foo
```

`--sign -` means "no identity", producing an ad-hoc signature. `--timestamp=none` suppresses the
secure timestamp, which is required offline; without it `codesign` tries to reach Apple's timestamp
server and fails on a machine without network.

`--force` replaces an existing signature. `--deep` signs nested code automatically, but `--deep`
during signing is discouraged: it hides which component actually failed. Sign explicitly instead
(step 5).

### 4. Understand the hardened runtime and the entitlements

The hardened runtime is the `runtime` flag in the CodeDirectory. It is enabled with:

```bash
codesign --force --sign - --options runtime --entitlements entitlements.plist Contents/MacOS/Foo
```

With the hardened runtime on, the kernel enforces the entitlement set. The two that matter for
injection work are:

- `com.apple.security.cs.disable-library-validation` — absent means only libraries signed by the
  same team identifier, or by Apple, may be loaded. Present means library validation is relaxed.
- `com.apple.security.cs.allow-unsigned-executable-memory` — permits `MAP_JIT` on unsigned pages.
- `com.apple.security.cs.allow-dyld-environment-variables` — permits `DYLD_*` environment
  variables to reach the process.

A hardened binary with `com.apple.security.cs.disable-library-validation` and
`com.apple.security.cs.allow-dyld-environment-variables` in its entitlements is the normal shape of
a third-party app that vendors a plugin system.

### 5. Re-sign a bundle in the correct order

Nested code is sealed from the inside out. The outermost signature covers the inner ones, so a
nested component that is signed *after* its container invalidates the container's seal.

```bash
cd /path/to/Foo.app

# 1. Frameworks, deepest first.
for fw in Contents/Frameworks/*.framework; do
  codesign --force --sign - --timestamp=none --options runtime "$fw"
done

# 2. Dynamic frameworks and other nested bundles.
for dylib in Contents/Frameworks/*/Versions/*/*.dylib; do
  [ -e "$dylib" ] || continue
  codesign --force --sign - --timestamp=none --options runtime "$dylib"
done

# 3. XPC services and helpers.
for xpc in Contents/XPCServices/*.xpc; do
  [ -e "$xpc" ] || continue
  codesign --force --sign - --timestamp=none --options runtime "$xpc"
done
for helper in Contents/Library/LoginItems/*.app Contents/Helpers/*; do
  [ -e "$helper" ] || continue
  codesign --force --sign - --timestamp=none --options runtime "$helper"
done

# 4. Plug-ins.
for plug in Contents/PlugIns/*.appex Contents/PlugIns/*.bundle; do
  [ -e "$plug" ] || continue
  codesign --force --sign - --timestamp=none --options runtime "$plug"
done

# 5. The main executable.
codesign --force --sign - --timestamp=none --options runtime Contents/MacOS/Foo

# 6. The bundle itself, last.
codesign --force --sign - --timestamp=none --options runtime Foo.app
```

`codesign --deep --sign - Foo.app` performs the same traversal automatically and is acceptable on a
scratch copy, but it applies one rule set to every component and is the reason some bundles end up
with a helper that lacks the entitlements it needs.

### 6. Preserve the metadata that matters

When re-signing a modified copy, the original entitlements, requirements and runtime flag must be
carried over explicitly:

```bash
codesign -d --entitlements - Foo.app 2>/dev/null > original-entitlements.plist
codesign -d -r- Foo.app 2>/dev/null > original-requirements.txt
codesign --force --sign - \
  --preserve-metadata=entitlements,requirements,flags,runtime \
  --timestamp=none \
  Foo.app
```

`--preserve-metadata=entitlements,requirements,flags,runtime` copies those four items from the
existing signature into the new one. It does not copy the identity, so the result is still ad-hoc
while keeping the entitlement set, the designated requirement and the hardened-runtime flag.

### 7. Verify

```bash
codesign -v --deep --strict --verbose=4 Foo.app
spctl -a -vv Foo.app
```

`codesign -v --deep --strict` prints nothing and exits `0` on success. `spctl -a -vv` prints
`accepted` for a properly notarized Developer ID build and `rejected (the code is valid but not
signed by a recognized authority)` for an ad-hoc signature — the latter is expected after a
re-sign and does not prevent the app from launching locally.

### 8. Inspect the requirement text

```bash
codesign -d -r- Foo.app 2>&1
codesign -d -r- --entitlements - Foo.app 2>&1
```

A typical Developer ID designated requirement reads:

```text
identifier "com.vendor.Foo" and anchor apple generic
  and certificate 1[field.1.2.840.113635.100.6.1.9] exists
  and certificate 1[field.1.2.840.113635.100.6.2.6] exists
  and certificate leaf[field.1.2.840.113635.100.6.1.13] exists
  and certificate leaf[subject.OU] = "TEAMID1234"
```

The short form `identifier "com.vendor.Foo" and anchor apple generic` binds the signature to the
bundle identifier and to Apple's root. A custom requirement lets a build accept only a specific
designated requirement, e.g. `identifier "com.vendor.Foo" and anchor apple generic and
certificate leaf[subject.OU] = "TEAMID1234"`. A patched copy whose identifier no longer matches
the requirement fails to launch even with an otherwise valid signature, which is the most common
cause of a `kill: 9` after an identifier change.

## Variations

- **Ad-hoc vs Developer ID.** An ad-hoc signature carries no certificate chain, so `spctl` rejects
  it, but Gatekeeper does not block a locally launched app that has never been quarantined. A file
  downloaded with the `com.apple.quarantine` attribute *is* blocked by Gatekeeper regardless of
  the signature; clear it with `xattr -d com.apple.quarantine Foo.app`.
- **Notarisation.** A Developer ID build distributed outside the store is stapled with a notarization
  ticket: `xcrun stapler validate Foo.app`. Re-signing removes the stapled ticket, so the ticket
  must be re-stapled or the app must be distributed by a channel that does not require it.
- **`ldid` as an alternative.** On jailbroken macOS/iOS devices `ldid -S` writes an ad-hoc
  signature with entitlements and avoids the `codesign` resource-envelope machinery entirely.
- **LIEF as an alternative signer.** LIEF 1.0.0 can read and rewrite Mach-O signatures, but it does
  not reproduce the `CodeResources` envelope the way `codesign` does; prefer the platform tool.
- **`optool`** strips the code signature entirely (`optool uninstall -s Foo.app`) and can inject a
  `LC_LOAD_DYLIB` load command, after which a manual re-sign is required.
- **iOS.** The same command sequence applies to an app directory, but the signing identity must be
  a valid provisioning profile match, and `codesign --verify` alone is not sufficient — the profile
  is checked at install time.

## Verification

Positive:

```bash
codesign -v --deep --strict --verbose=4 Foo.app ; echo "exit=$?"
codesign -dvvv Foo.app 2>&1 | grep -E 'Identifier=|TeamIdentifier=|flags='
codesign -d --entitlements - Foo.app 2>&1
```

Expected: `exit=0`, an `Identifier=` matching `CFBundleIdentifier`, and the entitlements XML
matching what was preserved.

Negative test, proving the seal is real:

```bash
cd /tmp && cp -R /path/to/Foo.app Foo.tamper.app
printf 'X' | dd of=Foo.tamper.app/Contents/MacOS/Foo bs=1 seek=4096 count=1 conv=notrunc
codesign -v --deep --strict Foo.tamper.app 2>&1 ; echo "exit=$?"
```

Expected: `a sealed resource is missing or invalid` and a non-zero exit. Re-sign the tampered copy
and confirm the exit code returns to `0`.

Negative test for the requirement, proving the identifier matters:

```bash
codesign --force --sign - --preserve-metadata=entitlements,requirements,flags,runtime \
  --timestamp=none Foo.tamper.app
codesign -v --deep --strict Foo.tamper.app 2>&1 ; echo "exit=$?"
```

Expected: `exit=0` with the preserved requirement, because the preserved requirement still refers
to the original identifier and `codesign` does not re-check it against `Info.plist` for ad-hoc
signing. Changing `CFBundleIdentifier` in `Info.plist` without re-deriving the requirement is the
failure this step guards against.

## Pitfalls

- `codesign -d` writes to stderr. Redirect it or the output appears missing.
- Signing the bundle before the nested components overwrites the nested seals. The container's
  `CodeResources` records the digests of the inner files, so it must be the last write.
- `--deep` during signing hides the failing component. Sign nested code explicitly when a
  verification error names a specific path.
- `--preserve-metadata` does not preserve the identity, the timestamp or the certificate chain. The
  result is ad-hoc even when the original was Developer ID signed.
- Re-signing with `--options runtime` on a binary that was not built for the hardened runtime can
  make the app crash at launch in ways unrelated to the patch, because the runtime enforces the
  entitlement set the code was not written for.
- An ad-hoc signature after re-signing invalidates the stapled notarization ticket.
- The `com.apple.quarantine` extended attribute is independent of the signature and keeps Gatekeeper
  blocking a re-signed app that is downloaded rather than built locally.
- Changing `CFBundleIdentifier` invalidates the preserved designated requirement; the app dies with
  `kill: 9` and no useful log line.
- Universal binaries hold two `LC_CODE_SIGNATURE` blobs. `codesign` handles both, but a manual
  `optool` edit on one slice can desynchronise them.

## References

- Apple, *Code Signing Guide* and *Code Signing Tasks* (developer.apple.com)
- Apple, *Technical Note TN2206: macOS Code Signing In Depth*
- Apple, *Notarizing macOS Software Before Distribution* and `xcrun stapler` documentation
- `man 1 codesign`, `man 1 security`, `man 1 spctl`
- `man 7 codesign` for the embedded signature superblob layout
- Sibling entries: `app-bundle-analysis.md`, `hardened-runtime-and-library-validation.md`,
  `mas-receipt-validation.md`
