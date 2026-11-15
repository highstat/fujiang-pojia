---
id: "ipa-repack-and-resign"
title: "IPA repack and re-sign"
domain: "ios"
kind: "playbook-ref"
platforms: "ios"
arch: "arm64"
difficulty: "intermediate"
tools: "optool, codesign, ldid, install_name_tool, lipo, ios-deploy, ideviceinstaller, pymobiledevice3"
verified: false
updated: "2026-11-15"
summary: "Unpack an IPA, inject a dylib into the app bundle with optool or by editing the Mach-O load commands, strip the stale code signature, re-sign every nested binary from the inside out and install the result on a device."
---

## Summary

An IPA is a ZIP whose single meaningful entry is `Payload/<App>.app`. Adding a dynamic
library means changing the main executable's load commands, which invalidates the code
signature of the whole bundle. The bundle therefore has to be stripped, signed again from the
innermost binary outwards, and installed with a tool that accepts the new signature.

This entry gives the layout, the two ways to inject a load command, the exact signing order,
and the installation paths for a stock device and a jailbroken one.

## Recognition

- `file app.ipa` reports `Zip archive data`; `unzip -l app.ipa` shows
  `Payload/App.app/App`, `Payload/App.app/Info.plist`, `Payload/App.app/Frameworks/…`.
- The bundle contains a `_CodeSignature/CodeResources` directory and the executable carries an
  `LC_CODE_SIGNATURE` load command: `otool -l Payload/App.app/App | grep -A2 LC_CODE_SIGNATURE`.
- An embedded provisioning profile sits at `Payload/App.app/embedded.mobileprovision`.
- Entitlement-sensitive capabilities show up as `application-identifier`, `keychain-access-groups`,
  `aps-environment`, `get-task-allow` and `com.apple.developer.team-identifier`.

## Method

### 1. Unpack the IPA

```bash
cd /path/to/work
mkdir -p ipa_work && cd ipa_work
unzip -o ../app.ipa -d unpacked
cd unpacked
ls Payload/
ls Payload/App.app/
```

The bundle layout that matters:

```text
Payload/App.app/
├── App                       # the main Mach-O executable
├── Info.plist                # CFBundleExecutable = "App"
├── _CodeSignature/           # bundle signature, must be removed before re-signing
├── embedded.mobileprovision  # provisioning profile
├── Frameworks/
│   └── Your.framework/
│       ├── Your              # the framework binary, same name as the framework
│       ├── Info.plist        # required by the loader
│       └── _CodeSignature/
├── PlugIns/                  # app extensions, each a separate bundle to sign
└── Watch/                    # watchOS app, a separate bundle to sign
```

### 2. Build the library to inject

A dylib must carry the right architecture and an `install_name` that the loader can resolve
at runtime:

```bash
cd /path/to/work/ipa_work
xcrun clang -dynamiclib \
  -arch arm64 -arch arm64e \
  -isysroot $(xcrun --sdk iphoneos --show-sdk-path) \
  -miphoneos-version-min=15.0 \
  -install_name "@executable_path/Frameworks/Your.dylib" \
  -framework Foundation \
  -o unpacked/Payload/App.app/Frameworks/Your.dylib \
  Your.m

lipo -info unpacked/Payload/App.app/Frameworks/Your.dylib
otool -L unpacked/Payload/App.app/Frameworks/Your.dylib
```

`@executable_path` resolves relative to the main executable, so
`@executable_path/Frameworks/Your.dylib` points at
`Payload/App.app/Frameworks/Your.dylib`. Keep the same path in the load command that is
injected.

### 3. Inject the load command with optool

optool edits the Mach-O load commands of a signed binary and removes the stale signature:

```bash
cd /path/to/work/ipa_work
optool install -c load \
  -p "@executable_path/Frameworks/Your.dylib" \
  -t unpacked/Payload/App.app/App
```

- `-c load` adds an `LC_LOAD_DYLIB` command.
- `-p` is the path written into the command.
- `-t` is the target Mach-O.
- `optool uninstall -t unpacked/Payload/App.app/App` removes it again.

optool needs enough header space for the extra load command. When the binary has no spare
header padding, it reports `Not enough space for load command` and the header must be
rebuilt (see step 4) or the binary must be rebuilt with a larger `-headerpad`.

### 4. The load-command alternative

Injecting by hand means adding an `LC_LOAD_DYLIB` to the Mach-O header, which requires the
header to have free space. `insert_name` from the `ldid`/`insert_dylib` family of tools does
it directly:

```bash
cd /path/to/work/ipa_work
insert_dylib \
  -i unpacked/Payload/App.app/Frameworks/Your.dylib \
  -p "@executable_path/Frameworks/Your.dylib" \
  -t unpacked/Payload/App.app/App
```

Or edit the header with LIEF 1.0.0, which rebuilds the load commands and the offsets:

```python
# add_dylib.py — python3 add_dylib.py
import lief

TARGET = "unpacked/Payload/App.app/App"
DYLIB = "@executable_path/Frameworks/Your.dylib"

binary = lief.MachO.parse(TARGET).at(0)
binary.add_library(DYLIB)
binary.write(TARGET)
```

After any of these, confirm the command is present:

```bash
otool -l unpacked/Payload/App.app/App | grep -A3 LC_LOAD_DYLIB
otool -L unpacked/Payload/App.app/App
```

The output of `otool -L` must list the dylib with its install name.

### 5. Strip the stale signature

The bundle carries a signature that no longer matches its content. Remove it everywhere
before signing:

```bash
cd /path/to/work/ipa_work
rm -rf unpacked/Payload/App.app/_CodeSignature
rm -rf unpacked/Payload/App.app/Frameworks/*/_CodeSignature
rm -rf unpacked/Payload/App.app/PlugIns/*/_CodeSignature
find unpacked/Payload -name "_CodeSignature" -type d -exec rm -rf {} +
```

Individual Mach-O binaries can also be stripped:

```bash
codesign --remove-signature unpacked/Payload/App.app/App
```

Remove the embedded profile as well when the bundle will be signed with a different
certificate or ad-hoc:

```bash
rm -f unpacked/Payload/App.app/embedded.mobileprovision
```

### 6. Sign the nested binaries first, then the app

The order is fixed: every binary that the app links or embeds is signed before the app
bundle itself, because signing the bundle seals the nested content.

```bash
cd /path/to/work/ipa_work
APP=unpacked/Payload/App.app

# 6a. plain dylibs placed in Frameworks/
codesign --force --sign - --timestamp=none --entitlements entitlements.plist \
  "$APP/Frameworks/Your.dylib"

# 6b. frameworks: the binary inside, then the framework bundle
codesign --force --sign - --timestamp=none --entitlements entitlements.plist \
  "$APP/Frameworks/Your.framework/Your"
codesign --force --sign - --timestamp=none --entitlements entitlements.plist \
  "$APP/Frameworks/Your.framework"

# 6c. app extensions and other nested bundles
for ext in "$APP"/PlugIns/*.appex; do
  [ -e "$ext" ] || continue
  codesign --force --sign - --timestamp=none --entitlements entitlements.plist "$ext"
done

# 6d. the app bundle itself, last
codesign --force --sign - --timestamp=none --entitlements entitlements.plist "$APP"
```

- `--force` replaces an existing signature.
- `--sign -` produces an ad-hoc signature. That is accepted by a jailbroken device and by a
  developer-mode device with a development profile, but not by a stock device with a
  provisioning profile.
- `--entitlements entitlements.plist` grants the capabilities the app needs. Without it the
  app loses keychain access, push notifications and the app group.
- `--timestamp=none` avoids a network round trip; a timestamped signature is not required for
  ad-hoc signing and the timestamp server is not reachable for an ad-hoc identity.

For a real certificate on a stock device:

```bash
codesign --force --sign "Apple Development: Your Name (XXXXXXXXXX)" \
  --entitlements entitlements.plist \
  --generate-entitlement-der \
  --timestamp=none \
  "$APP"
```

The provisioning profile must match the bundle identifier and the team, and it must be
embedded at `Payload/App.app/embedded.mobileprovision`.

Verify:

```bash
codesign --verify --deep --strict --verbose=4 unpacked/Payload/App.app
codesign -d --entitlements :- unpacked/Payload/App.app
```

`--deep` is acceptable in a verification command. It is not acceptable when *signing*:
`codesign --deep --sign -` is documented as unreliable because it may sign nested content
with the wrong identity.

On a jailbroken device `ldid` is the alternative:

```bash
ldid -Sentitlements.plist unpacked/Payload/App.app/App
ldid -Sentitlements.plist unpacked/Payload/App.app/Frameworks/Your.framework/Your
```

### 7. Repack and install

```bash
cd /path/to/work/ipa_work
cd unpacked
zip -qry ../repacked.ipa Payload
cd ..
ls -l repacked.ipa
```

`zip -qry` with a `Payload` argument preserves the required top-level directory. Do not add
extra attributes with `zip -X` for a normal IPA; the extended attributes are not needed and
some installers are strict about the directory layout.

### 8. Install

**Jailbroken device** (ad-hoc signature is enough):

```bash
ideviceinstaller -i repacked.ipa
```

or copy the bundle to the media directory and install from the device's package manager.

**Stock device with a free or paid developer account:**

```bash
ios-deploy --bundle unpacked/Payload/App.app --no-wifi --justlaunch
```

`ios-deploy` installs and launches. It requires the device to be in developer mode and the
host to trust the provisioning profile.

**pymobiledevice3:**

```bash
pymobiledevice3 apps install repacked.ipa
pymobiledevice3 apps list
```

**Developer disk image** — required for some tooling on iOS 17+:

```bash
pymobiledevice3 pdi mount
```

**Signing service** — for a stock device without a development machine, upload the IPA to a
service that re-signs it with the caller's certificate and profile; the resulting IPA is
installed with `ideviceinstaller`.

## Variations

### Frameworks instead of loose dylibs

A framework is a directory whose name ends in `.framework` and which contains a binary with
the same name, an `Info.plist`, and optionally `Modules/` and `Headers/`:

```text
Payload/App.app/Frameworks/Your.framework/
├── Your                    # Mach-O, install_name @rpath/Your.framework/Your
├── Info.plist              # CFBundleExecutable = "Your"
├── Modules/module.modulemap
└── Headers/Your.h
```

The binary's install name must match the runtime path:

```bash
install_name_tool -id "@rpath/Your.framework/Your" \
  unpacked/Payload/App.app/Frameworks/Your.framework/Your
otool -l unpacked/Payload/App.app/App | grep -A2 LC_RPATH
```

If the app does not have an `@rpath` that covers `Frameworks`, add one:

```bash
install_name_tool -add_rpath "@executable_path/Frameworks" unpacked/Payload/App.app/App
```

Every framework is signed twice: the binary first, then the `.framework` directory.

### App extensions

`PlugIns/*.appex` are separate bundles with their own executables and their own
entitlements. An extension signed after the app, or not signed at all, breaks the install
with `ApplicationVerificationFailed`.

### Watch apps

`Watch/*.app` and the companion `Watch/Watch*.app` are separate bundles and need their own
signing pass, with their own entitlements file.

### dylib injection into a jailed app with a re-signed binary

Injecting a dylib into an App Store binary requires a decrypted binary; see
[`fairplay-decrypted-binary-handling.md`](fairplay-decrypted-binary-handling.md).

### Removing the injection

```bash
optool uninstall -t unpacked/Payload/App.app/App
codesign --remove-signature unpacked/Payload/App.app/App
rm -rf unpacked/Payload/App.app/_CodeSignature
```

### Signature preservation

`codesign --preserve-metadata=entitlements,requirements,flags,runtime` keeps the original
entitlements while replacing the identity:

```bash
codesign --force --sign "Apple Development: Your Name (XXXXXXXXXX)" \
  --preserve-metadata=entitlements,requirements,flags \
  --timestamp=none \
  unpacked/Payload/App.app
```

### Simulator builds

A simulator slice (`arm64` for Apple Silicon, `x86_64` for Intel) has no code signature
requirement from the App Store, but the bundle still needs a signature for the simulator to
run it. `codesign --force --sign -` on the simulator slice is enough for local testing.

## Verification

1. Structure check. `unzip -l repacked.ipa | head` shows `Payload/App.app/App` and no
   absolute paths or `__MACOSX` entries.
2. Load-command check. `otool -L unpacked/Payload/App.app/App` lists the injected dylib with
   the expected install name.
3. Signature check. `codesign --verify --deep --strict --verbose=4 unpacked/Payload/App.app`
   prints `valid on disk` and `satisfies its Designated Requirement`.
4. Entitlement check. `codesign -d --entitlements :- unpacked/Payload/App.app` lists the
   expected keys; a missing `keychain-access-groups` shows up at runtime as a keychain
   error, not at signing time.
5. Install check. The install returns success and the app launches. `ideviceinstaller -l`
   lists the bundle identifier.
6. Runtime check. The injected library's constructor logs to the device console
   (`idevicesyslog | grep YourLib`) or to `NSLog`, proving the load command was honoured.
7. Negative test. Remove the injected library from the bundle, re-sign, reinstall, and
   confirm the app starts and behaves as before. Then confirm that a bundle with a stale
   `_CodeSignature` is rejected: `codesign --verify` reports `invalid signature` and the
   install fails.

## Pitfalls

- **Signing the app before the nested binaries.** The app signature seals the nested content;
  signing nested content afterwards invalidates it. Symptom at install:
  `ApplicationVerificationFailed` or a launch crash in `dyld`.
- **Using `codesign --deep --sign -`.** The `deep` flag does not guarantee correct signing of
  nested content. Sign each nested binary explicitly.
- **Forgetting `Info.plist` in an injected framework.** The loader rejects the framework:
  `dyld: Library not loaded: … Reason: no LC_LOAD_DYLIB command`.
- **Wrong install name.** `@rpath/Your.framework/Your` requires the app to have a matching
  `LC_RPATH`. Missing rpath gives
  `dyld: Library not loaded: @rpath/Your.framework/Your`.
- **Ad-hoc signature on a stock device.** `--sign -` produces no provisioning profile and no
  team. A stock device refuses to launch it: `The signature does not include a valid
  entitlement` or the app is killed at launch.
- **Losing entitlements.** Signing without `--entitlements` strips `keychain-access-groups`
  and `aps-environment`; the app installs but loses keychain items and push.
- **Stripping the signature but not the `LC_CODE_SIGNATURE` load command.** The loader then
  looks for a signature that is not there. `optool` and `insert_dylib` handle this;
  hand-edited headers often do not.
- **Forgetting `embedded.mobileprovision`.** A stock device requires the profile to be inside
  the bundle.
- **Repacking with the wrong root.** `zip` must be run so that `Payload/` is the top-level
  entry. Otherwise the installer reports `The archive is invalid`.
- **Device clock.** The provisioning profile has an expiry date; an expired profile gives
  `unable to install … The certificate is not valid`.
- **Developer mode.** iOS 16 and later refuse to install a development-signed app unless
  Developer Mode is enabled on the device.

## References

- Apple, "Embedding a dylib in your app during development":
  <https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/Dylib_Embedded/Introduction/Introduction.html>
- Apple code signing guide:
  <https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/CodeSigningGuide.html>
- `codesign` manual page:
  <https://keith.github.io/xcode-man-pages/codesign.1.html>
- optool: <https://github.com/aferrero2707/optool>
- `ldid`: <https://github.com/ProcursusTeam/ldid>
- libimobiledevice `ideviceinstaller`:
  <https://libimobiledevice.org/>
- `ios-deploy`: <https://github.com/phonegap/ios-deploy>
- `pymobiledevice3`: <https://github.com/doronz88/pymobiledevice3>
- Sibling entries: [`fairplay-decrypted-binary-handling.md`](fairplay-decrypted-binary-handling.md),
  [`ios-native-licence-patching.md`](ios-native-licence-patching.md),
  [`jailbreak-detection-bypass.md`](jailbreak-detection-bypass.md)
