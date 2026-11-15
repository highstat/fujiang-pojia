---
id: "apk-decode-rebuild-sign"
title: "APK decode, rebuild and sign"
domain: "android"
kind: "playbook-ref"
platforms: "android"
arch: "x86-64, arm, arm64"
difficulty: "intermediate"
tools: "apktool, zipalign, apksigner, keytool, jadx, adb"
verified: false
updated: "2026-11-15"
summary: "Decode an APK with apktool, edit smali or resources, rebuild it, page-align the native libraries with zipalign and sign the result with apksigner while keeping the signature-scheme, alignment-order and key-identity rules intact."
---

## Summary

An APK is a ZIP with a fixed layout, a DEX payload and an APK Signing Block. Every edit to
smali, resources or a native library invalidates the signature, and every write to the ZIP
container invalidates the block that v2/v3 signatures cover. This entry gives the exact round
trip: `apktool d` to decode, edit, `apktool b` to rebuild, `zipalign -P 16 4` to page-align the
uncompressed `.so` files, `apksigner sign` to produce a v1/v2/v3 signature, and
`apksigner verify --verbose --print-certs` to prove the result.

The order is not stylistic. `apksigner` does not align, and `zipalign` does not sign. Align
first, sign second. Signing first and aligning second yields an APK that installs on nothing.

Read this entry together with [`dex-smali-licence-patching.md`](dex-smali-licence-patching.md)
for the DEX edits and [`android-native-library-licence.md`](android-native-library-licence.md)
for `.so` replacement.

## Recognition

Observable signals that a package is a normal APK and how it was signed:

- The file is a ZIP whose first entry is `AndroidManifest.xml` in binary AXML form:
  `unzip -l app.apk | head` shows `AndroidManifest.xml`, `classes.dex` (plus `classes2.dex` …
  for multidex), `resources.arsc`, `lib/<abi>/lib*.so`, `assets/`.
- v1 (JAR) signature artefacts live in `META-INF/`: `META-INF/CERT.RSA` (or `*.EC` on some
  build systems), `META-INF/CERT.SF`, `META-INF/MANIFEST.MF`. Their absence means the APK has
  no v1 signature.
- The APK Signing Block is not a ZIP entry. It sits between the last local file entry and the
  central directory and is invisible to `unzip -l`. `zipalign` and `apksigner` are the tools
  that understand it.
- `apksigner verify --verbose --print-certs app.apk` reports the scheme in use and the
  signer identity:

  ```text
  Verifies
  Verified using v1 scheme (JAR signing): true
  Verified using v2 scheme (APK Signature Scheme v2): true
  Verified using v3 scheme (APK Signature Scheme v3): true
  Number of signers: 1
  Signer #1 certificate DN: CN=Android Debug, O=Android, C=US
  Signer #1 certificate SHA-256 digest: 9a:1f:...
  ```

- The build system leaves fingerprints: `apktool.yml` after a decode records
  `versionCode`, `versionName`, `minSdkVersion`, `targetSdkVersion`, `usesFramework`,
  `apkFileName`, `isFrameworkApk` and `doNotCompress`.
- A licence-gated app shows a specific artefact, not a generic one: a dialog reading
  `Enter license key`, a settings row `Premium (locked)`, an HTTP `403` on the entitlement
  endpoint, or a `SharedPreferences` key `premium` set to `false`.

## Method

### 1. Prepare the workspace

Use a scratch directory so the original APK is never overwritten:

```bash
cd /path/to/work
mkdir -p apk_work && cd apk_work
cp /path/to/app.apk ./app_original.apk
sha256sum app_original.apk | tee original.sha256
```

Tool versions assumed: `apktool` 2.12+ (bundles smali/baksmali 3.0.8), Android Build Tools
`zipalign` and `apksigner` from 35.0.0 or newer, JDK 17+.

```bash
apktool --version          # 2.12.0
zipalign -h | head -3      # Android Asset Packaging Tool alignment
apksigner version          # 0.9 / build-tools 35.0.0
```

### 2. Decode the APK

```bash
cd /path/to/work/apk_work
apktool d app_original.apk -f -o app_decoded
```

- `-f` forces overwrite of an existing output directory. Without it apktool aborts with
  `Directory already exists`.
- `-o app_decoded` sets the output directory.
- `-r` skips resource decoding and keeps `resources.arsc` and the raw `AndroidManifest.xml`
  binary. Use it when only DEX edits are planned: it is much faster and it sidesteps
  `aapt` decode failures on malformed resources. The manifest is then not editable as text.
- `-s` keeps the original DEX files and skips smali disassembly.

Decoded layout:

```text
app_decoded/
├── AndroidManifest.xml        # decoded text XML
├── apktool.yml
├── classes.dex                # only with -s
├── lib/arm64-v8a/libfoo.so
├── res/                       # decoded resources
├── smali/                     # smali_classes1
├── smali_classes2/            # only for multidex apps
└── unknown/                   # assets, files, kotlin metadata
```

### 3. Locate the decision point

Two tools, two views of the same code. jadx gives readable Java/Kotlin, smali gives the
bytes that will actually be rebuilt:

```bash
jadx -d jadx_out app_original.apk
grep -rn "isLicensed\|ValidLicense\|isRegistered\|LicenseManager" jadx_out/sources | head -40
```

In the decoded tree, find the smali counterpart:

```bash
grep -rln "IsLicensed\|ValidLicense\|isRegistered" app_decoded/smali* | head -20
```

Class-to-path mapping: package `com.vendor.app` plus class `LicenseManager` becomes
`smali/com/vendor/app/LicenseManager.smali`. The dex that holds the class determines the
directory:

```bash
grep -rn "LicenseManager" app_decoded/smali*/com/vendor/app/*.smali | head
```

### 4. Edit

See [`dex-smali-licence-patching.md`](dex-smali-licence-patching.md) for the smali edits and
[`android-native-library-licence.md`](android-native-library-licence.md) for `.so` edits.
Resource edits go in `res/values/strings.xml`; a boolean flag in `res/values/bools.xml` is a
one-line change and needs no smali work.

### 5. Rebuild

```bash
cd /path/to/work/apk_work
apktool b app_decoded -o build/app_built.apk
```

apktool writes intermediates into `app_decoded/build/` and the APK to `build/app_built.apk`.
Useful flags:

- `--use-aapt2` — force the aapt2 resource pipeline (default in 2.12+; pass it explicitly if
  the build fails with aapt1 errors on `styleable` or `attr` resources).
- `--aapt <path>` — point at a specific `aapt2` binary from Build Tools 35.0.0.

A build failure in `app_decoded/res/values/strings.xml` is a resource-decode artifact, not a
code error. Re-decode with `-r` and re-apply the smali edits, or fix the offending XML.

### 6. Align the native libraries

```bash
cd /path/to/work/apk_work
zipalign -P 16 -f -v 4 build/app_built.apk build/app_aligned.apk
```

- `4` is the alignment in bytes for uncompressed entries.
- `-p` page-aligns uncompressed shared libraries to a 4096-byte boundary. Android 11+ refuses
  to load an uncompressed `.so` whose offset is not page-aligned, and Android 15 devices with
  16 KB pages need `zipalign -P 16` (Build Tools 35.0.0+). Verify with:

  ```bash
  zipalign -c -v 4 build/app_aligned.apk
  ```

  Expected tail: `Verification succesful`.

Why the alignment step sits before signing: `zipalign` rewrites the ZIP central directory and
the local header offsets of the entries it moves. The APK Signing Block is not a ZIP entry, so
`zipalign` drops it, and the v2/v3 signature covers the whole file. A v1 signature survives
because it hashes entry *contents*, not offsets; v2 and v3 do not survive at all.

### 7. Sign

Create a debug keystore once per machine:

```bash
cd /path/to/work/apk_work
keytool -genkeypair -v \
  -keystore debug.keystore \
  -storepass android \
  -keypass android \
  -alias androiddebugkey \
  -keyalg RSA \
  -keysize 2048 \
  -validity 10000 \
  -dname "CN=Android Debug, O=Android, C=US"
```

Sign the aligned APK:

```bash
cd /path/to/work/apk_work
apksigner sign \
  --ks debug.keystore \
  --ks-key-alias androiddebugkey \
  --ks-pass pass:android \
  --key-pass pass:android \
  --v1-signing-enabled true \
  --v2-signing-enabled true \
  --v3-signing-enabled true \
  --v3.1-signing-enabled false \
  --out build/app_signed.apk \
  build/app_aligned.apk
```

- `--ks-pass pass:android` supplies the store password inline; the alternative
  `--ks-pass env:KS_PASS` reads `KS_PASS` from the environment and avoids the password
  appearing in the process list.
- `--key-pass` is only needed when the key password differs from the store password.
- `--min-sdk-version 24` tells apksigner to pick only the schemes that a device with that
  `minSdkVersion` understands, which is how a v2-only signature is produced deliberately.
- `--v4-signing-enabled true` additionally writes an `.idsig` file for incremental install.
  It does not affect the APK itself.
- `--rotation-min-sdk-version` (v3.1 only) pins the key-rotation floor.

### 8. Verify the signature

```bash
cd /path/to/work/apk_work
apksigner verify --verbose --print-certs build/app_signed.apk
```

Expected output shape:

```text
Verifies
Verified using v1 scheme (JAR signing): true
Verified using v2 scheme (APK Signature Scheme v2): true
Verified using v3 scheme (APK Signature Scheme v3): true
Signer #1 certificate DN: CN=Android Debug, O=Android, C=US
Signer #1 certificate SHA-256 digest: 9a:1f:...
```

`apksigner verify` exits non-zero and prints `DOES NOT VERIFY` when the block was damaged.

### 9. Install

```bash
adb install -r build/app_signed.apk
```

If the package is already installed under a different key:

```text
adb: failed to install build/app_signed.apk: Failure [INSTALL_FAILED_UPDATE_INCOMPATIBLE:
Package com.vendor.app signatures do not match previously installed version; ignoring!]
```

Uninstall first, which removes the app's data:

```bash
adb uninstall com.vendor.app
adb install build/app_signed.apk
```

## Variations

### Signature scheme coverage by Android version

| Scheme | Introduced | Honoured by | Notes |
| --- | --- | --- | --- |
| v1 (JAR signing) | Android 1.0 | every version | Hashes entry contents; survives a realign. Still the only scheme understood by API 23 and older. |
| v2 (APK Signature Scheme v2) | Android 7.0 (API 24) | API 24+ | Whole-file signature in the APK Signing Block. Ignored on API 23 and older. |
| v3 | Android 9 (API 28) | API 28+ | Adds key rotation with a proof-of-rotation chain. |
| v3.1 | Android 13 (API 33) | API 33+ | Rotation with a `rotation-min-sdk-version` floor; adds a new signature ID. |
| v4 | Android 9+ (install-time) | adb/incremental | `.idsig` sidecar only; not inside the APK. |

Platform constraints that interact with the scheme choice:

- Apps with `targetSdkVersion` 30 or higher must be signed with v2 or later. A v1-only APK
  fails to install with `INSTALL_PARSE_FAILED_NO_CERTIFICATES` on API 30+ devices.
- `apksigner` writes all enabled schemes into one APK. The device picks the strongest scheme
  it understands, so a multi-scheme APK is the portable choice.

### Keeping the original signature

If the release keystore is available, sign with it and the original signature is preserved
byte for byte:

```bash
apksigner sign \
  --ks release.jks \
  --ks-key-alias upload \
  --ks-pass env:KS_PASS \
  --key-pass env:KEY_PASS \
  --out build/app_signed.apk \
  build/app_aligned.apk
```

The certificate DER must be identical to the installed one; a different alias inside the same
keystore that holds a different key produces a different certificate and the same
`INSTALL_FAILED_UPDATE_INCOMPATIBLE` failure. Confirm the identity before signing:

```bash
keytool -list -v -keystore release.jks -alias upload | grep -A3 "Certificate fingerprints"
```

If the keystore is lost, the original signature cannot be reproduced. APK Signature Scheme v3
key rotation does not help here: rotation requires the *old* key to sign the proof-of-rotation
record. The only outcome is uninstall-and-reinstall, which loses app data and any server-side
account state bound to the install.

### Batched signing

`uber-apk-signer` performs align and sign in one step for a directory of APKs:

```bash
java -jar uber-apk-signer.jar -a --ks debug.keystore --ksKeyPass android --ksKeyAlias androiddebugkey --ksPass android build/
```

### App bundles

An `.aab` is not an APK and cannot be installed directly:

```bash
bundletool build --bundle=app.aab --output=out/base.apks \
  --ks=debug.keystore --ks-pass=pass:android --ks-key-alias=androiddebugkey --key-pass=pass:android
bundletool build-apks --bundle=out/base.apks --output=out/app.apks \
  --ks=debug.keystore --ks-pass=pass:android --ks-key-alias=androiddebugkey --key-pass=pass:android
bundletool install-apks --apks=out/app.apks
```

The generated `.apks` still has to be aligned and signed per variant.

### Signing without the Android SDK

`apksigner` ships as a jar inside the Build Tools (`lib/apksigner.jar`) and can run standalone:

```bash
java -jar /path/to/build-tools/35.0.0/lib/apksigner.jar sign --ks debug.keystore ...
```

## Verification

1. Signature check. `apksigner verify --verbose --print-certs build/app_signed.apk` must print
   `Verifies` and the expected scheme flags. A `DOES NOT VERIFY` means the APK was modified
   after signing, most often because `zipalign` ran last.
2. Alignment check. `zipalign -c -v 4 build/app_signed.apk` must report
   `Verification succesful`. Run it on the *signed* file: alignment is a property of the
   container, not of the signature.
3. Content check. `unzip -p build/app_signed.apk classes.dex | sha256sum` must differ from the
   original DEX when smali was edited, and `unzip -l build/app_signed.apk` must show the same
   entry set as the original plus the expected edits.
4. Install check. `adb install -r build/app_signed.apk` returns `Success`. Install over an
   existing copy with a different key and confirm the expected
   `INSTALL_FAILED_UPDATE_INCOMPATIBLE` before uninstalling, so the failure mode is understood
   rather than accidental.
5. Negative test. Reinstall the *original* APK (`adb install -r app_original.apk` after
   `adb uninstall`) and confirm the licence gate still blocks the feature. Then reinstall the
   patched build and confirm the feature is unlocked. A patch that only survives in memory, or
   one that "works" because the app was still logged in from a previous session, is not a
   patch.

## Pitfalls

- **Signing before aligning.** `apksigner sign` then `zipalign` produces an APK whose v2/v3
  signature no longer matches. Symptom: `apksigner verify` prints `DOES NOT VERIFY`, and the
  device refuses the install. Repair: align, then sign, in that order.
- **Missing signature after a container rewrite.** Any tool that rewrites the ZIP (some `zip`
  invocations, `apktool b` after a manual `zip` merge, some repack scripts) discards the APK
  Signing Block. Symptom on install:
  `INSTALL_PARSE_FAILED_NO_CERTIFICATES: Package /data/app/.../base.apk has no certificates`.
  Repair: re-run `apksigner sign` on the final container.
- **Signing with a different key over an existing install.** Symptom:
  `INSTALL_FAILED_UPDATE_INCOMPATIBLE`. Repair: `adb uninstall <package>` first, accepting the
  data loss.
- **Play Store rejection after re-signing.** Play ties app integrity to the upload
  certificate. A re-signed APK has a different certificate and fails the Play app-integrity
  signal, and Play refuses updates whose signer differs. See
  [`play-billing-entitlement-faking.md`](play-billing-entitlement-faking.md).
- **`apktool d` resource failures.** A malformed or heavily obfuscated `resources.arsc` makes
  aapt2 abort with `aapt2: error: resource ... not found`. Repair: re-decode with `-r` and
  work on smali only, or fix the offending resource file.
- **Rebuilt DEX checksum.** smali recomputes the DEX header SHA-1 (offset `0x0c`) and Adler-32
  (offset `0x08`). A DEX edited with a hex editor without recomputing them fails to parse:
  `INSTALL_PARSE_FAILED_UNEXPECTED_EXCEPTION: DexParser: Invalid checksum`.
- **16 KB page size.** Android 15 devices with 16 KB pages reject `.so` files not aligned to
  16 KB. Use `zipalign -P 16` from Build Tools 35.0.0+ and keep the libraries uncompressed.
- **Truncated keystore password.** `apksigner` prompts for the password when `--ks-pass` is
  omitted; a wrong password fails with `Failed to load signer` and no useful context.
- **Lost release keystore.** There is no recovery path. Plan the keystore custody before the
  first upload; Play App Signing means the *upload* key is the one Google knows, and the app
  signing key can be delegated to Google with an enrolment flow.
- **Signing a `resources.arsc` that apktool re-encoded.** apktool may rewrite `resources.arsc`
  when resources were decoded, which changes resource IDs. Apps that persist raw resource IDs
  break. Decode with `-r` to keep the original `resources.arsc` byte-for-byte.

## References

- Android developer docs, "Signing your apps":
  <https://developer.android.com/studio/publish/app-signing>
- Android developer docs, "APK Signature Scheme v2":
  <https://source.android.com/docs/security/features/apksigning/v2>
- Android developer docs, "APK Signature Scheme v3 and APK Signature Scheme v3.1":
  <https://source.android.com/docs/security/features/apksigning/v3>
- `apksigner` reference (Build Tools):
  <https://developer.android.com/tools/sdk/apksigner>
- `zipalign` reference:
  <https://developer.android.com/tools/sdk/zipalign>
- apktool 2.12+ release notes and usage:
  <https://github.com/iBotPeaches/apktool/releases>
- `keytool` documentation:
  <https://docs.oracle.com/en/java/javase/21/docs/specs/man/tools/keytool.html>
- Package manager error codes:
  <https://developer.android.com/reference/android/content/pm/PackageManager>
- Sibling entries: [`dex-smali-licence-patching.md`](dex-smali-licence-patching.md),
  [`android-native-library-licence.md`](android-native-library-licence.md),
  [`play-billing-entitlement-faking.md`](play-billing-entitlement-faking.md)
