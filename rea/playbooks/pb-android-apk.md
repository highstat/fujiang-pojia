# Playbook: Android APK licence bypass

**Target**: an Android application whose premium features are locked behind a Java/Kotlin
licence check, a native library check, or a cached entitlement flag.
**Outcome**: a rebuilt, signed APK that installs and unlocks the feature on a device with no
root and no Frida.

## 0. Preparation

```sh
mkdir -p work && cd work
cp /path/to/app.apk app.apk
sha256sum app.apk | tee app.sha256
aapt2 dump badging app.apk | head -20
apksigner verify --verbose --print-certs app.apk
unzip -l app.apk | grep -E 'classes.*dex|lib/.*\.so'
```

Record the package name, the version, the signing schemes and whether native code is present.

## 1. Locate the check

### Java / Kotlin layer

```sh
jadx app.apk -d jadx_out
rg -n -i 'licen|serial|activat|trial|expir|purchas|premium|subscription|unlock' jadx_out/sources
```

Typical class names: `LicenseManager`, `SubscriptionService`, `ProGuard`, `UnlockManager`,
`Entitlement`.

### Smali layer

```sh
apktool d -f app.apk -o app_decoded
rg -n -i 'licen|serial|activat|trial' app_decoded/smali*
```

### Native layer

```sh
unzip -o app.apk 'lib/*' -d app_lib
for f in app_lib/lib/*/*.so; do
  echo "== $f"; readelf -sW "$f" | grep -iE 'java_|licen|valid' | head
done
```

## 2. Read the decision

Open the candidate in jadx-gui and answer three questions:

1. **What is returned?** A boolean, an expiry date, a token, a feature list?
2. **Where does the state come from?** A constant, a file, `SharedPreferences`, a server?
3. **Who calls it?** The caller is the gate — the check method itself may be called from
   several places.

Trace from the premium feature backwards to the call. That path is the one that must be satisfied.

## 3. Patch

### Smali — force the boolean

```smali
.method public static isValid(Ljava/lang/String;)Z
    .registers 1
    const/4 v0, 0x1
    return v0
.end method
```

Byte form: `const/4 v0, 1` = `12 10`, `return v0` = `0F 00`.

### Smali — invert the branch

```smali
invoke-static {v0, v1}, Lcom/vendor/License;->isValid(Ljava/lang/String;)Z
move-result v0
if-eqz v0, :cond_unlicensed
```

To invert the zero test, change `if-eqz` to `if-nez` and rebuild the smali:

```
if-eqz v0, :cond_x     38 00 <offset16>  ->  if-nez v0, :cond_x     39 00 <offset16>
```

The displacement is measured in 16-bit code units from the instruction. This inversion keeps
the instruction length; let the assembler calculate the actual label displacement. A `goto`
is unconditional, not a branch inversion. Assembly success alone does not prove the desired path.

### Smali — bypass the caller

Find the call site and jump over the unlicensed branch:

```smali
    invoke-static {v0}, Lcom/vendor/License;->isValid()Z
    move-result v1
    if-eqz v1, :cond_unlicensed
```

Remove the guard entirely, or set the result register to 1 before the check.

### Native library

The JNI method returns `jboolean` in `w0`. arm64:

```
00 00 80 52 C0 03 5F D6      mov w0, #0 ; ret   (false)
20 00 80 52 C0 03 5F D6      mov w0, #1 ; ret   (true)
```

x86_64: `B0 01 C3`.

arm32 (thumb): `70 01` = `movs r0, #1`.

### Cached entitlement

If the decision reads a local flag, editing the state is the smallest change:

```sh
adb shell run-as com.vendor.app cat shared_prefs/com.vendor.app_preferences.xml
```

On a rooted device, `/data/data/com.vendor.app/shared_prefs/`. Set the flag to the "licensed"
value, then confirm the app accepts it after a restart.

## 4. Rebuild, align, sign

```sh
apktool b app_decoded -o app_unsigned.apk
zipalign -P 16 -f 4 app_unsigned.apk app_aligned.apk

# debug keystore
keytool -genkeypair -v -keystore my.keystore -alias mykey \
        -keyalg RSA -keysize 2048 -validity 10000 \
        -storepass android -keypass android \
        -dname "CN=Dev, O=Dev, C=US"

apksigner sign --ks my.keystore --ks-pass pass:android --key-pass pass:android \
               --v1-signing-enabled true --v2-signing-enabled true \
               --v3-signing-enabled true \
               --out app_signed.apk app_aligned.apk

apksigner verify --verbose --print-certs app_signed.apk
```

Replacing a `.so` inside the APK, keeping the path and the alignment:

```sh
zip -d app_aligned.apk lib/arm64-v8a/liblicense.so
(cd app_lib/lib/arm64-v8a && zip -0 ../..//../app_aligned.apk liblicense.so)  # path must match
zipalign -P 16 -f 4 app_aligned.apk app_aligned2.apk
apksigner sign --ks my.keystore ... app_aligned2.apk
```

If the original keystore is available, sign with it — then the APK updates the installed app
without an uninstall and the original data survives.

## 5. Install and verify

```sh
adb uninstall com.vendor.app          # only when the signature changed
adb install app_signed.apk
adb logcat -c
adb shell am start -n com.vendor.app/.MainActivity
adb logcat | grep -iE 'AndroidRuntime|FATAL|UnsatisfiedLink'
```

Then:

1. Repeat the operation that was locked.
2. Clear app data and repeat — the patch must hold from cold:
   `adb shell pm clear com.vendor.app`.
3. Confirm the running process is the patched one:
   `adb shell dumpsys package com.vendor.app | grep -i signer`.

## 6. Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `INSTALL_PARSE_FAILED_NO_CERTIFICATES` | the APK was edited after signing | sign last |
| `INSTALL_FAILED_UPDATE_INCOMPATIBLE` | different signing key | uninstall first, or sign with the original key |
| `INSTALL_FAILED_VERIFICATION_FAILURE` | v2/v3 signature mismatch | rebuild and sign from scratch, do not edit the signed APK |
| `UnsatisfiedLinkError` | ABI, loader dependency, or alignment problem | inspect logcat and ELF dependencies; use `zipalign -P 16` before signing |
| App crashes on launch | the smali branch offset is wrong | run `apktool b` and read its error |
| The feature is still locked | a second check in the native layer or the server | patch the native path too |

## Deliverable

`app_signed.apk`, the patch manifest with the smali or `.so` offsets, the original hash, and the
verification steps that were run.
