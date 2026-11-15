---
id: "dex-smali-licence-patching"
title: "DEX and smali licence patching"
domain: "android"
kind: "technique"
platforms: "android"
arch: "x86-64, arm, arm64"
difficulty: "intermediate"
tools: "jadx, apktool, baksmali, smali, adb"
verified: false
updated: "2026-11-15"
summary: "Locate a Java or Kotlin licence check in a DEX, recognise its smali shape, and rewrite the decision so the method returns the licensed value, including multidex and JNI-backed variants."
---

## Summary

Most licence gates on Android live in the DEX as a plain boolean method. The method calls a
validation helper, compares the returned boolean with zero, and returns `0` or `1`. In smali
that shape is two instructions wide, and the fix is to change the method so it always returns
`1` — either by replacing the body, by inverting the conditional branch, or by neutralising
the branch with a `nop`.

This entry covers the exact smali, the byte values behind it, how to find the right class in a
multidex package, and what to do when the decision is delegated to a native library.

## Recognition

The Java view (jadx 1.5.6) of a typical gate:

```java
public static boolean isLicensed(Context ctx) {
    if (LicenseChecker.validate(ctx, "license_key")) {
        return true;
    }
    return false;
}
```

The smali view of the same method:

```smali
.method public static isLicensed(Landroid/content/Context;)Z
    .locals 2
    .registers 3

    const-string v0, "license_key"

    invoke-static {p0, v0}, Lcom/vendor/app/licence/LicenseChecker;->validate(Landroid/content/Context;Ljava/lang/String;)Z
    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x1
    return v0

    :cond_0
    const/4 v0, 0x0
    return v0
.end method
```

The signature of the shape to look for:

- The return type is `Z` (boolean) and the method name matches the domain vocabulary:
  `isLicensed`, `hasLicense`, `isRegistered`, `isValid`, `isPro`, `checkLicense`,
  `validateLicense`, `isActivated`.
- `invoke-static` (or `invoke-virtual`) into a helper in a `licence`, `license`, `activation`,
  `subscription` or `billing` package, followed by `move-result v0`.
- `if-eqz v0, :cond_x` or `if-nez v0, :cond_x` on that register.
- The `const/4 v0, 0x0` + `return v0` pair in the fall-through path: the `0` return.
- The `.registers`/`.locals` directives immediately after `.method` and before the first
  instruction.

Secondary artefacts that confirm which method is the gate:

- A dialog string in `res/values/strings.xml`: `license_key_invalid`, `Subscription expired`,
  `ERR_LICENSE_013`, `Activate premium`.
- A `SharedPreferences` key `premium` or `licence_valid` read right after the check.
- A `Log` tag `LicenseManager` in the logcat output when the check fails.
- The helper class name appears in the stack trace of the failure, e.g.
  `com.vendor.app.licence.LicenseChecker.validate(LicenseChecker.java:88)`.

## Method

### 1. Decompile and find the gate

```bash
cd /path/to/work
jadx -d jadx_out app_original.apk
grep -rn "isLicensed\|hasLicense\|isRegistered\|isValid\|isPro\|checkLicense" jadx_out/sources | head -40
```

When R8 obfuscation hides the names, search for the strings and the package path instead:

```bash
grep -rn "license_key\|licence\|Invalid license\|not registered" jadx_out/sources | head -40
```

### 2. Map the class to its smali file

Package `com.vendor.app.licence`, class `LicenseChecker` maps to
`smali/com/vendor/app/licence/LicenseChecker.smali`. For a multidex package the same class
may live in `smali_classes2/`, `smali_classes3/` and so on.

```bash
cd /path/to/work
ls -d app_decoded/smali*
grep -rn "isLicensed" app_decoded/smali*/com/vendor/app/ 2>/dev/null | head
```

To confirm which DEX holds a class when the decoded tree is not available:

```bash
cd /path/to/work
for d in $(unzip -Z1 app_original.apk 'classes*.dex'); do
  unzip -p app_original.apk "$d" > "/tmp/$d"
  echo "== $d"
  java -jar baksmali-3.0.8.jar list classes "/tmp/$d" | grep -i "licen\|activation" | head
done
```

### 3. Read the method body

```bash
cd /path/to/work
sed -n '/\.method.*isLicensed/,/\.end method/p' app_decoded/smali/com/vendor/app/LicenseChecker.smali
```

### 4. Apply the edit

Pick one of the three edits below. Edit A is the most robust because it removes every
dependency of the method on the helper.

#### Edit A — replace the body

Keep the `.method` signature and the `.locals`/`.registers` directives unchanged; replace
everything between the directives and `.end method`:

```smali
.method public static isLicensed(Landroid/content/Context;)Z
    .locals 2
    .registers 3

    const/4 v0, 0x1
    return v0
.end method
```

The byte values behind that body, in DEX order:

| Instruction | Bytes | Meaning |
| --- | --- | --- |
| `const/4 v0, 0x1` | `12 10` | opcode `0x12` (format 11n), nibble pair `B=1` literal, `A=0` → `v0` |
| `const/4 v0, 0x0` | `12 00` | same opcode, literal `0` |
| `return v0` | `0f 00` | opcode `0x0f` (format 11x), register `v0` |
| `return-void` | `0e 00` | opcode `0x0e` (format 10x), only legal in a `void` method |
| `nop` | `00 00` | opcode `0x00` |

`return-void` (`0e 00`) must not be used in a method whose return type is `Z`; the runtime
throws `VerifyError: Expected a boolean but was void`. Use `const/4 v0, 0x1` plus
`return v0` (`12 10` / `0f 00`).

#### Edit B — invert the branch

When the licensed path is the fall-through and the unlicensed path is a label, the branch is
the only thing to change. Replace the conditional with an unconditional jump to the licensed
label:

```smali
    invoke-static {p0, v0}, Lcom/vendor/app/licence/LicenseChecker;->validate(Landroid/content/Context;Ljava/lang/String;)Z
    move-result v0

    goto :cond_0

    :cond_0
    const/4 v0, 0x1
    return v0
```

The branch encodings:

| Smali | Bytes | Format |
| --- | --- | --- |
| `if-eqz v0, :cond_x` | `39 00 xx xx` | 22t, opcode `0x39`, signed 16-bit offset in bytes |
| `if-nez v0, :cond_x` | `38 00 xx xx` | 22t, opcode `0x38` |
| `goto :cond_x` | `28 00 xx` | 30t, opcode `0x28`, signed 8-bit offset in 2-byte units |
| `nop` | `00 00` | format 10x |

`if-eqz` and `if-nez` differ only in the opcode byte (`39` versus `38`); `goto` uses the
shorter 30t form with opcode `28`. The high byte of a `goto` is `00` for any short forward
branch. The offset is relative to the start of the branch instruction, so copying the offset
byte from the `if-eqz` to the `goto` changes the distance — recompute it or let smali
assemble it.

#### Edit C — neutralise the branch

If the licensed path is the fall-through and the unlicensed path is the label, removing the
branch is enough: the method falls through to the `const/4 v0, 0x1` / `return v0` pair
regardless of what the helper returned.

```smali
    invoke-static {p0, v0}, Lcom/vendor/app/licence/LicenseChecker;->validate(Landroid/content/Context;Ljava/lang/String;)Z
    move-result v0

    nop

    const/4 v0, 0x1
    return v0
```

A single `nop` (`00 00`) replaces the two-byte `if-eqz`. When the branch is a 32-bit offset
form (`if-eqz` with a far target is still 22t; `goto/32` is `2a`), the replacement must keep
the instruction count stable, so use a `nop` plus padding rather than deleting the bytes
without adjusting the offsets. Editing the smali source and letting `smali` re-assemble avoids
that class of error entirely.

### 5. Handle the helper, not just the gate

A patched gate is bypassed while the helper still throws. If the helper raises
`IllegalStateException("License check failed")` or
`KotlinNullPointerException` from `Intrinsics.checkNotNull`, patch the helper to return `true`
as well, or make the gate skip the call entirely:

```smali
    const/4 v0, 0x1
    return v0
```

Kotlin's `Intrinsics.checkExpressionValueIsNotNull` calls appear as
`Lkotlin/jvm/internal/Intrinsics;->checkNotNull(Ljava/lang/Object;)V` and throw before the
patched return is reached. Removing the whole call chain, as Edit A does, avoids the issue.

### 6. Rebuild, align and sign

```bash
cd /path/to/work
apktool b app_decoded -o build/app_built.apk
zipalign -P 16 -f 4 build/app_built.apk build/app_aligned.apk
apksigner sign \
  --ks debug.keystore \
  --ks-key-alias androiddebugkey \
  --ks-pass pass:android \
  --key-pass pass:android \
  --out build/app_signed.apk \
  build/app_aligned.apk
apksigner verify --verbose --print-certs build/app_signed.apk
adb install -r build/app_signed.apk
```

The signature details are in [`apk-decode-rebuild-sign.md`](apk-decode-rebuild-sign.md).

### 7. DEX-only round trip without apktool

When only the DEX changed, apktool's resource pipeline is unnecessary. baksmali 3.0.8 and
smali 3.0.8 (both bundled with apktool 2.12+, and available as standalone jars from the
`google/smali` releases) work directly:

```bash
cd /path/to/work
mkdir -p dex_work && cd dex_work
unzip -o ../app_original.apk classes*.dex -d .
java -jar baksmali-3.0.8.jar d classes.dex -o smali_out
# edit smali_out/smali/com/vendor/app/licence/LicenseChecker.smali
java -jar smali-3.0.8.jar b smali_out -o classes_patched.dex
```

The rebuilt DEX must be put back into the container and the container re-signed:

```bash
cd /path/to/work/dex_work
zip -d ../build/app_built.apk classes.dex
zip -X -0 ../build/app_built.apk classes_patched.dex
mv ../build/app_built.apk ../build/app_built2.apk
```

Renaming `classes_patched.dex` to `classes.dex` is mandatory — the package manager only
loads a file named `classes.dex`, and `classes2.dex` and above must stay numbered
consecutively.

## Variations

### Multidex

- The DEX files are `classes.dex`, `classes2.dex`, … The decoded tree mirrors this as
  `smali/`, `smali_classes2/`, `smali_classes3/`.
- The gate can live in any of them. Search all of them:
  `grep -rn "isLicensed" app_decoded/smali*/`.
- `System.loadLibrary` in a `<clinit>` of the *application* class may pull a native component
  in from any dex; the gate itself might be in `classes2.dex` while the helper is in
  `classes.dex`.
- MinSdk below 21 uses the multidex support library, where the secondary dex files are
  generated at install time from `classes.dex` and are not editable in the APK. Patch the
  primary dex only.

### Native (JNI) decisions

A Java method with no body is a native decision:

```smali
.method public static native isLicensedNative(Landroid/content/Context;)Z
.end method
```

and the registration happens in `JNI_OnLoad`:

```smali
.method static constructor <clinit>()V
    .locals 1

    const-string v0, "licence"
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

    return-void
.end method
```

Patching the DEX does not change the answer in that case. Three options:

1. Patch the `.so` — see [`android-native-library-licence.md`](android-native-library-licence.md).
2. Hook the native method at the Java layer with Frida and force the return. The Java bridge
   works on native methods as well:

   ```js
   Java.perform(() => {
     const C = Java.use('com.vendor.app.licence.LicenseChecker');
     C.isLicensedNative.implementation = function (ctx) {
       console.log('[+] isLicensedNative -> true');
       return true;
     };
   });
   ```

   This needs the `frida-java-bridge` package installed and bundled with `frida-compile`;
   Frida 17 no longer ships the bridges inside the runtime. See
   [`play-billing-entitlement-faking.md`](play-billing-entitlement-faking.md).
3. Replace the native declaration with a Java implementation in smali: delete the `native`
   keyword from the method and give it a body. The `System.loadLibrary` call and the
   registration are then unused but harmless.

### Reflection-driven checks

When the gate is invoked reflectively (`Method.invoke`), the method name may be stored as a
string constant in a config class. Search for the string in the smali:

```bash
grep -rn "const-string.*\"isLicensed\"" app_decoded/smali* | head
```

The method it names is still the method to patch; reflection does not hide the body.

### Obfuscated and inlined gates

R8 can inline a tiny boolean method into every call site, leaving no method to patch. Two
outcomes:

- The inlined constant `const/4 v0, 0x0` appears at the call site. Patch each occurrence, or
  patch the field the constant was copied from.
- The check is folded into a `sget`/`iget` of a `static final boolean`. Changing the field's
  initialiser in the `<clinit>` of the owning class changes every use at once. That is the
  cheaper edit when it is available.

### Alternative packer layouts

Packed APKs store the real DEX in an asset (`assets/app.dex`, `assets/libjiagu.so`) and
unpack it at runtime. The decoded `smali/` then contains only the loader stub. The gate is
reachable only in the unpacked DEX, which is written to
`/data/data/<pkg>/cache/` or extracted into memory at start-up. See
[`android-native-library-licence.md`](android-native-library-licence.md) for the runtime
approach against the unpacked code.

## Verification

1. Static check. Re-read the patched method and confirm the smali is consistent:
   `sed -n '/\.method.*isLicensed/,/\.end method/p' app_decoded/smali/com/vendor/app/licence/LicenseChecker.smali`.
   A register-count mismatch is caught by the assembler, not by the device.
2. Build check. `apktool b` must complete without `Conflicting registers` or
   `Method must have register count` errors.
3. Signature check. `apksigner verify --verbose --print-certs build/app_signed.apk` prints
   `Verifies`.
4. Runtime check. `adb install -r build/app_signed.apk`, launch the app, and confirm the
   licensed path: the gate screen does not appear, the premium feature renders, and
   `adb logcat -s LicenseManager` shows no error.
5. Negative test. Reinstall the unmodified APK and confirm the gate returns. Then re-apply the
   patch to a fresh decode and confirm the gate is still bypassed. If the app caches the
   entitlement, clear it before the negative test:
   `adb shell pm clear com.vendor.app` (this also wipes the licence cache, so a check that
   only read a cached value will reappear).
6. Cross-process check. If the gate also runs in a `:license` service process, confirm the
   gate is bypassed there too: `adb shell ps -A | grep <package>` shows the extra process, and
   the service logcat must show the licensed branch.

## Pitfalls

- **The class is in another DEX.** Editing `smali/` when the class lives in `smali_classes2/`
  changes nothing and the app still refuses. Search every `smali*` directory.
- **Register count mismatch.** Writing `v3` after lowering `.registers` produces
  `Conflicting registers` at build time, or a `VerifyError` on the device when the count is
  only wrong in the low bits. Keep `.locals` and `.registers` exactly as they were.
- **Using `return-void` (`0e 00`) in a boolean method.** The runtime rejects it with
  `VerifyError: Expected a boolean but was void`. Use `12 10` plus `0f 00`.
- **Copying a branch offset byte-for-byte.** `if-eqz` uses a 16-bit byte offset while `goto`
  uses an 8-bit offset in 2-byte units. Reuse the wrong one and the jump lands in the middle
  of an instruction: `VerifyError` or a crash. Let smali compute it.
- **Patching the gate but not the exception.** A helper that throws before returning leaves
  the app crashing instead of licensed.
- **The check runs twice.** One copy sits in the UI, another in a background service or in
  a work manager job. Patch both, or patch the shared helper.
- **The DEX header checksum.** smali recomputes the SHA-1 at offset `0x0c` and the Adler-32
  at `0x08`. A DEX edited with a hex editor keeps the old values and the package manager
  rejects it.
- **Kotlin `Intrinsics` null checks.** `checkNotNull` on a value that the patched path no
  longer produces throws before the return.
- **The licence is validated server-side.** A patched gate that only unlocks the UI does not
  unlock the server response. See
  [`play-billing-entitlement-faking.md`](play-billing-entitlement-faking.md).
- **Tamper detection.** Some apps recompute a checksum over their own DEX or verify the
  signature at runtime. After a rebuild the check fails even though the licence gate is
  patched.

## References

- Dalvik executable format and instruction encoding:
  <https://source.android.com/docs/core/runtime/dalvik-bytecode>
- smali / baksmali 3.0.8: <https://github.com/google/smali>
- apktool 2.12+ (bundles smali 3.0.8): <https://github.com/iBotPeaches/apktool>
- jadx 1.5.6: <https://github.com/skylot/jadx/releases>
- Android "Verifying an APK's signature" and `PackageManager` install errors:
  <https://developer.android.com/studio/publish/app-signing>
- Sibling entries: [`apk-decode-rebuild-sign.md`](apk-decode-rebuild-sign.md),
  [`android-native-library-licence.md`](android-native-library-licence.md),
  [`play-billing-entitlement-faking.md`](play-billing-entitlement-faking.md)
