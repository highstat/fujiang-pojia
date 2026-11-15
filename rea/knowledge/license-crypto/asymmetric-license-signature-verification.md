---
id: "asymmetric-license-signature-verification"
title: "Asymmetric licence signature verification"
domain: "license-crypto"
kind: "technique"
platforms: "windows, macos, linux, android, ios"
arch: "x86, x86-64, arm64"
difficulty: "advanced"
tools: "radare2, openssl, Frida, dnSpyEx, LIEF"
verified: false
updated: "2026-11-15"
summary: "How applications verify signed licence blobs, where the embedded public key sits in each platform's binary layout, and the two routes to a valid licence — forge-and-swap the public key, or force the verification call to report success."
---

## Summary

An asymmetric licence check works in one direction only: the vendor holds the private key and
signs, the application holds the public key and verifies. Two attack routes follow from that
asymmetry, and the choice between them is decided by where the public key lives and whether
the verifier is in the application code or in a system library.

- **Route (a) — forge and swap.** Generate a key pair, sign a licence payload with the private
  key, and replace the embedded public key with the public key of the new pair. Requires that
  the key blob is replaceable and that no other integrity check covers it.
- **Route (b) — force the verifier to succeed.** Patch or hook the verification call so the
  boolean/STATUS result is always "valid". Requires knowing which API returns what, because
  "success" is `1` for `BOOL` and `0` for `NTSTATUS` and `OSStatus`.

Prerequisites: [Serial validation algorithm recovery](serial-validation-algorithm-recovery.md)
for the payload structure, and [Symmetric licence blob formats](symmetric-license-blob-formats.md)
when the payload is encrypted before signing.

## Recognition

**Algorithm fingerprints.** The imports or JNI symbols give the scheme away:

```bash
rabin2 -i target.exe | grep -iE 'verify|signature|bcrypt|crypt32|wintrust|openssl|sec'
rabin2 -i target.exe | grep -iE 'BCryptVerifySignature|CryptVerifySignature|WinVerifyTrust|EVP_DigestVerify|SecKeyVerifySignature'
rabin2 -s target.so | grep -iE 'Java_.*[Vv]erify|VerifySignature'
```

| Scheme | Marker | How the blob looks |
| --- | --- | --- |
| RSA PKCS#1 v1.5 | `CryptVerifySignature`, `RSA_verify`, `RSA_verify_bytes` | signature length = modulus length (256 bytes for RSA-2048) |
| RSA-PSS | `RSA_verify` with `RSA_PKCS1_PSS_PADDING`, `EVP_DigestVerify` with PSS padding | same length, randomised salt |
| ECDSA P-256/P-384 | `ECDSA_verify`, `d2i_EC_PUBKEY`, `BCRYPT_ECCPUBLIC_BLOB` | DER `SEQUENCE { INTEGER r, INTEGER s }`, typically 70-72 bytes |
| Ed25519 | `EVP_DigestVerify` with `EVP_PKEY_ED25519`, `Ed25519_verify` | 64 bytes, fixed |

**Public key location.** Look for the DER SubjectPublicKeyInfo prefix. The bytes are
architecture independent:

| Key | SPKI DER prefix (spaced lowercase hex) | Total length |
| --- | --- | --- |
| RSA-2048 | `30 82 01 22 30 0d 06 09 2a 86 48 86 f7 0d 01 01 01 05 00 04 82 01 0f 30 82 01 0a 02 82 01 01 00` | 294 bytes |
| Ed25519 | `30 2a 30 05 06 03 2b 65 70 03 21 00` | 44 bytes |
| EC P-256 | `30 59 30 13 06 07 2a 86 48 ce 3d 02 01 06 08 2a 86 48 ce 3d 03 01 07 03 42 00` | 91 bytes |

Common homes:

- **Windows PE**: `.rdata` of the main executable or of a helper DLL; a `.rsrc` resource;
  a `vendor.pub` / `license.pub` file next to the executable; embedded in the Authenticode
  certificate table of a signed driver (then the licence check is `WinVerifyTrust`).
- **macOS**: a Mach-O `__DATA_CONST` section, `Contents/Resources/` of the bundle, or a
  `SecKeyCreateWithData` call fed by a blob in `__TEXT,__const`.
- **Linux ELF**: `.rodata` of the executable or of a bundled `libcrypto`; `/etc/<vendor>/pub.pem`.
- **Android**: `assets/pubkey.der`, `res/raw/pubkey.pem`, or a blob inside `libnative.so`.
- **.NET**: the assembly's own `PublicKey` metadata entry (a public key *token*, not the key
  material), or an RSA blob built at runtime from `RSAParameters`.

**Error text.** `Signature verification failed`, `Invalid signature`, `License blob has been
tampered with`, `errSecVerifyFailed` (-67808), `STATUS_INVALID_SIGNATURE` (0xC000000D),
`CryptVerifySignature failed: 0x8009000d`.

## Method

### Step 1 — Find the verification call and its caller

```bash
r2 -q -c 'aaa; axt @ sym.imp.BCryptVerifySignature' target.exe
r2 -q -c 'aaa; axt @ sym.imp.CryptVerifySignature' target.exe
r2 -q -c 'aaa; axt @ sym.imp.EVP_DigestVerifyFinal' target.exe
```

Note that the verifier is rarely the decision point. The caller usually does:

1. parse the blob into fields,
2. call the verifier,
3. branch on the result.

So the blob parser must also be understood. Dump the caller:

```bash
r2 -q -c 'aaa; s 0x140002100; pdf' target.exe
```

### Step 2 — Extract the public key

Locate the DER blob by its ASN.1 header and dump it:

```bash
# locate the RSA-2048 SPKI prefix
r2 -q -c '/x 30820122300d06092a864886f70d0101010500' target.exe

# dump 294 bytes starting at the hit
r2 -q -c 'px 294 @ 0x140003c40' target.exe > /tmp/spki.hex
python3 - <<'PY'
import binascii
raw = open("/tmp/spki.hex").read().split()
open("/tmp/pub.der","wb").write(binascii.unhexlify("".join(raw)))
print(len(raw), "bytes")
PY
```

Or, for a PEM file shipped with the app:

```bash
openssl x509 -inform DER -in vendor.der -pubkey -noout > pub.pem
openssl pkey -pubin -inform DER -in vendor.der -text -noout
openssl asn1parse -inform DER -in vendor.der
```

An EC public key on the wire is often the raw uncompressed point (`04` + 64 bytes for P-256),
not SPKI. Wrap it before use:

```bash
python3 - <<'PY'
# build an SPKI for an uncompressed P-256 point
point = bytes.fromhex("04" + "11"*64)
prefix = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")
der = prefix + point
# prepend the length for the outer SEQUENCE (0x59 = 89)
open("ecpub.der","wb").write(der)
print(len(der))
PY
openssl pkey -pubin -inform DER -in ecpub.der -text -noout
```

### Step 3 — Route (a): forge a licence and swap the public key

**3a. Confirm the algorithm.** The blob format usually names the algorithm, or the code
selects it. With `openssl asn1parse` and a known-good blob, the signature length reveals it:
256 bytes → RSA-2048, 64 bytes → Ed25519, 70-72 bytes → ECDSA P-256.

**3b. Generate a replacement key pair.**

```bash
# RSA-2048
openssl genrsa -out my.key 2048
openssl rsa -in my.key -pubout -outform DER -out my_pub.der

# Ed25519
openssl genpkey -algorithm ED25519 -out my_ed.key
openssl pkey -in my_ed.key -pubout -outform DER -out my_ed_pub.der

# ECDSA P-256
openssl ecparam -name prime256v1 -genkey -noout -out my_ec.key
openssl pkey -in my_ec.key -pubout -outform DER -out my_ec_pub.der
```

**3c. Reproduce the signed payload.** The payload is usually a canonical serialisation
(`key=value` lines, a JSON blob, a licence struct). The exact byte layout matters; compare
against a blob the app accepts. Rebuild it byte for byte.

```bash
# RSA PKCS#1 v1.5 over SHA-256
openssl dgst -sha256 -sign my.key -out sig.bin payload.bin

# RSA PSS over SHA-256
openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 \
        -sign my.key -out sig_pss.bin payload.bin

# Ed25519 (raw message, no pre-hash)
openssl pkeyutl -sign -inkey my_ed.key -rawin -in payload.bin -out sig_ed.bin

# ECDSA P-256 (DER signature)
openssl dgst -sha256 -sign my_ec.key -out sig_ec.bin payload.bin
```

**3d. Swap the embedded public key.** The replacement must be the same length as the
original, otherwise the blob offsets move.

```python
# swap_key.py — replace the embedded SPKI with your own, same length
import lief, sys

binary = sys.argv[1]
vaddr  = int(sys.argv[2], 16)     # virtual address of the original SPKI
new    = open("my_pub.der", "rb").read()

pe = lief.parse(binary)
match = None
for section in pe.sections:
    if section.virtual_address <= vaddr < section.virtual_address + section.size:
        match = section
        break
if match is None:
    sys.exit("virtual address not inside any section")
offset = vaddr - match.virtual_address
old = bytes(match.content[offset:offset + len(new)])
if len(old) != len(new):
    sys.exit("length mismatch: %d vs %d" % (len(old), len(new)))
content = bytearray(match.content)
content[offset:offset + len(new)] = new
match.content = bytes(content)
pe.write("target_patched.exe")
print("patched %s at VA 0x%x" % (binary, vaddr))
```

LIEF 1.0.0 exposes `section.content` for PE and Mach-O; `patch_address()` exists on the PE
and Mach-O surfaces and is the direct alternative when the blob sits in a mapped section.
Re-sign after the change (see [Pitfalls](#pitfalls)).

**3e. Rebuild the licence file.** Concatenate the payload, the signature and any header in
the original field order, with the original lengths or length prefixes. Compare byte for byte
against a blob the app accepted, using the length fields to confirm the layout.

### Step 4 — Route (b): force the verification to succeed

Two mechanisms: a static patch inside the application, or a runtime hook.

#### 4a. Static patch of the in-binary decision

The usual x64 shape after a verifier returns a boolean:

```asm
0x140002150  call qword [rip+0x2b30]       ; BCryptVerifySignature / CryptVerifySignature
0x140002157  test eax, eax
0x140002159  je   0x140002190                ; success path
0x14000215b  mov  edi, 0x1                  ; failure path: "invalid signature"
```

Patch the conditional jump so the success path is always taken. `0F 84` (`JE` rel32) becomes
`0F 85` (`JNE` rel32) — invert the sense of the branch:

```
0F 84 40 00 00 00   ->   0F 85 40 00 00 00
```

When the verifier's own result is materialised with `setne`/`sete`, replace the byte sequence
directly:

```asm
0x140002150  mov  eax, 1
0x140002155  ...
0x140002158  cmp  eax, 1
0x14000215b  setne al                      ; 0F 95 C0
0x14000215e  movzx eax, al                 ; 0F B6 C0
0x140002161  test al, al                   ; 84 C0
0x140002163  je   0x140002180
```

The three-byte replacement `0F 95 C0` → `B0 01 C3` forces the function to return `1`
immediately:

```
0F 95 C0   ->   B0 01 C3      ; mov al, 1 ; ret
```

`B0 01 C3` is only safe when the `setne` is in the function's epilogue and the return
convention is `al`. When the function still has to restore the stack, use
`B0 01 90` (`mov al, 1` / `nop`) so control flow continues through the normal epilogue:

```
0F 95 C0   ->   B0 01 90
```

Other encodings seen in the wild:

| Original | Bytes | Replacement | Effect |
| --- | --- | --- | --- |
| `setne al` | `0F 95 C0` | `B0 01 90` | always "not equal" |
| `sete al` | `0F 94 C0` | `B0 01 90` | always "equal" |
| `movzx eax, al` after `test al, al` | `0F B6 C0` | `B0 01 90` | force the byte to 1 |
| `test al, al` + `je` | `84 C0` | `B1 01 90` | always "equal" → `al` = 1 |
| `je short` (rel8) | `74 xx` | `EB xx` | always jump |
| `jne short` (rel8) | `75 xx` | `74 xx` | invert |

ARM64 equivalents:

| Original | Bytes | Replacement | Effect |
| --- | --- | --- | --- |
| `cset w0, ne` | `1A 9F 40 1A` | `20 00 80 52 C0 03 5F D6` | `mov w0, #1` ; `ret` |
| `cset w0, eq` | `AA 9F 40 1A` | `20 00 80 52 C0 03 5F D6` | `mov w0, #1` ; `ret` |
| `tbz w0, #0, label` | `36 00 00 34` | `1F 20 03 D5` | `NOP` |

Verify a candidate patch against the original bytes before writing:

```bash
r2 -q -c '/x 0f95c0' target.exe
r2 -q -c 'px 16 @ 0x140002150' target.exe
```

#### 4b. Runtime hook with Frida 17

The reliable route when the verifier lives in a system library (`bcrypt.dll`, `wintrust.dll`,
`libcrypto`, `Security.framework`) that cannot be patched on disk.

```javascript
// force_verify.js — Frida 17.x
//   frida -f target.exe -l force_verify.js
//
// The success value differs per API. Set SUCCESS to the value the API uses.
const SUCCESS = ptr(1);   // BOOL / bool / int: 1 ; NTSTATUS / OSStatus: 0

function hook(moduleName, exportName, success) {
  let mod;
  try {
    mod = Process.getModuleByName(moduleName);
  } catch (e) {
    console.log("[!] module not loaded: " + moduleName);
    return;
  }
  const fn = mod.getExportByName(exportName);
  Interceptor.attach(fn, {
    onEnter(args) {
      this.hit = (this.hit || 0) + 1;
      if (this.hit < 5) {
        console.log("[hook] " + exportName + " hit #" + this.hit);
      }
    },
    onLeave(retval) {
      retval.replace(success);
    }
  });
  console.log("[+] hooked " + moduleName + "!" + exportName);
}

// Windows
hook("bcrypt.dll", "BCryptVerifySignature", ptr(0));        // NTSTATUS: STATUS_SUCCESS = 0
hook("crypt32.dll", "CryptVerifySignature", ptr(1));         // BOOL: TRUE = 1
hook("wintrust.dll", "WinVerifyTrust", ptr(0));              // LONG: S_OK = 0

// Linux / macOS with OpenSSL
hook("libcrypto.so.3", "EVP_DigestVerifyFinal", ptr(1));     // int: 1 = success
hook("libcrypto.so.3", "EVP_DigestVerify", ptr(1));          // int: 1 = success

// macOS Security.framework
hook("libSystem.B.dylib", "SecKeyVerifySignature", ptr(0));  // OSStatus: errSecSuccess = 0
```

`Interceptor.replace` is the alternative when the caller uses the return value directly and
the hook overhead matters:

```javascript
// replace_verify.js — Frida 17.x, returns 1 for a BOOL/bool API
const target = Process.getModuleByName("bcrypt.dll").getExportByName("BCryptVerifySignature");
const fake = new NativeCallback(function (hKey, padInfo, sig, sigLen, hash, hashLen, flags) {
  console.log("[fake] BCryptVerifySignature called, forcing success");
  return ptr(0);          // NTSTATUS STATUS_SUCCESS
}, "pointer", ["pointer", "pointer", "pointer", "uint32", "pointer", "uint32", "uint32"]);
Interceptor.replace(target, fake);
```

**Java.** Since Frida 17.0.0 the Java bridge is a separate package. Install it and bundle
with `frida-compile`:

```bash
npm install frida-java-bridge
frida-compile verify.java.ts -o verify.js
```

```typescript
// verify.java.ts
Java.perform(() => {
  const Signature = Java.use("java.security.Signature");
  Signature.verify.overload("[B").implementation = function (sig: Java.array('byte')) {
    console.log("[java] Signature.verify forced to true");
    return true;
  };
});
```

**.NET.** Patch the managed method directly in dnSpyEx 6.6.0: decompile the class, replace
the body of `VerifyData` with `return true;`, then rebuild. For `System.Security.Cryptography.RSA`
the target is `VerifyData(byte[], byte[], HashAlgorithmName, RSASignaturePadding)`;
for `System.Security.Cryptography.ECDsa` it is `VerifyData(byte[], byte[], HashAlgorithmName)`.
An IL-level equivalent of the native patch is to insert `ldc.i4.1; ret` in front of the
existing body.

**Apple `SecKeyVerifySignature` inside a Swift/ObjC app.** The C API is still the boundary;
hook `libSystem.B.dylib` as above. If the app uses `SecTrustEvaluateWithError` for a
self-signed certificate, that is a different check and is covered in
[Licence server protocol analysis](license-server-protocol-analysis.md).

### Step 5 — Confirm the decision point is reached

A patch that never executes produces no symptom. Confirm the hook fires:

```
[hook] BCryptVerifySignature hit #1
```

If the counter stays at zero, the app uses a different path: a statically linked crypto
library (no import to hook), an inlined verification routine, or the check runs in a separate
process or service. For statically linked OpenSSL, locate the routine by its string constants
or by the constant-time comparison loop and patch that instead.

## Variations

**Static OpenSSL with no dynamic symbols.** When `EVP_DigestVerifyFinal` is not in the import
table, the code was linked statically. Locate the function by the constant-time comparison
pattern or by the error string `digital signature routines: signature verification failure`:

```bash
r2 -q -c 'izz~signature verification failure' target.exe
r2 -q -c 'aaa; axt @@ str.*_signature_verification_failure' target.exe
```

**Windows Authenticode / `WinVerifyTrust`.** The check validates a signed file rather than a
licence blob. `WinVerifyTrust` lives in `wintrust.dll`, which is Windows Resource Protection
protected — do not patch it on disk. Use the runtime hook, or patch the *caller's* branch in
the application binary.

**Self-signed certificate chains.** Some products ship a certificate whose public key is also
embedded, and the licence is a signed file. The same forge-and-swap applies, but the new
certificate must also satisfy a chain: build it with `openssl x509` and set the CA flag so
the embedded root validates it.

**Java/JAR signing.** `java.security.Signature.verify` is called from many places. Narrow with
a stack filter before forcing the result:

```javascript
Java.perform(() => {
  const Signature = Java.use("java.security.Signature");
  Signature.verify.overload("[B").implementation = function (sig) {
    const st = Java.use("android.util.Log");
    st.e("licence", Java.use("java.lang.Exception").$stackTrace());
    return true;
  };
});
```

**Native iOS frameworks.** `SecKeyVerifySignature` is in `libSystem.B.dylib` on macOS and in
the `Security.framework` binary on iOS. On iOS, hook the Security framework's export via
`Process.enumerateModules()` and match on the path containing `/System/Library/Frameworks/Security.framework`.

**Hardware-bound signatures.** When the signature covers a machine fingerprint as well as the
payload, forging requires the same fingerprint the app collects. Combine with
[Hardware fingerprint binding](hardware-fingerprint-binding.md) and
[Offline activation and machine binding](offline-activation-and-machine-binding.md).

## Verification

1. **Signature-level check.** Verify the forged blob independently with OpenSSL:

   ```bash
   openssl dgst -sha256 -verify pub.pem -signature sig.bin payload.bin
   # Expected: "Verified OK"
   ```

   For PSS add `-sigopt rsa_padding_mode:pss`; for Ed25519 use
   `openssl pkeyutl -verify -inkey pub.pem -rawin -in payload.bin -sigfile sig.bin`.

2. **Positive test in the app.** Load the forged licence and confirm the licensed state
   appears: no expiry dialog, features unlocked, `about` box shows the licence as valid.
3. **Negative test — the patched check is really gone.** Replace the forged blob with a
   deliberately corrupted one (flip one byte in the signature) and confirm the app *still*
   accepts it. If it rejects the corrupted blob, the patch is not in force and the app
   validated the signature somewhere else — most likely in a second copy of the verifier or
   in a helper service.
4. **Negative test — the swapped key is the one in use.** Remove the forged licence and
   confirm the app returns to the unlicensed state, then re-add it and confirm it returns to
   the licensed state. A file that is cached but never re-verified is a false positive.
5. **Restart test.** Restart the process and re-check. A patch that only survives in memory
   is not a patch; a forged key that only survives until the next licence re-download is not
   a licence.
6. **Other-licence test.** Load a second, unrelated licence blob (from the vendor's real
   serial or a random blob) and confirm the acceptance criteria differ. A patch that accepts
   everything indicates the check was removed rather than satisfied.

## Pitfalls

- **Success value mismatch.** `BCryptVerifySignature` returns `NTSTATUS` (success = 0) while
  `CryptVerifySignature` returns `BOOL` (success = 1). Forcing `1` on an `NTSTATUS` API
  produces `STATUS_UNSUCCESSFUL` and the app still rejects. Read the return convention in the
  SDK header before patching.
- **`WinVerifyTrust` in a system DLL.** Patching `wintrust.dll` on disk breaks Windows
  Resource Protection. Use the runtime hook or patch the caller.
- **Signed container.** Modifying a Mach-O invalidates the code signature and the loader
  refuses to run it; re-sign with `codesign --force --deep --sign - <app>`. Modifying a PE
  invalidates Authenticode (the app still runs, but the signature check fails elsewhere);
  re-sign with `signtool sign /fd SHA256 /tr ...`. Modifying an APK invalidates the v2/v3
  signature; re-sign with `apksigner sign --ks key.jks ...` and `zipalign` first.
- **Embedded key length mismatch.** A different key size changes the blob length and shifts
  every offset after it. Match the original length exactly, or rebuild the container.
- **Payload canonicalisation.** Many apps hash a re-serialised structure (sorted key/value
  lines, JSON with fixed separators, a struct with fixed field order), not the raw file. Hash
  the same bytes the app hashes.
- **Two verification sites.** The GUI validates, and a service or an update check validates
  again with a different key. A forged key in the executable does not affect the service.
- **Timestamp / anti-rollback fields.** A blob with a `not-before` timestamp is refused if the
  system clock is earlier. Set the timestamp inside the valid window.
- **Hooking the wrong thread of control.** `Interceptor.attach` on a function that is called
  during early initialisation before the agent attaches misses the first call. Use
  `frida -f ...` (spawn, not attach) and hook libraries that are already loaded.
- **Overwriting `retval` on a non-scalar return.** `retval.replace(ptr(1))` writes 8 bytes;
  on a `BOOL` return that is fine, but do not use it on a struct-returning API.

## References

- Microsoft Cryptography API: `CryptVerifySignature`, `BCryptVerifySignature`,
  `WinVerifyTrust` — <https://learn.microsoft.com/windows/win32/api/wincrypt/>
  and <https://learn.microsoft.com/windows/win32/api/bcrypt/>
- Apple `SecKeyVerifySignature` — <https://developer.apple.com/documentation/security/1402396-seckeyverifysignature>
- OpenSSL 3.x `EVP_DigestVerify` family — <https://docs.openssl.org/3.0/man7/EVP_PKEY-SIGCTX/>
- RFC 8017 (PKCS #1 v2.2) and RFC 8032 (Ed25519) —
  <https://www.rfc-editor.org/rfc/rfc8017> , <https://www.rfc-editor.org/rfc/rfc8032>
- FIPS 186-4 (DSA/ECDSA) — <https://csrc.nist.gov/publications/detail/fips/186/4/final>
- Frida 17.x `Interceptor` API — <https://frida.re/docs/javascript-api/#interceptor>
- LIEF 1.0.0 section manipulation — <https://lief.re/doc/latest/>
- Sibling entries: [Serial validation algorithm recovery](serial-validation-algorithm-recovery.md),
  [Symmetric licence blob formats](symmetric-license-blob-formats.md),
  [Offline activation and machine binding](offline-activation-and-machine-binding.md)
