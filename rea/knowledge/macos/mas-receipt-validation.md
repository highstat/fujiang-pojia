---
id: "mas-receipt-validation"
title: "Mac App Store receipt validation"
domain: "macos"
kind: "technique"
platforms: "macos"
arch: "x86-64, arm64"
difficulty: "advanced"
tools: "codesign,r2,frida,openssl,otool"
verified: false
updated: "2026-11-15"
summary: "Describes where the Mac App Store receipt lives and how an app validates it locally, lists the observable refusal symptoms, and gives three routes to a validated state — supplying a structurally valid receipt file, patching the receipt read path, and forcing the validation result to success — with the exact ARM64 and x86_64 byte encodings and a Frida hook on SecStaticCodeCheckValidityWithErrors."
---

## Summary

A store build carries a signed receipt that the app checks before it enables purchased features.
The check has two halves: the receipt file must exist at a known path, and it must validate
cryptographically against Apple's chain. This entry describes both halves, the symptoms of a
missing or invalid receipt, and three routes to a validated state, each with the exact bytes or
commands. Reach for it when a store build refuses to start, shows an empty feature list, or prints
a receipt error.

## Recognition

- `Contents/_MASReceipt/receipt` exists in the bundle of a Mac App Store build and is absent from a
  Developer ID build.
- `codesign -d --entitlements - Foo.app` shows `com.apple.security.app-sandbox` set to `true` for a
  store build, and the bundle identifier carries a numeric suffix group typical of the store.
- At launch the app either exits immediately, shows a modal dialog reading
  `This application is not licensed.` / `Unable to validate the receipt.`, or starts with the
  purchased feature list empty and the premium entries greyed out.
- `SKReceiptRefreshRequest` fails with `SKError.paymentNotAllowed` or the app logs
  `receipt refresh failed` / `receipt is invalid`.
- `NSBundle.appStoreReceiptURL` returns `nil`, which the app turns into an immediate failure path.
- In the disassembly, the receipt path appears as the literal
  `Contents/_MASReceipt/receipt` or as the string `receipt` next to a call to
  `-[NSBundle appStoreReceiptURL]`.
- The binary imports `SecStaticCodeCheckValidityWithErrors`, `SecStaticCodeCheckValidity` or
  `SecCodeCheckValidity` from `/System/Library/Frameworks/Security.framework`.

## Method

### 1. Confirm the build type and locate the receipt

```bash
cd /path/to/Foo.app
ls -la Contents/_MASReceipt/ 2>/dev/null
file Contents/_MASReceipt/receipt 2>/dev/null
openssl pkcs7 -inform DER -in Contents/_MASReceipt/receipt -print_certs -noout 2>&1 | head -20
```

Expected: the receipt is a DER-encoded PKCS#7 SignedData container; `openssl pkcs7` prints the
certificate chain (Apple Worldwide Developer Relations and the Apple Mac Store Application
signing intermediates).

```bash
codesign -d --entitlements - Contents/MacOS/Foo 2>&1 | grep -A1 'app-sandbox'
codesign -dvvv Contents/MacOS/Foo 2>&1 | grep -E 'flags=|Identifier='
```

### 2. Map the receipt read path

```bash
otool -L Contents/MacOS/Foo | grep -i security
strings -a -t x Contents/MacOS/Foo | grep -iE 'MASReceipt|appStoreReceipt|receipt'
```

The literal `Contents/_MASReceipt/receipt` or the selector `appStoreReceiptURL` is the anchor. Some
older builds also look in the user container at
`~/Library/Application Support/<bundle-id>/.com.apple.appstore.receipt`; check both paths when
instrumenting.

```bash
ls -la ~/Library/Application\ Support/ 2>/dev/null | grep -i "$(plutil -extract CFBundleIdentifier raw -o - Contents/Info.plist)"
```

### 3. Find the validation call and its result

```bash
r2 -qc 'aaa; ii~SecStaticCode' Contents/MacOS/Foo
r2 -qc 'aaa; axt @@ sym.imp.SecStaticCodeCheckValidityWithErrors' Contents/MacOS/Foo
```

Expected: one or two call sites. Read each:

```bash
r2 -qc 'aaa; s 0xADDR; pdf' Contents/MacOS/Foo
```

The shape of a local receipt check is:

1. obtain the receipt URL,
2. test that the file exists,
3. create a `SecStaticCodeRef` from it,
4. call `SecStaticCodeCheckValidityWithErrors` and read the returned `OSStatus`,
5. branch on `errSecSuccess` (`0`) versus anything else.

Step 4 is the decision point: the return value lands in `w0` (ARM64) or `eax` (x86_64).

### 4. Route (a): supply a structurally valid receipt file

If the app only checks for the presence and the parseability of the receipt, a well-formed
container is enough. Build one:

```bash
mkdir -p /tmp/masreceipt && cd /tmp/masreceipt
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 365 \
  -subj "/CN=Local Receipt" 2>/dev/null
cat > payload.txt <<'EOF'
receipt
EOF
openssl smime -sign -in payload.txt -out receipt.p7s -signer cert.pem -inkey key.pem \
  -outform DER -nodetach -noattr 2>/dev/null
```

Install it into a copy of the bundle:

```bash
cd /path/to
cp -R Foo.app Foo.patched.app
mkdir -p Foo.patched.app/Contents/_MASReceipt
cp /tmp/masreceipt/receipt.p7s Foo.patched.app/Contents/_MASReceipt/receipt
codesign --force --sign - --timestamp=none Foo.patched.app
```

Expected: the presence check passes and the app proceeds past the launch-time refusal. A
cryptographic check still fails, because the Apple chain is absent; the failure moves from the
launch-time gate to the point where the app parses the receipt contents.

### 5. Route (b): patch the code path that reads the receipt

Two sub-cases.

Sub-case b1 — the presence test. Find the branch that follows the existence check and flip it:

```bash
r2 -qc 'aaa; /x 48000000' Contents/MacOS/Foo   # cbz x0, <addr>  (ARM64)
r2 -qc 'aaa; axt @@ str.MASReceipt' Contents/MacOS/Foo
```

Flip the ARM64 conditional branch:

```
0b 40 00 00 00   ->   1b 40 00 00 00     cbnz x0, <addr>  ->  cbnz negated to b
```

The exact pair of encodings depends on the branch; the general rule is that `CBZ` (`0b`),
`CBNZ` (`1b`) and `TBZ` (`36`) become their unconditional counterparts `B` (`14`), and `CMP` plus
`B.EQ` becomes `B.NE`.

Sub-case b2 — the receipt lookup itself. Patch the call that returns the receipt URL so it always
returns a valid path. On ARM64 a `BL` instruction is `94 xx xx xx`; replacing it with `MOV X0, #0`
plus `RET` (`00 00 80 d2` + `c0 03 5f d6`) makes the function return `nil`, which is the opposite
of what is wanted — use route (c) instead, which is more reliable.

### 6. Route (c): force the validation result to success

This is the smallest change: one return value.

ARM64 — the `OSStatus` is returned in `w0`. `mov w0, #0` is `MOVZ W0, #0, LSL #0`, encoded
`0x52800000`, little-endian bytes `00 00 80 52`. `mov w0, #1` is `0x52800020`, bytes
`20 00 80 52`.

```
00 00 80 52   ->   20 00 80 52     mov w0, #0  ->  mov w0, #1
```

Locate the site and patch it in place:

```bash
r2 -qc 'aaa; s 0xADDR; pd 3' Contents/MacOS/Foo
r2 -qc 'aaa; s 0xADDR; wx 20008052' Contents/MacOS/Foo
```

x86_64 — the `OSStatus` is returned in `eax`. `mov eax, 0` is `b8 00 00 00 00`; `mov eax, 1` is
`b8 01 00 00 00`.

```
b8 00 00 00 00   ->   b8 01 00 00 00
```

Verify the encoding before writing it:

```bash
python3 - <<'PY'
import struct
print("arm64 mov w0,#0 ->", struct.pack("<I", 0x52800000).hex(" "))
print("arm64 mov w0,#1 ->", struct.pack("<I", 0x52800020).hex(" "))
print("x86_64 mov eax,0 ->", struct.pack("<B", 0xB8) + struct.pack("<I", 0).hex(" "))
print("x86_64 mov eax,1 ->", struct.pack("<B", 0xB8) + struct.pack("<I", 1).hex(" "))
PY
```

Expected output:

```text
arm64 mov w0,#0 -> 00 00 80 52
arm64 mov w0,#1 -> 20 00 80 52
x86_64 mov eax,0 -> b8 00 00 00 00
x86_64 mov eax,1 -> b8 01 00 00 00
```

After patching the executable, the signature is invalid; re-sign the bundle:

```bash
codesign --force --sign - --timestamp=none Contents/MacOS/Foo
codesign --force --sign - --timestamp=none Foo.app
codesign -v --deep --strict --verbose=4 Foo.app
```

### 7. Route (c′): the runtime variant with Frida

Intercepting the validation call avoids modifying the binary at all. Frida 17.x removed the static
`Module.getExportByName`; use `Module.getGlobalExportByName`:

```javascript
// mas-receipt.js — Frida 17.x
const STATUS = { errSecSuccess: 0, errSecCSReq: -67050, errSecInvalidCSReq: -67061 };

function patch(name) {
  let addr;
  try {
    addr = Module.getGlobalExportByName(name);
  } catch (e) {
    console.log(`[mas] ${name} not found: ${e.message}`);
    return;
  }
  Interceptor.attach(addr, {
    onEnter(args) {
      console.log(`[mas] ${name}(${args[0]}, ${args[1]})`);
    },
    onLeave(retval) {
      console.log(`[mas] ${name} -> 0x${retval.toString(16)}`);
      retval.replace(STATUS.errSecSuccess);
    }
  });
}

patch('SecStaticCodeCheckValidityWithErrors');
patch('SecStaticCodeCheckValidity');
patch('SecCodeCheckValidity');
```

```bash
frida -f /path/to/Foo.app/Contents/MacOS/Foo -l mas-receipt.js
```

`SecStaticCodeCheckValidityWithErrors` writes a `CFErrorRef` into its third argument. Forcing the
status to `errSecSuccess` while the error out-parameter stays populated is fine for a gate that
only reads the status; if the app reads the error object, clear it as well:

```javascript
const objc = Process.getModuleByName('libobjc');
objc.ensureInitialized();
const ObjCNull = new ObjC.Object(ptr('0'));
```

A simpler variant that intercepts at the caller boundary is to hook the Objective-C wrapper:

```javascript
const nsBundle = Process.getModuleByName('Foundation');
nsBundle.ensureInitialized();
Interceptor.attach(Module.getGlobalExportByName('-[NSBundle appStoreReceiptURL]'), {
  onLeave(retval) { console.log('[mas] appStoreReceiptURL ->', retval); }
});
```

### 8. Record the patch

Note the exact file offset of the patched byte sequence, the original bytes, the new bytes and the
function that was changed. A patch without that record has no rollback.

```bash
r2 -qc 'aaa; s 0xADDR; p8 4' Contents/MacOS/Foo
```

## Variations

- **ARM64 vs x86_64.** The patch shape differs by one byte class and the register name: `w0` on
  ARM64, `eax` on x86_64. A universal binary needs both slices patched. Work on one slice with
  `lipo -thin arm64 -output Foo.arm64 Foo` and `lipo -thin x86_64 -output Foo.x64 Foo`.
- **Return type variations.** Some apps wrap the status in a `BOOL` or an `NSError**` out-parameter
  and return `0` for failure. Inspect the disassembly around the call and patch the value the
  caller actually reads.
- **Inlining.** The compiler may inline the status comparison, so no `call` to
  `SecStaticCodeCheckValidityWithErrors` exists in the disassembly. Search for the *import* entry
  and for the surrounding `cmp`/`b.ne` pair instead, or look for the literal `0` compared against
  a register right after a call into Security.
- **StoreKit-side validation.** An app that validates the receipt against Apple's
  `verifyReceipt` endpoint does not depend on the local file at all. The patch point moves to the
  JSON response handler: patch the `BOOL` that says "the server said yes".
- **Windows Store / Play Store analogues.** The Play Store equivalent is the `BillingClient`
  purchase token plus `PackageManager` signature verification, handled by Google's Play Services
  library inside the APK. The Windows Store equivalent is the `Windows.ApplicationModel.Store`
  licence file, a JSON document at `%ProgramFiles%\WindowsApps\<pkg>\AppxManifest.xml` metadata.
- **Non-store builds.** A Developer ID build has no `_MASReceipt` directory and no receipt check; a
  licence error there comes from a vendor server, not from Apple.

## Verification

Positive — the receipt path is now satisfied:

```bash
codesign -v --deep --strict --verbose=4 Foo.app ; echo "exit=$?"
r2 -qc 'aaa; s 0xADDR; p8 4' Contents/MacOS/Foo
```

Expected: `exit=0` and the patched bytes `20 00 80 52` (ARM64) or `b8 01 00 00 00` (x86_64) at the
patched address.

Negative — the check is really gone, not merely cached. Remove every piece of receipt state and
re-run:

```bash
rm -f ~/Library/Application\ Support/<bundle-id>/.com.apple.appstore.receipt
rm -rf ~/Library/Caches/<bundle-id>
mv Foo.app/Contents/_MASReceipt/receipt /tmp/receipt.bak   # for route (b)/(c)
./Contents/MacOS/Foo
```

Expected: the app still starts and the purchased features are still enabled. Then restore the
receipt and confirm the failure comes back, which proves the patch was the operative change:

```bash
mv /tmp/receipt.bak Foo.app/Contents/_MASReceipt/receipt
cp Foo.app/Contents/MacOS/Foo /tmp/Foo.patched.bin
codesign --force --sign - --timestamp=none Foo.app
```

For the Frida route, the negative test is to detach the agent: the app must fail again. If it keeps
working, the licence state was cached on disk and the hook proved nothing.

## Pitfalls

- The receipt file is covered by the bundle seal. Replacing it without re-signing gives
  `a sealed resource is missing or invalid` and the app never launches.
- A fabricated PKCS#7 container satisfies a presence check but fails a cryptographic one. Do not
  read a successful launch as proof that validation was bypassed.
- `SecStaticCodeCheckValidityWithErrors` reports through `CFErrorRef` as well as the status. Forcing
  only the status can leave a non-null error pointer that the app later dereferences.
- The `OSStatus` value `0` is `errSecSuccess`. Other `errSecCS*` values are negative and are easy
  to confuse with a "false" boolean.
- On modern macOS, Security.framework lives in the shared dyld cache. `Module.getGlobalExportByName`
  still resolves it, but a Frida script that enumerates modules by path will not find it.
- `openssl pkcs7 -inform DER` fails on a receipt that uses an unusual encoding. Use
  `openssl asn1parse -inform DER -in receipt` to inspect the raw structure instead.
- The receipt path is relative to the bundle; a bundle copied to another location changes the
  resolved path, and some apps additionally look beside the executable.
- A store build is sandboxed. Writing to `Contents/_MASReceipt/` inside `/Applications` requires
  elevation, and the modification must be made on a copy in a writable location.
- The `receipt` file is also the app's own tamper target. Some builds verify the receipt against a
  hash stored elsewhere in the bundle, which moves the failure to that comparison.

## References

- Apple, *Receipt Validation* and *Validating Purchases* (developer.apple.com, App Store
  documentation)
- Apple, *StoreKit Programming Guide* and the *Receipt Validation* documentation for
  `SKPaymentQueue` and `SKReceiptRefreshRequest`
- `man 3 SecStaticCodeCheckValidityWithErrors`, `man 3 SecCodeCheckValidity` — Security framework
- Apple, *Code Signing Guide* for the `CodeResources` seal covering `Contents/_MASReceipt/receipt`
- Sibling entries: `app-bundle-analysis.md`, `codesign-and-entitlements.md`,
  `hardened-runtime-and-library-validation.md`
