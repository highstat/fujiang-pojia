---
id: "checksum-and-integrity-repair"
title: "Checksum and integrity repair after patching"
domain: "native-core"
kind: "playbook-ref"
platforms: "-"
arch: "-"
difficulty: "advanced"
tools: "python3, LIEF, codesign, ldid, apksigner, zipalign, signtool, osslsigncode, readelf"
verified: false
updated: "2026-11-15"
summary: "Repairs the integrity structures that a byte patch breaks — PE optional header checksum, Authenticode, Mach-O code signatures, ELF build-ids, DEX checksums and APK/IPA signatures — and fixes the re-signing order each container demands."
---

## Summary

A patch changes bytes. Every container that carries a digest of those bytes now carries a
stale one, and each container reacts differently: PE recomputes an optional-header checksum,
Authenticode becomes invalid, a Mach-O code signature stops the process from launching, an ELF
build-id starts pointing at the wrong debug file, and an APK fails installation with a
signature mismatch.

This entry gives the repair for each container, the commands that verify the repair, and the
signing order that must be respected.

## Recognition

- `signtool verify /pa target.exe` reports *HashMismatch* or *NotSigned*.
- `codesign --verify --verbose=4 target.macho` reports `invalid signature` or
  `code object is not signed at all`.
- `apksigner verify --verbose app.apk` reports `DOES NOT VERIFY` with
  `ERROR: JAR_SIG_NO_SIG` or `INSTALL_PARSE_FAILED_NO_CERTIFICATES`.
- A Mach-O starts and dies immediately with `Code Signature Invalid` in the system log
  (`log show --predicate 'eventMessage contains "Code Signature"'`).
- `readelf -n target.elf` still shows the original build-id even though the file changed.
- `zipalign -c -v 4 app.apk` reports files that are not aligned, after a rebuild.

## Method

### Part 1 — PE optional header checksum

#### 1.1 Where it lives and when it matters

The checksum is a 4-byte field at optional-header offset `0x40`, i.e. at file offset
`e_lfanew + 24 + 64`. It is **optional for user-mode executables** and **mandatory for
drivers**, where the loader refuses to load a driver whose checksum does not match.

#### 1.2 The algorithm

The value is the `CheckSumMappedFile` algorithm:

1. Treat the file as an array of 16-bit little-endian words. If the file has an odd length, the
   last byte is treated as a word with a zero high byte.
2. Sum all the words, **excluding** the 4 bytes of the checksum field itself.
3. Fold the carry after each addition: `sum = (sum & 0xffff) + (sum >> 16)`.
4. Add the file length.
5. The result is the 32-bit checksum.

```
python3 - <<'PY'
import pathlib, struct, sys

def pe_checksum(path: str) -> int:
    data = pathlib.Path(path).read_bytes()
    e_lfanew = struct.unpack_from("<I", data, 0x3c)[0]
    csum_off = e_lfanew + 24 + 64           # optional header + 64
    total = 0
    size = len(data)
    for i in range(0, size - 1, 2):
        if csum_off <= i < csum_off + 4:
            continue                        # the checksum field is excluded
        total += data[i] | (data[i + 1] << 8)
        total = (total & 0xffff) + (total >> 16)
    if size % 2:
        total += data[-1]
        total = (total & 0xffff) + (total >> 16)
    total = (total & 0xffff) + (total >> 16)
    total += size
    return total & 0xffffffff

p = sys.argv[1] if len(sys.argv) > 1 else "target.exe"
print(hex(pe_checksum(p)))
PY
```

Cross-check the implementation against an independent one before trusting it:

```
python3 -c "import pefile; print(hex(pefile.PE('target.exe').generate_checksum()))"
```

If the two disagree, the fold order or the odd-length handling is wrong. Both must produce the
same value as the checksum stored in an unmodified, signed reference binary.

#### 1.3 Write it back

```
python3 - <<'PY'
import pathlib, struct

def pe_checksum(data: bytes) -> int:
    e_lfanew = struct.unpack_from("<I", data, 0x3c)[0]
    csum_off = e_lfanew + 24 + 64
    total = 0
    size = len(data)
    for i in range(0, size - 1, 2):
        if csum_off <= i < csum_off + 4:
            continue
        total += data[i] | (data[i + 1] << 8)
        total = (total & 0xffff) + (total >> 16)
    if size % 2:
        total += data[-1]
        total = (total & 0xffff) + (total >> 16)
    total = (total & 0xffff) + (total >> 16)
    total += size
    return total & 0xffffffff

p = pathlib.Path("target.exe")
data = bytearray(p.read_bytes())
e_lfanew = struct.unpack_from("<I", data, 0x3c)[0]
csum_off = e_lfanew + 24 + 64
value = pe_checksum(bytes(data))
data[csum_off:csum_off + 4] = struct.pack("<I", value)
p.write_bytes(data)
print(f"checksum at 0x{csum_off:x} set to 0x{value:08x}")
PY
```

Note the order dependency: the checksum covers the file, so write the checksum **last**, after
every other byte is final.

### Part 2 — Authenticode

#### 2.1 What breaks

Authenticode is a signature over a hash of the PE image. The hash covers the whole file except:

- the 4 bytes of the optional-header checksum field, which are hashed as zeros,
- the 8 bytes of the Certificate Table data directory entry, which are hashed as zeros,
- the attribute certificate table itself, which is excluded.

Every other byte — one flipped opcode — changes the hash, and `signtool verify` reports
*HashMismatch*. The file still runs on a machine with no enforcement, but Windows Defender
Application Control, WDAC policies, and SmartScreen react to the invalid signature.

#### 2.2 Where the certificate table is

Data directory index 4, at optional-header offset `0x90` (PE32+) or `0xa0` (PE32). Its
`VirtualAddress` field is a **file offset, not an RVA** — this directory is the one exception to
the RVA rule. It points at an array of `WIN_CERTIFICATE` structures:

```
dwLength          4 bytes   total size of this entry
wRevision         2 bytes   0x0200
wCertificateType  2 bytes   0x0002 = PKCS#7 SignedData
bCertificate      ...       the DER-encoded PKCS#7 blob
```

The table ends at the end of the file.

#### 2.3 Strip the signature

```
python3 - <<'PY'
import pathlib, struct

p = pathlib.Path("target.exe")
data = bytearray(p.read_bytes())
e_lfanew = struct.unpack_from("<I", data, 0x3c)[0]
opt = e_lfanew + 24
magic = struct.unpack_from("<H", data, opt)[0]
dd_base = opt + (0x70 if magic == 0x20b else 0x60)
cert_off = dd_base + 4 * 8
cert_rva, cert_size = struct.unpack_from("<II", data, cert_off)
print(f"certificate table at file offset 0x{cert_rva:x}, size 0x{cert_size:x}")

if cert_rva:
    data[cert_off:cert_off + 8] = b"\x00" * 8     # zero the directory entry
    del data[cert_rva:]                            # drop the certificate bytes
    p.write_bytes(data)
    print("signature stripped")
else:
    print("no certificate table present")
PY
```

Zeroing the directory entry without truncating the file is also accepted by Windows; the
residual bytes are then treated as overlay data. Truncating is cleaner because the file size
changes and the checksum must be recomputed.

LIEF offers the same operation; check the installed API before scripting:

```
python3 - <<'PY'
import lief
b = lief.PE.Binary("target.exe")
print("version", lief.__version__)
print("has_signatures", b.has_signatures)
print([a for a in dir(b) if "sign" in a.lower()])
for s in b.signatures:
    print(s)
PY
```

If `remove_signature` exists in the installed build, call it and write the binary back;
otherwise use the manual method above. Either way, recompute the optional header checksum
afterwards.

#### 2.4 Re-sign

```
# signtool (Windows, requires the cert in a PFX)
signtool sign /fd SHA256 /td SHA256 /tr http://timestamp.digicert.com /f cert.pfx /p pass target.exe

# osslsigncode (cross-platform)
osslsigncode sign -pkcs12 cert.p12 -pass pass -n "Vendor" \
    -i http://timestamp.digicert.com -in target.exe -out target-signed.exe
```

`signtool` updates the optional header checksum as part of signing, so do not recompute it
after signing — recompute before signing.

### Part 3 — Mach-O code signature

#### 3.1 What breaks

Every Mach-O on a modern macOS or iOS carries a code signature. The signature lives in
`LC_CODE_SIGNATURE` (load command `0x1d`), whose `dataoff` and `datasize` point at a
`CS_SuperBlob` in `__LINKEDIT`:

```
CS_SuperBlob   magic 0xfade0cc0, length, count, BlobIndex[]
BlobIndex      type, offset
blob types     0x00000 CodeDirectory, 0x00002 Requirements,
               0x00005 Entitlements, 0x10000 CMS signature (magic 0xfade0b01)
CodeDirectory  magic 0xfade0c02, ..., cdhash, page hashes, special-slot hashes
```

The CodeDirectory stores a hash of every 4 KiB or 16 KiB page of the mapped code, plus special
slots covering the `Info.plist`, the requirements, the entitlements and the CodeDirectory
itself. Editing one byte changes one page hash, and the kernel refuses to execute the image.

#### 3.2 Strip

```
# macOS, removes the LC_CODE_SIGNATURE load command and the blob
codesign --remove-signature target.macho

# optool, same effect
optool uninstall -S target.macho

# LIEF
python3 - <<'PY'
import lief
b = lief.MachO.Binary("target.macho")
print([a for a in dir(b) if "sign" in a.lower()])
print("code signature:", b.code_signature)
b.write("target-unsigned.macho")
PY
```

#### 3.3 Re-sign

```
# ad-hoc signature for macOS
codesign --force --sign - --timestamp=none target.macho

# preserve entitlements
codesign --force --sign - --entitlements entitlements.plist target.macho

# iOS: ad-hoc with ldid, which also writes the entitlements
ldid -Sentitlements.plist target.macho
ldid -S target.macho

# iOS: ad-hoc with codesign (works when the binary is not encrypted)
codesign --force --sign - target.macho
```

For a bundle, sign **inside out**: nested frameworks, then nested dylibs and the main
executable, then the bundle itself.

```
codesign --force --sign - "Payload/App.app/Frameworks/Frame.framework"
codesign --force --sign - "Payload/App.app/Frameworks/Frame.framework/Versions/A/Frame"
codesign --force --sign - "Payload/App.app/App"
codesign --force --sign - "Payload/App.app"
```

`--deep` applies the same identity to everything at once, which usually breaks frameworks that
need their own identity. Prefer explicit, ordered signing.

An encrypted iOS binary (`cryptid 1` in `LC_ENCRYPTION_INFO_64`) must be decrypted before it
can be re-signed; see `elf-pe-macho-layout` for the encryption geometry.

#### 3.4 Repair the load command after size changes

`LC_CODE_SIGNATURE.dataoff` and `datasize` are absolute file offsets. If the patch changed the
file size, the offset moved and the signature is not merely invalid but misplaced, which
produces a different error. Re-signing rebuilds both values, so the order is: patch → strip →
sign.

### Part 4 — ELF build-id

#### 4.1 What it is and what breaks

The build-id is a note in the `.note.gnu.build-id` section, inside a `PT_NOTE` segment:

```
namesz  4 bytes   4
descsz  4 bytes   16 (SHA-1), 8 (MD5) or 32 (SHA-256)
type    4 bytes   3 = NT_GNU_BUILD_ID
name    "GNU\0"
desc    the hash bytes
```

```
readelf -n target.elf
```

```
Displaying notes found in: .note.gnu.build-id
  Owner                Data size 	Description
  GNU                  0x00000010	NT_GNU_BUILD_ID (unique build ID bitstring)
    Build ID: 4a1c9d0f6b8e2c5f7a3b1d9e0c4f8a2b6d3e1c0
```

The loader does **not** validate the build-id, so a patched ELF still runs. What breaks is
tooling: `debuginfod` maps the build-id to a debug file and will hand out the wrong symbols;
`gdb` looking up a separate debug file by build-id will load stale symbols; RPM and DEB
packaging verifies the build-id of the binary against the debug package and fails the check.

#### 4.2 Repair options

**Leave it.** The build-id is meant to identify the *build*, not the file. A patched binary
that claims the original build-id will resolve to the original debug information, which is
misleading during debugging.

**Replace it with a distinct value of the same length.** Replacing the bytes in place keeps the
file size and the segment coverage intact:

```
python3 - <<'PY'
import pathlib, hashlib, struct

p = pathlib.Path("target.elf")
data = bytearray(p.read_bytes())
i = data.find(b"GNU\x00")
if i < 0:
    raise SystemExit("build-id note not found")
namesz, descsz, ntype = struct.unpack_from("<III", data, i - 12)
assert ntype == 3, ntype
desc_off = i + 4
new = hashlib.sha256(bytes(data)).digest()[:descsz]
data[desc_off:desc_off + descsz] = new
p.write_bytes(data)
print(f"build-id replaced at 0x{desc_off:x}, {descsz} bytes")
PY
```

**Remove it.**

```
objcopy --remove-section=.note.gnu.build-id target.elf
```

Removing the section leaves the `PT_NOTE` segment inconsistent on some targets; re-link the
note segment if the toolchain is available.

`patchelf` preserves the build-id; `eu-unstrip` can regenerate a separate debug file with a
matching id:

```
eu-unstrip -o target.debug target.elf
eu-readelf -n target.elf
```

### Part 5 — DEX, APK and IPA

#### 5.1 DEX header digests

The DEX header begins with:

```
offset 0x00  magic       "dex\n035\0" (8 bytes)
offset 0x08  checksum    uint32, Adler-32 of bytes 0x0c .. end of file
offset 0x0c  signature   20 bytes, SHA-1 of bytes 0x20 .. end of file
offset 0x20  file_size   uint32
```

The order matters: the SHA-1 covers the region from `0x20`, and the Adler-32 covers the region
from `0x0c`, which includes the SHA-1 field. So recompute the signature first, then the
checksum.

```
python3 - <<'PY'
import hashlib, pathlib, struct, zlib

p = pathlib.Path("classes.dex")
data = bytearray(p.read_bytes())
data[0x0c:0x20] = hashlib.sha1(bytes(data[0x20:])).digest()
data[0x08:0x0c] = struct.pack("<I", zlib.adler32(bytes(data[0x0c:])) & 0xffffffff)
struct.pack_into("<I", data, 0x20, len(data))
p.write_bytes(data)
print("dex header digests refreshed")
PY
```

Verify with `dexdump` or `baksmali`:

```
dexdump -f classes.dex | head -20
```

Tools that rebuild DEX (`apktool`, `baksmali`/`smali`) recompute both fields automatically.
Patching smali and rebuilding is the supported path; editing `classes.dex` directly is not.

#### 5.2 APK

An APK is a ZIP with three signature schemes:

| Scheme | Where it lives | What it covers |
| --- | --- | --- |
| v1 (JAR) | `META-INF/*.RSA`, `*.SF`, `*.MF` | each ZIP entry individually |
| v2 | the APK Signing Block before the central directory | the whole archive |
| v3 / v3.1 | the signing block, with key-rotation support | the whole archive |

Each ZIP entry carries a CRC-32 in both the local file header and the central directory. A
modified entry needs both CRCs updated, which every real ZIP writer does.

The ordering that must be respected:

1. Patch the payload (`classes.dex`, `lib/*.so`, resources).
2. Rebuild the ZIP archive.
3. `zipalign -P 16 -f 4 in.apk out.apk` — alignment changes the ZIP structure, and the v2/v3
   signature covers it, so alignment must come **before** signing.
4. `apksigner sign --ks release.jks --ks-pass pass:secret --out signed.apk out.apk`.
5. Verify.

```
zipalign -c -v 4 signed.apk
apksigner verify --verbose --print-certs signed.apk
```

`apksigner verify` reports the scheme in use (`Verified using v2 scheme: true`) and the signer
certificate. A failed v1 check with a passing v2 check is normal for a v2-only APK.

To strip an existing signature before rebuilding, remove the `META-INF` signature files and the
signing block; `apksigner` will refuse to sign an archive that still carries a conflicting
block, and `zipalign` complains about it.

#### 5.3 IPA

An IPA is a ZIP holding `Payload/<App>.app/`. Two signature layers live inside:

- The Mach-O executables, each with their own code signature.
- `_CodeSignature/CodeResources` inside the bundle, a plist of hashes of the bundle's
  resources.

After editing a binary inside the bundle:

```
codesign --force --sign - "Payload/App.app/Frameworks/Foo.framework/Foo"
codesign --force --sign - "Payload/App.app/App"
codesign --force --sign - "Payload/App.app"
zip -qry -y out.ipa Payload
```

`-y` preserves symbolic links, which iOS bundles rely on for framework versions. Then:

```
codesign --verify --verbose=4 "Payload/App.app"
unzip -p out.ipa Payload/App.app/_CodeSignature/CodeResources | head -20
```

Sideloading tools re-sign the IPA with their own certificate, so the internal signature is
replaced anyway; the bundle must still be internally consistent or the install fails.

### Part 6 — The re-sign and repack order

| Container | Order |
| --- | --- |
| PE | patch → recompute optional header checksum → sign → verify |
| PE (driver) | patch → recompute checksum (mandatory) → sign → verify |
| Mach-O | patch → strip old signature → sign → verify → repack if in a bundle |
| Mach-O bundle | patch nested code → sign nested code → sign bundle → repack |
| ELF | patch → update or remove build-id → no signature step unless `sbsign` was used |
| APK | patch payload → rebuild ZIP → `zipalign` → `apksigner sign` → verify |
| IPA | patch binary → `codesign` binary → `codesign` bundle → `zip` → verify |

Two rules hold across all of them:

1. **Digest last.** Anything that hashes the file must run after the last byte change.
2. **Sign before packaging.** A signature covers the container's structure, so the container
   must be final before signing, and the archive must be repacked after signing only when the
   archive itself is not covered by the signature.

## Variations

### Notarised macOS bundles

A bundle distributed through the App Store or stapled with a notary ticket carries an extra
layer: the ticket is stapled to the bundle as `_CodeSignature/CodeResources` plus a ticket
file, and the Developer ID signature must remain intact. Any code change voids both. Sign with
the same Developer ID identity and re-staple:

```
codesign --force --timestamp --options runtime --sign "Developer ID Application: Vendor (TEAMID)" App.app
xcrun stapler staple App.app
xcrun stapler validate App.app
```

### Universal (fat) binaries

Every architecture slice carries its own code signature, and a slice's signature covers only
that slice. Sign each slice separately and reassemble:

```
lipo -thin arm64 App.app/Contents/MacOS/App -output App-arm64
codesign --force --sign - App-arm64
lipo -create App-arm64 App-x86_64 -output App
codesign --force --sign - App.app
```

### Linux packages

Debian and RPM packages carry their own checksums over the payload, and the debug package is
matched to the binary by build-id. After patching a binary inside a `.deb` or `.rpm`, rebuild
the package metadata:

```
dpkg-deb --build patched/ patched.deb
rpmbuild -bb SPECS/app.spec
rpm -Kv patched.rpm
```

### Installers and self-extracting archives

An NSIS, Inno Setup or Squirrel installer carries a compressed copy of the real executable.
Patching the installer binary itself changes only the stub. Extract the payload, patch the
extracted file, and rebuild the installer; the stub's own signature covers the archive and
must be refreshed as well.

### App-bundled binaries in Electron and Java

Electron's `asar` archive may be protected by the *asar integrity* feature, which stores a
hash of the archive in the executable's resources or in a `Squirrel` manifest. Any change to
the archive invalidates it. The main Electron binary itself is a Mach-O or PE and follows the
Mach-O or PE rules above.

### APK Signature Scheme v4

v4 is not stored inside the APK; it is a separate `.idsig` file produced by
`apksigner sign --v4-signing-enabled`. It signs the whole APK and must be regenerated or
removed alongside the v2/v3 block.

## Verification

Per container:

```
# PE
python3 -c "import pefile; p=pefile.PE('target.exe'); print(hex(p.OPTIONAL_HEADER.CheckSum), hex(p.generate_checksum()))"
osslsigncode verify target.exe
signtool verify /pa target.exe
Get-AuthenticodeSignature .\target.exe | Format-List Status,StatusMessage

# Mach-O
codesign --verify --verbose=4 target.macho
codesign -d --entitlements :- target.macho
otool -l target.macho | grep -A4 LC_CODE_SIGNATURE
ldid -e target.macho

# ELF
readelf -n target.elf
file target.elf

# DEX / APK
dexdump -f classes.dex | head -20
zipalign -c -v 4 signed.apk
apksigner verify --verbose --print-certs signed.apk

# IPA
codesign --verify --verbose=4 "Payload/App.app"
unzip -t out.ipa
```

Negative tests, which matter more than the positive ones:

1. **Prove the signature check is real.** Flip one byte in the signed file and confirm the
   verifier now fails. If it still passes, the verifier is not looking at what you think.

   ```
   cp target-signed.exe probe.exe
   printf '\x90' | dd of=probe.exe bs=1 seek=1234 conv=notrunc
   osslsigncode verify probe.exe
   ```

   Expect a hash mismatch.

2. **Prove the checksum matters where it is enforced.** For a driver, an incorrect checksum
   makes the loader refuse the image; for a user-mode EXE it does not. Confirm which case
   applies before assuming the repair was necessary.

3. **Prove the signature covers the whole archive.** Extract `classes.dex` from the signed APK,
   change one byte, reinsert it, and confirm `apksigner verify` fails.

4. **Confirm the app still runs after the repair.** A file that verifies but does not launch
   has been broken by the repair, not by the patch. Run the original failing operation again.

## Pitfalls

- Recomputing the PE checksum after signing. `signtool` writes the checksum as part of
  signing; recomputing afterwards is harmless only if the value matches. Compute it before.
- Believing the PE checksum makes a patched binary "valid". It is a corruption detector for
  drivers and a loader sanity check for user-mode images, not a security feature. Authenticode
  is the security feature, and it cannot be repaired by recomputing a checksum.
- Treating the Certificate Table's `VirtualAddress` as an RVA. It is a file offset.
- Truncating the certificate table without zeroing the data directory entry. The loader then
  reads a certificate table from garbage offsets.
- Believing `codesign --remove-signature` is enough on iOS. The binary may still be encrypted
  (`cryptid 1`), and an encrypted binary cannot be signed until it is decrypted.
- Re-signing a bundle with `--deep` and breaking nested frameworks that need their own
  identity and their own entitlements.
- Running `zipalign` **after** `apksigner sign`. Alignment changes the ZIP structure that the
  v2/v3 signature covers, and the signature becomes invalid.
- Recomputing the DEX Adler-32 before the SHA-1. The Adler-32 covers the SHA-1 field, so the
  order is fixed.
- Assuming the ELF build-id is validated at load time. It is not; the binary runs. What breaks
  is debug-symbol resolution, which produces confusing wrong-symbol behaviour during
  debugging rather than a visible error.
- Regenerating a build-id as a hash of the patched file. The build-id identifies the build, not
  the file; hashing the file makes it match nothing and stops `debuginfod` from resolving it at
  all, which is sometimes the desired outcome.
- Forgetting the ZIP entry CRC-32 values when editing an archive with a raw hex editor. Use a
  real ZIP writer.
- Ignoring the self-integrity check inside the program. A patched binary that checksums its
  own code will fail at startup; the repair is to neutralise the check, not to make the
  checksum agree.

## References

- Microsoft PE format, Certificate Table data directory and `WIN_CERTIFICATE`: <https://learn.microsoft.com/windows/win32/debug/pe-format>
- Microsoft Authenticode portal: <https://learn.microsoft.com/windows/win32/seccrypto/cryptography-tools-signature-tools-portal>
- `CheckSumMappedFile`: <https://learn.microsoft.com/windows/win32/api/imagehlp/nf-imagehlp-checksummappedfile>
- Apple code signing guide: <https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/CodeSigningGuide.html>
- `codesign` and `codesign_allocate`: <https://keith.github.io/xcode-man-pages/codesign.1.html>
- ELF build-id notes: <https://sourceware.org/glibc/wiki/Glibc%20Build%20ID>
- `debuginfod` build-id based lookup: <https://sourceware.org/wiki/Debuginfod>
- Android APK signature schemes: <https://source.android.com/docs/security/features/apksigning>
- `apksigner` documentation: <https://developer.android.com/tools/apksigner>
- DEX file format: <https://source.android.com/docs/core/runtime/dex-format>
- Android `zipalign` documentation: <https://developer.android.com/studio/command-line/zipalign>
