---
id: "integrity-self-checks"
title: "Binary integrity self-checks"
domain: "anti-analysis"
kind: "technique"
platforms: "windows, macos, linux, android, ios"
arch: "x86, x86-64, arm64"
difficulty: "advanced"
tools: "LIEF,radare2,Ghidra,Python"
verified: false
updated: "2026-11-15"
summary: "How a program validates its own image with CRC-32, SHA-256, per-page hashes, Authenticode and loaded-module lists, how to locate each check, and how to neutralise or recompute the stored digest."
---

## Summary

An integrity self-check computes a digest over part of its own image and compares it against a
stored value. If they differ, the program assumes its code was patched and refuses to work.

The stored value is the weak point. It usually lives in the same file as the code it protects, so
a patch that changes the code without changing the stored digest is detectable, and a patch that
also updates the digest requires the attacker to recompute it. This entry covers the digest
families in use, how to locate each one, the byte-level patch that neutralises the comparison, and
the recompute procedure for the case where the digest is validated.

Related entries: [debugger-detection-techniques](./debugger-detection-techniques.md) for the
runtime probes that accompany these checks, [packers-and-unpacking](./packers-and-unpacking.md)
because a packed binary also carries a checksum of its own header.

## Recognition

Digest API imports:

| Digest | API | Module |
| --- | --- | --- |
| CRC-32 | custom table loop, `zlib` `crc32` | inlined table is the usual case |
| SHA-256 | `BCryptHashData` | `bcrypt.dll` |
| SHA-256 | `CryptHashData` | `advapi32.dll` |
| SHA-256 | `CC_SHA256` / `CC_SHA256_Update` / `CC_SHA256_Final` | `libSystem.B.dylib` (CommonCrypto) |
| SHA-256 | `EVP_Digest` | `libcrypto` |
| MD5 | `CryptHashData` with `CALG_MD5` | `advapi32.dll` |
| MD5 | `CC_MD5` | `libSystem.B.dylib` |
| SHA-1 | `CryptHashData` with `CALG_SHA1` | `advapi32.dll` |

The CRC-32 polynomial constant in its reflected form, `0xEDB88320`, appears little-endian in the
table as:

```
20 83 b8 ed
```

The digest algorithm identifiers as immediates:

| Constant | Meaning |
| --- | --- |
| `0x8003` | `CALG_MD5` |
| `0x8004` | `CALG_SHA1` |
| `0x800c` | `CALG_SHA_256` |
| `0x0000800c` | `CALG_SHA_256` (`ALG_ID` form) |

Authenticode verification calls `WinVerifyTrust` (`wintrust.dll`) with the action GUID
`{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}`, visible in `.rdata` as:

```
6b c5 aa 00 44 cd d0 11 8c c2 00 c0 4f c2 95 ee
```

An embedded SHA-256 digest is 32 raw bytes. Search for it directly:

```
r2 -q -c '/x 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08' target.exe
```

A hex-encoded digest appears as a 64-character ASCII string; a base64-encoded digest as a
44-character string ending in `=`:

```
r2 -q -c '/  9f86d081884c7d659a2feaa0c55ad015' target.exe
```

Loaded-module enumeration imports:

| Purpose | Windows | Linux | macOS |
| --- | --- | --- | --- |
| Enumerate modules | `EnumProcessModules` (psapi) / `K32EnumProcessModules` (kernel32) | `dl_iterate_phdr` | `_dyld_image_count`, `_dyld_get_image_name` |
| Enumerate threads | `CreateToolhelp32Snapshot` | `/proc/self/task` | `task_for_pid` |

Base-address checks compare `GetModuleHandle(NULL)` (or `dladdr`, or `_dyld_get_image_header`) with a
compiled-in constant. The constant is the PE `ImageBase` from the Optional Header, typically
`0x00400000` for an EXE and `0x10000000` for a DLL.

## Method

### 1. Determine what the check protects

The check names a range. Common choices:

- The whole file, hashed from the last byte of the file back to the end of the DOS stub.
- The `.text` section only.
- A specific function, hashed byte-for-byte from its entry to its last instruction.
- Per-page hashes: a table of `N` 32-bit values, one per 4 KiB page, compared page by page so the
  report names the changed page.

A per-function check usually stores the length next to the hash, so the table looks like a sequence
of `{ u32 hash; u32 length; }` or `{ u8 hash[16]; u32 length; }` records.

### 2. Locate the check

#### 2.1 By the stored digest

For SHA-256 and MD5 the stored digest is the strongest anchor.

```
rabin2 -zz target.exe | grep -E '^[0-9]+ 0x[0-9a-f]+ [0-9]+ [A-Za-z0-9+/=]{40,64}$'
```

For raw bytes, search for the digest prefix:

```
r2 -q -c '/x <first 8 bytes of the digest>' target.exe
```

Then take the cross-reference to the matching code:

```
r2 -q -c 'aaa; axt @ 0x00401200' target.exe
```

#### 2.2 By the CRC-32 table

The reflected CRC-32 table generated at runtime contains `0xEDB88320` as its first entry. In the
disassembly look for the constant, then for the loop that consumes it:

```
r2 -q -c '/x 20 83 b8 ed' target.exe
```

A hand-written CRC-32 routine usually has the shape:

```
mov  eax, 0xffffffff
.loop:
xor  al, byte [rcx + rsi]
shr  eax, 1
jnc  .carry
xor  eax, 0xedb88320
.carry:
inc  rsi
cmp  rsi, rdx
jb   .loop
not  eax
```

The final `not eax` is the final XOR with `0xFFFFFFFF`. The comparison against the stored value
follows immediately.

#### 2.3 By the digest API

```
rabin2 -i target.exe | grep -Ei 'BCryptHashData|CryptHashData|CC_SHA256|CC_SHA256_Update|EVP_Digest|crc32'
```

#### 2.4 By the module-list check

```
rabin2 -i target.exe | grep -Ei 'EnumProcessModules|CreateToolhelp32Snapshot|GetModuleHandle'
```

`dl_iterate_phdr` in an ELF, `_dyld_image_count` in a Mach-O.

### 3. Neutralise the comparison

The comparison, not the digest, is the decision point. Locate the `cmp`/`memcmp`/`bcrypt`-style
equality test that consumes the computed digest and make it always succeed.

| Pattern | Bytes | Neutralise |
| --- | --- | --- |
| x64 `cmp rax, imm32` | `48 3d xx xx xx xx` | set the immediate to the computed value, or invert the following jump |
| x64 `cmp rdx, rax` | `48 39 c2` | `48 31 d2` (`xor rdx, rdx`) breaks the digest, so instead patch the jump |
| x86 `cmp eax, imm32` | `3d xx xx xx xx` | `3d` form |
| `test eax, eax` + `jne` | `85 c0` `75 xx` | `74 xx` |
| `memcmp` result | call site | force the return value to 0 |

The general and safest form is to patch the conditional jump that follows the comparison:

```
; 0f 85 xx xx xx xx  jne rel32  ->  0f 84 xx xx xx xx  je rel32
```

Determine the polarity by reading the consumer: the branch that leads to the error path or the
abort call is the one to invert.

### 4. Recompute the digest after patching

When the check is left in place and only the code changes, the stored digest must be updated. The
stored value is a 4-byte CRC-32, an MD5 (16 bytes), a SHA-1 (20 bytes) or a SHA-256 (32 bytes).

Python helper that recomputes a CRC-32 over a byte range and writes it back:

```python
#!/usr/bin/env python3
"""Recompute and patch a CRC-32 stored in a file.

Usage: patch_crc32.py <file> <crc-offset-hex> <range-start-hex> <range-length-hex> [--big-endian]
"""
import struct
import sys
import zlib

POLY_REFLECTED = 0xEDB88320   # the constant seen in hand-written CRC-32 tables


def crc32_range(data: bytes, offset: int, length: int) -> int:
    """CRC-32 with the standard zlib convention: init 0xFFFFFFFF, final XOR 0xFFFFFFFF."""
    return zlib.crc32(data[offset:offset + length]) & 0xFFFFFFFF


def main() -> int:
    if len(sys.argv) < 5:
        print(__doc__)
        return 2
    path = sys.argv[1]
    crc_off = int(sys.argv[2], 16)
    start = int(sys.argv[3], 16)
    length = int(sys.argv[4], 16)
    big = "--big-endian" in sys.argv[5:]

    with open(path, "rb") as fh:
        data = bytearray(fh.read())

    value = crc32_range(bytes(data), start, length)
    fmt = ">I" if big else "<I"
    data[crc_off:crc_off + 4] = struct.pack(fmt, value)

    with open(path, "wb") as fh:
        fh.write(bytes(data))

    print(f"crc32 over 0x{start:x}..0x{start + length:x} = 0x{value:08x} -> wrote at 0x{crc_off:x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

The same helper recomputes a SHA-256 digest:

```python
import hashlib
import struct

def patch_sha256(path: str, digest_off: int, start: int, length: int) -> str:
    with open(path, "rb") as fh:
        data = bytearray(fh.read())
    digest = hashlib.sha256(bytes(data[start:start + length])).digest()
    data[digest_off:digest_off + 32] = digest
    with open(path, "wb") as fh:
        fh.write(bytes(data))
    return digest.hex()
```

For a CRC-32 that covers the field storing it, the self-reference must be removed first: compute
the CRC with the stored field zeroed, then write the result into the field.

```python
def patch_self_referential_crc32(path: str, crc_off: int, start: int, length: int) -> int:
    with open(path, "rb") as fh:
        data = bytearray(fh.read())
    saved = bytes(data[crc_off:crc_off + 4])
    data[crc_off:crc_off + 4] = b"\x00\x00\x00\x00"
    value = zlib.crc32(bytes(data[start:start + length])) & 0xFFFFFFFF
    data[crc_off:crc_off + 4] = saved
    data[crc_off:crc_off + 4] = struct.pack("<I", value)
    with open(path, "wb") as fh:
        fh.write(bytes(data))
    return value
```

### 5. Recompute the PE header checksum

Independently of any self-check, the PE Optional Header checksum must be updated after editing a
PE. The field is at offset `0x40` from the start of the Optional Header (both PE32 and PE32+):

```
lief.parse("target.exe")
pe = lief.parse("target.exe")
pe.optional_header.checksum = <computed>
pe.write("target.patched.exe")
```

With `pefile`:

```python
import pefile

pe = pefile.PE("target.exe")
pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()
pe.write("target.patched.exe")
```

The PE checksum covers the whole file with the checksum field itself treated as zero.

### 6. The runtime-only variant: hook the digest function

When the protected code is decrypted at runtime, patching the file is impossible. Replace the
digest function so it returns the expected value:

```javascript
// frida 17.x — force BCryptHashData to report the expected digest.
const bcrypt = Process.getModuleByName('bcrypt.dll');
Interceptor.replace(bcrypt.getExportByName('BCryptHashData'),
    new NativeCallback(function (hHash, pbInput, cbInput, dwFlags, pbOutput, cbOutput) {
        return 0;
    }, 'int', ['pointer', 'pointer', 'uint32', 'uint32', 'pointer', 'uint32']));
```

The cleaner hook is on the *comparison*, not the hash: replace `memcmp` so that a comparison over a
length equal to the digest size always returns 0.

```javascript
// frida 17.x — make memcmp of a 32-byte digest always succeed.
const libc = Process.getModuleByName('msvcrt.dll');
const origMemcmp = new NativeFunction(libc.getExportByName('memcmp'),
    'int', ['pointer', 'pointer', 'uint32']);
Interceptor.replace(libc.getExportByName('memcmp'),
    new NativeCallback(function (a, b, n) {
        if (n === 32 || n === 16 || n === 20) {
            return 0;
        }
        return origMemcmp(a, b, n);
    }, 'int', ['pointer', 'pointer', 'uint32']));
```

Blindly returning 0 for every 16/20/32-byte `memcmp` also masks unrelated comparisons (string
equality of those lengths). Hook the specific call site instead when precision matters.

### 7. Loaded-module checks

A program that enumerates its loaded modules and rejects unknown ones is checking for injected
libraries.

Windows:

```
EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed)
```

Linux, `dl_iterate_phdr`:

```c
static int cb(struct dl_phdr_info *info, size_t size, void *data) {
    /* compare info->dlpi_name against an allowlist */
    return 0;
}
dl_iterate_phdr(cb, NULL);
```

macOS:

```c
uint32_t count = _dyld_image_count();
for (uint32_t i = 0; i < count; i++) {
    const char *name = _dyld_get_image_name(i);
}
```

Neutralise the allowlist comparison by patching the branch, or hide the injected module:

- Windows: `UnmapViewOfFile` plus removal of the link, or load the library as a manual map so it
  never appears in the PEB loader list.
- Linux: `dlopen` with a name that the check does not scan for, or unlink the file from the
  filesystem after mapping so the link is gone.
- macOS: use `DYLD_INSERT_LIBRARIES` before the check runs, or remove the library from the dyld
  image list by loading it after the enumeration has happened.

Frida on Linux and macOS appears in the module list as `frida-agent-64.so` or
`libfrida-gadget.so`. On Windows the agent is injected through a remote thread and does not appear
in the loader list, which is one reason Windows targets are less likely to enumerate modules.

### 8. Authenticode and signature checks

`WinVerifyTrust` with `WINTRUST_ACTION_GENERIC_VERIFY_V2` verifies the embedded signature. A
program that calls it at runtime detects any modification of the signed image.

Neutralisation options:

- Patch the call so it always returns `S_OK` (`0`).
- Re-sign the patched binary with a self-signed certificate and install it in the Trusted Root
  store.
- Patch the security directory entry in the PE Optional Header (data directory index 4) so the
  loader finds no certificate.

On macOS the equivalent is the code signature:

```
codesign --verify --verbose=2 target.app
codesign --force --deep --sign - target.app
```

A modified Mach-O fails to load unless it is re-signed. After any edit:

```
codesign --force --sign - --options runtime target.app
```

On Android the check is the APK signature verified by the package manager. Modifying an APK
requires re-signing with `apksigner`:

```
zipalign -P 16 -f 4 target.apk target.aligned.apk
apksigner sign --ks release.keystore --out target.signed.apk target.aligned.apk
zipalign -c -P 16 -v 4 target.signed.apk
apksigner verify --verbose target.signed.apk
```

## Variations

- **In-memory checks.** The digest is computed over the loaded image, so a runtime patch of the
  code triggers it even though the file on disk is unchanged. Neutralise by hooking the hash
  function or by recomputing the expected value after the runtime patch.
- **Page-granular checks.** A table of per-page CRCs localises the modification. Neutralisation is
  the same as above; the recompute path has to rebuild the whole table.
- **Range table with lengths.** `{ hash, length }` records pin both what is hashed and how much.
  After a patch, recompute the hash for the affected record and update its length if the code grew.
- **Self-modifying code.** A target that decrypts a stub at runtime computes its digest over the
  *decrypted* bytes. The stored digest is over plaintext, so a static search for it finds the
  plaintext in `.rdata` even when the file holds ciphertext.
- **Split digest.** Half of the expected digest in one section, half in another, combined at
  runtime. A single search finds only half.
- **Hash of the hash.** The stored value is itself hashed with a keyed algorithm, so the obvious
  comparison never matches. The keyed algorithm or key is in the same binary.
- **Checksum of the whole file including the checksum.** Self-referential; requires the zero-the-
  field-before-computing procedure from section 4.
- **Tainted region checks.** The digest covers only the region containing the licence logic, so
  unrelated patches elsewhere do not trip it. Identify the range from the call that passes the
  start and length arguments to the hash function.
- **Managed assemblies.** A .NET assembly has its own strong-name and Authenticode checks, and the
  `Assembly.GetExecutingAssembly()` image can be hashed at runtime. The same neutralisation applies
  at the managed level.
- **ELF build-id.** Not a self-check but a related identity field: `readelf -n` shows the build-id
  note. Tools use it to match a symbol file to a binary, not to detect patching.

## Verification

1. **Establish the baseline.** Run the unmodified target and confirm it passes its own check. A
   target that already fails its check is not a useful baseline.
2. **Confirm the check fires.** Patch one byte in the protected range — for example flip a `nop` to
   `cc` in a scratch copy — and confirm the target now reports the modification. Expected: an
   error dialog, a non-zero exit, or a silent refusal to unlock. This proves which range is
   protected.
3. **Prove the neutralisation.** Apply the patch that bypasses the comparison and confirm the
   target runs its normal path with the byte change still present.
4. **Negative test.** Restore the original byte and confirm the target fails again, then re-apply
   the patch and confirm it passes. A patch that works only once is not a patch.
5. **Recompute path.** Instead of bypassing, recompute the digest and confirm the target passes
   with the check intact. This proves the stored digest was the gate rather than a red herring.
6. **Checksum and signature.** After any edit, verify the container is still loadable:

   ```
   rabin2 -I target.patched.exe
   codesign --verify --verbose=2 target.app
   apksigner verify --verbose target.apk
   ```

   Expected: no loader error, no signature error beyond the intended self-signature status.
7. **Scope check.** Repeat the run after a fresh launch and after clearing any cached state. A
   check that runs only on the first launch is not fully neutralised by a runtime hook that is
   injected after start-up.
8. **Module list.** After injecting a library, confirm the enumeration hook or hide still holds:
   print the module list from inside the target and compare with the pre-injection list.

## Pitfalls

- **CRC-32 initial and final XOR.** `zlib.crc32` already applies `init = 0xFFFFFFFF` and
  `final XOR = 0xFFFFFFFF`. A hand-written routine that starts from `0x00000000` produces a
  different value. Compare against the target's own routine, not against `zlib.crc32`, when the
  variants differ.
- **Byte order of the stored CRC.** Little-endian is the Windows convention; some toolchains store
  it big-endian. Confirm with the bytes the target loads and compares against.
- **The stored digest is not the whole story.** Some targets compare only the first 4 bytes of the
  digest as a quick filter and the full digest later. Patching the quick filter leaves the real
  check.
- **The protected range moves.** After a patch that changes code size, the offsets shift. Recompute
  the range from the code that passes the arguments, not from the previous analysis.
- **Authenticated data.** A digest computed with an HMAC key from a server cannot be recomputed
  offline. The patch path is the only path.
- **Anti-tamper in the loader.** A file that will not even load after a byte change indicates a
  loader-level or signature-level check rather than an in-program one.
- **Patching breaks the checksum.** The PE checksum and the Authenticode signature both cover the
  modified bytes. Recompute the checksum and re-sign, or the file fails before the program runs.
- **`EnumProcessModules` is itself easily hooked.** A program that enumerates modules and then
  calls an imported `EnumProcessModules` is one `Interceptor.replace` away from being satisfied.
  Enumeration through `LdrQueryProcess` or a manual `PEB` walk resists the hook.
- **Order of operations.** A runtime hook that is installed after the check has already executed
  changes nothing. Verify the check runs after the injection completes.
- **Hash over a mapped, relocated image.** The hash of the loaded image differs from the hash of
  the file because of relocations and import fixups. Recompute against the same view the target
  hashes.

## References

- `BCryptHashData` — https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcrypthashdata
- `CryptHashData` — https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-crypthashdata
- `WinVerifyTrust` — https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust
- `EnumProcessModules` — https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumprocessmodules
- `dl_iterate_phdr` — https://man7.org/linux/man-pages/man3/dl_iterate_phdr.3.html
- `_dyld_image_count` — https://developer.apple.com/documentation/dyld/dyld_image_count
- `codesign` — https://developer.apple.com/documentation/security/codesign
- `apksigner` — https://developer.android.com/tools/apksigner
- CRC-32 (reflected, polynomial `0xEDB88320`) — https://en.wikipedia.org/wiki/Cyclic_redundancy_check
- LIEF 1.0.0 — https://lief.re/doc/latest/
- radare2 — https://rada.re/n/
- Frida JavaScript API (17.x) — https://frida.re/docs/javascript-api/
