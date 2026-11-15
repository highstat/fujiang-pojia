---
id: "windows-integrity-and-tamper-checks"
title: "Windows integrity and tamper checks"
domain: "windows-native"
kind: "pattern"
platforms: "windows"
arch: "x86, x86-64"
difficulty: "advanced"
tools: "x64dbg,ScyllaHide,Frida,LIEF,pefile,r2,signtool"
verified: false
updated: "2026-11-15"
summary: "Catalogues the self-checks a Windows binary runs on itself — section CRCs, file digests, PE checksum, Authenticode, and the anti-debug queries — with the byte patch and the Frida override for each."
---

## Summary

A Windows binary that protects its licence usually protects itself at the same time, and the
self-protection is what stops a naive patch from loading. Three families exist: integrity
checks over the binary's own bytes (CRC, digest, PE checksum, Authenticode), debugger
detection, and timing checks.

Each family has three ways past it: patch the comparison in the file, patch the API call in
the file, or override the API at runtime. The runtime override is the safest option when the
binary is signed, because it changes nothing on disk.

This entry lists the checks with the exact API, the exact byte patterns, and the exact override.
It is the reference half of the licence work; the branch-hunting half is in
[win32-licence-ui-flow](win32-licence-ui-flow.md).

## Recognition

Observable symptoms:

- The patched binary refuses to start, or exits with `0xc000007b` / a `STATUS_INVALID_IMAGE`
  style error, or "the application has been modified".
- The program runs under the debugger but fails when launched normally, or the opposite.
- The program hangs for a second at startup (a deliberate timing delay) and then continues.
- A `File not found` or "corrupt installation" message after an edit that changed no visible
  behaviour.
- On Windows, SmartScreen or UAC warns "The publisher could not be verified" after an edit.
- The binary exits immediately when `IsDebuggerPresent` returns true, but the same binary
  started from a service or a scheduled task works.

## Method

Working directory for every command below: the directory that contains the target binary.

### 1. CRC32 over the `.text` section

The classic self-integrity check: compute CRC32 over the code section at startup and compare it
with a constant stored in `.rdata`.

Find the constant and confirm it against the section:

```bash
python3 - <<'PY'
import pefile, zlib, struct
pe = pefile.PE("target.exe")
for s in pe.sections:
    name = s.Name.rstrip(b"\x00").decode(errors="replace")
    if name in (".text", "CODE", ".code"):
        crc = zlib.crc32(s.get_data()) & 0xffffffff
        print(name, "crc32", hex(crc), "bytes", struct.pack("<I", crc).hex(" "))
        blob = open("target.exe","rb").read()
        for off in [i for i in range(len(blob)) if blob.startswith(struct.pack("<I", crc))]:
            print("  candidate at file offset", hex(off))
PY
```

Where it is found: a function that reads its own module base
(`GetModuleHandleW(NULL)`) and the PE headers, adds up the section range, and calls a CRC
routine. The CRC table is the giveaway: a 1 KB table of 32-bit constants starting with
`00 00 00 00`, `01 00 00 00`, ..., or the reflected table starting with
`00 00 00 00 96 30 07 77 2c 61 11 ee`.

How to patch it:

- Patch the comparison. The pattern `cmp dword ptr [rbx+10h], eax` (`39 43 10`) followed by
  `jne` is the usual shape. Flip the jump:

  ```text
     75 12   jne  loc_fail   ->   74 12   je  loc_fail
  ```

- Patch the CRC result after the call: replace the `mov eax, <crc>` with `xor eax, eax`
  (`31 c0`) so the stored and computed values differ. That is worse than patching the
  comparison, because some builds store the expected value at runtime and compare it twice.

- Neutralise at runtime by replacing the CRC routine's caller, not the table:

  ```javascript
  'use strict';
  const target = Module.getGlobalExportByName('CheckIntegrity');
  Interceptor.replace(target, new NativeCallback(function () { return 1; }, 'bool', []));
  ```

  If the CRC routine is static (no export), hook the module base instead and patch the
  computed value in memory: `Memory.patchCode(addr, 4, code => { code.writeU32(0); });`.

### 2. File digest compared against a stored digest

The program hashes its own file (SHA-256, SHA-1, MD5) and compares the result with a digest
embedded in the binary or in a signed licence blob.

Locate the embedded digest and compare it with the real file:

```bash
certutil -hashfile target.exe SHA256
python3 - <<'PY'
import hashlib
data = open("target.exe","rb").read()
for algo in ("md5","sha1","sha256"):
    d = hashlib.new(algo, data).digest()
    print(algo, d.hex(" "))
    print("   found in file at", [hex(i) for i in range(len(data)) if data.startswith(d)])
PY
```

Where it is found: `CreateFileW` on its own module path (`GetModuleFileNameW`) followed by
`CreateFileMappingW`/`MapViewOfFile` and `BCryptHashData`/`CryptHashData`.

How to patch it: the compare is a `memcmp`-style loop over 32 bytes; patch the branch after it.
The cleanest patch is to make the program hash a zero-length buffer, but the usual route is
the branch:

```text
   0f 85 6c 00 00 00   jne  loc_fail   ->   0f 84 6c 00 00 00
```

Because the digest is recomputed at runtime from the file on disk, patching the file changes
the digest and therefore requires patching the stored expected digest too, or patching the
comparison. Patching the comparison is the only stable choice.

### 3. PE checksum (`CheckSumMappedFile`)

`CheckSumMappedFile` and `MapFileAndCheckSum` from `imagehlp.dll` verify the PE `CheckSum`
field at optional header + `0x40`.

```bash
rabin2 -i target.exe | grep -Ei 'CheckSumMappedFile|MapFileAndCheckSum|imagehlp'
```

Note that Windows itself only enforces the PE checksum for kernel-mode drivers and some
system binaries; for ordinary user-mode EXEs the field is informational. A self-check that
calls `CheckSumMappedFile` explicitly is the program's own decision.

Recompute the checksum after any edit:

```bash
python3 - <<'PY'
import struct, sys

def pe_checksum(path):
    data = bytearray(open(path, "rb").read())
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    opt = e_lfanew + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    assert magic in (0x10b, 0x20b), "not a PE image"
    cksum_off = opt + 0x40
    struct.pack_into("<I", data, cksum_off, 0)
    total = 0
    for i in range(0, len(data) - 1, 2):
        if i == cksum_off or i == cksum_off + 2:
            continue
        total += data[i] | (data[i + 1] << 8)
        total = (total & 0xFFFFFFFF) + (total >> 32)
    total = (total & 0xFFFF) + (total >> 16)
    total = total + (total >> 16)
    total = total & 0xFFFF
    total += len(data)
    return total & 0xFFFFFFFF

path = sys.argv[1] if len(sys.argv) > 1 else "target.exe"
value = pe_checksum(path)
data = bytearray(open(path, "rb").read())
e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
struct.pack_into("<I", data, e_lfanew + 24 + 0x40, value)
open(path, "wb").write(data)
print("checksum set to", hex(value))
PY
```

The same value can be produced by the OS API, which is the authoritative implementation:

```c
#include <windows.h>
#include <imagehlp.h>

DWORD sum = 0;
if (!CheckSumMappedFile(L"target.exe", NULL, NULL, &sum))
    sum = 0;      /* mapped image not available */
```

### 4. Authenticode signature verification

The program calls `WinVerifyTrust` with `WINTRUST_ACTION_GENERIC_VERIFY_V2`
(`{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}`) and treats a non-zero result as "tampered".

Where it is found: `wintrust.dll!WinVerifyTrust`, or `crypt32.dll!CryptCATAdminCalcHashFromFileHandle`
followed by `CryptCATAdminEnumCatalogFromHash` for catalog-signed files.

```bash
rabin2 -i target.exe | grep -Ei 'WinVerifyTrust|CryptCAT|WintrustData'
powershell -Command "Get-AuthenticodeSignature .\target.exe | Format-List Status,StatusMessage,SignerCertificate"
```

How to patch it:

- Patch the call so it always succeeds. A near call `e8 <rel32>` becomes:

  ```text
   e8 9a 22 00 00   call [WinVerifyTrust]   ->   31 c0 90 90 90   (xor eax,eax + nops)
  ```

  `WinVerifyTrust` returns `LONG`; `0` is `S_OK`. The remaining NOPs keep the instruction
  length so the following code stays aligned.

- Patch the caller: flip the branch after the call.

- Strip the signature from the file. The certificate table is data directory index 4 and holds
  a **file offset**, not an RVA:

  ```bash
  signtool remove /s target.exe
  ```

  Manual equivalent with LIEF 1.0.0, to confirm where the signature lives before stripping it:

  ```python
  import lief
  pe = lief.PE.parse("target.exe")
  for chunk in pe.secure_chunks:
      print("signature blob at file offset", hex(chunk.offset), "size", hex(chunk.size))
  print("cert directory:", pe.data_directories[lief.PE.DataDirectory.CERTIFICATE_TABLE].RVA,
        pe.data_directories[lief.PE.DataDirectory.CERTIFICATE_TABLE].Size)
  ```

  LIEF 1.0.0 does not remove the signature blob in place, so strip it with the truncation
  below or with `signtool remove`.

  Manual equivalent with a hex edit, if the certificate table is the last thing in the file:

  ```bash
  python3 - <<'PY'
  import struct
  data = bytearray(open("target.exe","rb").read())
  e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
  opt = e_lfanew + 24
  magic = struct.unpack_from("<H", data, opt)[0]
  dd = opt + (0x70 if magic == 0x20b else 0x60)
  cert_off, cert_size = struct.unpack_from("<II", data, dd + 4*8)
  print("certificate table at file offset", hex(cert_off), "size", cert_size)
  if cert_size:
      struct.pack_into("<II", data, dd + 4*8, 0, 0)
      data = data[:cert_off]          # the table is normally last
      open("target.unsigned.exe","wb").write(data)
      print("stripped")
  PY
  ```

  Truncating is only safe when nothing follows the certificate table. Check for an overlay
  first (see [pe-section-and-entry-analysis](pe-section-and-entry-analysis.md)); an appended
  installer payload after the certificate table must be preserved and moved.

Removing the signature does not restore trust for a file that was downloaded with a
Mark-of-the-Web (Zone.Identifier) alternate data stream. Remove it explicitly:

```powershell
Unblock-File .\target.exe
```

### 5. Debugger detection

| Check | Where | How to patch |
| --- | --- | --- |
| `IsDebuggerPresent` | `kernel32.dll` | `call` → `xor eax,eax` + NOPs |
| `CheckRemoteDebuggerPresent` | `kernel32.dll` | patch the call or the output write |
| `NtQueryInformationProcess` (class 7) | `ntdll.dll` | patch the compare after the call |
| `NtSetInformationThread` (class 0x11) | `ntdll.dll` | patch the call to a no-op |
| `NtQuerySystemInformation` | `ntdll.dll` | patch the compare on the returned structure |
| PEB `BeingDebugged` | inline `fs:[0x30]` read | `mov al, [fs:30h]` → `xor eax,eax` |
| `ProcessDebugPort` / heap flags | `ntdll.dll` | see the runtime override below |

The PEB read is a two-byte sequence:

```text
   64 a1 30 00 00 00   mov eax, fs:[30h]     ; PEB
   80 78 02 00         cmp byte [eax+2], 0   ; BeingDebugged
```

`BeingDebugged` sits at PEB + `0x02`. Patch the compare:

```text
   80 78 02 00         cmp byte [eax+2], 0   ->   80 78 02 00  (unchanged) + xor
```

Simplest: replace `cmp byte [eax+2], 0` with `mov al, 0` (`b0 00`) plus NOPs:

```text
   80 78 02 00   ->   b0 00 90 90
```

The `NtQueryInformationProcess` classes that matter:

| Class | Name | Meaning |
| --- | --- | --- |
| 7 | `ProcessDebugPort` | non-zero port when debugged |
| 30 (0x1e) | `ProcessDebugObjectHandle` | non-zero handle when debugged |
| 31 (0x1f) | `ProcessDebugFlags` | **inverted**: returns 0 when debugged, 1 otherwise |

The `ProcessDebugFlags` inversion is a common source of mistakes: to report "not debugged" the
override must return a **non-zero** value.

`NtSetInformationThread` class 0x11 is ThreadHideFromDebugger; 0x01 is not an older
alias. SystemKernelDebuggerInformation (0x23) has two BOOLEAN fields.
SystemProcessInformation is class 5 and is not a portable DebugFlags record.

Use the [scoped helper](../../scripts/frida/bypass-anti-debug.js) for supported process
queries. It changes out-parameters after successful original calls, preserves unrelated
classes and checks buffer sizes. It does not cover all system-information queries.

For `WinVerifyTrust`:

```javascript
const wt = Process.getModuleByName('wintrust.dll');
Interceptor.replace(wt.getExportByName('WinVerifyTrust'),
  new NativeCallback(function () { return 0; }, 'int32', ['pointer', 'pointer', 'pointer']));
```

The `ScyllaHide` plugin covers the common queries at the kernel level, which is faster and more
complete than a per-API hook, and it also covers the timing APIs below. Load it before the
process starts, and verify the profile actually covers the APIs the binary imports.

### 6. Debugger probes based on `OutputDebugString`

`OutputDebugStringA`/`OutputDebugStringW` behave differently when a debugger is attached: the
string is delivered to the debugger and the call returns immediately; with no debugger the
call still travels to the debugger object and the elapsed time differs measurably.

```javascript
Interceptor.replace(k32.getExportByName('OutputDebugStringA'),
  new NativeCallback(function (s) { return undefined; }, 'void', ['pointer']));
Interceptor.replace(k32.getExportByName('OutputDebugStringW'),
  new NativeCallback(function (s) { return undefined; }, 'void', ['pointer']));
```

The classic probe uses the *exception* raised by `OutputDebugString` under a debugger
(`DBG_PRINTEXCEPTION_C`, `0x40010006`) and branches on whether it was raised; see
[native-exception-based-control-flow](native-exception-based-control-flow.md).

### 7. Timing checks

| API / instruction | Typical use |
| --- | --- |
| `QueryPerformanceCounter` | high-resolution delta around a code block |
| `GetTickCount` / `GetTickCount64` | millisecond delta |
| `timeGetTime` | millisecond delta, `winmm.dll` |
| `rdtsc` (`0f 31`) | raw cycle counter, no API call |

Recognition: two calls to the same counter in one function with a comparison of the two
results, often with the difference compared against a threshold such as `0x1000` (4096 ticks)
or `0x10000`.

Patch in the file: replace the second read with a copy of the first, or skip the comparison.
For `rdtsc`, the two-byte instruction `0f 31` can be replaced by `90 90` (two NOPs): the
registers keep the previous values, so two consecutive "reads" return the same number and the
delta is zero.

At runtime, freeze the counter:

```javascript
const k32 = Process.getModuleByName('kernel32.dll');
let tick = 0x1000;
Interceptor.replace(k32.getExportByName('GetTickCount'),
  new NativeCallback(function () { return tick++; }, 'uint32', []));
Interceptor.replace(k32.getExportByName('QueryPerformanceCounter'),
  new NativeCallback(function (out) {
    out.writeU64(0x100000);
    return 1;
  }, 'bool', ['pointer']));
```

A constant counter makes every delta zero. If the program compares against an absolute
timestamp (an expiry check), the counter must return a plausible current value rather than a
constant; check which one the code does before choosing.

### 8. Combined checks

Many binaries combine a CRC over `.text`, a hash of the file, an Authenticode check and a
debugger check in one "integrity service" that runs at startup and returns a single boolean.
Locate that service first: it is usually the only caller of all the APIs above, and patching
its return value neutralises the group.

```bash
r2 -q -c 'aaa; axt @@ sym.imp.*CheckSumMappedFile* sym.imp.*WinVerifyTrust* sym.imp.*IsDebuggerPresent*' target.exe
```

## Variations

- **Managed equivalents**: the .NET runtime performs its own integrity work (strong-name
  validation, ReadyToRun header checks). See
  [strong-name-and-authenticode](../windows-dotnet/strong-name-and-authenticode.md).
- **Self-modifying packers**: a packed binary recomputes its own CRC after unpacking, so the
  check compares against a runtime value, not a file value. Patch the compare, not the
  constant.
- **Server-side attestation**: the program sends a hash of itself (or of a section) to a
  licence server and the server rejects a mismatch. The patch is to the request or the
  response, not to the hash routine.
- **Windows drivers**: the PE checksum is enforced by the kernel for `.sys` files, and the
  image must be signed with a WHQL/attestation signature. The checksum must be recomputed
  after any edit.
- **MSIX/AppX packages**: the package signature covers the whole ZIP, so editing a file
  inside breaks the package signature before any code-level check runs. Re-sign with
  `signtool sign /fd SHA256 /fdw SHA256 /f cert.pfx /p <password> package.msix`.
- **ARM64**: the same APIs, the same bytes; only the instruction encodings for the patched
  instructions differ.
- **Kernel callbacks**: a driver-based check (`ObRegisterCallbacks`, `PsSetCreateProcessNotifyRoutine`)
  is outside the scope of a user-mode patch entirely.

## Verification

1. **Prove the check was neutralised, not merely bypassed for this run.** Re-run the patched or
   instrumented binary after clearing all cached state (registry values the program wrote,
   licence files, temp files) and confirm the check does not reassert itself.

2. **Negative test for the patch site.** Restore the original byte and confirm the failure
   returns: the program must again report "modified" or exit. If it does not, the patched site
   was not the check.

3. **Cross-tool agreement.** The static view (`r2 -q -c 'pd 20 @ <addr>'`), the runtime view
   (breakpoint hit count) and the observable behaviour must agree. A patch that shows
   correctly in the disassembly but does not change behaviour means the binary re-reads the
   file or recomputes the value elsewhere.

4. **Signature status.** After any edit, confirm the signature state explicitly:

   ```powershell
   Get-AuthenticodeSignature .\target.exe | Select-Object Status
   ```

   `NotSigned` is expected after an intentional strip; `HashMismatch` means the file was
   edited without re-signing, and Windows will treat it as untrusted.

5. **Debugger-state check.** With ScyllaHide enabled and with the Frida overrides active,
   confirm the binary still reaches the licensed path. If the binary now behaves differently
   from the non-debugged run, an override is returning an implausible value.

## Pitfalls

- **Editing the file invalidates the checksum and the signature at the same time.** The
  checksum is the cheap one: recompute it. The signature needs a certificate.
- **The Authenticode digest excludes only three regions**: the `CheckSum` field, the
  certificate table data-directory entry, and the certificate table itself. Everything else,
  including the headers, is covered.
- **The certificate table directory entry holds a file offset**, not an RVA. Truncating at the
  wrong offset destroys the file.
- **`ProcessDebugFlags` is inverted.** Overriding it to 0 makes the process look debugged.
- **A frozen clock can break a legitimate expiry check.** Replace the counter with a constant
  only when the code computes a delta; a constant absolute timestamp reads as 1970 and may be
  handled as "expired".
- **PEB checks survive the PEB itself being patched.** Some builds read `BeingDebugged` and
  also `NtGlobalFlag` (PEB + `0x68` on x64, `0x30` on x86) and the heap flags
  (`Heap.Flags` / `ForceFlags` at PEB + `0x18`/`0x10` on x64). Override the API, not the PEB.
- **Timing checks fail under a debugger even with ScyllaHide.** Single-stepping inflates every
  delta. Measure the delta of two consecutive reads in the same run, not wall-clock.
- **Some checks run only in a service or a child process.** Patching the parent does not
  affect a child that re-reads the file.
- **`CheckRemoteDebuggerPresent` writes to an output pointer.** Overriding the function to
  return false without zeroing the pointer leaves the previous value in place.
- **A CRC over `.text` computed at runtime changes when the code is patched.** If the CRC is
  computed over the live memory image, a patch made in memory changes the CRC; patch the
  comparison, not the stored value.

## References

- `IsDebuggerPresent`: <https://learn.microsoft.com/windows/win32/api/debugapi/nf-debugapi-isdebuggerpresent>
- `NtQueryInformationProcess`:
  <https://ntdoc.m417z.com/ntqueryinformationprocess>
- `NtSetInformationThread`: <https://ntdoc.m417z.com/ntsetinformationthread>
- `WinVerifyTrust`: <https://learn.microsoft.com/windows/win32/api/wintrust/nf-wintrust-winverifytrust>
- `CheckSumMappedFile`: <https://learn.microsoft.com/windows/win32/api/imagehlp/nf-imagehlp-checksummappedfile>
- Authenticode PE hashing: <https://learn.microsoft.com/openspecs/office_file_formats/ms-oshared/9177d4b2-d2d2-4ef1-9d0b-11046b71b2fe>
- `signtool` reference: <https://learn.microsoft.com/windows-hardware/drivers/devtest/signtool>
- Frida JavaScript API (`Interceptor.replace`): <https://frida.re/docs/javascript-api/>
- ScyllaHide: <https://github.com/x64dbg/ScyllaHide>
- Cross-reference: [win32-licence-ui-flow](win32-licence-ui-flow.md)
