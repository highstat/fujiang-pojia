---
id: "pe-section-and-entry-analysis"
title: "PE section and entry point analysis"
domain: "windows-native"
kind: "format"
platforms: "windows"
arch: "x86, x86-64, arm64"
difficulty: "intro"
tools: "rabin2,r2,dumpbin,LIEF,pefile,Ghidra"
verified: false
updated: "2026-11-15"
summary: "Reads a Windows PE image from the DOS header through the section table to the entry point and import directory, and flags packed or protected images before any licence work begins."
---

## Summary

The PE header is the cheapest map of a Windows binary: it names the sections, gives the entry
point, and lists the DLLs the program needs before it runs a single instruction. Licence logic
lives in sections, so the section table tells where to look and what kind of code is there.

Use this entry as the first pass over any native Windows target: establish the image type
(PE32 vs PE32+), the section layout, the entry point, and the import set. If the image is packed
or protected, the header is the evidence, and every later step (finding the check, patching it)
depends on reaching the unpacked code first.

Cross-reference: [managed-native-interop-hybrid](../windows-dotnet/managed-native-interop-hybrid.md)
for the case where the licence decision is delegated to a native DLL that needs the same
treatment.

## Recognition

Symptoms that point here:

- The target is a bare `.exe`/`.dll` with no accompanying source or symbols, and the first
  question is "where does the code live".
- A hex dump opens with `4d 5a` and the analyst cannot say where the sections begin.
- `rabin2 -S` lists section names the author never chose: `UPX0`, `.themida`, `.vmp0`, `.vmp1`,
  `.aspack`, `.enigma1`, `.ndata`, `.sforce`, `CODE`, `.petite`.
- `rabin2 -i` returns a handful of imports (5 to 20) for a program that clearly needs
  `kernel32`, `user32`, `gdi32`, `advapi32`.
- The entry point address does not fall inside `.text`.
- A section named `.text` has `VirtualSize` far larger than `SizeOfRawData`, or has
  `IMAGE_SCN_MEM_WRITE` set, meaning the code rewrites itself at runtime.

Header facts that identify the format:

| Field | PE32 | PE32+ |
| --- | --- | --- |
| Optional header magic | `0x010b` → bytes `0b 01` | `0x020b` → bytes `0b 02` |
| Optional header size | 224 bytes (`e0 00`) | 240 bytes (`f0 00`) |
| ImageBase | 4 bytes, usually `0x00400000` | 8 bytes, usually `0x0000000140000000` |
| Data directory base | optional header + `0x60` | optional header + `0x70` |

## Method

Working directory for every command below: the directory that contains the target file.

### 1. Dump the raw header before trusting any tool

Open the file in a hex editor, or dump the first 512 bytes:

```bash
xxd -l 512 target.exe
```

Read it as a fixed chain of offsets:

- `0x00`: DOS signature, bytes `4d 5a` ("MZ").
- `0x3c`: `e_lfanew`, a 4-byte little-endian file offset to the NT headers. Typical value
  `e8 00 00 00` (0xe8) for MSVC-located headers, or `d8 00 00 00` for some linkers.
- At `e_lfanew`: NT signature, bytes `50 45 00 00` ("PE\0\0"). If these bytes are absent, the
  file is not a PE image.
- `e_lfanew + 4`: COFF file header, 20 bytes.

COFF file header layout, offsets relative to its own start:

| Offset | Size | Field |
| --- | --- | --- |
| `0x00` | 2 | `Machine` — `0x014c` = x86, `0x8664` = x64, `0xaa64` = ARM64 |
| `0x02` | 2 | `NumberOfSections` |
| `0x04` | 4 | `TimeDateStamp` |
| `0x08` | 4 | `PointerToSymbolTable` |
| `0x0c` | 4 | `NumberOfSymbols` |
| `0x10` | 2 | `SizeOfOptionalHeader` — `0xe0` for PE32, `0xf0` for PE32+ |
| `0x12` | 2 | `FileCharacteristics` |

`FileCharacteristics` flags worth noting: `0x0002` executable image, `0x0020` large address
aware, `0x2000` DLL, `0x0100` 32-bit machine.

- `e_lfanew + 0x18`: optional header.
- `e_lfanew + 0x18 + SizeOfOptionalHeader`: section table, 40 bytes per entry.

### 2. Map the optional header fields

Offsets below are relative to the start of the optional header.

| Offset | Size | Field |
| --- | --- | --- |
| `0x00` | 2 | `Magic` — `0x010b` PE32, `0x020b` PE32+ |
| `0x04` | 4 | `SizeOfCode` |
| `0x08` | 4 | `SizeOfInitializedData` |
| `0x0c` | 4 | `SizeOfUninitializedData` |
| `0x10` | 4 | `AddressOfEntryPoint` (RVA) |
| `0x14` | 4 | `BaseOfCode` |
| `0x18` | 4 (PE32) | `BaseOfData` |
| `0x18` | 8 (PE32+) | `ImageBase` |
| `0x20` | 4 | `SectionAlignment` (usually `00 10 00 00`) |
| `0x24` | 4 | `FileAlignment` (usually `00 02 00 00` or `00 10 00 00`) |
| `0x38` | 4 | `SizeOfImage` |
| `0x3c` | 4 | `SizeOfHeaders` |
| `0x40` | 4 | `CheckSum` |
| `0x44` | 2 | `Subsystem` — `2` = GUI, `3` = console |
| `0x46` | 2 | `DllCharacteristics` — `0x0040` = ASLR, `0x0100` = NX, `0x0400` = no SEH |
| `0x5c` | 4 | `NumberOfRvaAndSizes` — normally 16 |

The entry point RVA lives at optional header + `0x10`. Convert it to a file offset by finding
the section that contains it:

```text
for each section S:
    if S.VirtualAddress <= RVA < S.VirtualAddress + max(S.VirtualSize, S.SizeOfRawData):
        file_offset = RVA - S.VirtualAddress + S.PointerToRawData
```

### 3. Read the section table

Each section header is 40 bytes:

| Offset | Size | Field |
| --- | --- | --- |
| `0x00` | 8 | `Name`, null-padded ASCII |
| `0x08` | 4 | `VirtualSize` (in memory) |
| `0x0c` | 4 | `VirtualAddress` (RVA) |
| `0x10` | 4 | `SizeOfRawData` (on disk) |
| `0x14` | 4 | `PointerToRawData` (file offset) |
| `0x24` | 4 | `Characteristics` |

`Characteristics` bits that decide where a licence check can live:

| Value | Name | Meaning for licence work |
| --- | --- | --- |
| `0x20000000` | `IMAGE_SCN_MEM_EXECUTE` | runnable code; the check itself |
| `0x40000000` | `IMAGE_SCN_MEM_READ` | code and read-only data |
| `0x80000000` | `IMAGE_SCN_MEM_WRITE` | writable data, or self-modifying code |
| `0x00000020` | `IMAGE_SCN_CNT_CODE` | contains instructions |
| `0x00000040` | `IMAGE_SCN_CNT_INITIALIZED_DATA` | contains initialized data |
| `0x00000080` | `IMAGE_SCN_CNT_UNINITIALIZED_DATA` | `.bss` equivalent, zero at load |
| `0x02000000` | `IMAGE_SCN_MEM_DISCARDABLE` | relocatable, may be dropped after load |

The four sections that matter in almost every Windows binary:

- `.text` — code. A licence comparison, a call to `MessageBoxW`, an RSA verification routine.
- `.rdata` — read-only data: import descriptors, string literals, constants, vtables. Licence
  error messages and the expected CRC or hash live here.
- `.data` — writable initialized data: cached licence state, the serial buffer, class members.
- `.rsrc` — resources: dialog templates (`RT_DIALOG`, type 5), string tables (`RT_STRING`,
  type 6), version info (`RT_VERSION`, type 16), manifests (`RT_MANIFEST`, type 24).

A licence check that lives in `.text` and reads a key from `.data` and a message from `.rdata`
is the ordinary case. A check whose message lives in `.rsrc` and whose templates also live in
`.rsrc` is the dialog-driven case.

### 4. Use the tools

```bash
# Whole-image summary: arch, bits, class, subsystem, stripped flags
rabin2 -I target.exe

# Section table: name, paddr, size, vaddr, vsize, permissions
rabin2 -S target.exe

# Entry point and exports
rabin2 -e target.exe

# Import table: library, symbol, type
rabin2 -i target.exe

# Full PE header dump
rabin2 -H target.exe
```

Interpretation of `rabin2 -S` output columns: `paddr` is the file offset of the section,
`vaddr` is the RVA, `vsize` is the in-memory size, `perm` renders the characteristics as
`rwx` strings. A section whose `vsize` is much larger than `size` is a BSS-like or
self-expanding region.

MSVC toolchain, from a Visual Studio developer prompt:

```bat
dumpbin /headers target.exe
dumpbin /imports target.exe
dumpbin /dependents target.exe
dumpbin /exports target.exe
```

`dumpbin /headers` prints `entry point` as `ImageBase + AddressOfEntryPoint` and lists the
sections with their characteristics flags spelled out.

LIEF 1.0.0, scripted so the result is repeatable:

```bash
python3 - <<'PY'
import lief
pe = lief.PE.parse("target.exe")
print("machine", pe.header.machine, "magic", hex(pe.optional_header.magic))
print("entry rva", hex(pe.optional_header.addressof_entrypoint))
print("imagebase", hex(pe.optional_header.imagebase))
for s in pe.sections:
    print(s.name, "rva", hex(s.virtual_address), "vsize", hex(s.size),
          "raw", hex(s.offset), hex(s.physical_size),
          "chars", hex(s.characteristics))
for imp in pe.imports:
    print(imp.name, [e.name if e.name else str(e.ordinal) for e in imp.entries])
PY
```

pefile, for scripts that need the raw RVA-to-offset mapping:

```bash
python3 - <<'PY'
import pefile
pe = pefile.PE("target.exe")
print("entry", hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint), "fileoff",
      hex(pe.get_offset_from_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint)))
for s in pe.sections:
    print(s.Name.rstrip(b"\x00").decode(), hex(s.VirtualAddress),
          hex(s.Misc_VirtualSize), hex(s.SizeOfRawData), hex(s.PointerToRawData),
          hex(s.Characteristics), "entropy", round(s.get_entropy(), 3))
print("imphash", pe.get_imphash())
PY
```

### 5. Read the import directory by hand when a tool is unavailable

The import directory is data directory index 1, an RVA pair (`ImportTable` RVA and size) at
optional header + `0x68` for PE32, `0x78` for PE32+. It points at an array of
`IMAGE_IMPORT_DESCRIPTOR`, 20 bytes each, terminated by an all-zero descriptor:

| Offset | Field |
| --- | --- |
| `0x00` | `OriginalFirstThunk` — RVA to the INT (names), 0 if bound |
| `0x0c` | `Name` — RVA to the DLL name string |
| `0x10` | `FirstThunk` — RVA to the IAT (addresses patched by the loader) |

Each DLL name is a plain ASCII string such as `KERNEL32.dll`. The INT entries point at
`IMAGE_IMPORT_BY_NAME` structures: a 2-byte hint followed by the ASCII name
(`MessageBoxW`, `RegQueryValueExW`). A minimal import table with only `LoadLibraryA` and
`GetProcAddress` is the classic packer signature.

### 6. Detect packing or protection

Run all three checks; any one of them is a warning, all three together are conclusive:

```bash
python3 - <<'PY'
import pefile, math
pe = pefile.PE("target.exe")
def entropy(b):
    if not b: return 0.0
    counts = [0]*256
    for x in b: counts[x] += 1
    n = len(b)
    return -sum((c/n)*math.log2(c/n) for c in counts if c)
for s in pe.sections:
    data = s.get_data()
    e = entropy(data)
    flags = []
    if e > 7.2: flags.append("HIGH-ENTROPY")
    if s.Misc_VirtualSize > s.SizeOfRawData * 4: flags.append("EXPANDS")
    if s.Characteristics & 0x20000000 and s.Characteristics & 0x80000000:
        flags.append("RWX")
    if s.Name.rstrip(b"\x00") in (b"UPX0", b"UPX1", b".vmp0", b".vmp1", b".themida"):
        flags.append("KNOWN-PACKER-NAME")
    print(s.Name.rstrip(b"\x00").decode(errors="replace"), round(e,3), flags)
if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
    n = sum(len(i.imports) for i in pe.DIRECTORY_ENTRY_IMPORT)
    print("imported symbols", n)
else:
    print("no import directory")
print("entry section", pe.get_section_by_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
PY
```

Interpretation:

- Section entropy above 7.2 for a data section means encrypted or compressed content. Native
  code normally sits between 5.5 and 6.8.
- Entry point outside `.text` means the loader jumps into a decompression stub.
- Fewer than about 20 imports means the real import table is rebuilt at runtime.
- A section that is both executable and writable means self-modifying code.

### 7. Act on a packed image

1. Try the packer's own unpacker first:

   ```bash
   upx -l target.exe
   upx -d target.exe -o target.unpacked.exe
   ```

2. Otherwise unpack at runtime: load the image in x64dbg, let the unpacker finish, break on the
   original entry point (dump the image with Scylla), then rebuild the import table with the
   x64dbg "Import Reconstruction" / Scylla "Fix Dump" plugin, or with `ImpREC`.

3. Compare the dumped image against the packed one. The unpacked `.text` holds the licence
   strings and the real import table; the packed stub holds only the loader.

## Variations

- **PE32+ (x64, ARM64)**: `ImageBase` is 8 bytes, there is no `BaseOfData` field, and the data
  directories start 16 bytes later. Every optional-header offset after `0x18` is identical, so
  `AddressOfEntryPoint` at `0x10` and `CheckSum` at `0x40` are stable across both.
- **DLL versus EXE**: `FileCharacteristics & 0x2000` marks a DLL. A DLL has no meaningful
  entry point; find the export table (data directory index 0) and the `DllMain`/`DllMainCRTStartup`
  instead.
- **.NET assemblies**: data directory index 14 (CLR Runtime Header) is present. The IL, not the
  native code, holds the logic; see [il-licence-check-editing](../windows-dotnet/il-licence-check-editing.md).
- **Delay imports**: data directory index 13 holds a separate table for DLLs bound at first
  call. `rabin2 -i` does not always show them; `dumpbin /imports` does.
- **.NET NativeAOT**: no CLR header, but the image is native with embedded managed metadata.
  Use the native path and the REA `inspect_binary_layout` view.
- **Drivers (`.sys`)**: the PE checksum *is* enforced, the file is expected to be signed, and
  `SectionAlignment` equals `FileAlignment` (0x200). Entry-point analysis still applies but the
  licence question is usually answered server-side.

## Verification

Prove the header reading is correct rather than assumed:

1. **Round-trip the entry point.** Take the entry-point RVA from the header, convert it to a file
   offset with the section formula, and check that the bytes there disassemble to a plausible
   function start:

   ```bash
   r2 -q -c 's entry0; pd 12' target.exe
   ```

   A valid entry point ends with `ret`/`jmp` and pushes/loads the stack cookie or the
   `__security_init_cookie` pattern; garbage bytes mean the offset mapping is wrong.

2. **Cross-check two tools.** `rabin2 -e`, `dumpbin /headers` and the LIEF script must agree on
   the entry point RVA and on the section list. Disagreement means the file is not a plain PE
   (it may be a PE with an appended overlay, or a memory dump).

3. **Negative test for the packer detector.** Run the entropy/import script on a known
   unprotected binary: expect entropy under 7.0 per section and more than 20 imports. If the
   detector fires on a normal binary, the thresholds are wrong, not the binary.

4. **Overlay check.** Confirm that the file ends where the last section ends, or account for the
   difference:

   ```bash
   python3 -c "import pefile;p=pefile.PE('target.exe');import os;last=max(s.PointerToRawData+s.SizeOfRawData for s in p.sections);print('file',os.path.getsize('target.exe'),'sections end',last)"
   ```

   A non-zero difference is an overlay: an installer payload, an appended Authenticode
   certificate, or a second embedded PE. Overlay content is a separate binary with its own
   header and its own licence logic.

## Pitfalls

- **Editing a byte invalidates two things at once**: the PE `CheckSum` field and the
  Authenticode signature. Recompute or re-sign, or the loader and Windows will reject the file.
  See [windows-integrity-and-tamper-checks](windows-integrity-and-tamper-checks.md).
- **The certificate table is a file offset, not an RVA.** Data directory index 4 holds a raw
  file offset; every other directory holds an RVA. Converting it as an RVA lands in the wrong
  place.
- **Matching section names is not proof.** Legitimate binaries use `.text`, `.rsrc`, `.reloc`,
  but also `.data1`, `.didat`, `CODE`, `DATA`, `BSS` (Delphi, MASM, MinGW). Combine the name
  with the entropy and import-count evidence.
- **High entropy in `.rsrc` is normal.** Compressed resources, PNG payloads and CAB archives all
  score high. Restrict the entropy heuristic to `.text` and `.rdata`.
- **The entry point is not the licence check.** A check invoked from `WndProc` or from a
  thread has no relation to `AddressOfEntryPoint`.
- **`SizeOfRawData` is padded to `FileAlignment`.** Two sections can share a file offset region
  for BSS-like content; the trailing bytes are zeros and are not part of the data.
- **`VirtualSize` smaller than `SizeOfRawData`** happens when a section is padded on disk; the
  extra bytes are alignment, not content.
- **Rebuilding a dumped image** produces imports that are wrong until the import table is fixed.
  A licence check that calls `MessageBoxW` through a rebuilt IAT must be re-resolved before the
  dump is analysed.

## References

- Microsoft PE Format specification: <https://learn.microsoft.com/windows/win32/debug/pe-format>
- `IMAGE_SECTION_HEADER`, `IMAGE_OPTIONAL_HEADER64`, `IMAGE_IMPORT_DESCRIPTOR`:
  <https://learn.microsoft.com/windows/win32/debug/pe-format>
- LIEF 1.0.0 PE documentation: <https://lief.re/doc/latest/api/python/pe.html>
- pefile documentation: <https://pefile.readthedocs.io/>
- radare2 `rabin2` usage: <https://man.archlinux.org/man/rabin2.1>
- UPX project: <https://upx.github.io/>
- Cross-reference: [managed-native-interop-hybrid](../windows-dotnet/managed-native-interop-hybrid.md)
