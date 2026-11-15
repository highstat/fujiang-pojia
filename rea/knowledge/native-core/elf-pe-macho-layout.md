---
id: "elf-pe-macho-layout"
title: "ELF, PE and Mach-O layout for patching"
domain: "native-core"
kind: "format"
platforms: "-"
arch: "-"
difficulty: "intermediate"
tools: "radare2, rabin2, LIEF, readelf, objdump, otool"
verified: false
updated: "2026-11-15"
summary: "Translates virtual addresses to file offsets in ELF, PE and Mach-O images so a patch lands on the intended byte instead of an adjacent one, and locates the real entry point when the declared one is a packer stub."
---

## Summary

Every byte-level patch starts with one question: *this virtual address — where is it in the file?*
The three mainstream formats answer it with different tables. ELF maps memory with program
headers (`PT_LOAD`), PE maps memory with its section table, and Mach-O maps memory with
`LC_SEGMENT_64` load commands. Section tables exist in all three but only two of them drive the
loader.

This entry gives the conversion formula and a worked example for each format, explains what the
loader actually reads, and shows how to find the genuine entry point when the declared entry
points at unpacking code.

## Recognition

- Magic bytes at offset 0: `7f 45 4c 46` (ELF), `4d 5a` (PE, `MZ`), `cf fa ed fe` (Mach-O 64-bit
  little endian), `ca fe ba be` (fat/universal binary).
- A file whose section table exists but whose program headers are absent or nonsensical: a
  deliberately corrupted image, or a packed stub that reconstructs them.
- An image with one huge writable segment named `UPX0` and one read/execute segment named `UPX1`:
  the declared entry point is a decompressor, not the program.
- A PE with three or fewer imports (`kernel32.dll` only) but a large `.text` section: packed.
- A Mach-O whose `LC_ENCRYPTION_INFO_64` block reports `cryptid 1`: the first page of `__TEXT` is
  encrypted on disk and is decrypted by the loader at launch.

## Method

### Step 1 — Confirm the container before computing anything

Working directory: the folder holding the target.

```
xxd -l 16 target.bin
```

```
00000000: 7f45 4c46 0201 0100 0000 0000 0000 0000  .ELF............
00000000: 4d5a 9000 0300 0000 0400 0000 ffff 0000  MZ............
00000000: cffa edfe 0100 0007 0000 0001 0000 0000  ................
```

For PE, the `MZ` header is only a stub. The real header starts at the DWORD at offset `0x3c`:

```
xxd -s 0x3c -l 4 target.exe
0000003c: 8000 0000                                ....
xxd -s 0x80 -l 4 target.exe
00000080: 5045 0000                                PE..
```

### Step 2 — ELF: the program headers are the only thing the loader reads

The kernel maps a file by walking `PT_LOAD` entries. Section headers (`Elf64_Shdr`) can be
deleted entirely and the binary still loads and runs.

```
readelf -lW target.elf
```

The conversion for an address `va` that falls inside a `PT_LOAD` segment is:

```
file_offset = va - p_vaddr + p_offset
```

Validity test: the address must satisfy `p_vaddr <= va < p_vaddr + p_filesz`. Addresses in the
range `p_vaddr + p_filesz .. p_vaddr + p_memsz` exist only in memory; they have no file bytes and
cannot be patched on disk.

The section table gives the same answer with a different anchor:

```
readelf -SW target.elf | grep -E 'Name|\.text|\.rodata|\.data|\.bss'
```

`sh_addr` is the virtual address, `sh_offset` the file offset, `sh_size` the size in bytes.
For a section whose contents live in a `PT_LOAD`, `sh_offset` and the program-header formula
agree; for `.bss` (`SHT_NOBITS`) `sh_offset` is meaningless and only the memory image exists.

### Step 3 — ELF worked example

Given this `readelf -lW` output for a non-PIE x86-64 executable:

```
  LOAD           0x000000 0x0000000000400000 0x000f40 0x000f40 R E 0x1000
  LOAD           0x001000 0x0000000000402000 0x002468 0x002800 R   0x1000
  LOAD           0x004000 0x0000000000405000 0x000800 0x0011a0 RW  0x1000
```

with `e_entry = 0x400f60` and `.text` at `sh_addr = 0x400a40`, `sh_offset = 0x0a40`,
`sh_size = 0x500`:

| Virtual address | Segment used | File offset |
| --- | --- | --- |
| `0x400a40` (`.text` start) | LOAD @ `0x400000` | `0x400a40 - 0x400000 + 0x0000` = `0x0a40` |
| `0x400f60` (`e_entry`) | LOAD @ `0x400000` | `0x400f60 - 0x400000 + 0x0000` = `0x0f60` |
| `0x402340` | LOAD @ `0x402000` | `0x402340 - 0x402000 + 0x1000` = `0x1340` |
| `0x405120` | LOAD @ `0x405000` | `0x405120 - 0x405000 + 0x4000` = `0x4120` |
| `0x405800` (`.bss`) | LOAD @ `0x405000` | none — past `p_filesz` `0x800` |

Note the third row: the address looks like `0x402340` but the byte lives at `0x1340` in the file.
Applying the address directly as an offset lands 0x1010 bytes away, inside the wrong code.

### Step 4 — PE: the section table drives mapping, the data directories carry the loader tables

Parse order:

1. `e_lfanew` at file offset `0x3c` — offset of the `PE\0\0` signature.
2. `IMAGE_FILE_HEADER` (20 bytes) at `e_lfanew + 4`: `Machine`, `NumberOfSections`,
   `SizeOfOptionalHeader`, `TimeDateStamp`.
3. `IMAGE_OPTIONAL_HEADER` at `e_lfanew + 24`. For PE32+ it starts with `Magic = 0x20b` and
   contains `ImageBase` at optional-header offset `0x18`, `AddressOfEntryPoint` at offset `0x10`,
   `SectionAlignment` at `0x20`, `FileAlignment` at `0x24`, `SizeOfHeaders` at `0x3c`, and the
   16 data directories starting at offset `0x70`.
4. The section table starts at `e_lfanew + 4 + 20 + SizeOfOptionalHeader`, with 40 bytes per
   `IMAGE_SECTION_HEADER`.

Conversion for an RVA `rva` inside a section:

```
file_offset = rva - VirtualAddress + PointerToRawData
```

A section occupies `VirtualSize` bytes in memory but `SizeOfRawData` bytes on disk. When
`SizeOfRawData > VirtualSize` the tail is file-alignment padding. When `VirtualSize >
SizeOfRawData` the tail is zero-fill that exists only in memory.

### Step 5 — PE worked example

Header facts: `e_lfanew = 0x80`, `NumberOfSections = 5`, `SizeOfOptionalHeader = 0xf0`,
`ImageBase = 0x140000000`, `AddressOfEntryPoint = 0x2a10`, `SizeOfHeaders = 0x400`.

Section table starts at `0x80 + 4 + 20 + 0xf0 = 0x188`:

| Section | VirtualAddress (RVA) | VirtualSize | PointerToRawData | SizeOfRawData |
| --- | --- | --- | --- | --- |
| `.text` | `0x1000` | `0x1f40` | `0x0400` | `0x2000` |
| `.rdata` | `0x3000` | `0x0c00` | `0x2400` | `0x0c00` |
| `.data` | `0x4000` | `0x0600` | `0x3000` | `0x0400` |
| `.reloc` | `0x5000` | `0x01a0` | `0x3400` | `0x0200` |

| RVA | Section | File offset |
| --- | --- | --- |
| `0x2a10` (entry point) | `.text` | `0x2a10 - 0x1000 + 0x0400` = `0x1e10` |
| `0x3180` (string in `.rdata`) | `.rdata` | `0x3180 - 0x3000 + 0x2400` = `0x2580` |
| `0x42c0` (global in `.data`) | `.data` | `0x42c0 - 0x4000 + 0x3000` = `0x32c0` |
| `0x5180` | `.reloc` | `0x5180 - 0x5000 + 0x3400` = `0x3580` |

An RVA below `SizeOfHeaders` (`0x400`) is a file offset already: the PE headers are mapped
1:1 at the image base.

### Step 6 — Mach-O: `LC_SEGMENT_64` load commands drive mapping

The header is 32 bytes (`mach_header_64`); load commands follow immediately at offset `0x20`.
Each load command is 8 bytes of header (`cmd`, `cmdsize`) plus payload.

Mapping rule for a file offset inside a segment:

```
vaddr = seg.vmaddr + (file_offset - seg.fileoff)
```

and the inverse, for a virtual address inside a segment:

```
file_offset = seg.fileoff + (vaddr - seg.vmaddr)
```

Validity test for the inverse: `vaddr < seg.vmaddr + seg.vmsize` and the computed offset must be
below `seg.fileoff + seg.filesize`. The `__DATA` segment usually has `vmsize > filesize`; the
difference is the BSS zero-fill.

Section `offset` fields in current Mach-O are absolute file offsets. In images produced before
roughly 2006 they are relative to the enclosing segment's `fileoff`; check with
`otool -l` before trusting a raw offset.

### Step 7 — Mach-O worked example

`otool -l target.macho` reports:

```
LC_SEGMENT_64  __TEXT         vmaddr 0x100000000 vmsize 0x4000 fileoff 0x0000 filesize 0x4000
LC_SEGMENT_64  __DATA_CONST   vmaddr 0x100004000 vmsize 0x1000 fileoff 0x4000 filesize 0x1000
LC_SEGMENT_64  __DATA         vmaddr 0x100005000 vmsize 0x2000 fileoff 0x5000 filesize 0x1000
LC_MAIN        entryoff 0x1a40
```

with sections `__TEXT,__text` at `addr 0x100001000 size 0x0c40 offset 0x1000` and
`__TEXT,__cstring` at `addr 0x100001c40 size 0x1a0 offset 0x1c40`.

| Item | Virtual address | File offset |
| --- | --- | --- |
| `__text` start | `0x100001000` | `0x1000` |
| entry point | `0x100000000 + 0x1a40` = `0x100001a40` | `0x1a40` |
| string at `0x1c80` | `0x100001c80` | `0x1c80` |
| `__got` entry at `0x4020` | `0x100004020` | `0x4020` |
| `__DATA` at `0x5000` | `0x100005000` | `0x5000` |
| `__DATA` at `0x6100` | `0x100006100` | none — past `filesize` `0x1000` |

`LC_MAIN` stores `entryoff`, an **offset relative to the start of the `__TEXT` segment**, not a
virtual address. Add `__TEXT.vmaddr` to get the address.

### Step 8 — Load command versus section, per format

| Format | What the loader maps | What a debugger reads |
| --- | --- | --- |
| ELF | program headers (`PT_LOAD`, `PT_DYNAMIC`, `PT_INTERP`) | section headers; `SHT_NOBITS` for `.bss` |
| PE | the section table (each `IMAGE_SECTION_HEADER` becomes a mapping) | same table, plus the data directories |
| Mach-O | `LC_SEGMENT_64` / `LC_SEGMENT` load commands | sections inside those segments |

Consequences:

- ELF section headers can be stripped; the program headers cannot. `readelf -S` on a
  section-stripped ELF prints nothing and the binary still runs.
- Mach-O sections can be dropped with `strip -S`; the segments remain and the image still runs.
- PE has no separate "load command" concept, but the data directories in the optional header are
  the loader-visible tables: index 1 is the import directory, index 5 is the base relocation
  table, index 9 is the TLS directory, index 13 is the delay-import descriptor, index 4 is the
  certificate table. Patching a PE that moves code between sections must keep the relocation
  directory consistent, because the loader only applies relocations it finds there.

### Step 9 — Find the real entry point behind a packer stub

1. Establish that the entry point is a stub.

   ```
   rabin2 -I target.exe | grep -i entry
   rabin2 -S target.exe | grep -i -E 'UPX|aspack|petite|mpress'
   r2 -q -c 'iS~entry; ie' target.exe
   ```

   A packed binary has a tiny import table, a high-entropy section, and an entry point inside
   the packed region.

2. For ELF, `e_entry` is in the ELF header at offset `0x18` (64-bit). For PE it is the RVA in the
   optional header; convert with the section table. For Mach-O it is `LC_MAIN.entryoff` relative
   to `__TEXT`.

3. Locate the tail of the stub. Packers end the stub with a jump to the original entry point.
   In x86-64 the stub ends with `e9 <rel32>`; in x86 with `e9 <rel32>` or `ff 25 <disp32>`; in
   ARM64 with `b <imm26>` (`0x14000000` mask) or `br x16`.

   ```
   r2 -q -c 'aaa; pdf @ entry0' target.exe
   ```

   The last instruction of the stub is the jump. The OEP is
   `stub_end + rel32` for `e9`, `target` for a resolved address, and `pc + (imm26 << 2)` for
   ARM64 `b`.

4. Cross-check with the constructor tables, which run before the entry point and frequently
   contain the actual unpacker:

   ```
   rabin2 -i target.elf          # .init_array / .fini_array addresses
   objdump -s -j .init_array target.elf
   r2 -q -c 'iS~init_array; pxq 32 @ section..init_array' target.elf
   ```

   On PE, TLS callbacks run before the entry point and are listed in the TLS directory (data
   directory index 9); a packer that only unpacks in the TLS callback hides the stub from `OEP`.

5. On Mach-O, check `LC_ENCRYPTION_INFO_64`: `cryptid 1` means the first page of `__TEXT` is
   encrypted on disk and decrypted by the loader, so the declared entry point bytes on disk are
   ciphertext. Patch a location outside the first `0x4000` bytes of `__TEXT`, or patch after the
   loader has run.

6. When the stub is self-modifying, static recovery is unreliable. Dump the decrypted image from
   memory and diff it against the file, then patch the dump instead of the packed file.

### Step 10 — Read a section's raw offset and size with r2, rabin2 and LIEF

radare2 (`iS` prints vaddr, paddr, size, vsize):

```
r2 -q -c 'iS' target.exe
```

rabin2 (`-S` for sections, `-Sj` for JSON):

```
rabin2 -S target.exe
rabin2 -Sj target.exe | python3 -m json.tool | head -40
```

LIEF 1.0.0, PE:

```
python3 - <<'PY'
import lief
b = lief.PE.Binary("target.exe")
for s in b.sections:
    print(f"{s.name:10} rva=0x{s.virtual_address:08x} vsize=0x{s.virtual_size:06x} "
          f"raw=0x{s.pointerto_raw_data:06x} rawsz=0x{s.size:06x}")
PY
```

LIEF 1.0.0, ELF — use the segments, not the sections, for the offset:

```
python3 - <<'PY'
import lief
b = lief.ELF.Binary("target.elf")
for seg in b.segments:
    if seg.type == lief.ELF.Segment.TYPE.LOAD:
        print(f"LOAD vaddr=0x{seg.virtual_address:012x} off=0x{seg.file_offset:06x} "
              f"filesz=0x{seg.physical_size:06x} memsz=0x{seg.virtual_size:06x} "
              f"flags={seg.flags}")
PY
```

LIEF 1.0.0, Mach-O:

```
python3 - <<'PY'
import lief
b = lief.MachO.Binary("target.macho")
for seg in b.segments:
    print(f"{seg.name:12} vmaddr=0x{seg.virtual_address:012x} off=0x{seg.file_offset:06x} "
          f"filesz=0x{seg.file_size:06x} vmsz=0x{seg.virtual_size:06x}")
for sec in b.sections:
    print(f"  {sec.name:16} addr=0x{sec.virtual_address:012x} off=0x{sec.offset:06x} "
          f"size=0x{sec.size:06x}")
PY
```

If LIEF attribute names differ in the installed build, list them instead of guessing:

```
python3 -c "import lief; print([a for a in dir(lief.PE.Section) if not a.startswith('_')])"
```

## Variations

### 32-bit containers and the same rules

- ELF32: `Elf32_Phdr` is 32 bytes; `p_filesz`/`p_memsz` stay 32-bit; a `PT_LOAD` can hold a
  non-zero `p_offset` differing from `p_vaddr % page_size` only if the kernel honours the
  congruence. The formula is unchanged.
- PE32: `AddressOfEntryPoint` is at optional-header offset `0x10` as well, but `ImageBase` is at
  optional-header offset `0x1c` and is 4 bytes.
- Mach-O 32-bit: `struct mach_header` is 28 bytes, load commands start at `0x1c`, and
  `LC_MAIN` is absent — the entry point is `LC_UNIXTHREAD` (`e_entry` in the thread state) or the
  first `LC_LOAD_DYLIB` thread.

### Universal (fat) binaries

A fat Mach-O holds several thin images. `lipo -thin arm64 target.app -output target-arm64` extracts
one; every offset in this entry then refers to the thin file. `rabin2 -A target.app` lists the
architectures, each with its own `baseaddr` and `segments`.

### Images whose file offset is not addressable

Overlay data appended after the last section (a self-extracting archive, an appended ZIP) has no
virtual address at all. Patch it by absolute file offset; do not attempt an RVA conversion.
Detect the overlay as `file_size - (last_section.PointerToRawData + last_section.SizeOfRawData)`.

### Patching in memory instead of on disk

When the on-disk bytes cannot be reached — encrypted pages, self-modifying code, a mapped file
whose sections are not writable — apply the same offsets to the runtime image:

```
# Frida 17.x
const base = Process.getModuleByName("target.exe").base;
const off  = 0x1e10;                       // file offset == RVA for .text in this image
Memory.patchCode(base.add(off), 5, "b801000000");
```

`Memory.patchCode` takes the runtime address, not the file offset; the RVA equals the file
offset only for a module whose sections are laid out contiguously from the image base, which is
true for PE but not for a PIE ELF or a Mach-O with `__DATA` at a different file offset.

## Verification

1. Confirm the mapping, do not assume it. Write a byte, then read it back through the loader's
   view of the address:

   ```
   python3 - <<'PY'
   import lief
   b = lief.PE.Binary("target.exe")
   for s in b.sections:
       if s.virtual_address <= 0x2a10 < s.virtual_address + max(s.virtual_size, s.size):
           off = 0x2a10 - s.virtual_address + s.pointerto_raw_data
           print(f"entry RVA 0x2a10 -> file offset 0x{off:x}")
   PY
   ```

   Expect `file offset 0x1e10`.

2. Cross-check with a disassembler. The byte at the computed offset must be the start of the
   instruction the debugger shows at that address:

   ```
   xxd -s 0x1e10 -l 16 target.exe
   r2 -q -c 'pd 3 @ 0x140002a10' target.exe
   ```

   Both must show the same opcode bytes.

3. Negative test: deliberately compute a wrong offset by using the RVA as a file offset and
   confirm the disassembly at `0x2a10` differs from the disassembly at `0x1e10`. A mapping that
   is never checked against a wrong value has not been tested.

4. After editing, re-parse the whole file to prove it is still structurally valid:

   ```
   rabin2 -S target-patched.exe > /dev/null && echo "sections parse"
   r2 -q -c 'iI' target-patched.exe | head -5
   ```

5. For a packed image, verify the OEP candidate by loading the patched file and confirming the
   program reaches the original code, not the stub. A correct offset into a decompressor still
   fails.

## Pitfalls

- Using the RVA/VA as a file offset on PE. The two differ by `PointerToRawData - VirtualAddress`
  and are frequently off by thousands of bytes.
- Using the section table for ELF while the program headers disagree with it — possible after a
  hand-edited binary, and the loader follows the program headers.
- Patching a `.bss` address or any VA past `p_memsz`-relative `p_filesz` on disk: those bytes
  never existed in the file.
- Trusting `sh_offset` of an `SHT_NOBITS` section. It is a placeholder.
- Treating `LC_MAIN.entryoff` as an absolute address. It is relative to `__TEXT`.
- Reading Mach-O section `offset` as segment-relative in an old image and landing in the wrong
  segment.
- Assuming the section table is present. `readelf -S` printing nothing on ELF means use the
  program headers; `otool -l` printing no `LC_SEGMENT_64` means the image is not loadable.
- Patching the first page of an encrypted Mach-O (`cryptid 1`); the file bytes are ciphertext.
- Trusting `AddressOfEntryPoint` on a packed PE. The real entry is in a TLS callback or reached
  by the stub's final jump.
- Forgetting that a PE whose code moved between sections needs a matching update to the base
  relocation directory, otherwise the loader relocates the new location incorrectly.
- Offsets shift after any edit that changes the file size. Apply edits at the highest offset
  first, or write into a pre-existing section's slack rather than growing the file.

## References

- System V ABI, ELF gABI: <https://www.sco.com/developers/gabi/> — `PT_LOAD` mapping rules.
- ELF64 specification, Linux Foundation: <https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.sheader.html>
- Microsoft PE format: <https://learn.microsoft.com/windows/win32/debug/pe-format>
- Microsoft PE COFF spec revision 8.3: <https://download.microsoft.com/download/t/8/9/t89c22b4-7d63-4071-92e5-6a64b0f43a70/pecoff_v83.docx>
- Apple Mach-O Programming Topics, load commands and segments: <https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/MachOOverview.html>
- `llvm-objdump --macho --private-headers`: <https://llvm.org/docs/CommandGuide/llvm-objdump.html>
- LIEF documentation: <https://lief.re/doc/latest/>
- radare2 documentation: <https://r2.re>
