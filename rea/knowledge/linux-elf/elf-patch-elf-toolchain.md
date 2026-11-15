---
id: "elf-patch-elf-toolchain"
title: "ELF patching with the patchelf and LIEF toolchain"
domain: "linux-elf"
kind: "technique"
platforms: "linux"
arch: "x86, x86-64, arm64"
difficulty: "intermediate"
tools: "patchelf,lief,r2,dd,python3,rasm2"
verified: false
updated: "2026-11-15"
summary: "Catalogues what each patchelf subcommand changes in the ELF structure, explains the layout-corruption failure mode that stops a patched binary from loading, presents LIEF 1.0.0 as the safer rewriting path, and covers byte-level .text patching plus the build-id and package-signature consequences."
---

## Summary

Editing an ELF binary touches a structure that the loader trusts: the program headers, the dynamic
segment, the string tables and the section header table all reference each other by offset. This
entry covers the `patchelf` operations and the structural change each one makes, the failure mode
where a patched binary stops loading, the LIEF 1.0.0 API for a safer rewrite, raw byte patching of
`.text`, and the signature and `build-id` consequences. Reach for it when a patch is needed and the
binary must still start.

## Recognition

- `patchelf --print-needed ./target` lists `libc.so.6` and friends.
- `patchelf --print-rpath ./target` shows `RUNPATH` entries; `readelf -d ./target` shows the
  corresponding `DT_RUNPATH` or `DT_RPATH` tag.
- `readelf -l ./target` shows a `PT_INTERP` segment with `INTERP` at offset 0 pointing at
  `/lib64/ld-linux-x86-64.so.2`.
- `readelf -S ./target` lists `.dynstr`, `.dynsym`, `.gnu.hash`, `.text` and `.note.gnu.build-id`.
- After a bad `patchelf` run, the loader prints
  `error while loading shared libraries: ... cannot open shared object file: No such file or directory`
  or `ld.so: error: ... unsupported dynamic tag` or the binary dies with `Segmentation fault` before
  `main`.
- `file ./target` after a corrupt rewrite reports `not a dynamic executable` or
  `ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), for GNU/Linux 3.2.0, not stripped`
  where the interpreter string is gone.
- `readelf -h ./target` shows `Section header string table index` out of range or `Number of section
  headers: 0` after a truncated rewrite.

## Method

### 1. Establish the baseline

```bash
cd /path/to/work
cp ./target ./target.orig
sha256sum ./target.orig
file ./target
readelf -h ./target | head -20
readelf -d ./target
readelf -l ./target | grep -A2 INTERP
```

Keep `target.orig`. Every operation below is reversible only from that copy.

### 2. The patchelf operations and what each changes

```bash
patchelf --print-needed ./target
patchelf --print-rpath ./target
patchelf --print-interpreter ./target
```

**`--replace-needed OLD NEW`** rewrites one `DT_NEEDED` entry in `.dynstr`. If `NEW` is longer than
`OLD`, the string table must grow; `patchelf` moves `.dynstr` to a new offset and updates
`DT_STRTAB`, `DT_STRSZ` and the section header for `.dynstr`.

```bash
patchelf --replace-needed libcurl.so.4 libcurl.so.4.8.0 ./target
readelf -d ./target | grep NEEDED
```

**`--add-needed NEW`** appends a `DT_NEEDED` entry, growing `.dynstr` in the same way. The new
library is searched *after* the existing entries.

```bash
patchelf --add-needed libhook.so ./target
readelf -d ./target | grep NEEDED
```

**`--remove-needed OLD`** deletes a `DT_NEEDED` entry. The string stays in `.dynstr` as dead space;
only the dynamic array shrinks.

```bash
patchelf --remove-needed libcurl.so.4 ./target
readelf -d ./target | grep NEEDED
```

**`--set-rpath PATH`** replaces the run path. Newer `patchelf` writes `DT_RUNPATH`; `--force-rpath`
writes the older `DT_RPATH`, which is searched *before* the `LD_LIBRARY_PATH` and is the only one
honoured for setuid binaries.

```bash
patchelf --set-rpath '$ORIGIN/../lib' ./target
readelf -d ./target | grep -E 'RUNPATH|RPATH'
```

Use the single quotes so the shell does not expand `$ORIGIN`.

**`--remove-rpath`** deletes both `DT_RUNPATH` and `DT_RPATH`.

```bash
patchelf --remove-rpath ./target
readelf -d ./target | grep -E 'RUNPATH|RPATH'   # -> no output
```

**`--set-interpreter PATH`** replaces the `PT_INTERP` segment content, which is the path of the
dynamic loader the kernel executes.

```bash
patchelf --set-interpreter /lib64/ld-linux-x86-64.so.2 ./target
readelf -l ./target | grep -A2 INTERP
```

**`--replace-needed` plus `--set-rpath`** is the classic combination for redirecting a library:

```bash
patchelf --replace-needed libreal.so.1 libfake.so.1 ./target
patchelf --set-rpath '$ORIGIN' ./target
```

### 3. The layout-corruption failure mode

`patchelf` versions before 0.14 rewrote the ELF in place and could leave the file inconsistent.
The symptoms are specific:

- the section header table is left with a wrong count or a wrong `e_shoff`, so `readelf -S` prints
  `Section header string table index 0 points to a null string` or `readelf: Warning: .got.plt section is not in a segment`;
- `PT_DYNAMIC` keeps its old `p_offset`/`p_filesz`, so the dynamic array no longer overlaps the
  `.dynamic` section and the loader reads zeros instead of tags;
- the `PT_INTERP` string is overwritten with NUL bytes because the new interpreter path was written
  over the old one without extending the segment.

Detect the damage before running anything:

```bash
readelf -h ./target | grep -E 'Start of section headers|Number of section headers|Size of section headers'
readelf -S ./target | grep -E '\[.*\] \.dynstr|\.dynamic|\.dynsym'
readelf -d ./target | grep -E 'NEEDED|STRTAB|STRSZ'
readelf -l ./target | grep -B1 -A3 'Dynamic section'
```

Repair path: restore `target.orig` and use LIEF instead, or use a current `patchelf` (0.18 or
later), which rebuilds the layout properly.

### 4. LIEF 1.0.0 as the safer path

```python
#!/usr/bin/env python3
# lief_rewrite.py — LIEF 1.0.0
import lief

binary = lief.ELF.parse("target")
if binary is None:
    raise SystemExit("parse failed")

# Add a DT_NEEDED entry.
binary.add_library("libhook.so")

# Replace an existing entry.
entry = binary.get_library("libreal.so.1")
if entry is not None:
    entry.name = "libfake.so.1"

binary.write("target.lief")
```

```bash
python3 lief_rewrite.py
readelf -d target.lief | grep NEEDED
readelf -h target.lief | grep -E 'Number of section headers'
```

LIEF rebuilds the segment and section layout rather than editing in place, so the result stays
loadable. It also preserves the `PT_INTERP` segment and the `.note.gnu.build-id` note by default.

For the interpreter and the run path:

```python
binary.interpreter = "/lib64/ld-linux-x86-64.so.2"
binary.rpath = ["$ORIGIN/../lib"]
binary.write("target.lief")
```

### 5. Patch a byte at a virtual address with LIEF

```python
#!/usr/bin/env python3
# lief_patch.py — LIEF 1.0.0, patch one byte at a virtual address
import lief
import struct
import sys

PATH = "target"
VADDR = 0x1234
NEW_BYTE = 0x90            # NOP on x86-64

binary = lief.ELF.parse(PATH)
if binary is None:
    raise SystemExit("parse failed")

# Preferred path: the patch_address helper exposed by the binary surfaces.
if hasattr(binary, "patch_address"):
    binary.patch_address(VADDR, [NEW_BYTE])
    binary.write("target.patched")
    print("patched via patch_address")
    sys.exit(0)

# Fallback: map the virtual address to a file offset through the segments
# and write the byte directly.
def vaddr_to_offset(binary, vaddr):
    for segment in binary.segments:
        if segment.type == lief.ELF.Segment.TYPE.LOAD:
            if segment.virtual_address <= vaddr < segment.virtual_address + segment.virtual_size:
                return segment.file_offset + (vaddr - segment.virtual_address)
    raise SystemExit(f"virtual address 0x{vaddr:x} is not mapped by a PT_LOAD segment")

offset = vaddr_to_offset(binary, VADDR)
print(f"vaddr 0x{VADDR:x} -> file offset 0x{offset:x}")

data = bytearray(open(PATH, "rb").read())
print("before:", data[offset:offset + 4].hex(" "))
data[offset] = NEW_BYTE
print("after: ", data[offset:offset + 4].hex(" "))
open("target.patched", "wb").write(bytes(data))
```

The fallback is the portable one: `patch_address` is present on the Mach-O and PE surfaces across
LIEF versions and on the ELF surface in recent releases, so always keep the segment-mapped write
available.

### 6. Byte-level patching of `.text`

Build the byte sequence with the assembler first:

```bash
rasm2 -a x86 -b 64 -d 'mov eax, 1'
rasm2 -a arm -b 64 -d 'mov w0, #1'
```

Expected:

```text
b8 01 00 00 00
20 00 80 52
```

`mov eax, 0` is `b8 00 00 00 00`; `mov eax, 1` is `b8 01 00 00 00`.
`mov w0, #0` is `00 00 80 52`; `mov w0, #1` is `20 00 80 52`.

Locate the site, then patch it with any of the three tools:

```bash
# radare2 (virtual addressing is on by default for ELF)
r2 -qc 'aaa; s 0x1234; p8 8' ./target
r2 -w -qc 'wx b801000000 @ 0x1234; q' ./target
r2 -qc 'aaa; s 0x1234; p8 8' ./target
```

```bash
# GNU coreutils dd, hex offsets accepted
printf '\xb8\x01\x00\x00\x00' | dd of=./target bs=1 seek=$((0x1234)) count=5 conv=notrunc
```

```bash
# Python
python3 - <<'PY'
path = "target"
offset = 0x1234
new = bytes.fromhex("b8 01 00 00 00".replace(" ", ""))
with open(path, "r+b") as f:
    f.seek(offset)
    old = f.read(len(new))
    f.seek(offset)
    f.write(new)
print("old:", old.hex(" "))
print("new:", new.hex(" "))
PY
```

`dd` without `conv=notrunc` truncates the file at the write point, destroying everything after it.

### 7. The build-id and the signature consequences

ELF has no general code signature that the loader enforces. What does exist:

- **GNU build-id.** A `.note.gnu.build-id` section holds a hash of the binary. Nothing checks it at
  load time, but debuggers, `debuginfod`, `rpm -V` and reproducible-build tooling use it to match a
  binary with its symbols. After patching, regenerate or clear it:

```bash
readelf -n ./target | grep -A2 'Build ID'
# rebuild with a matching id:
gcc -Wl,--build-id=sha1 -o target.rebuilt target.c
```

- **GPG detached signatures.** A release tarball can carry a detached signature over the file:

```bash
gpg --detach-sign -u keyid ./target          # produces ./target.sig
gpg --verify ./target.sig ./target            # fails after any byte change
```

- **`dpkg-sig` / `debsigs`.** Package-level signature for `.deb` files, verified with
  `debsigs-verify`. The signature covers the `.deb` archive, not the installed file, so a patched
  installed binary is not covered by it.
- **RPM signatures.** `rpm --checksign pkg.rpm` verifies the RPM header and payload signatures; a
  patched *installed* file is detected by `rpm -V pkgname` (file digest mismatch), not by the
  package signature.
- **UEFI Secure Boot / pesign.** A signed kernel or a signed initramfs is verified by the kernel
  under lockdown. `sbverify --list ./target` lists the certificates; the signing tool is
  `sb-sign` from the `pesign` package:

```bash
sb-sign --cert /etc/pki/pesign/x509.crt --key /etc/pki/pesign/x509.key --output ./target.signed ./target
sbverify --list ./target.signed
```

A binary with a PE/COFF signature must be patched *before* signing, never after.

## Variations

- **`ld` instead of `patchelf`.** Recompiling with `-Wl,--wrap=sym` or linking a replacement
  library produces a binary that is correct by construction, at the cost of a toolchain and the
  original build flags.
- **`chrpath`.** A smaller tool that edits `DT_RPATH`/`DT_RUNPATH` in place; it does not grow the
  string table, so it cannot lengthen a path.
- **`patchelf --shrink`** removes the section header table entirely. Smaller output, but tools that
  need sections (radare2 symbol loading, `objdump -d`) lose their anchors; use `--shrink-rpath` or
  keep the sections when analysis follows the patch.
- **`LIEF` on other formats.** The same `parse`/`add`/`write` pattern applies to PE and Mach-O; the
  1.0.0 API surface is documented per format.
- **Static binaries.** `patchelf` reports `patchelf: cannot modify section header` or cannot find a
  dynamic segment; there is nothing to patch structurally. Only raw byte patching applies.
- **PIE and ASLR.** A `Type: DYN` PIE is loaded at a random base; `r2` resolves virtual addresses
  relative to the load base, so a runtime address must be rebased before it is used as a file
  offset. `readelf -l` gives the mapping needed to convert.
- **Android.** An `arm64` ELF inside an APK is loaded by the same linker but with the linker
  namespace restrictions of the platform; `DT_NEEDED` additions must resolve to a library inside the
  APK's native library directory.

## Verification

Positive — the structural change landed and the binary still loads:

```bash
cd /path/to/work
readelf -d ./target | grep -E 'NEEDED|RUNPATH|RPATH'
readelf -l ./target | grep -A2 INTERP
readelf -h ./target | grep -E 'Number of section headers|Start of section headers'
ldd ./target
./target ; echo "exit=$?"
```

Expected: the new entry is present, `ldd` resolves every dependency, and the program exits with its
normal status.

Negative — the patch is real and not cosmetic. Confirm the byte changed and that the behaviour
changed:

```bash
r2 -qc 'aaa; s 0x1234; p8 8' ./target
./target > /tmp/after.txt 2>&1 ; echo "exit=$?"
```

Expected: the bytes at the address match the new sequence and the program's output differs from
the unpatched run.

Negative — the layout is intact. Compare the section and segment tables of the patched copy
against the original:

```bash
readelf -S ./target.orig > /tmp/sec.orig
readelf -S ./target      > /tmp/sec.new
diff <(grep -E '^\s*\[' /tmp/sec.orig | awk '{print $2}') <(grep -E '^\s*\[' /tmp/sec.new | awk '{print $2}')
```

Expected: no output, i.e. the section list is unchanged in names and order.

Negative — the signature story:

```bash
gpg --verify ./target.sig ./target
```

Expected: `BAD signature` after any byte change. That is the expected consequence of patching a
signed artefact, and it is the reason a rebuild or a re-sign must follow the patch.

## Pitfalls

- `dd` without `conv=notrunc` truncates the file at the write point. Always pass it.
- `patchelf` on a stripped binary keeps the section table but drops nothing else; on a binary with
  a `DT_RELR` or a `DT_GNU_HASH` with a bloom filter, an old `patchelf` rebuild can produce a
  loader error about `unexpected reloc type`.
- Growing `.dynstr` shifts the file offsets of everything after it. A patch applied by file offset
  before the `patchelf` run is invalid afterwards; always re-locate the site after a structural
  edit.
- `patchelf --set-rpath '$ORIGIN'` must be quoted, otherwise the shell expands `$ORIGIN` to an empty
  string and the run path becomes empty.
- `LD_LIBRARY_PATH` overrides `DT_RUNPATH` for non-setuid binaries, so a `patchelf` run path may
  appear to be ignored during testing. `ldd` shows the real resolution order.
- LIEF `write()` may reorder sections and drop some non-essential notes. Compare
  `readelf -S` before and after.
- The build-id mismatch makes `gdb` refuse to load separate debug info: `warning: .gnu_debuglink
  section in ELF file has CRC mismatch` or `no debugging symbols found`.
- RPM's `rpm -V` reports a `5` digest mismatch after any patch; that is not a broken installation.
- Patching a binary that is `strip`ped and that has no symbol table makes the site unlocatable by
  name; work from a byte pattern instead of a symbol name.
- Patching inside a shared library changes the library's own build-id, and every consumer links
  against the new file silently.

## References

- `man 1 patchelf` and the NixOS/patchelf README for the exact subcommand semantics
- LIEF 1.0.0 documentation — `lief.ELF.parse`, `lief.ELF.Library`, `Binary.add`, `Binary.write`
  and the binary patching API (lief.re/doc/latest)
- `man 1 readelf`, `man 1 objdump`, `man 1 nm` — ELF structure inspection
- `man 1 gpg`, `man 1 rpm`, `man 1 dpkg-sig`, `man 8 sbverify` — the signature mechanisms that
  exist for ELF artefacts
- `man 2 ld.so` — the loader that consumes the structures patched here
- Sibling entries: `elf-interposition-ld-preload.md`, `linux-desktop-licence-flow.md`
