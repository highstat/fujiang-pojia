---
id: "import-table-and-plt-got-surgery"
title: "Import table and PLT/GOT surgery"
domain: "native-core"
kind: "technique"
platforms: "-"
arch: "x86, x86-64, arm64"
difficulty: "advanced"
tools: "LIEF, radare2, rabin2, objdump, otool, optool, patchelf"
verified: false
updated: "2026-11-15"
summary: "Adds, redirects and audits the import table on PE, the PLT/GOT on ELF and the two-level namespace on Mach-O, so a call can be redirected to code of your own without rebuilding the target."
---

## Summary

The import table is the seam between a program and the code it calls. On PE it is the
import directory and the IAT; on ELF it is the PLT/GOT pair driven by `JUMP_SLOT` relocations;
on Mach-O it is the two-level namespace of `LC_LOAD_DYLIB` and the `__got`/`__stubs` sections.

Redirecting a call through that seam is more stable than rewriting the code, survives
recompilation better, and — on PE and ELF — is the only way to substitute a function the
program calls from many places.

## Recognition

- PE: a data directory entry at optional-header offset `0x78` (index 1) pointing at an array of
  20-byte `IMAGE_IMPORT_DESCRIPTOR` structures.
- ELF: a `.rela.plt` (or `.rel.plt`) section of `R_*_JUMP_SLOT` relocations and a `.plt` section
  whose entries are 16 bytes on x86-64.
- Mach-O: `LC_LOAD_DYLIB` load commands and a `__DATA_CONST,__got` section holding
  `__la_symbol_ptr` and `__got` symbol pointers.
- A call site that goes through a thunk: `call qword ptr [rip+0x2000]` on x86-64 PE,
  `call 0x201020` to a PLT stub on ELF, `bl 0x100003f00` to a Mach-O stub.

## Method

### Part 1 — PE import directory

#### 1.1 Layout

The optional header's data directory index 1 holds the RVA and size of the import directory.
Each entry is a 20-byte `IMAGE_IMPORT_DESCRIPTOR`:

| Offset | Field | Meaning |
| --- | --- | --- |
| 0x00 | `OriginalFirstThunk` | RVA of the ILT (import lookup table), the array of `IMAGE_IMPORT_BY_NAME` pointers |
| 0x04 | `TimeDateStamp` | `0` normally, `0xffffffff` when bound |
| 0x08 | `ForwarderChain` | index of the first forwarder reference |
| 0x0c | `Name` | RVA of the NUL-terminated DLL name |
| 0x10 | `FirstThunk` | RVA of the IAT (import address table) |

The array is terminated by an all-zero descriptor. The ILT and the IAT have the same shape:
one entry per imported symbol, terminated by a zero entry (or, for a 64-bit import by ordinal,
the high bit set).

An ILT entry points at an `IMAGE_IMPORT_BY_NAME`: a 2-byte hint followed by the NUL-terminated
ASCII name. An IAT entry points at the same structure on disk; the loader overwrites the IAT
entries with the resolved addresses at load time.

#### 1.2 Read the current table

```
rabin2 -i target.exe
r2 -q -c 'ii' target.exe
r2 -q -c 'iij' target.exe | python3 -m json.tool | head -60
```

Manual read:

```
python3 - <<'PY'
import lief
b = lief.PE.Binary("target.exe")
for imp in b.imports:
    print(imp.name)
    for e in imp.entries:
        print("   ordinal", e.ordinal, "name", e.name, "iat", hex(e.address))
PY
```

#### 1.3 Redirect an existing call to your own DLL

Two levels of ambition:

**Level A — replace the name in place.** If your exported function has a name no longer than the
one already imported, overwrite the `IMAGE_IMPORT_BY_NAME` blob and the DLL name string, and
leave the ILT and IAT untouched. The loader then resolves your DLL's export.

```
python3 - <<'PY'
import pathlib

p = pathlib.Path("target.exe")
data = bytearray(p.read_bytes())

old_dll = b"kernel32.dll\x00"
old_sym = b"CreateFileW\x00"
new_dll = b"mydrv.dll\x00\x00\x00"     # must be <= len(old_dll)
new_sym = b"MyVerify\x00"              # must be <= len(old_sym)

i = data.find(old_dll)
j = data.find(old_sym)
assert i >= 0 and j >= 0, "anchor not found"
assert len(new_dll) <= len(old_dll) and len(new_sym) <= len(old_sym)

data[i:i+len(old_dll)] = new_dll.ljust(len(old_dll), b"\x00")
data[j:j+len(old_sym)] = new_sym.ljust(len(old_sym), b"\x00")
p.write_bytes(data)
print(f"dll name at 0x{i:x}, symbol at 0x{j:x}")
PY
```

The name string must be replaced with the same length or the structure shifts and every
following RVA breaks. Padding with NULs is enough: `"mydrv.dll\x00\x00\x00"` fills an 11-byte
slot exactly, and the trailing NULs sit inside the slack of the original string.

**Level B — add a new import.** Add a second `IMAGE_IMPORT_DESCRIPTOR` for your DLL, with its
own ILT, its own name string, its own `IMAGE_IMPORT_BY_NAME`, and an IAT placed in a new
section (or appended to the existing `.idata`).

The manual layout for a new section `.hook` at RVA `0x7000`, raw offset `0x3600`. The
`IMAGE_IMPORT_BY_NAME` blob must sit at a lower RVA than the tables, because both the ILT entry
and the IAT entry point *at* the blob:

```
0x7010:  04 00 48 6f 6f 6b 56 65 72 69 66 79 00    ; hint 0x0004, "HookVerify\0"
0x7014:  10 70 00 00 00 00 00 00                   ; ILT[0]=0x7010, ILT[1]=0
0x7020:  10 70 00 00 00 00 00 00                   ; IAT[0]=0x7010, IAT[1]=0
0x7030:  6d 79 68 6f 6f 6b 2e 64 6c 6c 00          ; "myhook.dll\0"
0x7034:  00 00 00 00 00 00 00 00 00 00 00 00       ; zero descriptor (20 bytes)
```

The two descriptors occupy `0x7034` onwards: one 20-byte descriptor for `myhook.dll` with
`OriginalFirstThunk = 0x7014`, `Name = 0x7030`, `FirstThunk = 0x7020`, followed by the 20-byte
all-zero terminator.

Then extend the import data directory: the RVA stays `0x7000` and the size becomes at least
`0x54` (descriptor + terminator + tables + strings). And add a call thunk in the code:

```
ff 25 1a 70 00 00    call qword ptr [rip+0x701a]
```

`0x701a` is the IAT slot address (`0x7020`) minus the address of the next instruction.

**Level C — LIEF.** LIEF 1.0.0 has a PE builder that regenerates the import directory. The
configuration must explicitly keep imports, otherwise the rebuilt binary keeps the code but
loses the import table and fails to load:

```
python3 - <<'PY'
import lief

target = lief.PE.Binary("target.exe")

# config_t() controls what the builder carries over from the original binary.
cfg = lief.PE.Builder.config_t(imports=True)
cfg.imports = True

builder = lief.PE.Builder(target, cfg)

lib = builder.add_library("myhook.dll")     # returns an lief.PE.Import
lib.add_entry("HookVerify")

builder.build()
builder.write("target-hooked.exe")
print("written target-hooked.exe")
PY
```

Notes on this API:

- `lief.PE.Builder.config_t(imports=True)` is the requirement. Without it the builder's
  default configuration drops the original import directory, and the rebuilt binary has no
  imports at all.
- `add_library` returns the new `lief.PE.Import`; `add_entry` appends an `IMAGE_IMPORT_BY_NAME`.
- Attribute and method names move between LIEF major versions. Check the installed build
  before scripting:

  ```
  python3 -c "import lief; print(lief.__version__); print([a for a in dir(lief.PE.Builder) if not a.startswith('_')]); print([a for a in dir(lief.PE.Import) if not a.startswith('_')])"
  ```

- In some LIEF builds the call is `add_import` rather than `add_library`; both existed across
  the 0.13/0.14 line. If `add_library` is missing, use `add_import`.
- LIEF also exposes `binary.imports` as a list of `lief.PE.Import` objects whose entries can be
  inspected with `entry.name` and `entry.address`.

#### 1.4 Delay-load imports

A delay-loaded DLL is described by data directory index 13, an array of 32-byte
`ImgDelayDescr` structures:

| Offset | Field |
| --- | --- |
| 0x00 | `grAttrs` (`1` = RVA-based, `0` = VA-based) |
| 0x04 | `rvaDLLName` |
| 0x08 | `rvaHmod` |
| 0x0c | `rvaIAT` |
| 0x10 | `rvaINT` |
| 0x14 | `rvaBoundIAT` |
| 0x18 | `rvaUnloadIAT` |
| 0x1c | `dwTimeStamp` |

The array is terminated by a zero descriptor. The delay-load helper `__delayLoadHelper2` lives
in `delayimp.dll` and resolves the import on first call, which means the IAT slot still holds a
pointer to the helper until then.

Consequences for patching:

- A delay-loaded import is *not* in the regular import directory, so `rabin2 -i` may not list it.
  Inspect directory index 13 explicitly:

  ```
  rabin2 -i target.exe | grep -i delay
  python3 - <<'PY'
  import lief
  b = lief.PE.Binary("target.exe")
  for d in b.delay_imports:
      print(d.name, [e.name for e in d.entries])
  PY
  ```

- Redirecting a delay-loaded call means patching the IAT slot *after* the helper has resolved
  it, or replacing the entry in the delay-load INT so the helper resolves your DLL instead.

### Part 2 — ELF PLT and GOT

#### 2.1 Mechanics

For a dynamically linked ELF, an external call goes through a PLT stub. On x86-64 each stub is
16 bytes:

```
ff 25 <disp32>      jmp qword ptr [rip+disp32]   ; the .got.plt slot
68 <index>          push  <reloc index>
e9 <rel32>          jmp   PLT0
```

`PLT0` is the resolver stub:

```
ff 35 <disp32>      push qword ptr [rip+GOT+8]    ; link_map
ff 25 <disp32>      jmp  qword ptr [rip+GOT+16]   ; _dl_runtime_resolve
```

The `.got.plt` table starts with three reserved entries: the address of `_DYNAMIC`, the link
map pointer and the resolver address. The `.rela.plt` section holds one `R_X86_64_JUMP_SLOT`
relocation per slot; the relocation's `r_offset` is the address of the `.got.plt` slot, and its
addend is the symbol.

The lazy-binding sequence on the first call: the PLT stub pushes the relocation index and jumps
to `PLT0`, which pushes the link map and jumps to the resolver. The resolver writes the real
address into the `.got.plt` slot and patches the PLT stub to jump directly to it. Every
subsequent call goes straight through the slot.

#### 2.2 Inspect

```
readelf -rW target.elf | grep JUMP_SLOT
readelf -SW target.elf | grep -E '\.plt|\.got'
objdump -d -j .plt target.elf | head -40
objdump -R target.elf | head -30
rabin2 -i target.elf
r2 -q -c 'ii' target.elf
r2 -q -c 'ir' target.elf | grep JUMP_SLOT
```

#### 2.3 Redirect a PLT entry to your own function

**Static, at file level.** Overwrite the 16-byte PLT stub with a jump to your function. Because
the stub is at a known address, the relative jump must reach it:

```
python3 - <<'PY'
import pathlib, struct

p = pathlib.Path("target.elf")
data = bytearray(p.read_bytes())

# PLT stub for strcmp at file offset 0x1120, virtual address 0x401120
stub_off = 0x1120
stub_va  = 0x401120
hook_va  = 0x404000        # inside your own code, must be within +-2 GiB

rel = (hook_va - (stub_va + 5)) & 0xffffffff
patch = b"\xe9" + struct.pack("<I", rel) + b"\x90" * 11
data[stub_off:stub_off + 16] = patch
p.write_bytes(data)
print("patched stub at", hex(stub_off), "->", hex(hook_va))
PY
```

The same trick works on ARM64, where the PLT stub is 16 bytes of `adrp`/`ldr`/`br` and can be
replaced with a `b` to your function if it is within ±128 MiB.

**Dynamic, by rewriting the GOT slot.** Leave the code alone and change the pointer the call
reads. Two ways:

- Patch the `.got.plt` slot on disk. This works only with eager binding, because the lazy
  resolver overwrites the slot on the first call. Force eager binding by setting `DF_BIND_NOW` in
  `DT_FLAGS` or `DT_BIND_NOW` in the dynamic section, or by running with `LD_BIND_NOW=1`.
- Patch the slot in memory after the first call has resolved it. This is the classic GOT hook:

  ```
  # Frida 17.x
  const m = Process.getModuleByName("target.elf");
  const slot = m.getExportByName("strcmp");   // points into the GOT slot
  ```

  To locate the slot without symbols, read the PLT stub and compute the RIP-relative target.

**Symbol interposition, no patching at all.** Export the same symbol name from your own shared
object and preload it:

```
LD_PRELOAD=./intercept.so ./target
```

The dynamic linker resolves the symbol to the first definition in the search order. This only
affects calls that go through the PLT; a call to a function defined in the same object and
bound locally is not interposable.

For an ELF built with `-fno-plt` (calls through the GOT directly) or with `-Bsymbolic`
(local binding wins), interposition fails — check the dynamic section:

```
readelf -dW target.elf | grep -E 'SYMBOLIC|BIND_NOW|FLAGS'
```

#### 2.4 Add a library dependency

```
patchelf --add-needed libmyhook.so target.elf
patchelf --replace-needed libfoo.so.1 libmyhook.so target.elf
patchelf --print-needed target.elf
```

`patchelf --replace-needed` changes the `DT_NEEDED` string; the new name must not be longer
than the old one unless `patchelf` can relocate, which it handles by rewriting the dynamic
section. Verify afterwards with `readelf -dW`.

### Part 3 — Mach-O two-level namespace

#### 3.1 Mechanics

A Mach-O that links against another library records an `LC_LOAD_DYLIB` load command per
dependency, each naming a path:

```
cmd LC_LOAD_DYLIB (0xc)
cmdsize 0x38
dylib struct: name offset 0x10, timestamp 0, current_version 0x10000, compat 0x10000
```

The two-level namespace means the loader must find each symbol in a specific dylib, not by
global search order. The pieces are:

| Piece | Location | Role |
| --- | --- | --- |
| `__TEXT,__stubs` | text segment | one stub per lazy symbol |
| `__DATA_CONST,__got` | data segment | the pointer table |
| `__la_symbol_ptr` | symbol in `__got` | points at the first lazy stub |
| `__got` | symbol in `__got` | points at the first non-lazy pointer |

On arm64 a stub is:

```
adrp x16, <got page>
ldr  x17, [x16, <got offset>]
br   x17
```

Each `__got` entry is 8 bytes: a pointer either to the stub (for a lazy symbol) or directly to
the resolved address (for a non-lazy symbol). The stub's `br x17` reads the *same* entry, so
after the first call the entry holds the real function address.

#### 3.2 Inspect

```
otool -L target.macho                 # linked libraries
otool -l target.macho | grep -A8 LC_LOAD_DYLIB
otool -l target.macho | grep -A10 __got
otool -Iv target.macho                # indirect symbols (the __got entries)
otool -Iv target.macho | grep -i strcmp
rabin2 -L target.macho
rabin2 -i target.macho
r2 -q -c 'ii' target.macho
```

#### 3.3 Redirect a symbol to your own code

Options, in order of intrusiveness:

1. **Change the `__got` entry** at runtime to point at your function. The stub's `br x17` then
   goes there. This survives the lazy-binding step only if the entry is patched after the first
   call; patch the stub instead to be sure.

2. **Patch the stub** in `__TEXT,__stubs` to branch to your function. On arm64, replace
   `adrp/ldr/br` with a 4-byte `b` to your code — only possible within ±128 MiB. Otherwise use
   an absolute sequence (`movz`/`movk`/`movk`/`br`).

3. **Change the `__la_symbol_ptr` entry** to point at your own stub. This is a pure data change
   and needs no code.

4. **Interpose at the dyld level** with `DYLD_INSERT_LIBRARIES` — works only for binaries without
   hardened runtime and library validation, and is blocked by SIP for system binaries.

#### 3.4 Add a load command with optool

`optool` inserts load commands into an existing Mach-O without a full relink:

```
# add a dylib dependency
optool install -c load -p /usr/lib/libmyhook.dylib target.macho

# add an rpath so the loader can find it
optool install -c rpath -p @executable_path/Frameworks target.macho

# remove the existing code signature (the file changed, so it is invalid anyway)
optool uninstall -S target.macho

# verify
otool -L target.macho
```

`optool install -c load -p <path>` writes an `LC_LOAD_DYLIB`. The path must exist at load time
or the process will fail to launch with a dyld error.

With LIEF:

```
python3 - <<'PY'
import lief
b = lief.MachO.Binary("target.macho")
b.add_library("/usr/lib/libmyhook.dylib")
b.write("target-hooked.macho")
print("ok")
PY
```

LIEF 1.0.0 also supports removing and re-adding the code signature; see
`checksum-and-integrity-repair`.

### Part 4 — Audit after surgery

Whatever the format, re-parse and re-resolve:

```
rabin2 -i target.exe
readelf -rW target.elf | grep JUMP_SLOT
otool -L target.macho
```

and confirm the loader still resolves everything. The practical test is to run the binary with
the dynamic loader's diagnostics enabled:

```
LD_DEBUG=bindings ./target 2>&1 | grep -i hook
DYLD_PRINT_BINDINGS=1 ./target.macho 2>&1 | grep -i hook
```

## Variations

### Importing a function that does not exist yet

On PE, an imported name that no DLL exports causes a load-time failure with a hard error
dialog. Import by ordinal instead when the ordinal is stable, or ensure your DLL exports the
exact name with the exact case.

### Delay-load and bound imports

A PE with `TimeDateStamp = 0xffffffff` in the import descriptor has *bound* imports: the IAT
already holds the resolved addresses. Patching the on-disk IAT then has no effect because the
loader skips resolution. Clear the timestamp field to `0` to force resolution.

### `__fastcall` and other PE calling conventions

The imported symbol's decoration (`_name@16`, `name@16` on x86, undecorated on x64) affects the
name string in the `IMAGE_IMPORT_BY_NAME`. On x86, the stdcall callee pops its arguments, so
your exported function must use the same convention or the stack will be corrupted.

### ELF `R_*_GLOB_DAT` versus `R_*_JUMP_SLOT`

`JUMP_SLOT` relocations drive the PLT; `GLOB_DAT` relocations fill ordinary global variables
holding function pointers. A call through a function pointer stored in a global is not affected
by PLT redirection — patch the global.

### Mach-O chained fixups

Modern binaries use `LC_DYLD_CHAINED_FIXUPS` instead of separate relocations. The fixup
information is a bitmap describing which pointers need rebasing, stored in `__DATA` with the
fixup commands in `__LINKEDIT`. Editing a `__got` entry is still possible, but the fixup chain
must stay consistent or dyld rejects the image.

### Fully static binaries

An ELF with no `PT_INTERP` and no `.plt` has no dynamic linking at all; redirection requires
patching the call site, not the import table.

## Verification

1. Re-parse the modified file with every parser available; a malformed import table often
   still parses but fails at load time.

   ```
   rabin2 -i target.exe
   readelf -aW target.elf > /dev/null && echo "elf parses"
   otool -L target.macho
   ```

2. Confirm the new import appears with the expected RVA and that the ILT and IAT entries agree:

   ```
   python3 - <<'PY'
   import lief
   b = lief.PE.Binary("target.exe")
   for imp in b.imports:
       print(imp.name)
       for e in imp.entries:
           print("   ", e.name, hex(e.address))
   PY
   ```

3. Confirm the loader actually resolves it, using the loader's own tracing:

   ```
   LD_DEBUG=bindings ./target 2>&1 | grep myhook
   ```

4. Prove the redirection is what changed the behaviour: remove the import (or restore the
   original file) and confirm the original behaviour returns; then re-apply and confirm the new
   behaviour. If the behaviour is unchanged, the import was added but not called.

5. Negative test — confirm the original imports still resolve. A broken import table produces a
   process that exits before `main` with a loader error, which is easy to distinguish from a
   licence failure. Check the exit code and the loader output, not just the UI.

6. For Mach-O, confirm the load command chain is correct and that dyld accepts the binary:
   `otool -L target.macho` lists the new library and `dyld_info` shows the bindings.

## Pitfalls

- Replacing a DLL name string with a different length. Every RVA after it shifts and the
  binary fails to load. Pad with NULs to the original length or relocate the string and update
  the descriptor.
- Forgetting that the `IMAGE_IMPORT_BY_NAME` hint is 2 bytes before the name; writing the name
  at the blob's start yields a name shifted by two characters.
- Using LIEF's PE builder without `config_t(imports=True)`. The rebuilt binary keeps its code
  and loses its imports, and the failure looks like a broken dependency rather than a missing
  table.
- Patching a bound-import IAT on disk (`TimeDateStamp = 0xffffffff`). The loader skips
  resolution and keeps its own values.
- Patching the `.got.plt` slot on disk while the binary uses lazy binding. The resolver
  overwrites the slot on the first call and the patch is lost.
- Assuming a `.rela.plt` slot's file offset equals its virtual address. Use the segment mapping.
- Forgetting the `DF_1_PIE`/`DT_FLAGS_1` interaction on ELF: adding a `DT_NEEDED` changes the
  library search order and can change which definition wins.
- Trusting `LD_PRELOAD` interposition for a symbol resolved with `-Bsymbolic` or bound locally.
- On Mach-O, adding an `LC_LOAD_DYLIB` without an rpath, or with a path that does not exist at
  load time. dyld refuses to launch the process.
- Editing a Mach-O's `__got` while the binary uses chained fixups without updating the fixup
  chain.
- Forgetting that a modified Mach-O or PE must be re-signed before it will load on a system
  with enforced code signing — see `checksum-and-integrity-repair`.

## References

- Microsoft PE format, import table and `IMAGE_IMPORT_DESCRIPTOR`: <https://learn.microsoft.com/windows/windows/win32/debug/pe-format>
- Microsoft PE format, delay-load imports: <https://learn.microsoft.com/windows/win32/debug/pe-format#delay-load-imports>
- System V gABI, PLT and GOT: <https://www.sco.com/developers/gabi/>
- ELF for the ARM ABI, and the `R_*_JUMP_SLOT` relocation: <https://github.com/ARM-software/abi-aa>
- Apple Mach-O Programming Topics, dynamic libraries and the two-level namespace: <https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/MachOOverview.html>
- `dyld` and chained fixups: <https://developer.apple.com/documentation/dyld>
- LIEF documentation, PE and Mach-O builders: <https://lief.re/doc/latest/>
- optool: <https://github.com/aferrero2707/optool>
- patchelf: <https://github.com/NixOS/patchelf>
