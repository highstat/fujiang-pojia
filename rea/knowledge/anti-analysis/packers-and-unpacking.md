---
id: "packers-and-unpacking"
title: "Packers and unpacking"
domain: "anti-analysis"
kind: "technique"
platforms: "windows, macos, linux, android"
arch: "x86, x86-64, arm64"
difficulty: "advanced"
tools: "radare2,LIEF,Frida,Ghidra,Scylla"
verified: false
updated: "2026-11-15"
summary: "Identify a packed binary by section names, entropy, entry point and import table, then recover the original image through static unpacking, runtime dumping, or in-memory analysis, and rebuild a usable file."
---

## Summary

A packer compresses or encrypts the original code, stores it in a compressed section, and adds a
stub that decompresses it at run time and hands control to the original entry point. The original
image is still in the process memory once the stub has run, so unpacking is a memory problem, not
a decryption problem.

This entry covers three parts: how to recognise that a binary is packed (section names, entropy,
entry point, import table), how to recover the original image (static tools, runtime dumping,
in-memory analysis), and how to turn a memory dump into a file that loads again (import table,
entry point, section table).

Related entries: [integrity-self-checks](./integrity-self-checks.md) for the header checksum a
packer usually writes, [debugger-detection-techniques](./debugger-detection-techniques.md) for the
anti-debug checks packed binaries often carry in their stub.

## Recognition

### Section names

```
rabin2 -S target.exe
```

Packer section names:

| Packer | Sections |
| --- | --- |
| UPX | `UPX0`, `UPX1`, `UPX2` |
| ASPack | `.aspack`, `.adata` |
| Themida / WinLicense | `.themida`, `.winlice` |
| VMProtect | `.vmp0`, `.vmp1`, `.vmp2` |
| NsPack | `.nsp0`, `.nsp1` |
| MPRESS | `.MPRESS1`, `.MPRESS2` |
| Petite | `.petite` |
| Yoda's Protector | `.yP` |
| PECompact | `.perplex` |
| MEW | `MEW` |
| Enigma | `.enigma1`, `.enigma2` |
| The Boomerang | `.boom` |
| Obsidium | `.obsidium` |

### Entropy

Packed sections have an entropy near 8.0 (bits per byte); normal code sits around 5.0 to 6.5.

LIEF 1.0.0 section entropy:

```python
#!/usr/bin/env python3
"""Print the per-section Shannon entropy of a binary."""
import math
import sys
import lief


def shannon(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    n = len(data)
    total = 0.0
    for c in counts:
        if c:
            p = c / n
            total -= p * math.log2(p)
    return total


binary = lief.parse(sys.argv[1])
for section in binary.sections:
    raw = bytes(section.content)
    print(f"{section.name:<12} vaddr=0x{section.virtual_address:08x} "
          f"size={section.size:<8} entropy={shannon(raw):.3f} "
          f"lief_entropy={section.entropy:.3f}")
```

Expected output on a UPX-packed PE:

```
UPX0         vaddr=0x00010000 size=693760   entropy=0.000
UPX1         vaddr=0x00b10000 size=8192     entropy=7.981
.rsrc        vaddr=0x00b12000 size=4096     entropy=5.104
```

A high-entropy section with a low-entropy neighbour, or an `entropy=0.000` section that is
non-empty on disk, is the classic packed layout.

Detect It Easy identifies packers from signatures and prints the packer name directly:

```
diec target.exe
```

### Entry point

The entry point of a packed binary sits in the unpacking stub, not in the original code section.
Compare the entry point address against the section ranges:

```
rabin2 -S -e target.exe
```

On a UPX-packed PE the entry point is inside `UPX1` while the original entry point belongs to the
`UPX0` region that is empty on disk.

The stub is recognisable by its own shape: a call to `VirtualAlloc` or `VirtualProtect`, a
loop over a buffer, and a final `jmp` to the decrypted region.

### Import table

A packed binary imports almost nothing from the original program: typically `kernel32.dll` with
`LoadLibraryA`, `GetProcAddress`, `VirtualAlloc`, `VirtualProtect`, and maybe `ExitProcess`.

```
rabin2 -i target.exe
```

Expected on a packed PE: 5 to 15 imports in total, all from `kernel32.dll`, none from the
application's real dependency set. A real Delphi program imports `VCL`/`RTL` symbols; a real
.NET binary has no native import table at all but a `mscoree.dll` `_CorExeMain`.

### Other markers

| Marker | Where |
| --- | --- |
| UPX magic | bytes `55 50 58 21` (`UPX!`) in the overlay or the last section |
| Resource-based packers | `.rsrc` with `RCDATA` blobs named `PACKAGEINFO`, `DAT` |
| Import directory pointing into the packed section | `rabin2 -i` shows odd RVAs |
| TLS callbacks | `rabin2 -S` plus a TLS directory with a callback, used to run code before the entry point |

## Method

### 1. Identify the packer

```
diec target.exe
```

Cross-check the section names and the entropy from section 1 of this entry. If the packer is
identified, the static route in section 2 usually works. If it is not, go to the dynamic route in
section 3.

### 2. Static unpacking

#### 2.1 UPX

```
upx -d target.exe -o target.unpacked.exe
upx -t target.exe
```

`-t` tests the file and reports the packer version and the compression method. If `-d` fails with
"not packed by UPX", the magic bytes have been patched — restore them. The UPX magic is a
`UPX!` signature (`55 50 58 21`) plus a version and checksum block in the last section. A common
anti-unpack trick is to overwrite the magic with `00 00 00 00`; restoring the original bytes from
a clean copy of the same file is the fastest fix.

#### 2.2 Generic static unpackers

```
pip install unipacker
unipacker -d target.exe -o target.unpacked.exe
```

`unipacker` emulates the entry point with Unicorn and dumps the unpacked image. It handles a
useful range of x86 PE packers.

Online services accept a file upload:

```
unpac.me
```

Treat any upload as a disclosure of the artefact; use it only on binaries you are authorised to
analyse.

#### 2.3 RetDec unpacker

RetDec ships an unpacker for some PE packers:

```
retdec-unpacker target.exe
```

It produces a directory with the unpacked PE and the reconstruction metadata.

#### 2.4 When the static route fails

Packed binaries that self-modify, that decrypt with a key derived from the environment, or that
check their own integrity have no static route. Go to section 3.

### 3. Dynamic unpacking

#### 3.1 Windows: Scylla

Scylla runs the target under a debugger, waits for the unpacking to finish, dumps the process image
and rebuilds the import table.

1. Start x64dbg with the packed file.
2. Set a breakpoint on the original entry point. The OEP is usually a tail jump in the stub:
   `jmp OEP` (`e9 xx xx xx xx` or `ff 25 xx xx xx xx`).
3. Run until the breakpoint hits.
4. Open the Scylla plugin (`Plugins` → `Scylla`), choose `Current Dump` / `IAT` and press `Dump`.
5. Scylla walks the loader's module list and reconstructs the import table, writing
   `target.dump.exe`.

Scylla writes the dump with the OEP as the new entry point and the rebuilt IAT. Fix the checksum
afterwards if the loader complains.

ImpREC is the older alternative: it produces a `.idt` (import table) and a `.rec` (reconstruction)
file that a separate tool converts back into a PE.

#### 3.2 Linux: dump the mapped image

With GDB:

```
gdb -p 12345 -batch -ex 'gcore /tmp/target.core'
```

Then rebuild the ELF from the core, or open the core directly in Ghidra with the original binary
as the symbol source.

With Frida, dump the mapped segments of the main module and the unpacked library:

```javascript
// frida 17.x — dump every mapping of a module to /tmp.
const fs = require('fs');
const pid = Process.id;

function dumpModule(moduleName, outPath) {
    const mod = Process.findModuleByName(moduleName);
    if (mod === null) {
        console.log('module not found: ' + moduleName);
        return;
    }
    const out = new File(outPath, 'wb');
    const lines = fs.readFileSync('/proc/self/maps', 'utf8').split('\n');
    for (const line of lines) {
        if (line.indexOf(mod.name) === -1) {
            continue;
        }
        const parts = line.split(' ');
        const range = parts[0].split('-');
        const start = ptr('0x' + range[0]);
        const end = ptr('0x' + range[1]);
        if (start.compare(mod.base) < 0) {
            continue;
        }
        const size = end.sub(start).toInt32();
        console.log('dumping ' + range[0] + '-' + range[1] + ' (' + size + ' bytes)');
        out.write(start.readByteArray(size));
    }
    out.flush();
    out.close();
}

dumpModule('libtarget.so', '/tmp/libtarget.dump.bin');
```

The dump is a raw memory image, not an ELF. Rebuild it with the LIEF 1.0.0 API by loading the
original ELF, replacing the segment content with the dumped bytes, and writing it out:

```python
import lief

binary = lief.parse("libtarget.so")
for segment in binary.segments:
    if segment.type == lief.ELF.Segment.TYPE.LOAD:
        with open("/tmp/seg_" + segment.name.replace("/", "_") + ".bin", "rb") as fh:
            data = fh.read()
        print(segment.name, len(data))
        # segment.content is writable in LIEF 1.0.0
        segment.content = list(data)
binary.write("/tmp/libtarget.unpacked.so")
```

If the packer allocated a fresh buffer and copied the decompressed code there rather than
unpacking in place, that buffer is a separate anonymous mapping. Find it by looking for an
executable anonymous region whose size matches the original code:

```
cat /proc/<pid>/maps | grep 'r-xp.* 00:00 0'
```

#### 3.3 macOS: `lldb` core dump

```
lldb -p 12345
(lldb) process save-core /tmp/target.core
```

Or in one shot:

```
lldb -p 12345 -o 'process save-core /tmp/target.core' -o 'detach' -o 'quit'
```

Open the core together with the original binary in Ghidra, or rebuild the Mach-O from the core
with LIEF 1.0.0.

The on-disk binary of a Mach-O that unpacks into a new segment is harder: the decompressed code
usually lands in a `__DATA` or malloc region. Dump it the same way as the ELF case, but note that
a raw blob is not a Mach-O — rebuild the load commands with `optool` or LIEF.

#### 3.4 Android

An APK with a packed `lib/*.so` is unpacked the same way as an ELF. The extra complication is that
the library may be loaded by a custom class loader that downloads the real payload at run time.

```
adb shell ls -l /data/data/com.example.app/files/
adb pull /data/data/com.example.app/files/libreal.so
```

### 4. In-memory analysis

Dumping is not always necessary. Attach a debugger after the unpacker has run and analyse the
memory image in place.

Ghidra: `File` → `Import` the original binary, then `Window` → `Memory Map` → add the base address
of the unpacked region and set the analysis options for that block.

radare2: map the region manually.

```
r2 -q -c 'e anal.in=io.maps; oo+ /tmp/target.dump.bin 0x00000000' target
```

With GDB:

```
gdb -p 12345
(gdb) info proc mappings
(gdb) x/64i 0x7f8e4c000000
```

The practical rule: when the packer unpacks in place, the file on disk plus the memory image is the
same layout, and the memory image can be disassembled with the file as the base. When it unpacks
into a fresh buffer, that buffer is a separate blob and the import table must be recovered from
the loader.

### 5. Rebuilding a usable file from a dump

A memory dump is not a loadable file. Four things have to be repaired.

**Entry point.** The OEP is where the stub jumped. It is visible in the tail of the stub:

```
; e9 rel32  jmp OEP
```

and in the dump as the address that the `jmp` targets. Set it in the Optional Header.

**Import table.** The dump has the Import Address Table filled with runtime addresses and the
Import Name Table intact in most cases. Scylla reconstructs the IAT by walking the loader's
module list. Without Scylla, dump the module list from the process and rebuild the descriptors:

```javascript
// frida 17.x — list the loaded modules and their base addresses.
Process.enumerateModules().forEach(function (m) {
    console.log(m.name + ' base=' + m.base + ' size=' + m.size + ' path=' + m.path);
});
```

**Section table.** A raw dump has no sections. Rebuild a section table from the program headers:
one section per `PT_LOAD`, with `vaddr` from `p_vaddr`, `size` from `p_memsz`, and the file
content taken from the dumped bytes. LIEF 1.0.0 does this:

```python
import lief

binary = lief.parse("target.exe")
print([s.name for s in binary.sections])
```

LIEF rebuilds a PE from a template; a faster route is to keep the original section table and only
replace the section contents with the dumped bytes, which keeps the entry point and the data
directories intact.

**Checksum and signature.** Recompute the PE checksum and re-sign. See
[integrity-self-checks](./integrity-self-checks.md).

### 6. Packed binaries that also fight back

Many packed stubs carry their own countermeasures:

| Countermeasure | Response |
| --- | --- |
| Anti-debug in the stub | ScyllaHide, or dump with a non-debugger method |
| Integrity check of the own image | Recompute the digest after patching, see [integrity-self-checks](./integrity-self-checks.md) |
| TLS callbacks that run before the entry point | Set a breakpoint on the TLS callback, or dump after it runs |
| Process hollowing into a new allocation | Track the new allocation and dump it |
| Self-deleting the file on disk | Dump from memory; the file may already be gone |
| Decryption key derived from the file hash | Patch the key derivation or the hash source |

For the last one, the practical approach is to break on the point where the key is used and read
it, then dump after decryption rather than trying to derive the key statically.

## Variations

- **Trix / the "Cortex" family.** Multi-layer packers: a stub unpacks a second stub which unpacks
  the payload. Dump at each layer and confirm the entropy drops before moving on.
- **Native AOT packers.** Commercial protectors (Themida, VMProtect, CodeVirtualizer) do not
  simply decompress; they move code into a virtual machine. Unpacking means dumping the handler
  table and reconstructing the interpreter, or driving the interpreter with an input that reaches
  the interesting branch.
- **ELF packers.** UPX works on ELF (`upx -d`). Custom ELF packers usually allocate with `mmap`
  and mark the region `PROT_READ|PROT_EXEC`, which is visible in `/proc/<pid>/maps` as `r-xp` on an
  anonymous region.
- **Mach-O.** The Apple code signature prevents a modified binary from loading, so re-sign after
  every edit: `codesign --force --deep --sign - target.app`.
- **Java packers.** A jar with an obfuscated loader unpacks at run time. Attach to the JVM and
  dump the loaded classes from the heap, or use a Java agent to write the decrypted class bytes.
- **.NET.** A .NET obfuscator that encrypts the IL is unpacked by hooking `Assembly.Load` and
  dumping the decrypted `MethodBody`. The `dnSpyEx` debugger can also load the assembly from a
  memory dump.
- **Partial unpacking.** Some packers only unpack on demand per page. The dump is incomplete; use
  the target's own function calls to force the remaining pages to be unpacked before dumping.
- **Anti-dump.** The stub checks whether a debugger is present and exits. ScyllaHide and a
  non-debugger dump avoid this.
- **UPX with a broken magic.** Restoring the `UPX!` magic is the standard repair; the version and
  checksum fields must also be intact.

## Verification

1. **Confirm the unpacked file is valid before analysing it.**

   ```
   rabin2 -I target.unpacked.exe
   rabin2 -i target.unpacked.exe | head -40
   rabin2 -S target.unpacked.exe
   ```

   Expected: a plausible section table with named sections, an import table with the real
   dependency set, and an entry point inside a code section rather than in the stub.

2. **Compare the import count.** A packed PE has 5 to 15 imports; the unpacked PE has hundreds.
   A count that did not increase means the import table was not rebuilt.

3. **Compare the entropy.** The unpacked code section should show entropy between 5.0 and 6.5. A
   value near 7.9 means the dump captured compressed data.

4. **Run the unpacked file.** Launch it and confirm it behaves like the original: the licence
   dialog appears, the UI comes up, the network calls fire. A dump that only imports cleanly but
   crashes on start has a wrong entry point or a wrong data directory.

5. **Negative test.** Re-run the packer detection on the output. `diec target.unpacked.exe` should
   report no packer, and `upx -t` should report that the file is not UPX-packed.

6. **Verify the OEP.** Break on the OEP in the debugger and confirm the first instructions are
   plausible prologue code, not a jump back into the stub.

7. **Verify the rebuilt imports.** Compare the import list of the unpacked file with the list
   captured from the live process. Every module in the live list must appear in the rebuilt file.

8. **Checksum and signature.**

   ```
   codesign --verify --verbose=2 target.unpacked.app
   ```

   Expected: valid after re-signing.

## Pitfalls

- **Wrong layer.** Dumping too early captures the compressed image; the entropy stays near 7.9 and
  the import table is still tiny. Dump after the OEP transfer, not at the stub entry.
- **Wrong process.** The unpacking may happen in a child process or in a helper that writes the
  result back to disk. Check `ps` for a spawned process and dump that one.
- **Base-address drift.** The dump is a memory image; the section RVAs in the file no longer match.
  Either map the dump at the original base in the disassembler or rebuild the section table.
- **The `Scylla` IAT scan.** Scylla's automatic import recovery finds only what the loader
  currently has resolved. Imports that were resolved and freed, or delay-loaded imports, are
  missing. Use ImpREC or a manual `GetProcAddress` trace to recover them.
- **UPX magic tampering.** `upx -d` fails with "NotPackedException". Restore the magic bytes, or
  unpack dynamically.
- **Checksums.** The PE checksum and the Authenticode signature cover the modified bytes. A dump
  written by Scylla often has a zero checksum; the loader tolerates this for user-mode EXEs, but
  drivers and some loaders do not.
- **Signature stripping.** On macOS and iOS, a modified Mach-O does not load. `optool install -c
  load -p path` plus `codesign --force --sign -` is the repair chain.
- **Anti-dump inside the stub.** The stub can detect `NtQueryInformationProcess` and call
  `RtlExitUserProcess`. Use the non-debugger dump route or ScyllaHide.
- **Section names in a dump.** A raw dump has no section names. Any analysis tool that groups by
  section will show one anonymous block; re-import the original file as the base and overlay the
  dump.
- **Ghidra core import.** A core file without the matching binary loads as raw data. Import the
  binary first, then use `Window` → `Memory Map` to add the segments.
- **Time.** Runtime unpacking is slow when the packer has anti-dump timing loops. Break on the
  anti-dump loop's exit rather than waiting for it.

## References

- UPX — https://github.com/upx/upx
- `unipacker` (Unicorn-based generic unpacker) — https://github.com/unicorn-engine/unipacker
- RetDec — https://github.com/avast/retdec
- Detect It Easy — https://github.com/horsicq/Detect-It-Easy
- Scylla (PE import rebuilder) — https://github.com/mandiant/Scylla
- ImpREC — https://github.com/kirschju/ImpREC
- LIEF 1.0.0 — https://lief.re/doc/latest/
- Frida JavaScript API (17.x) — https://frida.re/docs/javascript-api/
- `gcore(1)` — https://man7.org/linux/man-pages/man1/gcore.1.html
- `process save-core` (LLDB) — https://lldb.llvm.org/use/map.html
- `codesign` — https://developer.apple.com/documentation/security/codesign
- `optool` — https://github.com/aferrero2707/optool
