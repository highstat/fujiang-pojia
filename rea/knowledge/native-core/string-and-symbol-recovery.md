---
id: "string-and-symbol-recovery"
title: "String and symbol recovery"
domain: "native-core"
kind: "technique"
platforms: "-"
arch: "x86, x86-64, arm64"
difficulty: "intermediate"
tools: "radare2, rabin2, FLOSS, strings, python3"
verified: false
updated: "2026-11-15"
summary: "Separates real strings from instruction bytes, extracts UTF-16LE and obfuscated strings, and recovers symbols for stripped binaries through static heuristics and dynamic tracing."
---

## Summary

Strings are the fastest anchor for locating a licence check, but a raw `strings` dump of a modern
binary is full of false positives: instruction bytes and immediate constants routinely look like
printable text. This entry covers the reliable extraction commands, the heuristics that separate
a real string from an accidental one, wide strings on Windows, the common obfuscation shapes
(stack strings, XOR loops, per-byte arithmetic), and symbol recovery from dynamic traces.

## Recognition

- A `mov` that writes a 32-bit or 64-bit immediate into a stack slot: `mov dword ptr [rbp-0x20],
  0x6c6c6568` — the bytes spell `hell` when read little-endian.
- Long runs of `00` between non-zero bytes in a data section: a UTF-16LE string.
- A loop with a `xor`, `add`, `sub` or `rol` on a byte followed by `inc` and a backward branch:
  a runtime string decoder.
- A function whose only job is to write a fixed set of bytes into a caller-provided buffer:
  a decryption stub.
- An ELF with `.symtab` absent but `.dynsym` present, and a PE with an RSDS debug directory
  pointing at a `.pdb` that is not on disk: stripped but recoverable.

## Method

### Step 1 — Enumerate strings with the right tool for the right scope

radare2 distinguishes data-section strings from whole-file strings:

```
r2 -q -c 'iz' target.exe            # strings in data sections only (fewer false positives)
r2 -q -c 'izz' target.exe           # strings across the whole file, including code sections
r2 -q -c 'izzj' target.exe         # JSON: {"strings":[{"vaddr":...,"string":...,"length":...}]}
r2 -q -c 'iZ' target.exe            # strings with their cross-references
r2 -q -c 'izz~license' target.exe   # filter by substring
```

rabin2 exposes the same thing outside the interactive shell:

```
rabin2 -z  target.exe     # strings in data sections
rabin2 -zz target.exe     # strings in the whole file
rabin2 -zzj target.exe    # JSON output
```

GNU `strings` for quick triage:

```
strings -a -t x target.exe        # absolute file offset, hex
strings -a -t x -n 6 target.exe   # minimum length 6
strings -a -el target.exe         # UTF-16LE (16-bit little endian)
strings -a -eb target.exe         # UTF-16BE
```

`-t x` gives the file offset of each string, which converts to a virtual address through the
section table — see `elf-pe-macho-layout`.

### Step 2 — Separate real strings from instruction bytes

A string is credible when all of the following hold:

- It is a run of printable bytes terminated by `00` (or `0a 00` for a C string in a section
  with fixed-size slots).
- It starts at an address that is not inside a disassembled instruction. radare2's `iz` already
  enforces the section filter; `izz` does not.
- It is referenced by code as a data address: `lea rdi, [rip+0x1234]` on x86-64,
  `adrp x0, ...` + `add x0, ...` on ARM64, `push <addr>` on x86-32.

Check the third condition — it is the strongest filter:

```
r2 -q -c 'izz~license' target.exe
r2 -q -c 'axt @@ str.*license*' target.exe
```

A string with no cross-reference is either dead data or a false positive.

**The immediate-as-string heuristic.** Compilers build short strings on the stack with
immediate moves. In x86-64:

```
48 c7 45 e0 68 65 6c 6c     ; mov qword ptr [rbp-0x20], 0x6c6c6568
c7 45 e0 68 65 6c 6c        ; mov dword ptr [rbp-0x20], 0x6c6c6568
c7 44 24 08 68 65 6c 6c     ; mov dword ptr [rsp+8], 0x6c6c6568
```

The immediate `0x6c6c6568` is the ASCII bytes `68 65 6c 6c` = `hell`, in reverse order. A
four-character string written one DWORD at a time appears as four 4-byte immediates that
concatenate in memory.

This scanner extracts them:

```
python3 - <<'PY'
import struct, pathlib, sys

data = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "target.exe").read_bytes()

# (opcode prefix, displacement length) for the common "mov [mem], imm32" forms
FORMS = [
    (b"\x48\xc7\x44\x24", 1),   # mov qword [rsp+disp8], imm32 (sign-extended)
    (b"\x48\xc7\x45",     1),   # mov qword [rbp+disp8], imm32
    (b"\x48\xc7\x85",     4),   # mov qword [rbp+disp32], imm32
    (b"\xc7\x44\x24",     1),   # mov dword [rsp+disp8], imm32
    (b"\xc7\x45",         1),   # mov dword [rbp+disp8], imm32
    (b"\xc7\x85",         4),   # mov dword [rbp+disp32], imm32
]

hits = []
for prefix, dlen in FORMS:
    start = 0
    while True:
        i = data.find(prefix, start)
        if i < 0:
            break
        start = i + 1
        imm_off = i + len(prefix) + dlen
        if imm_off + 4 > len(data):
            continue
        imm = struct.unpack_from("<I", data, imm_off)[0]
        b = struct.pack("<I", imm)
        if all(0x20 <= c < 0x7f or c == 0 for c in b):
            txt = b.rstrip(b"\x00").decode("ascii", "replace")
            if len(txt) >= 2:
                hits.append((imm_off - len(prefix) - dlen, txt))

for off, txt in sorted(set(hits)):
    print(f"0x{off:08x}  {txt!r}")
PY
```

The same trick applies on ARM64: `MOVZ`/`MOVK` pairs build a 32-bit constant in two
instructions (`0x52800000 | imm16` and `0x72a00000 | (imm16 << 16)`), so a stack-string builder
appears as a `str`/`stp` of `w0`/`x0` after the pair.

### Step 3 — Extract UTF-16LE wide strings

Windows binaries store `L"..."` literals as UTF-16LE. GNU `strings -el` finds them directly:

```
strings -a -el -t x target.exe | head -40
```

A standalone scanner, when GNU binutils is unavailable or when a minimum length and alignment
rule is needed:

```
python3 - <<'PY'
import pathlib, sys

data = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "target.exe").read_bytes()
MIN = 4

def runs(buf, base):
    out = []
    i = 0
    n = len(buf)
    while i + 1 < n:
        chars = []
        j = i
        while j + 1 < n:
            lo, hi = buf[j], buf[j + 1]
            if hi == 0 and (0x20 <= lo < 0x7f or lo in (0x09, 0x0a, 0x0d)):
                chars.append(chr(lo))
                j += 2
            else:
                break
        if len(chars) >= MIN:
            out.append((base + i, "".join(chars)))
            i = j
        else:
            i += 1
    return out

hits = runs(data, 0)
for off, txt in hits:
    print(f"0x{off:08x}  {txt!r}")
print(f"# {len(hits)} wide strings")
PY
```

Practical notes:

- Scan at even offsets as well as odd; a wide string inside a resource blob rarely starts on a
  4-byte boundary.
- `0x00` in the high byte is the giveaway that the run is UTF-16LE ASCII. CJK text has non-zero
  high bytes, so widen the predicate to `\u4e00 <= c <= \u9fff` for Chinese strings.
- Windows also keeps wide strings in the resource section (dialog templates, string tables) and
  in the manifest, which `strings -el` will show as garbage unless decoded.

### Step 4 — Recognise obfuscated strings

Common shapes, with the byte pattern to look for:

**Stack string built DWORD by DWORD.** A sequence of `mov [rbp-xx], imm32` into consecutive
slots, followed by a single use of the buffer. The scanner in Step 2 finds the pieces; the
ordering comes from the displacement values.

**XOR loop.**

```
0x140001000:  48 8d 75 e0        lea  rsi, [rbp-0x20]
0x140001004:  48 8d 6d f8        lea  rbp, [rbp-0x18]
0x140001008:  80 30 5a           xor  byte ptr [rax], 0x5a
0x14000100b:  48 ff c0           inc  rax
0x14000100e:  48 39 c5           cmp  rbp, rax
0x140001011:  75 f5              jne  0x140001008
```

Signature: a `xor byte ptr [reg], imm8` (`80 30` / `80 31` / `80 32` / `80 33`) inside a loop with
a backward branch. The key is the immediate. Extract it, then XOR the buffer bytes with it to
recover the plaintext.

**Per-byte add/sub.**

```
0x140001008:  80 28 41           sub  byte ptr [rax], 0x41
```

`80 28` = `sub byte ptr [rax], imm8`; `80 00` = `add byte ptr [rax], imm8`.

**Rolling key.** The key changes each iteration: `xor byte ptr [rax], dl` where `dl` is updated
in the loop body.

**Decryption stub.** A function whose signature is `(uint8_t *buf, size_t len)` and whose body
contains an arithmetic loop over `buf[0..len)`. Locate it by finding the loop, then find its
caller — that caller is where the plaintext appears at runtime.

**Base64 or hex blob.** A long run of `A-Za-z0-9+/=` in a data section. Decode it and check for
a licence JSON or a signature envelope.

Search for these patterns with radare2:

```
r2 -q -c '/x 8030; /x 8031; /x 8028; /x 8000' target.exe
```

### Step 5 — Recover stack strings automatically

FLOSS (FireEye/mandiant) does the whole job: it resolves the immediate-to-stack heuristic and
the XOR/ADD/SUB decoder patterns, and reports the recovered strings with the offset they come
from.

```
floss --only stackstrings target.exe
floss --only decoded --only stackstrings target.exe
floss --json --verbose target.exe > floss.json
```

FLOSS also reports "decoded" strings, which are the obfuscated ones it could evaluate
statically. Its output is JSON with the offset and the decoded value.

Without FLOSS, the two-step manual route works:

1. Locate the function that fills the buffer (see Step 4).
2. Run the target under a debugger or Frida and read the buffer *after* the fill and *before*
   the comparison. This is the reliable way for rolling-key decoders.

```
# Frida 17.x: dump the decrypted buffer at the point of use
Interceptor.attach(Module.getGlobalExportByName("strcmp"), {
  onEnter(args) {
    console.log("strcmp:", args[0].readCString(), "|", args[1].readCString());
  }
});
```

Dumping at the comparison point sidesteps the entire decoder analysis: whatever the routine
produces is by definition the plaintext.

### Step 6 — Recover symbols for a stripped binary

**ELF.** `.symtab` is gone but `.dynsym` survives with the exported symbols. If a separate
debug file exists, use it:

```
readelf -sW target.elf | head -30
eu-readelf -s target.elf.debug | head -30
```

Attach the debug info at runtime:

```
gdb -q target.elf
(gdb) info functions
(gdb) add-symbol-file target.elf.debug 0x400000
(gdb) info functions check
```

**PE.** The debug directory holds an RSDS record with the PDB GUID and age. With the matching
`.pdb`:

```
llvm-pdbutil dump -summary target.pdb
llvm-pdbutil dump -symbols target.pdb | grep -i licence
```

Match the GUID before trusting the PDB — a mismatched PDB gives plausible but wrong names. The
GUID sits at the start of the RSDS record inside the `.pdb` debug entry:

```
python3 - <<'PY'
import pathlib, struct
d = pathlib.Path("target.exe").read_bytes()
i = d.find(b"RSDS")
if i > 0:
    guid = d[i+4:i+20]
    age = struct.unpack_from("<I", d, i+20)[0]
    print("GUID", guid.hex(), "age", age)
    print("PDB", d[i+24:d.find(b"\x00", i+24)].decode())
PY
```

**Mach-O.** The symbol table survives in `LC_SYMTAB` unless stripped; `nm` and `dsymutil` read it.

```
nm -nm target.macho | head -40
dsymutil target.macho
```

**Runtime symbolisation.** Debuggers and Frida resolve an address to a name from the loaded
module's symbol table even when the on-disk file is stripped:

```
# Frida 17.x
const d = DebugSymbol.fromAddress(0x140001234);
console.log(d.toString());

Process.enumerateModules().forEach(m => {
  if (m.name === "target.exe") {
    m.enumerateSymbols().forEach(s => {
      if (/licen/i.test(s.name)) console.log(s.name, s.address);
    });
  }
});
```

Note that on Windows the module's export table survives stripping and `enumerateSymbols`
reports exports and, for PDB-mapped modules, the PDB symbols once they are loaded.

### Step 7 — Confirm each recovered string is real

A recovered string is trustworthy when it is:

- Referenced by code (cross-reference exists).
- Semantically consistent with the surrounding strings — a licence checker produces
  `Invalid licence key`, `license_id`, `https://vendor/api`, not `hhell`.
- Reproducible: run the decryption routine twice, or re-run the scanner, and confirm the same
  plaintext.

## Variations

### Android DEX

DEX strings live in the `string_ids` table and are referenced by index from the code items.

```
jadx -d out target.apk
r2 -q -c 'izz' classes.dex | head -40
```

### .NET

The user-string heap (`#US`) holds UTF-16 literals; tools that list them:

```
ilspycmd --ilcode target.dll | grep -n 'ldstr'
```

### Resource-embedded strings

Windows `.rsrc` holds string tables and dialog templates; PE resources are not in the string
section and `strings` misses them. Use LIEF:

```
python3 - <<'PY'
import lief
b = lief.PE.Binary("target.exe")
for r in b.resources:
    print(r.id, r.name, r.type)
PY
```

### Rust and Go

Rust panic strings are real strings in `.rodata` and name the failing check:
`r2 -q -c 'izz~panicked at' target`. Go binaries keep names in `.gopclntab` even when
stripped of the ELF symbol table.

### Encrypted resources

A licence blob stored as an encrypted file next to the executable is decrypted by a routine in
the binary; the key derivation is in the same binary. Recover both — see the `license-crypto`
domain entries.

## Verification

1. Cross-check every recovered string against the raw bytes at the reported offset:

   ```
   r2 -q -c 'iz' target.exe | head -20
   xxd -s 0x2580 -l 32 target.exe
   ```

   The hex dump must show the same characters followed by a `00`.

2. Cross-check with an independent tool. GNU `strings` and radare2 must agree on the byte
   content of a string (their offsets differ by section base, which is expected).

3. Prove a stack-string recovery by checking that the recovered text is referenced: run the
   `axt` command on the buffer's address and confirm the code that reads it.

4. Prove a decoder recovery by executing it. Feed the recovered plaintext back into the
   comparison at runtime and confirm the application accepts it.

5. Negative test — confirm the false-positive rate: list every string the scanner reports and
   check that each one has a cross-reference. Strings without an xref are candidate false
   positives, not necessarily errors; each must be justified individually.

6. For symbol recovery, verify the mapping is not coincidental: call the recovered function from
   a debugger and check the stack frame matches the expected signature.

## Pitfalls

- Treating every printable run in the binary as a string. Instruction bytes produce thousands of
  them.
- Reading the immediate of a `mov` in the wrong endianness. x86 and ARM64 immediates are stored
  little-endian, so `0x6c6c6568` is `hell`.
- Forgetting that the immediate only holds *part* of the string. A four-character store is
  usually the start of a longer string built by several stores.
- Assuming `izz` respects section boundaries. It does not; use `iz` for that.
- Missing UTF-16LE strings because only ASCII extraction was run. Windows error messages and
  registry paths are usually wide.
- Assuming a decoder can be recovered statically. Rolling-key and table-driven decoders need
  dynamic observation.
- Trusting a `.pdb` whose GUID does not match the binary's RSDS record.
- Assuming a stripped binary has no symbols at all: `.dynsym`, the PE export table and
  `LC_SYMTAB` usually survive.
- Trying to dump memory of a process whose pages are encrypted by the OS (iOS `cryptid 1`) — the
  decrypted text only exists after the loader runs.
- Concluding a string is a licence check because it says "license". It may be a third-party
  dependency's string. Confirm the cross-reference chain reaches application code.

## References

- Mandiant FLOSS (FireEye), advanced string extraction: <https://github.com/mandiant/flare-floss>
- radare2 string commands: <https://r2.re>
- GNU binutils `strings`: <https://www.gnu.org/software/binutils/manual/html_node/strings.html>
- LLVM `llvm-pdbutil`: <https://llvm.org/docs/CommandGuide/llvm-pdbutil.html>
- GDB symbol files: <https://sourceware.org/gdb/onlinedocs/gdb.html/File-Formats>
- Frida JavaScript API, `DebugSymbol` and `Process.enumerateModules`: <https://frida.re/docs/javascript-api/>
- LIEF documentation: <https://lief.re/doc/latest/>
