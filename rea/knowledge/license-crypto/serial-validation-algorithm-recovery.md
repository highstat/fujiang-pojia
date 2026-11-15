---
id: "serial-validation-algorithm-recovery"
title: "Serial validation algorithm recovery"
domain: "license-crypto"
kind: "pattern"
platforms: "windows, macos, linux, android, ios"
arch: "x86, x86-64, arm64"
difficulty: "advanced"
tools: "radare2, Ghidra, Frida, Python"
verified: false
updated: "2026-11-15"
summary: "Catalogue of the six serial-validation shapes, with the disassembly fingerprint that identifies each one, the commands that extract the comparison operands, and the test that separates a whole-string checksum from a per-group check."
---

## Summary

A serial check is one comparison between something derived from user input and something the
vendor baked into the binary. The hard part is not finding the comparison, it is identifying
*which* comparison and pulling both operands out of the disassembly so the algorithm can be
re-implemented. Six shapes account for the overwhelming majority of real targets:

| Shape | Shape of the check | Where the truth lives |
| --- | --- | --- |
| (a) Direct equality | `memcmp`/`strcmp` against a literal | one constant in `.rodata`/`.rdata` |
| (b) Character class + checksum | per-character class test, then one accumulator compare | class rules + one stored total |
| (c) Transform-then-compare | hash/XOR/rotate the input, compare the digest | transform routine + stored digest |
| (d) Per-block arithmetic | each group of the serial checked independently | one rule per group |
| (e) Field decomposition | serial split into customer id, expiry, checksum | one check per field |
| (f) Container decode | Base32/Base64/custom alphabet decoded, then validated | alphabet table + inner check |

Reach for this entry when the app accepts an arbitrary-looking string and either accepts or
rejects it. The goal is a specification, not a patch: once the shape is known, the algorithm
can be written out in Python and turned into a keygen (see
[Keygen construction from a recovered algorithm](keygen-construction.md)).

## Recognition

Start from the observable failure, not from the binary. Collect:

- The exact error text: `Invalid license key`, `Serial number is not registered`,
  `ERR_LICENSE_013`, `Activation failed (code 0x8007000d)`.
- Which UI element reacts: a modal at startup, a greyed-out menu, a silent exit code.
- Whether the serial format is visible: `XXXXX-XXXXX-XXXXX`, 25 characters in Crockford Base32,
  a 40-hex blob.
- Whether the same serial behaves differently on a second machine. Different behaviour is the
  strongest hint that a machine field is folded into the check (shape (e) or a hardware digest).

Then triage the binary:

```bash
# working directory: the directory holding the target
rabin2 -zzq target.exe | grep -iE 'serial|licen[cs]e|regist|activat|invalid|expire|unlock'
rabin2 -i target.exe | grep -iE 'memcmp|strcmp|strncmp|CryptHash|BCryptHash|CryptVerify|Base64'
```

Strings that pair a validity message with a format hint usually point straight at the call site:

```bash
r2 -q -c 'izz~Invalid' target.exe
r2 -q -c 'izz~XXXXX' target.exe
```

## Method

### Step 1 — Locate the decision point

Find the cross-reference from the failure string to the comparing function:

```bash
r2 -q -c 'aaa; axt @@ str.*' target.exe 2>/dev/null | grep -i -B2 -A2 invalid
```

On a large binary, `aaa` is slow. Narrow first:

```bash
r2 -q -c 'izz~invalid_serial; axt @@ str.*_invalid_serial' target.exe
```

If the string is not present (message built at runtime, or in a resource), pivot to the import
that must be used by any string comparison:

```bash
r2 -q -c 'aaa; axt @ sym.imp.memcmp' target.exe
r2 -q -c 'aaa; axt @ sym.imp.strcmp' target.exe
```

Each cross-reference is a candidate call site. Confirm by reading the function that contains it:

```bash
r2 -q -c 'aaa; s 0x1400012f0; pdf' target.exe
```

### Step 2 — Classify the shape

Dump the comparison neighbourhood and match it against the table below.

#### (a) Direct equality against an embedded constant

Signature: a call to `memcmp`/`strcmp`/`strncmp` where one argument is a pointer into a
read-only section and the other points at user input.

```asm
; x64
0x140001230  lea  rdx, [rip+0x2a1f]        ; 0x140003c55 -> .rdata "7F3A-9C11-5B0E"
0x140001237  mov  rcx, 0xc                 ; length 12
0x14000123c  call qword [rip+0x2a40]       ; memcmp
0x140001242  test eax, eax
0x140001244  jne  0x140001290              ; -> "Invalid license key"
```

The literal may be obfuscated (stack strings, XOR-decoded blobs). If the string at the
cross-reference target is printable, it *is* the serial. Extract it:

```bash
r2 -q -c 'ps @ 0x140003c55' target.exe
```

Recovery is then trivial and the real work is finding *where* the constant lives: as a literal,
as a 16/32-byte AES key, or as a downloaded server-side pair.

#### (b) Character-class + checksum comparison

Signature: a loop that (i) tests each character against a class, and (ii) accumulates a value
into a register, followed by a single comparison against a stored total.

```asm
0x140001310  xor  eax, eax                 ; accumulator
0x140001312  mov  rdx, 0xc                 ; length
0x140001319  mov  rcx, rsi                 ; input
0x14000131c  movzx ebx, byte [rcx+rax]     ; c = s[i]
0x140001320  cmp  bl, 0x2d                 ; '-'
0x140001324  je   0x140001342
0x140001326  cmp  bl, 0x30                 ; '0'
0x14000132a  jb   0x140001360              ; -> reject
0x14000132c  cmp  bl, 0x39                 ; '9'
0x14000132f  jbe  0x140001344
0x140001331  sub  bl, 0x41                 ; 'A'
0x140001334  cmp  bl, 0x19                 ; <= 'Z'
0x140001337  ja   0x140001360              ; -> reject
0x140001339  add  bl, 0x26                 ; 'A'->10 .. 'Z'->35
0x14000133b  jmp  0x140001344
0x140001342  xor  ebx, ebx                 ; separator contributes 0
0x140001344  imul ebx, ebx, 0x1f           ; weight 31
0x140001347  add  eax, ebx                ; accumulate
0x140001349  inc  rax
0x14000134b  cmp  rax, rdx
0x14000134e  jne  0x14000131c
0x140001350  cmp  eax, 0x2c4               ; stored expected checksum
0x140001355  jne  0x140001360
```

Class checks frequently go through the C locale table instead of explicit ranges:

```asm
0x140001320  mov  rcx, [rip+0x1a40]        ; __ctype_b_loc()
0x140001327  movzx eax, bl
0x14000132a  test byte [rcx+rax*2], 0x04   ; _ISdigit
```

Recover the class rules by finding the comparison immediates and the `sub`/`add` pair that maps
a character to its numeric value. `sub bl, 0x41` followed by `add bl, 0x26` is the classic
`A..Z -> 10..35` mapping.

#### (c) Transform-then-compare

Signature: the input is passed through a hash, a rolling XOR, a rotation, or a byte shuffle,
and the *result* is compared with a stored digest.

```asm
0x140001410  lea  rdx, [rip+0x2b90]        ; 32-byte stored digest
0x140001417  mov  rcx, 0x20
0x14000141c  call qword [rip+0x2b98]       ; memcmp(digest, computed, 32)
0x140001422  test eax, eax
0x140001424  jne  0x140001470
```

The transform is upstream. Find it by walking backwards to the last write into the buffer that
becomes the compared operand, or by locating a known crypto import:

```bash
r2 -q -c 'aaa; axt @ sym.imp.CryptCreateHash; axt @ sym.imp.BCryptCreateHash; axt @ sym.imp.EVP_DigestInit_ex' target.exe
```

Custom transforms are usually a tight loop with shifts and XORs:

```asm
0x1400013a0  mov  eax, [rcx]              ; read 4 bytes
0x1400013a3  rol  edx, 0x07
0x1400013a6  xor  edx, eax
0x1400013a8  add  edx, 0x9e3779b9
0x1400013ae  mov  [rdi], edx
0x1400013b4  add  rcx, 4
0x1400013b7  cmp  rcx, rsi
0x1400013ba  jne  0x1400013a0
```

Immediate constants like `0x9e3779b9` (golden ratio), `0x5a827999`, `0x6ed9eba1` are hash
constants and immediately identify the transform as a TEA/XTEA-style or Murmur-style mix.

#### (d) Per-block arithmetic

Signature: the serial is cut into fixed-width groups and **each group is checked
independently**. The distinguishing feature is a nested loop, an index multiplied by a stride,
or a divide by the group length.

```asm
0x140001500  mov  rax, rsi                 ; input
0x140001503  xor  ecx, ecx                 ; group index
0x140001505  mov  edx, 5                   ; group width
0x14000150a  mov  r8, rax
0x14000150d  mov  r9d, 3                   ; group count
0x140001514  imul r10d, ecx, edx           ; offset = group * width
0x140001518  mov  r11d, 0                  ; per-group accumulator
0x14000151d  movzx esi, byte [r8+r10]
0x140001521  add  r11d, esi
0x140001524  inc  r10d
0x140001527  cmp  r10d, edx
0x14000152a  jl   0x14000151d
0x14000152c  cmp  r11d, dword [r9+rcx*4+0x140003c00]  ; table[group]
0x140001533  jne  0x140001560
0x140001535  inc  ecx
0x140001537  cmp  ecx, r9d
0x14000153a  jne  0x140001514
```

The `cmp r11d, [table + group*4]` line is the tell: the expected value is indexed by the
group index, so different groups have different rules.

#### (e) Field decomposition

Signature: the string is split on a separator and each field is parsed separately.

```asm
0x140001600  mov  rdi, rsi
0x140001603  mov  al, 0x2d                 ; '-'
0x140001605  call qword [rip+0x2f10]       ; strchr(s, '-')
0x14000160b  test rax, rax
0x14000160e  je   0x1400016a0
0x140001610  mov  byte [rax], 0            ; truncate first field
0x140001613  mov  rdi, rsi
0x140001616  mov  rdx, 10
0x14000161b  call qword [rip+0x2f18]       ; strtol(customer_id)
0x140001621  mov  rsi, rax
0x140001624  lea  rdi, [rax+1]
0x140001627  mov  edx, 0x2d
0x14000162b  call qword [rip+0x2f0c]       ; strchr(rest, '-')
```

`sscanf`/`strtol`/`atoi` usage tells the field types. A field that must satisfy `now < expiry`
is a date or a timestamp; a field compared against a range is a customer id.

#### (f) Container decode before validation

Signature: a decode step precedes the real check. Look for a 64-byte or 32-byte alphabet
table in `.rodata`, or a call to a base64/base32 decoder.

```bash
r2 -q -c 'px 128 @ 0x140003d00' target.exe    # expect the alphabet
r2 -q -c 'aaa; axt @ sym.imp.Convert.FromBase64String' target.exe   # .NET
```

Alphabet tables are unmistakable:

```
0x140003d00  "+/0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmno"  .rdata
```

For Base64 the last alphabet byte is `=`; for Crockford Base32 the alphabet is
`0123456789ABCDEFGHJKMNPQRSTVWXYZ` (no I, L, O, U). Custom alphabets are just a different
64-byte table — the decoder logic is identical, so once the table is known the decode is
reproducible.

### Step 3 — Extract the comparison operands

The operands are the two things compared. Get them out mechanically rather than by eye.

```bash
# 1. Disassemble the comparing function with resolved operands
r2 -q -c 'aaa; pdf @ 0x140001230' target.exe

# 2. JSON form, one instruction per entry: offset, opcode, operands, jump target
r2 -q -c 'aoj 24 @ 0x140001230' target.exe
```

Machine-readable extraction of the instruction stream for a function:

```bash
# working directory: the directory holding target.exe
r2 -q -c 'aaa; af @ 0x140001230; afbj' target.exe > /tmp/fcn.json
python3 - <<'PY'
import json, subprocess
ops = json.loads(subprocess.check_output(
    ["r2", "-q", "-c", "aoj 40 @ 0x140001230", "target.exe"]).decode())
for op in ops:
    print(f"{op['offset']:#x}  {op['opcode']:<12} {op['disasm']}")
PY
```

Dump the bytes at each operand that points into a read-only section, and print them as a
string:

```bash
r2 -q -c 'px 32 @ 0x140003c55' target.exe
r2 -q -c 'ps @ 0x140003c55' target.exe
```

For the stored digest of shape (c):

```bash
r2 -q -c 'px 32 @ 0x140004120' target.exe
# 9f 86 3d a1 4c 72 0b e5  ...
```

### Step 4 — Distinguish "checksum over the whole string" from "per-group check"

This distinction decides the keygen design, so settle it before writing any code.

| Signal | Whole-string checksum | Per-group check |
| --- | --- | --- |
| Number of compare instructions against a constant | one | one per group |
| Loop bound | total serial length | group length (stride) or group count |
| Accumulator reset | once, before the loop | once per group (nested loop) or once per call |
| Expected value source | one constant | table indexed by group, or a call argument |
| Error text | one generic message | message per group, or one with the group index |
| Behaviour on a wrong middle group | whole serial rejected | only that group rejected |

Decisive test: change one character in the middle of the serial and observe which comparison
fails. Set a breakpoint on every compare that feeds a conditional jump and see which one
trips.

```bash
r2 -q -c 'aaa; s 0x14000134c; db' target.exe
```

In a debugger, break on the compare at the accumulator check, then modify the serial to
perturb only group 2. If the failing compare is the group-indexed table lookup, the check is
per-group. If the failing compare is a single final compare against a stored total, it is a
whole-string checksum.

The static tell is the accumulator. Search for the register that is compared against a
constant and see where it is last written:

```bash
r2 -q -c 'aaa; pdf @ 0x140001300' target.exe | grep -n 'eax\|ebx\|ecx'
```

`add eax, ebx` inside the loop followed by a single `cmp eax, imm` after the loop = whole
string. `add r11d, esi` inside an inner loop whose bound is the group width = per group.

### Step 5 — Recover the class rules and constants

Class rules live in three places: explicit range compares, a `__ctype_b_loc` table use, or a
256-byte lookup table of your own. Dump the latter:

```bash
r2 -q -c 'px 256 @ 0x140003d40' target.exe
```

Character-to-value mapping is visible as a `sub`/`add` pair or a table index. Note it down as a
mapping table, not as an expression, because the code often branches:

```python
# recovered mapping, written as an explicit table
def v(c: str) -> int:
    if '0' <= c <= '9':
        return ord(c) - 0x30
    if 'A' <= c <= 'Z':
        return ord(c) - 0x41 + 10
    if 'a' <= c <= 'z':
        return ord(c) - 0x61 + 10
    raise ValueError(c)
```

### Step 6 — Write the recovered algorithm down as a spec

Produce a Python function that returns `True` for the vendor's own serial and `False` for a
mutated one. Only then move to
[Keygen construction from a recovered algorithm](keygen-construction.md).

```python
ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def v(c: str) -> int:
    return ALPHABET.index(c)

def checksum(serial: str) -> int:
    total = 0
    for i, ch in enumerate(serial):
        if ch == '-':
            continue
        total += v(ch) * 31
    return total

def validate(serial: str) -> bool:
    if len(serial) != 12:
        return False
    return checksum(serial) == 0x2c4
```

## Variations

**Platform deltas.** The shapes are identical across platforms; only the API surface changes.

- Windows native: `CryptVerifySignature`/`BCryptVerifySignature` for signed blobs,
  `CryptCreateHash`/`BCryptCreateHash` for digests, `memcmp` for direct equality.
- macOS: `CCCryptorCreate`/`CCCrypt` for symmetric transforms, `CommonCrypto` digests,
  `SecKeyVerifySignature` for asymmetric checks.
- Linux ELF: `strcmp`/`memcmp` from glibc, `EVP_DigestVerifyFinal` for signature checks,
  often `libcrypto.so.3` statically linked into the binary.
- Android: the check frequently lives in `libnative.so` (JNI) or in Kotlin code; the JNI entry
  `Java_com_vendor_app_License_check` is the cross-reference anchor.
- .NET: `string.Equals`, `Span.SequenceEqual`, `Convert.FromBase64String`;
  use dnSpyEx 6.6.0 to read the IL directly rather than the disassembly.
- iOS: Objective-C `isEqualToString:`/`isEqualToData:`; `SecKeyVerifySignature` in frameworks.

**Architecture deltas.**

- x86-32 comparison idioms: `cmp dword [esp+4], imm`; `repe cmpsb` for inline string compare.
- x64: `movzx eax, byte [rdx+rax]` for table lookups; `lea rdx, [rip+disp32]` for RIP-relative
  constants.
- ARM64: `cmp w0, #0x2d` (`0x71000d1f` style encodings), `ldrb w8, [x0, x1]`, `adrp`/`add` pairs
  for constants — always resolve the `adrp` + `add` pair before reading a literal.

**Managed equivalents.** In .NET, `string.op_Equality` compiles to a length compare plus a
sequence compare; the *length constant* is often the strongest fingerprint, since the whole
algorithm collapses to one `ldc.i4` + `ceq`.

**Anti-analysis variants.** If the constant is not present as a literal, the binary builds it
at runtime: stack strings (`mov byte [rbp-0x20], 0x41`), XOR-decoded buffers, or a VM
interpreter. In those cases hook the compare at runtime and read the operand straight out of
the register (see [Hardware fingerprint binding](hardware-fingerprint-binding.md) for the
Frida patterns).

## Verification

1. **Positive test.** Feed the recovered validator the vendor's own serial. It must return
   `True` and the comparison in the binary must not be taken.
2. **Negative test.** Mutate one character of the vendor serial. The validator must return
   `False` *and* the failing compare must be the same one the patched binary takes. If the
   validator returns `False` but the binary still accepts, the real check is elsewhere.
3. **Group sensitivity test.** For a per-group check, mutate a character in group 2 only and
   confirm that the group-2 rule fails while group 1 and group 3 rules are untouched. This is
   the test that distinguishes shape (d) from a whole-string checksum.
4. **Cross-check against the binary.** Confirm that at least one comparison constant in the
   disassembly matches a constant in the recovered spec. A spec with no matching constant was
   guessed, not recovered.
5. **Coverage.** Run the validator against at least 200 random valid-format serials and confirm
   the accept rate matches the binary's accept rate. A recovered algorithm that accepts
   everything is missing a rule.

## Pitfalls

- **Wrong constant, right function.** A `memcmp` against a UI string ("OK", "Done") looks like a
  serial comparison. Confirm the constant's content and length before assuming.
- **Length check mistaken for the check.** `cmp rcx, 12` followed by `memcmp` — the length is
  not the algorithm; the constant after it is.
- **The check runs twice.** The UI validates the serial, and a background service validates it
  again. Patching the UI copy leaves the service copy. Locate all call sites of the validating
  function, not just the one that shows the dialog.
- **Case-insensitive comparison.** `strcasecmp`/`_stricmp`/`toLowerCase` means `a` and `A` are
  both valid; a spec that rejects lowercase will fail the positive test.
- **Locale-dependent class checks.** `isalpha`/`isdigit` behave differently under a non-C
  locale; `__ctype_b_loc` reads the locale table at runtime, so the class set is not a compile
  time constant.
- **Unicode.** A UTF-8 serial validated byte-wise differs from one validated with `wchar_t`.
  Check whether the length compare uses `0xc` (bytes) or `0x18` (UTF-16 code units).
- **Hash truncation.** A 20-byte SHA-1 compared with `memcmp` of only the first 8 bytes means
  the stored constant is truncated; compare the same number of bytes the binary compares.
- **The constant is XOR-encoded.** If the extracted bytes are non-printable garbage while the
  program accepts a valid serial, look for a decode loop that writes into that buffer before
  the compare.
- **Offsets move between versions.** The file offset, the virtual address and the r2 flag
  address differ. Always record the virtual address and re-locate by content, not by raw
  offset.

## References

- radare2 6.2.6 command reference: `pdf`, `aoj`, `axt`, `izz`, `px`, `ps` —
  <https://radare.org/docs/>
- Ghidra 12.2 decompiler and scripting —
  <https://ghidra-sre.org/docs/GhidraDocs/ghidra_docs_latest/>
- LIEF 1.0.0 for reading sections and symbols programmatically —
  <https://lief.re/doc/latest/>
- Frida 17.x JavaScript API (instance-side `Process.getModuleByName`) —
  <https://frida.re/docs/javascript-api/>
- PKCS #1 v2.2 (RSA) and FIPS 186-4 (ECDSA) for the digest-compare shapes —
  <https://www.rfc-editor.org/rfc/rfc8017>
- Sibling entries: [Keygen construction from a recovered algorithm](keygen-construction.md),
  [Symmetric licence blob formats](symmetric-license-blob-formats.md),
  [Asymmetric licence signature verification](asymmetric-license-signature-verification.md)
