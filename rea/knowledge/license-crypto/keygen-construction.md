---
id: "keygen-construction"
title: "Keygen construction from a recovered algorithm"
domain: "license-crypto"
kind: "technique"
platforms: "windows, macos, linux, android, ios"
arch: "x86, x86-64, arm64"
difficulty: "advanced"
tools: "Python, Frida, radare2"
verified: false
updated: "2026-11-15"
summary: "Turn a recovered serial-validation routine into a working generator: choose the search direction, handle multi-group checksums with carries, and validate the output against the target binary before shipping a keygen."
---

## Summary

A recovered validation routine is a *specification*; a keygen is a *search strategy* on top of
it. The three questions that decide the strategy are:

1. **Which field is unknown?** A serial that validates but contains no free text is a closed
   set. If the vendor's serial contains a customer id or a date that the customer chooses,
   the checksum field is computable and the generator is a closed-form function.
2. **Is the algorithm invertible?** If the checksum field is `f(known fields)`, compute it. If
   the checksum field is a *transform* (MD5 truncation, HMAC, custom mix) of the known fields,
   there is no closed form — the problem becomes "find `x` with `f(x) == target`", i.e. a
   search over the checksum space, optionally framed as a constraint problem.
3. **Is the check per group or per serial?** A per-group check decomposes into independent
   sub-problems, one per group, which is easier than the monolithic case.

This entry walks the decisions in order and ends with a complete worked example: a three-group
serial whose third group is a weighted sum of the first two groups modulo 36.

Prerequisite: [Serial validation algorithm recovery](serial-validation-algorithm-recovery.md).

## Recognition

A keygen target shows up as:

- A serial format with an obviously "computed" trailing group:
  `XXXXX-XXXXX-CCCC`, `AAAA-BBBB-CCCC-DDDD`, a 25-character Crockford Base32 blob where the
  last 5 characters look random but the first 20 follow a pattern.
- An error message that distinguishes field failures from checksum failures:
  `Invalid checksum (group 3)`, `Checksum mismatch`, `ERR_BAD_SIG`. A per-group message names
  the group and tells the reader the check is per-group.
- Registration screens where the customer id and expiry are user-editable while the checksum
  field is not.
- A vendor keygen page: `https://vendor.example/activate` with a form field `serial` and a
  `customer id` field. The page usually states the format, which pins the group count and
  widths.

## Method

### Step 1 — Write the algorithm back out in Python

Transcribe the disassembly into a function that takes the raw serial and returns a verdict.
Keep the constants exactly as recovered — the same character values, the same multipliers,
the same modulus, the same comparison direction. A transcription that "normalises" the input
(maps to upper case, strips dashes) hides the actual accept set.

```python
# recovered_spec.py — transcribed from the disassembly, one line per instruction group
ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def v(ch: str) -> int:
    return ALPHABET.index(ch)

def validate(serial: str) -> bool:
    if len(serial) != 14:          # "XXXXX-XXXXX-CCCC"
        return False
    g1, g2, g3 = serial[0:5], serial[6:10], serial[11:15]
    for ch in g1 + g2 + g3:
        if ch not in ALPHABET:
            return False
    return checksum(g1, g2) == g3
```

Run it against the vendor's serial first:

```bash
python3 -c "import recovered_spec as s; print(s.validate('7F3A-9C11-5B0E'))"
```

Expected: `True`. If it prints `False`, the transcription is wrong — do not go further.

### Step 2 — Decide the search direction

| Situation | Direction | Cost |
| --- | --- | --- |
| Checksum is an arithmetic function of the known fields | compute the missing field | microseconds |
| Checksum is a truncated hash of the known fields | brute force the checksum space | 36^4 = 1,679,616 for a 4-char group |
| Per-group checks, each group independent | solve each group separately | sum of the parts |
| A field is a date/timestamp the user picks | enumerate dates, compute the checksum | days × 1.68M (batchable) |
| Checksum depends on unknown fields too | search the joint space | combinatorial, needs pruning |

The default is compute-from-known. Only fall back to brute force when the recovered code
shows a digest or a non-invertible mix instead of an accumulator.

### Step 3 — Handle multi-group checksums with carry

Two accumulator styles appear in real serials.

**Style A — additive accumulator.** Each group contributes `sum(weight_i * value_i)` and the
total is reduced modulo the group base.

**Style B — polynomial / rolling accumulator.** The group is a base-36 number and the
accumulator is multiplied by 36 before each digit is added. This is the base-36 equivalent of
"shift left one digit, add the next", and it is where carries matter:

```python
# Style B, base-36 polynomial hash, MSB first, with explicit carry
def poly36(groups, weights=None, mod=None):
    acc = 0
    pos = 0
    for g in groups:
        for ch in g:
            if weights is not None:
                acc = acc + weights[pos] * v(ch)
            else:
                acc = acc * 36 + v(ch)      # shift-and-add, carry is implicit
            pos += 1
    if mod is not None:
        acc %= mod
    return acc
```

When the recovered code adds a contribution into a multi-digit base-36 accumulator instead of
multiplying, carry must be propagated explicitly:

```python
def add_into(acc: int, contribution: int, width: int, base: int = 36) -> int:
    """Add `contribution` into the low `width` base-`base` digits of `acc`, with carry."""
    for i in range(width):
        digit = acc % base
        digit += contribution % base
        carry, digit = divmod(digit, base)
        acc = acc - digit + (digit * (base ** i))
        contribution = contribution // base + carry
    return acc
```

Getting the carry wrong is the classic reason a keygen produces serials that the app rejects
only for *some* prefixes. Compare against the binary with the Frida trace in Step 6 rather
than reasoning about it in the abstract.

### Step 4 — Handle per-group checks

When the disassembly shows an expected-value table indexed by the group number
(`cmp r11d, [table + rcx*4]`), the check decomposes. Each group has its own rule, and a
serial is valid only if every group satisfies its own rule. Build one solver per group:

```python
def solve_group(rules, group_index, candidates):
    """Return the first candidate satisfying the rule for `group_index`."""
    for cand in candidates:
        if rules[group_index](cand):
            return cand
    return None
```

Do not assume the groups are independent until the disassembly confirms it. If the loop that
computes group 3 reads characters from group 1, the groups are coupled and the search must be
over the joint space.

### Step 5 — Validate the generator against the target

Two independent validations are needed.

**5a. Static cross-check.** Every constant in the Python spec must appear as an immediate or
as data in the binary.

```bash
r2 -q -c 'aaa; /x 2c040000' target.exe     # expected checksum 0x2c4, little endian
r2 -q -c 'izz~7F3A' target.exe
```

**5b. Runtime cross-check with Frida 17.** Hook the comparison and print both operands for any
serial the app sees. This confirms the expected constant and the comparison length without
having to satisfy the UI.

```javascript
// trace_cmp.js — Frida 17.x, run with:
//   frida -f target.exe -l trace_cmp.js
const libc = Process.getModuleByName("libc.so.6");   // Windows: kernel32.dll, macOS: libSystem.B.dylib
const strcmp = libc.getExportByName("strcmp");

Interceptor.attach(strcmp, {
  onEnter(args) {
    const a = args[0].readCString();
    const b = args[1].readCString();
    if (a !== null && b !== null && (a.length < 64) && (b.length < 64)) {
      console.log("[strcmp] " + a + "  ||  " + b);
    }
  }
});
```

Expected output for a valid serial:

```
[strcmp] 7F3A-9C11-5B0E  ||  7F3A-9C11-5B0E
```

**5c. Feed the generated serial back in.** If the app exposes a command-line check, use it:

```bash
./target --check-serial 7F3A-9C11-5B0E
echo $?     # 0 = accepted, non-zero = rejected
```

If there is no CLI, drive the GUI and confirm the dialog, or write the generated serial into
the input buffer at runtime:

```javascript
// write_serial.js — Frida 17.x
const readCString = (ptr) => ptr.isNull() ? null : ptr.readCString();
const strcmp = Process.getModuleByName("libc.so.6").getExportByName("strcmp");
let seen = 0;
Interceptor.attach(strcmp, {
  onEnter(args) {
    const a = readCString(args[0]);
    const b = readCString(args[1]);
    if (a !== null && b !== null && a.includes("-") && a.length === 15 && seen++ < 20) {
      console.log("[cmp] " + a + " || " + b);
    }
  }
});
```

### Step 6 — Worked example: 3 groups, group 3 = weighted sum of groups 1 and 2 mod 36

**The recovered facts.** From the disassembly of the validating function:

```
0x140001600  mov  rax, rsi                 ; input
0x140001603  xor  ecx, ecx                 ; char index
0x140001605  mov  edx, 9                   ; 9 characters consumed: 5 + 4
0x14000160a  mov  r8d, [r9+rcx*4]          ; weight = WEIGHTS[rcx]
0x14000160f  movzx esi, byte [rax+rcx]     ; c = s[i]
0x140001613  cmp  sil, 0x2d                ; skip '-'
0x140001616  je   0x140001620
0x140001618  imul esi, esi, 0x24           ; value * 36
0x14000161b  add  eax, esi
0x14000161d  inc  rcx
0x14000161f  cmp  rcx, rdx
0x140001622  jne  0x14000160a
0x140001624  mov  edx, 0x1a3600            ; 36^4 = 1679616
0x140001629  xor  ecx, ecx
0x14000162b  div  edx                      ; total mod 36^4
0x14000162d  mov  rcx, rax
0x140001630  mov  rdx, 0x100
0x140001635  div  rdx                      ; split into 4 base-36 digits
...
```

Recovered constants:

- Alphabet: `0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ`, value = index (0..35).
- Group widths: 5, 4, 4. Separators: `-` at positions 5 and 10.
- Weights for the 9 characters of groups 1 and 2, read from the table at `0x140003c00`:
  `1, 2, 3, 5, 8, 13, 21, 34, 55`.
- The accumulator adds `value * weight * 36` per character (not `value * weight`), i.e. the
  total is a base-36-weighted sum, and the result is reduced mod `36^4 = 1,679,616`.
- The 4 characters of group 3 are the base-36 digits of that remainder, most significant
  first.

**Arithmetic reasoning for the weights.** The weights `1, 2, 3, 5, 8, 13, 21, 34, 55` are
Fibonacci numbers. Their purpose is *diffusion*: each output digit must depend on every input
digit, so that a single-character typo changes the whole checksum group rather than only its
low digits. Concretely, with the recovered `value * weight * 36` accumulation:

- The contribution of character *i* is `v_i * w_i * 36`. Because every term carries a factor
  of 36 and the modulus is `36^4`, the least significant output digit depends on **all**
  characters (it is `sum(v_i * w_i) mod 36`), the second digit depends on the carry out of
  that sum, and so on.
- The minimum weight is 1 and the largest is 55, so no single character can be "shadowed" by a
  later one: changing the last character by 1 changes the total by `55 * 36 = 1980`, which
  changes at least the low two output digits.
- The weights are **not** superincreasing: `1+2+3+5+8+13+21+34 = 87 > 55`. So the map is not
  injective over the full 36^9 input space — roughly one in `36^4 / 36^9` collisions exist
  per checksum value. That is fine: a licence system only needs the checksum to be
  *checkable*, not collision-free. Do not write a keygen that assumes uniqueness.

**The generator.**

```python
# keygen.py — 3-group serial, group 3 = weighted sum of groups 1-2 (base-36) mod 36^4
ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
BASE     = 36
MOD      = BASE ** 4          # 1679616
WIDTHS   = (5, 4, 4)
WEIGHTS  = (1, 2, 3, 5, 8, 13, 21, 34, 55)   # 9 weights: group1 (5) + group2 (4)

def v(ch: str) -> int:
    return ALPHABET.index(ch)

def b36_encode(value: int, width: int) -> str:
    """Encode `value` as `width` base-36 digits, most significant first."""
    out = []
    for _ in range(width):
        value, rem = divmod(value, BASE)
        out.append(ALPHABET[rem])
    if value:
        raise ValueError("value does not fit in %d base-36 digits" % width)
    return "".join(reversed(out))

def b36_decode(group: str) -> int:
    acc = 0
    for ch in group:
        acc = acc * BASE + v(ch)
    return acc

def checksum_value(group1: str, group2: str) -> int:
    """Weighted sum over the 9 characters of groups 1 and 2, times 36, mod 36^4."""
    total = 0
    idx = 0
    for group in (group1, group2):
        for ch in group:
            total += v(ch) * WEIGHTS[idx] * BASE
            idx += 1
    return total % MOD

def checksum_group(group1: str, group2: str) -> str:
    return b36_encode(checksum_value(group1, group2), 4)

def generate(group1: str, group2: str) -> str:
    """Compute group 3 from groups 1 and 2."""
    for group, width in ((group1, WIDTHS[0]), (group2, WIDTHS[1])):
        if len(group) != width:
            raise ValueError("group must be %d characters" % width)
        if any(ch not in ALPHABET for ch in group):
            raise ValueError("character outside the base-36 alphabet")
    return "%s-%s-%s" % (group1, group2, checksum_group(group1, group2))

def validate(serial: str) -> bool:
    parts = serial.split("-")
    if len(parts) != 3:
        return False
    g1, g2, g3 = parts
    if len(g1) != 5 or len(g2) != 4 or len(g3) != 4:
        return False
    if any(ch not in ALPHABET for ch in serial.replace("-", "")):
        return False
    return checksum_group(g1, g2) == g3

if __name__ == "__main__":
    import sys
    if len(sys.argv) == 3:
        print(generate(sys.argv[1], sys.argv[2]))
    else:
        print(generate("7F3A", "9C11"))
        print(validate(generate("7F3A", "9C11")))
```

Worked arithmetic, `group1 = "7F3A"`, `group2 = "9C11"`:

| position | char | value | weight | contribution `value * weight * 36` |
| --- | --- | --- | --- | --- |
| 0 | `7` | 7 | 1 | 252 |
| 1 | `F` | 15 | 2 | 1080 |
| 2 | `3` | 3 | 3 | 324 |
| 3 | `A` | 10 | 5 | 1800 |
| 4 | `9` | 9 | 8 | 2592 |
| 5 | `C` | 12 | 13 | 5616 |
| 6 | `1` | 1 | 21 | 756 |
| 7 | `1` | 1 | 34 | 1224 |
| 8 | `9` | 9 | 55 | 17820 |

Total = 252 + 1080 + 324 + 1800 + 2592 + 5616 + 756 + 1224 + 17820 = **31,464**.
`31,464 mod 1,679,616 = 31,464`. Base-36 digits of 31,464:
`31,464 = 24 * 1296 + 240` → `24` = `O`; `240 = 6 * 36 + 24` → `6`, `24` = `O`.
So the four digits are `O`, `6`, `6`, `O` → group 3 = `O66O`.

```
7F3A-9C11-O66O
```

**Step 7 — Brute-force the checksum space when there is no closed form.**

If group 3 is the first 4 characters of `MD5(group1 + "-" + group2)` instead of an
arithmetic sum, there is no closed form. Search the space directly:

```python
# search_hash.py — brute force the 4-character checksum group
import hashlib, itertools, sys

ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
GROUP1, GROUP2 = "7F3A", "9C11"
TARGET = sys.argv[1] if len(sys.argv) > 1 else None   # expected hex digest prefix, optional

def digest(group1: str, group2: str) -> str:
    return hashlib.md5(f"{group1}-{group2}".encode()).hexdigest()

def brute(group1: str, group2: str, target: str | None = None):
    """Yield (candidate, digest) for all 36^4 candidates."""
    for combo in itertools.product(ALPHABET, repeat=4):
        cand = "".join(combo)
        d = digest(group1 + "-" + group2 + "-" + cand)
        if target is None or d.startswith(target):
            yield cand, d

if __name__ == "__main__":
    for cand, d in brute(GROUP1, GROUP2, TARGET):
        print(cand, d)
        break
```

`36^4 = 1,679,616` iterations of a single MD5 take well under a minute in CPython, and less
than a second in C. Parallelise with `multiprocessing.Pool` if the target needs many.

**Step 8 — Constraint-solver route for arithmetic checksums with several unknowns.**

When the checksum depends on more than one unknown group, model the recovered arithmetic as
constraints and let a solver find the assignment:

```python
# solve_z3.py — pip install z3-solver
from z3 import Int, Solver, And, sat

BASE = 36
MOD = BASE ** 4
ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
WEIGHTS = (1, 2, 3, 5, 8, 13, 21, 34, 55)

def v(ch: str) -> int:
    return ALPHABET.index(ch)

group1, group2 = "7F3A", "9C11"
known = 0
idx = 0
for group in (group1, group2):
    for ch in group:
        known += v(ch) * WEIGHTS[idx] * BASE
        idx += 1

# unknown group 3 digits: x0 (MSB) .. x3 (LSB)
x = [Int(f"x{i}") for i in range(4)]
s = Solver()
for xi in x:
    s.add(And(xi >= 0, xi <= 35))
unknown = x[0] * BASE ** 3 + x[1] * BASE ** 2 + x[2] * BASE + x[3]
s.add((known + unknown) % MOD == 0)   # solver picks any consistent group 3
if s.check() == sat:
    m = s.model()
    out = "".join(ALPHABET[m[xi].as_long()] for xi in x)
    print("candidate group 3:", out)
```

Note that the solver only helps when the recovered arithmetic is expressible as constraints
over integers. A hash-based checksum is opaque to z3 and must be searched.

## Variations

**Per-group vs whole-serial checks.** Per-group checks decompose into independent
sub-problems, and each group's rule may have a different shape (group 1 = character class,
group 2 = date, group 3 = weighted sum). A single Python file with one function per group
mirrors the disassembly and makes bugs local.

**Date-bound serials.** When group 2 encodes a date, enumerate candidate dates, compute the
checksum for each, and emit one serial per day. Generate a whole year in a second, and
remember that the app compares against *its own* clock — see
[Trial and expiry enforcement](trial-and-expiry-enforcement.md).

**Customer-id-bound serials.** When group 1 is a customer id issued by the vendor, the keygen
is only useful if the customer id space is guessable (sequential integers). Enumerate
`id = 1..100000` and produce one serial per id.

**Field-ordered serials.** Some formats are `PREFIX-KEY-SERIAL`, where the serial depends on a
vendor-issued key. The key is the free parameter; the keygen takes the key as input and
outputs the serial.

**Multi-product keygens.** One binary may host several algorithms selected by a product code
in the serial's first field. Recover the dispatcher and build one generator path per product
code.

**Managed targets.** In .NET, the same algorithm is expressed as LINQ or a `Span<char>` loop;
transcribe the C#, not the IL, and keep the same constants. In Kotlin/Java, watch for
`Character.getNumericValue` and `BigInteger` — a base-36 accumulator implemented as
`BigInteger` changes the arithmetic order but not the result.

**Runtime-only recovery.** If the constants are decrypted at startup, transcribe them from a
Frida dump instead of the binary. See
[Symmetric licence blob formats](symmetric-license-blob-formats.md) for the dump procedure.

## Verification

1. **Self-consistency.** `validate(generate(g1, g2))` must be `True` for a large sample of
   random `(g1, g2)` pairs. Run at least 10,000 pairs; a mismatch rate above zero means the
   transcription is wrong.
2. **Vendor-serial consistency.** The vendor's own serial must satisfy the same spec
   (`validate(vendor_serial) == True`). If not, the algorithm is misread — go back to
   [Serial validation algorithm recovery](serial-validation-algorithm-recovery.md).
3. **Binary cross-check.** Every constant in the spec appears in the binary:
   `r2 -q -c '/x 1a360000' target.exe` finds the `36^4` modulus, and the weight table is
   readable with `px 36 @ 0x140003c00`.
4. **Live acceptance.** Feed at least one generated serial to the real app and confirm the
   licensed state (feature unlocked, no expiry dialog). This is the only test that proves
   the whole chain.
5. **Negative test.** Feed a serial with one character changed in group 3 and confirm it is
   rejected. Then feed a serial with one character changed in group 1 and confirm it is
   rejected — that specifically proves the checksum covers groups 1 and 2.
6. **Second-target test.** If the same keygen is expected to work on a second build, run it
   there. A keygen that only works against one build usually encodes an offset-dependent
   constant.

## Pitfalls

- **The vendor serial does not validate.** The most common cause is dropping a normalisation:
  the binary lowercases the input, strips dashes, or maps `O`/`0` and `I`/`L` (Crockford
  Base32). Re-read the code before assuming the algorithm is wrong.
- **The base is not 36.** Base 32 (Crockford), Base 31 (Alphenum), and base 36 all appear. The
  base is the modulus in the disassembly: `div` by `0x20`, `div` by `0x24`, or a lookup table
  of that length in `.rodata`.
- **Weight order reversed.** Weights may apply right-to-left. If the self-consistency test
  fails but the vendor serial is close, try the reversed weight vector before rewriting
  anything else.
- **Carry dropped.** In the additive style, forgetting to reduce intermediate values lets the
  accumulator exceed 32 bits and the `div` result changes. Reduce modulo `MOD` at the same
  point the binary does.
- **Endianness.** A 32-bit accumulator read with `mov eax, [rdi]` is little endian on x86 and
  ARM64 in LE mode; a big-endian target (some ARM64 BE builds, some network appliances) needs
  the bytes reversed.
- **Prefix byte.** Some formats prepend a fixed byte or a length byte before hashing. It is
  part of the hashed data; omitting it gives a wrong digest.
- **Case-sensitive comparison in the app.** The generator emits uppercase; if the binary
  compares with `memcmp` against an uppercase literal, that matches, but if it lowercases the
  input first, the generator must lowercase too.
- **Guessing vs recovering.** A keygen that works on one serial and fails on another is a
  guess. Use the Frida trace from Step 5 to print the expected operand and confirm.
- **Rate limiting and lockout.** Repeated failures can trigger a delay or a lockout. Throttle
  the testing loop and never point a live keygen at a production activation server.

## References

- radare2 6.2.6 (`/x` byte search, `px` hex dump, `aoj` instruction JSON) —
  <https://radare.org/docs/>
- Frida 17.x JavaScript API and `Interceptor` semantics —
  <https://frida.re/docs/javascript-api/>
- Z3 Python bindings and the SMT-LIB standard — <https://github.com/Z3Prover/z3>
- Python `hashlib` and `itertools` documentation — <https://docs.python.org/3/library/>
- Sibling entries: [Serial validation algorithm recovery](serial-validation-algorithm-recovery.md),
  [Trial and expiry enforcement](trial-and-expiry-enforcement.md)
