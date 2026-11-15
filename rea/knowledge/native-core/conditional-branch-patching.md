---
id: "conditional-branch-patching"
title: "Conditional branch patching"
domain: "native-core"
kind: "technique"
platforms: "-"
arch: "x86, x86-64, arm64"
difficulty: "intermediate"
tools: "radare2, r2pipe, Ghidra, xxd, python3"
verified: false
updated: "2026-11-15"
summary: "Inverts, neutralises or replaces conditional jumps with exact opcode bytes for x86, x64 and ARM64, and shows how to force a check function to return true without breaking the surrounding control flow."
---

## Summary

A licence check almost always ends in a conditional jump: compare a computed value, branch to the
failure path. Patching that jump is the smallest reversible change available. This entry lists
the complete conditional-jump encodings, the exact byte substitutions for inversion and
neutralisation, the "return true" byte sequences, and the two mistakes that break more binaries
than the check itself — an inverted branch that runs the failure path, and a patched function
whose ABI is wrong for the caller.

## Recognition

- A compare immediately followed by a branch: `cmp`/`test` then `je`, `jne`, `jz`, `jnz`, `jg`,
  `jl`, `b.eq`, `b.ne`.
- A boolean-returning function: the caller consumes the result in `AL` (x64), `al`/EAX (x86) or
  `w0` (ARM64) and branches on it.
- Failure-path strings referenced from the block the branch guards: `Invalid license key`,
  `Serial number is not registered`, `ERR_LICENSE_013`.
- A validation function that ends with a single `ret` and returns a small integer, whose result
  the caller tests immediately.

## Method

### Step 1 — Locate the branch, not the string

Anchors on the failure string first, then take the cross-reference to the code that uses it.

```
r2 -q -c 'aaa; iz~license; axt @@ str.*license*' target.exe
```

In Ghidra: search the string, then right-click the result and choose *References → Show References
To*. The reference site is inside the failure block; the branch that guards it is a few
instructions earlier.

For a boolean function, walk backwards from the caller instead:

```
r2 -q -c 'aaa; axt @@ sym.imp.*' target.exe          # who calls the interesting import
r2 -q -c 'aaa; pdf @ 0x140001234' target.exe        # the call site
```

Search for the raw opcode directly when nothing is named:

```
r2 -q -c '/x 0f85; /x 740f; /x 54000000' target.exe
```

Ghidra: *Search → For Byte Sequence* with `0f 85` or `54 00 00 00`, restricted to the executable
block.

### Step 2 — x86/x64 conditional jump encodings

Two encodings cover every x86/x64 conditional branch:

| Form | Bytes | Displacement | Range |
| --- | --- | --- | --- |
| short `Jcc` | `7x` where `x` is the condition nibble | `rel8` | -128 .. +127 |
| near `Jcc` | `0F 8x` | `rel32` | ±2 GiB |
| `SETcc` | `0F 9x` | none | writes `AL` |
| `CMOVcc` | `0F 4x` / `0F 8x` (reg form) | none | writes a register |

The condition nibble and its partner:

| Nibble | Condition true | Condition false | Flags tested |
| --- | --- | --- | --- |
| `0` | `JO` | `JNO` | OF |
| `1` | `JNO` | `JO` | OF |
| `2` | `JB` / `JC` | `JAE` / `JNB` | CF |
| `3` | `JAE` / `JNB` | `JB` / `JC` | CF |
| `4` | `JE` / `JZ` | `JNE` / `JNZ` | ZF |
| `5` | `JNE` / `JNZ` | `JE` / `JZ` | ZF |
| `6` | `JBE` / `JNA` | `JA` / `JNBE` | CF or ZF |
| `7` | `JA` / `JNBE` | `JBE` / `JNA` | CF or ZF |
| `8` | `JS` | `JNS` | SF |
| `9` | `JNS` | `JS` | SF |
| `A` | `JP` / `JPE` | `JNP` / `JPO` | PF |
| `B` | `JNP` / `JPO` | `JP` / `JPE` | PF |
| `C` | `JL` / `JNGE` | `JGE` / `JNL` | SF != OF |
| `D` | `JGE` / `JNL` | `JL` / `JNGE` | SF != OF |
| `E` | `JLE` / `JNG` | `JG` / `JNLE` | ZF or SF != OF |
| `F` | `JG` / `JNLE` | `JLE` / `JNG` | ZF or SF != OF |

Inverting a conditional branch is therefore a single-bit change on the low nibble:
`nibble ^= 1`, equivalently `opcode ^ 1` on the low byte of the last opcode byte.

```
74 12        je  +0x12          ->   75 12        jne +0x12
0f 84 40 00 00 00   je rel32    ->   0f 85 40 00 00 00   jne rel32
0f 8c 40 00 00 00   jl rel32    ->   0f 8d 40 00 00 00   jge rel32
```

Note that `0f 84` and `0f 85` are the *same length*, so inverting a near jump never disturbs the
code layout. Short jumps invert in place as well.

### Step 3 — ARM64 conditional branch

`B.cond` uses this layout:

```
31 30 0 0 1 0 1 0 0   imm19        cond
```

encoded as `0x54000000 | (imm19 << 5) | cond`. The condition field uses the same encoding
semantics as AArch64's `CSEL`/`CCMP` conditions:

| `cond` | Mnemonic | | `cond` | Mnemonic |
| --- | --- | --- | --- | --- |
| `0` | `EQ` | | `8` | `HI` |
| `1` | `NE` | | `9` | `LS` |
| `2` | `CS` / `HS` | | `A` | `GE` |
| `3` | `CC` / `LO` | | `B` | `GT` |
| `4` | `MI` | | `C` | `LE` |
| `5` | `PL` | | `D` | `AL` |
| `6` | `VS` | | `E` | `NV` |
| `7` | `VC` | | `F` | — |

`imm19` is a signed word offset: `imm19 = (target - pc) >> 2`, range ±1 MiB.

Inverting an ARM64 condition is `cond ^= 1` in the low nibble, which pairs
`EQ`↔`NE`, `CS`↔`CC`, `MI`↔`PL`, `VS`↔`VC`, `HI`↔`LS`, `GE`↔`GT`, `LE`↔`GT`.

Concrete examples, little-endian byte order:

```
b.eq  #0x40        ; 40 00 00 54   ->   b.ne #0x40        ; 40 00 00 55
b.ne  #0x40        ; 40 00 00 55   ->   b.eq  #0x40        ; 40 00 00 54
b.eq  #-0x24       ; dc ff ff 54   ->   b.ne  #-0x24       ; dc ff ff 55
```

Inverting an ARM64 branch changes only the low byte, so the instruction length is preserved.

### Step 4 — Neutralise a jump entirely

Replace the jump with an equivalent-length no-op so that no code below moves:

| Original | Length | Replacement | Meaning |
| --- | --- | --- | --- |
| `e9 xx xx xx xx` (`jmp rel32`) | 5 | `90 90 90 90 90` | fall through |
| `eb xx` (`jmp rel8`) | 2 | `90 90` | fall through |
| `0f 84 xx xx xx xx` (`je rel32`) | 6 | `90 90 90 90 90 90` | fall through |
| `74 xx` (`je rel8`) | 2 | `90 90` | fall through |
| `e8 xx xx xx xx` (`call rel32`) | 5 | `90 90 90 90 90` | skip the call |
| `ff 25 xx xx xx xx` (`jmp [rip+disp]`) | 6 | `90 90 90 90 90 90` | fall through |
| ARM64 `b imm26` (`0x14000000` mask) | 4 | `1f 20 03 d5` | fall through (`nop`) |
| ARM64 `b.cond imm19` | 4 | `1f 20 03 d5` | fall through (`nop`) |
| ARM64 `bl imm26` | 4 | `1f 20 03 d5` | skip the call |

The ARM64 architectural no-op is `0xD503201F`, stored little-endian as `1f 20 03 d5`.

When the branch must become an unconditional jump to the *same* place it already goes — a
length-preserving "always take this path" that also keeps the following code unreachable —
overwrite the jump with a jump to the next instruction:

```
e9 00 00 00 00 90      ; jmp +0 (to the byte after this instruction) ; nop padding
```

This is the safe way to remove a 6-byte `0f 84` while preserving instruction boundaries.

### Step 5 — "Return 1" / "return true" patches

For a boolean function whose success is signalled by a non-zero return value:

x86-64 (SysV and Microsoft x64 both return the low byte in `AL`; `mov eax,1` also sets `AL`):

```
b8 01 00 00 00 c3       ; mov eax, 1 ; ret
```

x86 32-bit (cdecl, result in `AL`; if the callee owns stack arguments, use `ret N`):

```
b0 01 c3                ; mov al, 1 ; ret
b0 01 c2 00 00          ; mov al, 1 ; ret 0     (stdcall, one stack argument)
b0 01 c2 04 00          ; mov al, 1 ; ret 4     (stdcall, two stack arguments)
```

ARM64 (result in `w0`/`x0`):

```
20 00 80 52 c0 03 5f d6    ; mov w0, #1 ; ret
```

`0x52800020` is `MOVZ w0, #1`; `0xD65F03C0` is `RET`.

AArch32:

```
01 20 a0 e3 1e ff 2f e1    ; mov r0, #1 ; bx lr
```

**The x64 bool-in-AL variant.** On x86-64 the ABI returns a `bool` in `AL`, but writing `AL`
zero-extends into `RAX`. A patch that only sets `AL` while leaving the upper bits of `RAX`
undefined is not expressible with `mov al, imm8`; the correct minimal x64 sequence is therefore
either of:

```
b0 01 c3                ; mov al, 1 ; ret        (RAX becomes 1)
b8 01 00 00 00 c3       ; mov eax, 1 ; ret       (identical effect)
```

The AL rule matters when the value is *not* a bool:

- The function returns a status code where `0` means success. Returning `1` produces a
  "licence invalid" outcome with a different message. Read the caller's comparison before
  choosing `0` or `1`.
- The function returns a pointer or handle. Returning `1` yields a near-null pointer that the
  caller dereferences, causing a crash instead of a clean success.

The failure mode to check for first: the caller compares the whole `eax`/`rax`, not `al`. Then
`mov eax, 1` and `mov al, 1` are identical, and the actual question is which constant the caller
expects.

### Step 6 — Avoid the "unreachable fall-through" mistake

The classic failure mode is not the opcode, it is the direction of the patch. Consider:

```
0x140001000:  74 1a              je   0x14000101c      ; equal -> skip the failure block
0x140001002:  b8 00 00 00 00     mov  eax, 0
0x140001007:  e8 7b 00 00 00     call 0x140001087      ; set_error("Invalid license key")
0x14000100c:  c3                 ret
0x14000100d:  90 90 90 90 90 90 90 90 90 90 90
0x14000101c:  b8 01 00 00 00     mov  eax, 1
0x140001021:  c3                 ret
```

Here `je` skips the failure block. Inverting it to `jne` makes the failure block run *always* —
the binary now rejects every input, which is the opposite of the intent.

The three correct options, in order of preference:

1. **Invert a branch that guards the success path.** Only when the branch's *taken* side is the
   success side. Verify by disassembling both sides before editing.
2. **Redirect the branch to the success path.** Rewrite the displacement instead of the opcode.
   For `74 1a` at `0x140001000`, jumping to `0x14000101c` needs `rel8 = 0x1c - (0x140001000 +
   0x140001002) = 0x1a` — already the case. To force the success path unconditionally, change
   `74 1a` to `eb 1a` (unconditional short jump) — same length, same target, branch always taken.
   For a near jump, `0f 84 40 00 00 00` → `e9 41 00 00 00 90` (`jmp` to the same target, plus one
   padding byte).
3. **Patch the failure block's exit** to return the success value.

A second variant of the same mistake: the branch target is a `throw`, an `abort`, or a call to
`exit`. Neutralising the branch with NOPs makes execution fall into the *next* function's code,
which usually crashes. Neutralise by redirecting to a `ret`, not by falling through.

### Step 7 — Find the branch reliably

```
# radare2: cross-references to the string, then the function
r2 -q -c 'aaa; iz~Invalid license; axt @@ str.Invalid_license_key' target.exe

# radare2: disassemble the candidate function
r2 -q -c 'aaa; s fcn.validate_license; pdf' target.exe

# radare2: all cross-references into a range
r2 -q -c 'aaa; axt @ 0x140001000' target.exe

# radare2: raw byte search for short and near conditional jumps
r2 -q -c '/x 7400; /x 0f8500000000' target.exe
```

In Ghidra: *Window → Symbol Tree → Functions*, then for a candidate function open the
*Decompiler* view and look at the `if` statement. The listing shows the raw branch, and the
*References* window on the failure string lists the cross-references. Ghidra's *Search →
For Instructions* with the mnemonic `JumpConditional` lists every conditional branch in the
program.

For ARM64, search for the `B.cond` mask:

```
r2 -q -c '/x 54000000' target.arm64
```

### Step 8 — Apply the patch and record it

Write a patch script that records the original bytes so the change is reversible:

```
python3 - <<'PY'
import re, pathlib
p = pathlib.Path("target.exe")
data = bytearray(p.read_bytes())
off = 0x1e10
assert data[off:off+2] == bytes.fromhex("74 1a"), data[off:off+6].hex(" ")
data[off:off+2] = bytes.fromhex("eb 1a")     # je -> jmp, same target
p.write_bytes(data)
print("patched", hex(off), "74 1a -> eb 1a")
PY
```

Keep a log of `offset | original bytes | new bytes | reason` for every change; a patch without a
record is a patch without a rollback.

## Variations

### ARM32 and Thumb

- ARM mode: `B<cond> rel24` occupies 4 bytes with the condition in the top nibble:
  `0x0N000000 | imm24`. `B` unconditional is `0xEA000000`. Inversion is the same `N ^= 1`
  on bits 31:28.
- Thumb (32-bit): `B<cond> rel8` is `0xD000 | (cond << 8) | imm8`; `B` unconditional short is
  `0xE000 | imm8`; `B.W` wide is a 4-byte `0xF000 0x8000 | imm11` pair.

### Compiler-generated redundant checks

Optimisers keep a branch and its inverse when both sides are reachable and the values differ
only in the return. Patching one leaves the other intact. Confirm with a disassembly that shows
both:

```
0x140001000:  74 05        je   0x140001007
0x140001002:  b8 00 00 00 00  mov eax, 0
0x140001007:  c3           ret
```

Inverting the `je` here is the correct fix, because both paths converge on the same `ret` and
only the `mov` differs.

### Checks implemented as a lookup

A table-driven check indexes an array with a checksum of the input:

```
0x140001000:  8b 05 3a 20 00 00   mov eax, dword ptr [rip+0x203a]
0x140001006:  8b 4d 08            mov ecx, dword ptr [rbp+8]
0x140001009:  03 c8               add ecx, eax
0x14000100b:  83 f8 0f            cmp eax, 0xf
0x14000100e:  77 1f               ja  0x14000102f
```

No branch to invert — patch the table entry or the range check instead. See
`function-identification-fingerprints` for the constant-identification side.

### Indirect branches through a table of function pointers

A dispatch table of `jmp qword ptr [rbx*8 + table]` has no patchable branch; patch the table
slot, or patch the value the dispatcher compares against.

### Managed equivalents

- .NET IL: `brfalse` / `brtrue` / `beq` / `bne.un` — invert the opcode or edit the IL with
  dnSpyEx or `ilspycmd` and recompile.
- Java/Dalvik: `if-eqz v0, +0x1a` (`0x38 0x0e` on a register v0) — the same inversion applies
  to the opcode's low nibble pair, or use smali.

### Runtime-only variant

When the branch cannot be patched on disk (self-check, hash of the code section, encrypted
section), intercept at runtime instead:

```
# Frida 17.x: replace the validator with a callback that always succeeds
const mod = Process.getModuleByName("target.exe");
const fn  = mod.getExportByName("validate_license");
const ok  = new NativeCallback(() => 1, 'int', []);
Interceptor.replace(fn, ok);
```

`Interceptor.replace` needs the target to be in a writable, non-signed page; on iOS with
`Process.codeSigningPolicy` set to `optional` this works, otherwise use
`memory.patchCode` on a copy of the page.

## Verification

1. Re-read the patched bytes and confirm they are what was intended:

   ```
   xxd -s 0x1e10 -l 6 target.exe
   ```

   Expect `eb 1a 90 90 90 90` for the example above.

2. Disassemble the patched region and confirm the control flow now reaches the success path and
   that the failure block is still intact but unreachable:

   ```
   r2 -q -c 'aaa; pd 10 @ 0x140001000' target.exe
   ```

3. Run the original failing operation. A licence prompt that previously rejected the key must
   now be accepted, and the application must reach the licensed state, not merely skip a dialog.

4. Negative test — prove the check is gone and not merely bypassed for cached state: clear the
   licence cache and the saved preferences, restart the process, and repeat the operation. A
   patch that only survives in memory is not a patch.

5. Negative test — prove nothing else broke: exercise a path that legitimately fails (an empty
   key, a malformed key) and confirm the application still reports the failure rather than
   crashing. A patch that makes every input succeed usually also removed an error path that
   other code depends on.

6. Confirm the patched function still honours its calling convention: in Ghidra's decompiler,
   check that the return value is still consumed correctly and that the stack balance is
   unchanged if a `ret N` was substituted.

## Pitfalls

- Inverting a branch whose *taken* side is the failure path. This produces a binary that rejects
  everything. Always disassemble both sides before flipping the opcode.
- Replacing a 5-byte `e9` with 4 bytes of NOP and a `ret`, which shifts every later byte.
  Padding must be added, or the branch must be replaced in place.
- Forgetting the `0f` prefix length difference between `0f 84` (6 bytes) and `74` (2 bytes).
  A 6-byte near jump cannot become a 2-byte short jump without a rebuild.
- ARM64 `B.cond` has only a 19-bit displacement (±1 MiB). A branch further away cannot be
  inverted by rewriting the immediate — it has to be rewritten as an inverted `B` plus a
  `B.cond` trampoline, or the target must be inlined.
- Assuming `mov eax, 1` sets a boolean correctly. It does for `bool`, but a status code that
  uses `0` for success needs `0`, and a pointer return needs a real object.
- Assuming `mov al, 1` leaves the upper bits of `RAX` alone. Writing `AL` zero-extends to `RAX`.
- Patching a `call` when the intent was the branch that follows it, leaving the callee's side
  effects in place.
- NOP-ing a branch whose target is a `throw` or `abort`, so execution falls into unrelated code
  and crashes instead of failing cleanly.
- Trusting the failure string's cross-reference as *the* check. A string is often referenced
  from a reporting helper that several checks share.
- Patching a branch inside a function that is called from two places with different
  expectations, so one caller now gets a value it cannot use.
- Patching a branch inside a library that is code-signed on macOS or iOS: the loader refuses the
  image until it is re-signed.

## References

- Intel 64 and IA-32 Architectures Software Developer's Manual, Volume 2, sections 3.4
  (conditional moves) and 4.1 (control transfer instructions): <https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html>
- AMD64 Architecture Programmer's Manual, Volume 2, `Jcc` and `SETcc`: <https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/programmer-references/40332.pdf>
- Arm Architecture Reference Manual for A-profile, `B.cond` and `Cond` encodings: <https://developer.arm.com/documentation/ddi0487/latest/>
- LLVM LangRef, `br` instruction and condition codes: <https://llvm.org/docs/LangRef.html>
- radare2 documentation: <https://r2.re>
- Ghidra documentation, Program Analysis: <https://ghidra.re/ghidra_docs/GhidraClass/Program.pdf>
- Frida JavaScript API, `Interceptor.replace`: <https://frida.re/docs/javascript-api/>
