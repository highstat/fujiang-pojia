---
id: "inline-hook-patching"
title: "Inline hook patching in the binary"
domain: "native-core"
kind: "technique"
platforms: "-"
arch: "x86, x86-64, arm64"
difficulty: "advanced"
tools: "radare2, Ghidra, xxd, python3, Frida"
verified: false
updated: "2026-11-15"
summary: "Redirects a call site or a function prologue to your own code with exact displacement arithmetic for x86-64 E8 calls and ARM64 B/BLR instructions, including trampolines, ASLR handling and byte-pattern matching."
---

## Summary

Two shapes of inline patch cover almost every case: change where a `call` goes, or change what
happens when a function is entered. The first is a single instruction edit with a computed
relative displacement. The second overwrites the prologue with a jump and needs a trampoline
holding the displaced original bytes.

Both have one hard constraint: the jump target must be reachable. On x86-64 a relative call or
jump reaches ±2 GiB; on ARM64 a `B` reaches ±128 MiB and a `B.cond` only ±1 MiB. Everything
else in this entry follows from that.

## Recognition

- A call through the import table: `call qword ptr [rip+0x2000]` on x86-64, or
  `bl` to a PLT stub on ARM64.
- A function prologue that is exactly `b8 <imm32> e9 <rel32>` — a hot-patch stub left by the
  linker, ready to be redirected.
- A function that starts with `endbr64` (`f3 0f 1e fa`) — CET/IBT enabled code; a hook must
  preserve it or the indirect branch into the hook is rejected.
- A call site whose callee is a two-instruction thunk (`jmp qword ptr [rip+disp]`) — the
  relocation point.

## Method

### Step 1 — Choose the patch point

| Situation | Patch | Risk |
| --- | --- | --- |
| The call site is under your control and the call's return value is what matters | rewrite the `call` displacement | breaks if the call has side effects the original callee provided |
| The callee is called from many places, or its identity must be preserved for all callers | overwrite the prologue and install a trampoline | needs a relocated prologue; RIP-relative operands must be fixed |
| The import is already resolved through an IAT/GOT slot | rewrite the slot's pointer | see `import-table-and-plt-got-surgery` |

Prefer the call-site patch when the goal is "make this one check pass". Prefer the prologue
patch when the goal is "log or replace every call".

### Step 2 — x86-64 call-site redirection (E8 rel32)

The `call rel32` encoding is `e8` followed by a signed 32-bit displacement relative to the
address of the *next* instruction:

```
rel32 = target_va - (call_va + 5)
```

Worked example. The call instruction sits at VA `0x140001234`, RVA `0x1234`. With `.text` at
RVA `0x1000` and `PointerToRawData` `0x400`, the call is at file offset `0x634`.

Original target `0x140002000`:

```
rel32 = 0x140002000 - (0x140001234 + 5) = 0x140002000 - 0x140001239 = 0xdc7

original:  e8 c7 0d 00 00     call 0x140002000
```

Redirect to `0x140003000`:

```
rel32 = 0x140003000 - 0x140001239 = 0x1dc7

patched:   e8 c7 1d 00 00     call 0x140003000
```

Verify the patched bytes decode to the intended target:

```
r2 -q -c 'pd 1 @ 0x140001234' target.exe
```

The displacement is signed 32-bit: the reachable range is `call_va - 0x80000000` to
`call_va + 0x7fffffff`. A target outside that range — a DLL loaded far away, a different
process — needs an indirect form:

```
48 b8 11 22 33 44 55 66 77 88   mov rax, 0x8877665544332211
ff e0                         jmp rax
```

That is 12 bytes, too long for a 5-byte call site. The compact alternative is to jump through a
pointer stored in the patch's own trailing bytes:

```
ff 25 00 00 00 00           jmp qword ptr [rip+0]
11 22 33 44 55 66 77 88    .qword 0x8877665544332211
```

14 bytes total, and the 8-byte address is position-independent.

The same math applies to `jmp rel32` (`e9`) and to `call rel32` in 32-bit code, where the
reachable range is only ±2 GiB but the address space is smaller anyway.

### Step 3 — Prologue patching and the trampoline

Overwriting the prologue of a function `F` at `F` with a jump to your hook `H` means the
original instructions in the overwritten region must be executed somewhere else. That somewhere
is the trampoline:

```
[trampoline]
  <relocated bytes F+0 .. F+N-1>
  jmp F+N

[F]
  jmp H              (the patched bytes)
  <rest of the original function>
```

**Choose N carefully.** N must cover the complete instructions at the start of `F`. Splitting an
instruction in half produces garbage. Typical N values: 5 (x86) or 14 (x86-64, covering a
`mov rax, imm64` plus `jmp rax` patch) or 12.

**Two patch forms:**

```
; 5-byte, relative — usable only when H is within +-2 GiB of F
e9 <rel32>                      ; jmp H

; 11-byte, absolute — clobbers R11 (volatile on SysV x86-64)
49 bb <imm64> 41 ff e3          ; mov r11, imm64 ; jmp r11

; 14-byte, absolute, clobbers nothing
ff 25 00 00 00 00 <imm64>      ; jmp qword ptr [rip+0] ; .qword H
```

The 5-byte form is the classic. It fails whenever the hook lives in a different module loaded
far away, which is the normal case on 64-bit Windows and on Linux with PIE.

**Trampoline back-jump arithmetic.** The trampoline's final `jmp` must return to `F+N`:

```
rel32 = (F + N) - (trampoline_va + N + 5)
```

Worked example: `F = 0x140004000`, `N = 5`, trampoline placed at `0x140005000` in the same
module's slack space.

```
rel32 = 0x140004005 - (0x140005000 + 5 + 5) = 0x140004005 - 0x14000500a = 0xfffffefb

trampoline:  55              push rbp
             48 89 e5        mov  rbp, rsp
             48              (the first byte of the next instruction)
             e9 fb fe ff ff  jmp 0x140004005
```

**Relocating RIP-relative operands.** If any instruction in the first N bytes references memory
through RIP, the copy in the trampoline points at the wrong address. Two ways out:

1. Choose N so that no RIP-relative instruction is included — but then the patch cannot
   overwrite the `mov rax, imm64` that precedes the jump.
2. Adjust the displacement in the trampoline copy by the delta between the two locations:

```
new_displacement = old_displacement + (trampoline_va - F)
```

The byte length of the displacement stays the same only if the delta fits in the same signed
field; a `disp32` usually does, an `ip-relative` in a `mov` with `disp8` does not. Verify by
disassembling the trampoline after it is written.

**Stack alignment.** The x86-64 ABI requires `RSP % 16 == 0` at the call boundary. The
`jmp`-based patches do not touch `RSP`, so the alignment that the caller established is
preserved. The `push rax ; ret` trampoline variant *does* push, breaking alignment by 8 bytes
and causing crashes in functions that use `movaps` — avoid it.

**CET / IBT.** On systems with Intel CET, indirect branches must land on an `endbr64`. If the
original function begins with `f3 0f 1e fa` (`endbr64`), the trampoline must start with it
too, and the hook must as well.

### Step 4 — ASLR and position-independent code

- **Intra-module, PC-relative redirection survives ASLR.** `E8 rel32` and `E9 rel32` compute
  their target from the current instruction pointer, so as long as both the call site and the
  target live in the same module, the pair moves together and the patch stays correct.
- **Cross-module redirection does not survive ASLR.** The distance between the call site and a
  DLL's code depends on the load order and the randomisation offsets. A patched `e8` that
  worked once will jump somewhere else after a reboot. Use an absolute form, or patch the
  import/GOT slot instead.
- **Absolute addresses baked into the file are wrong from the start** on any ASLR system. A
  file-level patch containing `48 b8 <imm64>` is only correct for a non-PIE binary with a fixed
  image base (a PE with `ImageBase = 0x140000000` and no relocation, an ELF `ET_EXEC`).
- **PIE and shared objects** compute every absolute address through a relocation. The
  relocation table must cover the patched bytes; otherwise the loader adjusts them and the
  patch is wrong. If a patch changes the size of a section, the relocation table must be
  rebuilt.

Consequence for file-level patching: prefer PC-relative forms, or prefer to patch at runtime
where the real addresses are known.

### Step 5 — ARM64: B, BL and BLR

ARM64's unconditional branch is a 26-bit signed word offset:

| Instruction | Encoding | Displacement | Range |
| --- | --- | --- | --- |
| `B` | `0x14000000 \| (imm26 << 0)` | `imm26 = (target - pc) >> 2` | ±128 MiB |
| `BL` | `0x94000000 \| (imm26 << 0)` | same | ±128 MiB |
| `B.cond` | `0x54000000 \| (imm19 << 5) \| cond` | `imm19 = (target - pc) >> 2` | ±1 MiB |
| `BR Xn` | `0xd61f0000 \| (Rn << 5)` | register | full 64-bit |
| `BLR Xn` | `0xd63f0000 \| (Rn << 5)` | register | full 64-bit |

`BL` is `B` with the top bit of the 26-bit field set — the "27th bit" that distinguishes a
call from a jump.

Worked example: a `B` at VA `0x100001000` targeting `0x100002000`.

```
offset = 0x100002000 - 0x100001000 = 0x1000
imm26 = 0x1000 >> 2 = 0x400
encoding = 0x14000000 | 0x400 = 0x14000400

original:  00 04 00 14        b 0x100002000
```

Redirect to `0x100003000`:

```
offset = 0x2000, imm26 = 0x800
encoding = 0x14000800

patched:   00 08 00 14        b 0x100003000
```

To convert a `B` into a `BL` (a call rather than a jump), set bit 31 of the opcode field:
`0x14000800` becomes `0x94000800`, bytes `00 08 00 94`.

**Absolute jump on ARM64.** There is no single instruction that loads a 64-bit immediate and
branches. Use a four-instruction sequence:

```
10 00 82 d2     movz x16, #0x1000
50 00 a0 f2     movk x16, #0x0002, lsl #16
10 00 c0 f2     movk x16, #0x0000, lsl #32
00 02 3f d6     blr  x16
```

`0xD2820010` is `MOVZ X16, #0x1000`; `0xF2A00050` is `MOVK X16, #2, LSL #16`;
`0xF2C00010` is `MOVK X16, #0, LSL #32`; `0xD63F0200` is `BLR X16`. Together they load
`0x0000000200001000` and branch to it.

`X16` and `X17` are the inter-procedure-call scratch registers in AArch64 and are safe to
clobber for a jump. On arm64e, pointer authentication is enabled: a `BLR` to a signed pointer
needs the `PACIASP`/`AUTIASP` pair around it, and `BL` to a local target needs `BTI c` at the
destination.

**ARM64 NOP** is `0xD503201F`, stored as `1f 20 03 d5`.

### Step 6 — Keep the patch stable across builds

An offset-based patch breaks with every rebuild. A pattern-based patch survives. Match on the
instruction bytes with wildcards over the displacement fields, and require the match to be
unique.

```
python3 - <<'PY'
import pathlib, re, sys

data = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "target.exe").read_bytes()

# 48 8b 05 ?? ?? ?? ??   mov rax, [rip+disp32]
# e8 ?? ?? ?? ??         call rel32
PATTERN = re.compile(rb"\x48\x8b\x05....\xe8....", re.S)

for m in PATTERN.finditer(data):
    off = m.start()
    disp = int.from_bytes(data[off+3:off+7], "little", signed=True)
    target_rva = (off + 7 + disp)          # file offset == RVA only in this image layout
    rel = int.from_bytes(data[off+7:off+11], "little", signed=True)
    callee = off + 11 + rel
    print(f"0x{off:08x}  load=0x{off+7+disp:08x}  call=0x{callee:08x}")
PY
```

Rules for a stable matcher:

- Anchor on at least 16 bytes of surrounding context, not on the 5 bytes being replaced.
- Wildcard every displacement and every relative offset — those are the fields that change
  between builds.
- Require exactly one match. Zero matches means the pattern is too specific; several matches
  means the patch is ambiguous.
- Prefer matching a *string reference plus a call* over matching a call alone: the string is
  semantically meaningful and rarely duplicated.
- Verify the matched call's callee is a function you have already identified, so a coincidental
  match cannot be patched.
- Store the pattern, the expected match count and the offset in the patch script, and fail loudly
  when the count is not exactly one.

### Step 7 — Apply the patch at runtime when the file cannot hold it

```
# Frida 17.x — patch a single instruction
const base = Process.getModuleByName("target.exe").base;
const off  = 0x634;                         // file offset of the call
Memory.patchCode(base.add(off), 5, "e8c71d0000");
```

```
# Windows: change page protection, write, restore
# VirtualProtect(addr, len, PAGE_EXECUTE_READWRITE, &old);
// memcpy(addr, bytes, len);
// FlushInstructionCache(GetCurrentProcess(), addr, len);
// VirtualProtect(addr, len, old, &old2);
```

On Linux and macOS use `mprotect` with `PROT_EXEC|PROT_WRITE` and, on aarch64, clear the
instruction cache with `__builtin___clear_cache` after writing.

```
# GDB
(gdb) set {char[5]}0x140001234 = {0xe8,0xc7,0x1d,0x00,0x00}
```

## Variations

### Import-slot (IAT/GOT) hooks

Redirecting the pointer that the call reads is invisible to the disassembly and needs no
displacement arithmetic. On PE the slot lives in the import address table; on ELF in
`.got.plt`; on Mach-O in the `__got` section. See
`import-table-and-plt-got-surgery`.

### Hardware-assisted and instrumentation alternatives

Frida's `Interceptor.attach` gives a hook with no file modification at all, and it handles the
trampoline relocation for you. Use it when the target is signed, when the file is shared, or
when a rebuild invalidates the pattern.

### 32-bit x86

`E8 rel32` is the same but the address space is 4 GiB, so the ±2 GiB range covers almost
everything. `call [imm32]` (`ff 15`) reads an absolute address and is the x86 form of an IAT
call — patch the pointer, not the instruction.

### ARM32 / Thumb

Thumb has two branch encodings: 16-bit `B<cond> rel8` (`0xD000 | cond << 8 | imm8`) and 32-bit
`B.W` (`0xF000 0x8000 | imm11`). `BL` is 32-bit in Thumb-2 (`0xF000 0xF800 | imm11` or the
`0xE800`-family wide encodings). Thumb code is addressed in 2-byte units, so the displacement
arithmetic must use the halfword offset.

### Managed runtimes

JIT-compiled code cannot be patched on disk. Hook the JIT's entry point or the managed method
itself: for .NET, replace the compiled method body or detour `JitInfo`; for the JVM, patch the
resolved native method pointer.

### Rust and C++ thunks

Rust functions that are `#[no_mangle]` and exported are ordinary functions. C++ virtual calls
go through a vtable slot — patch the slot rather than the callee, which is the "inline" form of
a vtable hook.

## Verification

1. Disassemble the patched region and confirm the target is what was intended:

   ```
   r2 -q -c 'pd 2 @ 0x140001234' target.exe
   ```

   Expect `call 0x140003000`.

2. Compute the displacement independently and compare:

   ```
   python3 - <<'PY'
   va, nxt, target = 0x140001234, 0x140001239, 0x140003000
   rel = (target - nxt) & 0xffffffff
   print(hex(rel), rel.to_bytes(4, "little").hex(" "))
   PY
   ```

   Expect `0x1dc7` and `c7 1d 00 00`.

3. Confirm the patch does not change the file size and that the bytes around the patch are
   untouched:

   ```
   cmp -l original.exe patched.exe | head
   ```

   Every reported difference must be inside the intended byte range.

4. For a prologue patch, confirm the trampoline executes correctly: the hook must observe the
   original arguments, and the original function must still produce its normal result. Check
   the relocated bytes for correctness by disassembling the trampoline.

5. Negative test — prove the redirection is what changed the behaviour, not something else:
   restore the original bytes, confirm the old behaviour returns, then re-apply the patch and
   confirm the new behaviour. A patch that is not reversible has not been tested.

6. Negative test for RIP-relative relocation: verify the trampoline's absolute accesses point
   at the same data as the original. Read the same global through the trampoline and through the
   original and compare the values.

7. For a pattern-matched patch, run the matcher against a *different build* of the same target
   and confirm it still finds exactly one match. A pattern that only works on one binary is not
   stable.

## Pitfalls

- Computing the displacement relative to the start of the instruction instead of the start of
  the next instruction. Every `e8` patch is off by five when this is wrong.
- Using a 5-byte relative jump to reach a hook in another module. On 64-bit Windows and on
  PIE Linux the distance routinely exceeds 2 GiB and the jump lands in unrelated memory.
- Splitting an instruction with the prologue patch. The displaced bytes must be whole
  instructions.
- Copying RIP-relative instructions into the trampoline without adjusting the displacement.
  The copy reads the wrong address, usually producing a crash far from the patch.
- Using `push rax ; ret` as a jump. It breaks the 16-byte stack alignment and cannot cross a
  stack unwind safely.
- Ignoring CET: a hook entered by an indirect branch must start with `endbr64`.
- Assuming a file-level absolute address survives ASLR.
- Patching a call whose original callee had side effects that the program depends on (opening a
  file, initialising a subsystem, incrementing a reference count).
- Patching the *callee* of a call that is used for something else entirely — the name `check`
  often belongs to a general-purpose helper.
- Patching a `BL` on ARM64 and turning it into a `B`: the return address is no longer pushed,
  and the caller resumes at the wrong place.
- Forgetting that `BL` on arm64e requires `BTI c` at the destination for indirect-branch
  tracking.
- Patching a call site inside a function that is duplicated per-architecture in a fat binary
  or per-ABI slice in a universal app: the patch must be applied to every slice.

## References

- Intel 64 and IA-32 Architectures Software Developer's Manual, Volume 2, `CALL` and `JMP`
  relative forms: <https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html>
- System V AMD64 ABI, calling convention and register usage: <https://gitlab.com/x86-psABIs/x86-64-ABI>
- Arm Architecture Reference Manual for A-profile, `B`, `BL`, `BR`, `BLR`: <https://developer.arm.com/documentation/ddi0487/latest/>
- Arm64 ABI, procedure call standard and inter-procedure-call registers: <https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst>
- Intel Control-flow Enforcement Technology: <https://www.intel.com/content/www/us/en/developer/articles/technical/intel-cet.html>
- radare2 documentation: <https://r2.re>
- Frida JavaScript API, `Memory.patchCode`: <https://frida.re/docs/javascript-api/>
- MinHook and Microsoft Detours, reference trampoline implementations: <https://github.com/TsudaKageyu/minhook>
