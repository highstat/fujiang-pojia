---
id: "obfuscation-llvm-mir"
title: "LLVM-based obfuscation"
domain: "anti-analysis"
kind: "technique"
platforms: "windows, macos, linux, android"
arch: "x86, x86-64, arm64"
difficulty: "advanced"
tools: "Ghidra,Binary Ninja,angr,Python,radare2"
verified: false
updated: "2026-11-15"
summary: "The ollvm transformation family — control-flow flattening, bogus control flow, instruction substitution and function splitting — how each is recognised in a disassembly, and the step-by-step recipe that recovers the original control-flow graph."
---

## Summary

LLVM-based obfuscation modifies the program during compilation, so the binary never contains the
straight-line code a compiler would have produced. The transformations come from the ollvm
toolchain and its forks, and they compose: flattening turns a function into a state machine, bogus
control flow adds blocks that never execute, instruction substitution rewrites arithmetic into
obscure equivalents, and function splitting cuts the result into pieces that only fit together
again through the dispatcher.

The compiler's optimiser cannot undo any of this, because each transformation preserves the
observable behaviour. The decompiler's problem is not correctness but shape: the Ghidra
decompiler reconstructs a CFG from the basic blocks, and a flattened function is a single
dispatcher block with N successors, so the output is a switch with N cases and no readable
structure.

This entry covers each transformation, its byte-level signature, and a concrete de-flattening
recipe that works from the raw bytes: find the state variable, enumerate the case values, map each
case to its block, and rebuild the edges.

Related entries: [control-flow-flattening](./control-flow-flattening.md) covers the flattening
technique in depth, including opaque predicates and the symbolic-execution route.

## Recognition

### Transformation signatures

| Pass | What it does | Byte-level signature |
| --- | --- | --- |
| `fla` | control-flow flattening | one dispatcher with a jump table plus `mov [stack], imm` before every jump back to it |
| `bcf` | bogus control flow | opaque predicate followed by a conditional jump into an unreachable block |
| `sub` | instruction substitution | `xor`, `add`, `sub`, `and`, `or` replaced by equivalent sequences |
| `spli` / `split` | function splitting | one function becomes several, dispatched through a common entry |
| `ind` | indirect branches | `jmp` replaced by `jmp reg` or `jmp [mem]` |
| `fw` | function wrapper | a wrapper function calls the real one through an opaque chain |
| `sra` | struct field randomisation | field access via computed offsets |

### The dispatcher

A flattened function contains one basic block with an unusually large number of successors. In
x86 it typically looks like a switch over the state variable:

```
; 32-bit jump-table dispatcher
mov  eax, dword [ebp-0x4]
cmp  eax, 0x1c
ja   .default
jmp  dword [eax*4 + 0x00401230]      ; ff 24 85 30 12 41 00
```

or a compare chain:

```
mov  eax, dword [ebp-0x4]
cmp  eax, 0x00
je   .case_00
cmp  eax, 0x01
je   .case_01
...
```

The jump-table instruction is `ff 24 85 <imm32>` (x86) or `ff 24 85 <imm32>` (x64 with a
32-bit absolute table) / `ff 24 8d <disp32>` (RIP-relative).

### The state variable

The state variable is written immediately before every jump back to the dispatcher. In x86-32
that is a store of an immediate to a negative stack displacement:

```
c7 45 fc 0a 00 00 00      mov  dword [ebp-0x4], 0x0a
e9 xx xx xx xx            jmp  dispatcher
```

Other encodings of the same store:

| Encoding | Instruction |
| --- | --- |
| `c7 45 fc imm32` | `mov dword [ebp-0x4], imm32` |
| `c7 85 00 00 00 00 imm32` | `mov dword [ebp+disp32], imm32` |
| `c7 05 xx xx xx xx imm32` | `mov dword [rip+disp32], imm32` (global state variable) |
| `b8 imm32` + `89 45 fc` | `mov eax, imm32` then `mov [ebp-0x4], eax` |
| `89 05 xx xx xx xx` | `mov [rip+disp32], eax` |

On arm64 the store is `str w0, [sp, #0x10]` (`90 0b 00 b9`-style immediates) or a global store
through `adrp`/`add`.

### Bogus control flow

An opaque predicate is an expression the compiler cannot fold but that always has the same value.
The classic form writes a constant non-zero value into a register, tests it, and branches on the
result:

```
31 c0                xor  eax, eax
0d 78 56 34 12       or   eax, 0x12345678
...
85 c0                test eax, eax
75 11                jne  .dead_block        ; always taken
```

The `or` with a non-zero immediate can never be folded away because the register is not known to
be zero at that point in the compiler's model, but at run time `eax` is `0x12345678` and the
branch is always taken.

Other forms:

| Form | Bytes | Behaviour |
| --- | --- | --- |
| `x ^ x == 0` | `31 c0 85 c0` | always zero |
| `x * x >= 0` | `0f af c0` | always non-negative |
| `x + 1 != x` | `83 c0 01 39 c0` | always true |
| `x / x == 1` | with a guard | always true for `x != 0` |
| `x & 0x7fffffff == x` | `83 e0 7f 39 c0` | tautology after masking |

### Instruction substitution

`sub` replaces one instruction with an equivalent but less obvious sequence:

| Original | Substitution |
| --- | --- |
| `xor eax, eax` | `mov eax, 0` + `sub eax, eax`, or `and eax, 0` |
| `x * 2` | `x + x`, or `x << 1` written as `shl eax, 1` via a register copy |
| `x / 2` | `x >> 1` |
| `x ^ y` | `~x ^ ~y` |
| `x - y` | `x + (-y)` |
| `x == 0` | `!(x)` expressed as `x ^ 1` on a booleanised copy |

The substitution preserves semantics but removes the pattern a matcher looks for.

### Function splitting

`split` cuts a function into chunks of roughly equal size and moves each chunk into its own
function, with the entry point dispatching to the chunk that contains the original offset. The
result is a family of small functions with meaningless names that call each other through
computed indices.

The signature is a cluster of small functions of near-identical size, none of which is called
directly, plus a dispatcher that computes the target index from the original program counter.

## Method

### 1. Confirm the transformation

```
r2 -q -c 'aaa; axt @@ fcn.*' target
```

Look for the dispatcher: a function whose single basic block has more than a handful of
successors.

In Ghidra, the Function Graph makes it visible. A flattened function shows one node with a fan of
edges.

```
python3 - <<'PY'
# quick count of the successors of each function, via Ghidra's flat API in a script
PY
```

A practical shortcut in Ghidra: open the function graph and look for a node with more than about
ten outgoing edges. That node is the dispatcher.

### 2. Find the state variable

Scan the binary for immediate stores to a stack slot or a global, and group by the destination.
The slot with the most writes is the state variable.

```python
#!/usr/bin/env python3
"""Find the ollvm fla state variable by grouping immediate stores by destination.

Usage: find_state.py <binary> [--base 0x400000]
"""
import re
import struct
import sys
from collections import defaultdict

# mov dword [ebp+disp8], imm32     -> c7 45 disp8 imm32
PAT_EBP_DISP8 = re.compile(rb"\xc7\x45(.)(.{4})", re.S)
# mov dword [ebp+disp32], imm32    -> c7 85 disp32 imm32
PAT_EBP_DISP32 = re.compile(rb"\xc7\x85(.{4})(.{4})", re.S)
# mov dword [rip+disp32], imm32    -> c7 05 disp32 imm32
PAT_RIP_DISP32 = re.compile(rb"\xc7\x05(.{4})(.{4})", re.S)


def scan(data: bytes):
    stores = defaultdict(list)     # key -> list of (offset, immediate)
    for m in PAT_EBP_DISP8.finditer(data):
        disp = struct.unpack("b", m.group(1))[0]
        imm = struct.unpack("<I", m.group(2))[0]
        stores[("stack", disp)].append((m.start(), imm))
    for m in PAT_EBP_DISP32.finditer(data):
        disp = struct.unpack("<i", m.group(1))[0]
        imm = struct.unpack("<I", m.group(2))[0]
        stores[("stack", disp)].append((m.start(), imm))
    for m in PAT_RIP_DISP32.finditer(data):
        disp = struct.unpack("<i", m.group(1))[0]
        imm = struct.unpack("<I", m.group(2))[0]
        stores[("global", m.start() + 10 + disp)].append((m.start(), imm))
    return stores


def main() -> int:
    path = sys.argv[1]
    with open(path, "rb") as fh:
        data = fh.read()

    stores = scan(data)
    ranked = sorted(stores.items(), key=lambda kv: len(kv[1]), reverse=True)

    for (kind, key), entries in ranked[:10]:
        if len(entries) < 3:
            continue
        values = sorted({imm for _, imm in entries})
        print(f"{kind} {key!r}: {len(entries)} stores, {len(values)} distinct values")
        print("   values:", ", ".join(hex(v) for v in values[:32]))
        for off, imm in entries[:8]:
            print(f"   0x{off:08x}  ->  0x{imm:x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

Expected output on a flattened function:

```
stack -4: 27 stores, 27 distinct values
   values: 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10, ...
   0x0040119c  ->  0x1
   0x004011c4  ->  0x2
```

A single slot with one store per distinct immediate is the state variable. If the values are
sequential (`0x1`, `0x2`, `0x3`, ...), the flattening used a counter; if they are arbitrary
constants, the values are hashes of the original block addresses.

### 3. Locate the dispatcher and read the case map

The dispatcher is the block that reads the state slot. Find the jump table:

```
r2 -q -c '/x ff2485' target
```

Read the table: each 4-byte entry is a code address for one case value. The table index is the
state value, so `table[value]` is the block that runs when the state is set to `value`.

With Capstone, the dispatcher can be identified as the basic block containing a `jmp` with a
memory operand whose index register is scaled by 4:

```python
#!/usr/bin/env python3
"""Locate the ollvm dispatcher (a jump through a scaled index) and dump the case map."""
import struct
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_32


def main() -> int:
    path = sys.argv[1]
    mode = CS_MODE_64 if len(sys.argv) > 2 and sys.argv[2] == "64" else CS_MODE_32
    with open(path, "rb") as fh:
        data = fh.read()

    md = Cs(CS_ARCH_X86, mode)
    md.detail = True

    for insn in md.disasm(data, 0x0):
        if insn.mnemonic != "jmp" or not insn.operands:
            continue
        op = insn.operands[0]
        if op.type != 3:            # X86_OP_MEM
            continue
        mem = op.mem
        if mem.index == 0 or mem.scale != 4:
            continue
        table_va = insn.address + insn.size + mem.disp
        file_off = table_va - 0x400000
        if file_off < 0 or file_off + 16 > len(data):
            continue
        print(f"dispatcher jmp at 0x{insn.address:08x} -> table 0x{table_va:08x}")
        for i in range(16):
            entry = struct.unpack("<I", data[file_off + i * 4:file_off + i * 4 + 4])[0]
            print(f"   case {i:#04x} -> 0x{entry:08x}")
        break
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

The `0x400000` image base has to be replaced with the base of the file being read; derive it from
the PE Optional Header or from the ELF program headers.

### 4. Extract the blocks and build the edge set

For every case value `v` with block address `B(v)`, the block body runs from `B(v)` until the next
store to the state slot. That store gives the successor: if the block stores `w`, the edge is
`B(v) -> B(w)`.

The recipe in full:

1. Extract the set of state values from the scan in step 2.
2. Read the jump table to obtain `B(v)` for each value.
3. Disassemble from `B(v)` until a store to the state slot is found. Record the stored value `w`.
4. The successor of `B(v)` is `B(w)`. If the block falls through into another block without a
   state store, the edge is a fall-through edge.
5. Repeat for every value. The result is the original CFG, minus the dispatcher.

A Python skeleton for step 3 and 4:

```python
#!/usr/bin/env python3
"""Build the de-flattened edge set of an ollvm fla function."""
import struct
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

STATE_SLOT_DISP = -4          # adjust to the value found by find_state.py
IMAGE_BASE = 0x400000


def find_state_store(md, code, start, limit):
    """Return (address, value) of the next 'mov dword [ebp-4], imm32'."""
    for insn in md.disasm(code, start):
        if insn.address >= limit:
            return None
        raw = bytes(insn.bytes)
        if raw[:3] == b"\xc7\x45" and struct.unpack("b", raw[3:4])[0] == STATE_SLOT_DISP:
            value = struct.unpack("<I", raw[4:8])[0]
            return insn.address, value
    return None


def main() -> int:
    path = sys.argv[1]
    with open(path, "rb") as fh:
        data = fh.read()

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    code = data[IMAGE_BASE:]

    # case map, filled in from the jump table
    case_map = {0x1: 0x401200, 0x2: 0x401280, 0x3: 0x401310}

    edges = []
    for value, block in sorted(case_map.items()):
        store = find_state_store(md, code, block - IMAGE_BASE, block - IMAGE_BASE + 0x400)
        if store is None:
            print(f"case {value:#x} block 0x{block:x}: no state store found")
            continue
        addr, next_value = store
        successor = case_map.get(next_value)
        print(f"case {value:#x} block 0x{block:x} -> state {next_value:#x} "
              f"-> block {successor if successor is None else hex(successor)}")
        if successor is not None:
            edges.append((block, successor))

    with open("deflatten_edges.txt", "w") as fh:
        for src, dst in edges:
            fh.write(f"{src:#x} {dst:#x}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

### 5. Rebuild the CFG in a tool

**Ghidra.** Two routes.

*Route A — patch the flow.* Replace the state store with a direct jump to the successor block and
remove the dispatcher. The patch is a jump to an address, so it does not fit in the space the
immediate store occupied. Use Ghidra's flow override instead: in the listing, right-click the
state store and set "Set Fall-through"/"Set Jump" to the successor address, or use the
`FlowOverride` API in a script. Then right-click the decompiler window and choose
"Clear Flow and Repair" to rebuild the flow graph, followed by "Force Decompile".

*Route B — a script that does the whole job.* Community Ghidra scripts for ollvm exist in the
Script Manager under the names `ollvm_deflatten`, `OLLVMDeobfuscator` and `NoMoreObfuscation`. The
general shape of such a script is:

```python
# GhidraScript — sketch of a de-flattening script
import struct
from ghidra.program.model.symbol import RefType
from ghidra.program.model.address import AddressFactory

state_disp = -4
md = currentProgram.getListing()
mem = currentProgram.getMemory()
func = getFunctionContaining(currentAddress)

# 1. collect (block address, state value) pairs
blocks = {}
for inst in md.getInstructions(func.getBody(), True):
    raw = bytes(inst.getBytes())
    if raw[:3] == b"\xc7\x45" and struct.unpack("b", raw[3:4])[0] == state_disp:
        value = struct.unpack("<I", raw[4:8])[0]
        blocks[value] = inst.getAddress()

# 2. for every block, find where it jumps back to the dispatcher and redirect it
for value, addr in blocks.items():
    inst = getInstructionAt(addr)
    print("state %s written at %s" % (value, addr))
```

**Binary Ninja.** Binary Ninja's HLIL does not de-flatten automatically. The HLIL can be
post-processed: read the state variable's definition through `hlil` and rewrite the state
assignment into a direct call or jump with the Binary Ninja Python API. The `hlil` graph is
available for inspection, and the "flattened CFG recovery" is done by iterating over the
`HighLevelILFunction` instructions, finding the assignment to the state variable, and replacing
the following block with an unconditional jump to the mapped target.

**Manual re-implementation.** For a licence algorithm, the cheapest route is often to reimplement
the block bodies in Python. The edge set from step 4 gives the order of operations, and each block
body is a short sequence of arithmetic. A de-flattened licence check is usually 20 to 60 lines of
Python once the state machine is recovered.

### 6. Bogus control flow

The unreachable blocks must be removed, otherwise the decompiler still emits them.

1. Find the opaque predicates: a conditional jump whose condition is a constant. In the
   disassembly these look like `test reg, reg` / `jne` where the register was just loaded with a
   non-zero immediate, or a `cmp` against a value that cannot be reached.
2. For each predicate, determine the constant outcome and delete the dead successor block.
3. In Ghidra, use "Clear Code Bytes" on the dead block, or delete the instruction that creates it.

A practical detector: the dead block usually has no predecessor other than the predicate branch,
and it ends in a jump back to the dispatcher with a state value that no live block ever writes.

### 7. Instruction substitution

Substitution does not change the control flow, so it does not need a separate recovery step. It
only matters when a byte pattern match is the goal. Reverse the substitution in the disassembly
view, or reimplement the arithmetic in the manual Python route, where the obfuscated sequence
becomes ordinary arithmetic again.

## Variations

- **Hikari and other forks.** The Hikari fork adds `constenc`, `bogus` (splitting one
  instruction into several), `vm` (an instruction-level virtualiser) and improved `bcf`. The
  `vm` pass is the hardest: each original instruction becomes a call into a bytecode interpreter,
  and recovering the original requires interpreting the bytecode.
- **Flattening with a computed state.** Some variants derive the next state from the previous one
  rather than storing a constant, for example `state = state * 3 + 7`. The recovery then has to
  solve for the mapping rather than read a table.
- **Flattening with a hash.** The state values are hashes of the original block addresses, so the
  case map cannot be read from a table directly; the dispatcher compares against a chain of
  constants instead of using a jump table.
- **Multiple levels.** Nested flattening: a flattened function calls another flattened function.
  Recover the innermost first.
- **Mixed with a VM.** A function may be flattened and its blocks then interpreted by a bytecode
  VM. The de-flattening still recovers the block bodies; the interpreter remains.
- **arm64.** The dispatcher uses `adrp`/`add` plus `br xN` or a `tbz`/`b.eq` compare chain. The
  state store is `str wN, [sp, #imm]`. The same recipe applies with the encodings changed.
- **Java and .NET.** The same passes exist for the JVM and for IL. The decompiler suffers the
  same way: a `switch` over a state variable instead of the original branches. The recovery recipe
  is identical, with the "state store" being a `putstatic`/`stloc`.
- **Opaque predicates over the stack.** Instead of a register, the predicate uses a value read
  from the stack slot that the flattening already uses, so the two transformations interact.
- **Anti-analysis of the obfuscator itself.** Some builds append a checksum of the original code
  to the binary before flattening. Patching the obfuscated code breaks the checksum. See
  [integrity-self-checks](./integrity-self-checks.md).

## Verification

1. **Baseline.** Run the target unmodified and record the behaviour that the analysis must
   reproduce. Without a baseline there is nothing to compare the recovered logic against.
2. **Dispatcher confirmation.** Verify the dispatcher has the expected number of successors and
   that each case value in the table points into the function body. A table entry pointing outside
   the function means the jump table was misidentified.
3. **Edge-set completeness.** Every block must have at least one outgoing edge, and every live
   block must be reachable from the entry block. Report unreachable blocks: they are the bogus
   control flow blocks and must be explained, not silently dropped.
4. **Re-decompilation proof.** After the patch and "Clear Flow and Repair", the Ghidra decompiler
   output must show the original branch structure instead of one switch with N cases. Expected: the
   number of `if` statements rises and the number of switch cases falls.
5. **Semantic check.** Reimplement the recovered logic in Python and compare its result with the
   target's output for a set of inputs. For a licence check, feed valid and invalid keys and
   compare the accept/reject decision.
6. **Negative test.** Re-apply the obfuscation pattern mentally: confirm that the recovered logic
   still rejects an invalid key. A recovery that accepts everything is wrong.
7. **Dead-block accounting.** Count the removed blocks. The count must equal the number of
   opaque predicates found. A mismatch means a live block was deleted by mistake.

## Pitfalls

- **The state slot is not always `-4`.** It can be any negative displacement, and it can be a
  global. The scan in step 2 reports the candidates ranked by store count; the state variable is
  usually the top one within the flattened function, not in the whole binary. Run the scan over
  the function's byte range.
- **Stores to the state slot that are not transitions.** The dispatcher itself writes the state
  variable on entry. Exclude the dispatcher block from the block set.
- **Case values are not the block order.** The state values are arbitrary constants. Sort the
  recovered blocks by their position in the original function, not by the state value.
- **Blocks that fall through.** Not every block ends with a state store. Some blocks fall through
  into the next block, and the fall-through is an edge.
- **The jump table may be encrypted.** Some builds decode the table at run time. Dump the table
  from memory after it is decoded.
- **The dispatcher may be shared.** Two functions can share one dispatcher, or the dispatcher may
  be a separate function. A shared dispatcher means the state slot differs per function.
- **Splitting breaks the address mapping.** The `split` pass moves blocks into new functions, so
  the original program counter no longer maps to the block address. The entry dispatcher computes
  the target index from the original offset; read that computation to find the mapping.
- **Ghidra's "Clear Flow and Repair" resets the decompiler but not the bytes.** The listing still
  shows the original obfuscated instructions. That is fine for reading the recovered logic, but a
  re-analysis of the listing still shows the obfuscation.
- **Patching does not fit.** A state store is 7 bytes; a near jump is 5 bytes. Use flow overrides
  or patch the dispatcher's branch instead of trying to inline the jump.
- **Opaque predicates that depend on runtime values.** A predicate that reads an argument can
  genuinely be false for some inputs. Only remove a block when the predicate is constant.
- **The decompiler is not wrong.** A flattened function decompiles to a switch because that is
  what it is. Treat the switch output as the specification of the state machine and write the
  recovery as a script rather than by hand.
- **Obfuscated code is not always the licence check.** A large flattened region may be an
  unrelated string decoder. Locate the region that reaches the licence decision before investing
  in the recovery.

## References

- ollvm obfuscator passes (`fla`, `bcf`, `sub`, `split`) — https://github.com/obfuscator-llvm/obfuscator
- LLVM pass documentation — https://llvm.org/docs/Index.html
- Ghidra 12.2 — https://github.com/NationalSecurityAgency/ghidra/releases
- Ghidra Script Manager and community deobfuscation scripts — https://github.com/NationalSecurityAgency/ghidra
- Binary Ninja Python API — https://binary.ninja/python-api/
- `angr` — https://github.com/angr/angr
- `miasm` — https://github.com/cea-sec/miasm
- Capstone disassembly engine — https://www.capstone-engine.org/
- radare2 — https://rada.re/n/
