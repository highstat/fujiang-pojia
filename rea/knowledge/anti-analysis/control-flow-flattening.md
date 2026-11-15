---
id: "control-flow-flattening"
title: "Control-flow flattening and opaque predicates"
domain: "anti-analysis"
kind: "technique"
platforms: "windows, macos, linux, android, ios"
arch: "x86, x86-64, arm64"
difficulty: "advanced"
tools: "Ghidra,Binary Ninja,angr,miasm,radare2"
verified: false
updated: "2026-11-15"
summary: "The mechanics of the flattening dispatcher, the state-variable encoding, and the opaque predicates that hide the real branches, plus the concrete tool command sequence that recovers the original control-flow graph."
---

## Summary

Control-flow flattening replaces the branches of a function with a state machine. Every original
block ends with an assignment to a state variable and a jump to a single dispatcher. The dispatcher
reads the state variable and jumps to the block that owns that state value. The result is a
function whose real structure is a graph, but whose machine shape is one switch with N arms.

Opaque predicates support the transformation. They are conditions that always evaluate the same
way at run time but that the compiler cannot fold, so the compiler has to emit the branch. They
serve two purposes: they create blocks that never execute, and they hide the real condition of a
branch behind an opaque wrapper.

Recovery is mechanical. Find the state variable, read the case map, split the function into
blocks, build the edge set, and either rebuild the graph in a decompiler or reimplement the
function.

Related entries: [obfuscation-llvm-mir](./obfuscation-llvm-mir.md) covers the wider ollvm pass
family, [integrity-self-checks](./integrity-self-checks.md) covers the checksum that often
accompanies an obfuscated build.

## Recognition

### The flattened shape

The flattened function has three kinds of basic block:

1. The **pre-header**, which initialises the state variable.
2. The **dispatcher**, with one outgoing edge per case value.
3. The **blocks**, each ending with a state store and a jump back to the dispatcher.

The dispatcher is the only block with many successors. Everything else has exactly two: a
conditional edge to a block and an unconditional edge to the dispatcher.

In radare2, count the successors of each block:

```
r2 -q -c 'aaa; agCj @@ fcn.main' target
```

In Ghidra, open the Function Graph (`Window` → `Function Graph`) and look for the node with the
largest fan-out.

### The state variable encoding

| Form | Bytes | Meaning |
| --- | --- | --- |
| `mov dword [ebp-0x4], imm32` | `c7 45 fc imm32` | stack slot, the common case |
| `mov dword [ebp+disp32], imm32` | `c7 85 disp32 imm32` | stack slot with a large displacement |
| `mov dword [rip+disp32], imm32` | `c7 05 disp32 imm32` | global state variable |
| `mov eax, imm32` then `mov [ebp-0x4], eax` | `b8 imm32` / `89 45 fc` | when the value is reused |
| `mov word [ebp-0x2], imm16` | `66 c7 45 fe imm16` | 16-bit state variable |
| `mov qword [rbp-0x8], imm32` | `48 c7 45 f8 imm32` | 64-bit store of a 32-bit value |

On arm64 the store is `str wN, [sp, #imm]` with the scaled immediate encoded in the instruction,
or a global store through `adrp`/`add`/`str`.

### The dispatcher encoding

Switch with a jump table:

```
; 32-bit
mov  eax, dword [ebp-0x4]
cmp  eax, 0x1c
ja   .default
jmp  dword [eax*4 + 0x00401230]      ; ff 24 85 30 12 41 00
```

Switch with a compare chain:

```
mov  eax, dword [ebp-0x4]
cmp  eax, 0x00
je   .case_00
cmp  eax, 0x01
je   .case_01
```

Switch through a computed jump (`ind` pass):

```
mov  eax, dword [ebp-0x4]
lea  eax, [eax + eax*2]
jmp  dword [eax*4 + 0x00401230]
```

The `ind` variant multiplies the state value before indexing, so the table index is not the state
value. Recover the mapping by evaluating the arithmetic for every state value.

### Opaque predicate encoding

| Predicate | Bytes | Constant outcome |
| --- | --- | --- |
| `x ^ x` | `31 c0 85 c0` | always zero |
| `x + 1 != x` | `83 c0 01 39 c0` | always non-zero |
| `x * x >= 0` | `0f af c0 85 c0` | always non-negative |
| `x & 0x7fffffff == x` | `83 e0 7f 39 c0` | always true |
| `x | 0x12345678` | `0d 78 56 34 12` | always non-zero |
| `x & 0x12345678 != 0` | `25 78 56 34 12` | always non-zero |

The `or`/`and` with a constant immediate is the classic `bcf` output, because the optimiser
cannot fold a bitwise operation on a value it does not track, while at run time the value is
provably non-zero.

### Why the decompiler struggles

The Ghidra and Binary Ninja decompilers reconstruct the CFG from the basic blocks and then look
for structured control flow (if-then, loops, switch). A flattened function defeats this in two
ways:

- The dispatcher block has N successors and cannot be expressed as a structured construct, so it
  becomes a `switch` with N cases.
- The real edges between blocks are encoded as data (the state values), not as branch targets, so
  the decompiler's edge analysis never sees them.

The result is a decompilation like:

```c
void func(int a) {
    switch (state) {
    case 1: ...
    case 2: ...
    case 3: ...
    }
}
```

with `state` never assigned inside the function, because the assignments were folded into the
dispatcher's own bookkeeping or live in the block tails.

## Method

### 1. Isolate the flattened function

```
r2 -q -c 'aaa; afl~main' target
```

Start with the function that holds the licence decision or the string decoder. A flattened
function is usually larger than its neighbours and has a high basic-block count:

```
r2 -q -c 'aaa; aflj @ fcn.main | jq .[].nbbs' target
```

### 2. Find the dispatcher

In radare2, print the block that has the most outgoing edges:

```
r2 -q -c 'aaa; agCj @@ fcn.func_00401100' target
```

Alternatively search for the jump-table instruction:

```
r2 -q -c '/x ff2485' target
r2 -q -c '/x ff248d' target
```

In Ghidra, the "Script Manager" ships a small script for this; the manual equivalent is to sort
the function's basic blocks by successor count.

### 3. Find the state variable

Search for immediate stores that are followed by a jump to the dispatcher:

```
r2 -q -c 'aaa; /ad mov dword [ebp' target
```

or scan the raw bytes for the encodings in the table above and group by destination. The slot
that receives one store per block is the state variable.

```
r2 -q -c '/x c745fc' target
```

Expected output on a flattened function:

```
0x0040119c  c745fc01000000  mov dword [ebp-0x4], 1
0x004011c4  c745fc02000000  mov dword [ebp-0x4], 2
0x004011f0  c745fc03000000  mov dword [ebp-0x4], 3
```

### 4. Build the case map

Read the jump table. With the dispatcher at `D` and the table at `T`:

```
r2 -q -c 'px 128 @ 0x00401230' target
```

Expected output:

```
0x00401230  0x00401180  0x00401198  0x004011b0  0x004011c8  ...
```

Table entry `i` is the block for state value `i`. If the dispatcher is a compare chain instead of
a table, read the `je` targets in order and map them to the compared constants.

### 5. Extract the blocks and the edges

For each block, disassemble forward until the next state store. The stored value names the
successor.

```
r2 -q -c 'aaa; pdf @ 0x00401180' target
```

Expected output for one block:

```
0x00401180  mov eax, [ebp+8]
0x00401183  add eax, 0x1234
0x00401188  mov [ebp-0x8], eax
0x0040118b  mov dword [ebp-0x4], 0x5
0x00401192  jmp 0x00401120           ; dispatcher
```

The block's edge is `0x00401180 -> case 0x5`.

A script that produces the edge list is in
[obfuscation-llvm-mir](./obfuscation-llvm-mir.md), section 4. The output is a list of pairs:

```
0x401180 0x4011f0
0x401198 0x401180
0x4011b0 0x401240
```

### 6. Rebuild the graph

**Option A — re-decompile in Ghidra.**

The reliable way to make the Ghidra decompiler show the original structure is to change the flow,
not just to annotate it.

1. In the listing, locate each state store instruction.
2. Right-click the instruction that follows the state store (the jump to the dispatcher) and set
   the flow to the successor block: right-click → "Set Jump" (or "Set Fall-through"), and enter
   the successor address from the edge list.
3. Delete the dispatcher block from the flow: select the block and use "Clear Code Bytes", or set
   its flow to fall through into the first block.
4. Right-click the decompiler window and choose "Clear Flow and Repair".
5. Choose "Force Decompile" (or delete the function and re-create it with `F`).

Expected result: the decompilation shows the original if/else and loop structure instead of one
switch.

**Option B — community Ghidra scripts.**

The Ghidra Script Manager (`Window` → `Script Manager`) carries deobfuscation scripts for this
family. The well-known ones are `ollvm_deflatten`, `OLLVMDeobfuscator` and `NoMoreObfuscation`.
They take the function or the program, locate the dispatcher, and rewrite the flow
automatically. Run them from the Script Manager with the target function selected, then re-decompile
and compare against the manual edge list to confirm the script found the same blocks.

**Option C — Binary Ninja.**

Binary Ninja does not de-flatten automatically, but the HLIL can be rewritten. The recipe:

1. Open the function, switch to HLIL.
2. Find the assignment to the state variable: search the HLIL for the `VAR` or `SUB` that stores
   the immediate, and note the variable (`var_4` in the example).
3. Read the dispatcher's switch: the HLIL shows a `SWITCH` on the state variable with one branch
   per case; each branch body is the block.
4. For each block, find the assignment that sets the state variable to the successor value, and
   compute the target address from the case map.
5. Replace the block's tail with an unconditional jump to that address in the HLIL.

The Binary Ninja Python API for the rewrite:

```python
# Binary Ninja Python API — sketch of the HLIL rewrite.
bv = current_view
bv.disasm_type = 'hlil'
func = bv.get_functions()[0]

state_var = None
for block in func.hlil.blocks:
    for insn in block.operations:
        if insn.operation == MediumLevelILOperation.SetVar:
            state_var = insn.dest
            break

# case_map: state value -> target function address
case_map = {1: 0x401180, 2: 0x401198, 3: 0x4011b0}

for block in func.hlil.blocks:
    for insn in block.operations:
        if insn.operation == MediumLevelILOperation.SetVar and insn.dest == state_var:
            target = case_map.get(insn.value)
            print("block 0x%x -> 0x%x" % (block.start, target))
```

The Graphviz output of the HLIL graph makes the result easy to check:

```
File -> Export Graphviz...
```

**Option D — symbolic execution with `angr` or `miasm`.**

When the state values are not literal constants — for example the next state is computed as
`state = table[state] ^ 0x5a` — the mapping has to be solved rather than read. Symbolic
execution solves it.

`angr`:

```python
#!/usr/bin/env python3
"""Recover the case map of a flattened function with angr."""
import angr
import claripy

proj = angr.Project("target", auto_load_libs=False)
cfg = proj.analyses.CFGFast()

func = cfg.functions.get(addr)     # addr of the flattened function
if func is not None:
    for node in func.graph.nodes():
        for block in node.blocks:
            insns = block.capstone.insns
            if insns and insns[0].mnemonic == "mov" and "ebp" in insns[0].op_str:
                print(hex(block.address), insns[0].op_str)
```

A more targeted approach: run angr's symbolic execution from the function entry with a symbolic
state variable and enumerate the reachable successors:

```python
state = proj.factory.entry_state(addr=func_addr)
state = proj.factory.call_state(func_addr, 0x41414141)
simgr = proj.factory.simulation_manager(state)
simgr.explore(find=lambda s: True, num_find=64)
for sim in simgr.found:
    print(hex(sim.addr))
```

`miasm` does the same with explicit expression manipulation:

```python
from miasm import analysis
from miasm.core.locationdb import LocationDB
from miasm.ir.symbexec import SymbolicExecutionEngine

loc_db = LocationDB()
from miasm.bin.pe import PE
pe = PE("target.exe")
mdis = pe.disasm(loc_db)
ira = analysis.ira.IRA(mdis, loc_db)
s = SymbolicExecutionEngine(ira)
addr = 0x401100
s.run_at(addr)
print(s.eval_expr(ira.get_irs()[s.stop]))
```

The symbolic route pays off when the state values are computed; for literal constants the byte-level
recipe is faster.

### 7. Remove the opaque predicates

1. List the conditional branches that are not real conditions: the predicate reads a register that
   was loaded with a constant, or compares against a value that the code can never produce.
2. For each, decide the constant outcome and delete the dead successor. In Ghidra, select the dead
   block and use "Clear Code Bytes"; in a script, remove the instruction that creates it.
3. Re-run the decompiler and confirm the dead blocks are gone.

A reliable detector for a dead block: it has exactly one predecessor (the opaque branch), and the
state value it stores is not stored by any live block.

### 8. Reimplement in Python

For a licence check the fastest deliverable is a reimplementation. Take the edge list, order the
blocks by a topological sort of the entry block, and translate each block body into Python.

```python
#!/usr/bin/env python3
"""Skeleton of a de-flattened reimplementation."""
import networkx as nx

EDGES = [
    (0x401100, 0x401180),
    (0x401180, 0x4011f0),
    (0x4011f0, 0x401240),
    (0x401240, 0x4011b0),
]

graph = nx.DiGraph()
graph.add_edges_from(EDGES)

entry = 0x401100
order = list(nx.dfs_preorder_nodes(graph, entry))
print("block order:", ", ".join(hex(a) for a in order))
```

`networkx` gives the topological order, the dominator tree and the strongly connected components,
which is enough to reconstruct loops from the edge set alone.

## Variations

- **Indirect-branch flattening.** The dispatcher computes the target into a register and does
  `jmp reg` (`ff e0`) or `jmp [mem]` (`ff 25`). The jump table is no longer a contiguous array of
  addresses, and the mapping is computed. Solve the arithmetic per state value.
- **Computed state values.** The next state is a function of the current one, for example
  `state = state * 3 + 7 mod N`. The case map is a permutation, not an identity. Solve it by
  evaluating the expression for every state value.
- **Hashed state values.** The state constants are hashes of the original block addresses. The
  dispatcher uses a compare chain instead of a table. Recover the mapping by deobfuscating the
  hash, or by tracing the runtime values: set a breakpoint on the state store and record the
  sequence of values for one execution.
- **Opaque predicates over the argument.** A predicate that reads the function argument can be
  genuinely true or false. Only blocks whose predicate is a compile-time constant may be deleted.
- **Nested flattening.** A flattened function contains another flattened function. Recover the
  innermost first.
- **Flattening plus an instruction-level VM.** The block bodies are bytecode interpreter calls.
  The de-flattening recovers the block structure, and the interpreter is a separate problem.
- **Split functions.** The `split` pass moves blocks into separate functions, and the dispatcher
  calls them. Recover the mapping from the call target of each block instead of from a jump table.
- **Switch-based flattening on managed code.** The same pattern appears in C# (`switch` over a
  `state` local) and in Java (`tableswitch` over an `int` field). The recovery is the same, and
  ILSpy and jadx both show the state machine clearly.
- **Inter-procedural state.** The state variable lives in a global shared between functions. The
  dispatcher may be a separate function called from every block. Find it by following the
  cross-references of the global.

## Verification

1. **Structural check.** The rebuilt graph must satisfy the properties of the original code: one
   entry, a reducible CFG if the original had no irreducible loops, and every live block reachable.
   Compare the block count against the number of distinct state values.
2. **Trace check.** Instrument the original binary and record the sequence of state values for one
   run. The rebuilt graph must contain a path through exactly that sequence of blocks, in that
   order. This is the decisive test: it validates the case map and the edge set at once.
3. **Re-decompilation check.** After the flow repair, the Ghidra output must contain the branch
   structure. Expected: the number of switch cases drops and the number of conditionals rises.
4. **Semantic check.** Reimplement the recovered logic and compare with the target's output across
   a set of inputs, including the invalid cases. For a licence check, the accept/reject decision
   must match on every sample.
5. **Negative test.** Feed an invalid key to the reimplementation and confirm it is rejected. A
   recovery that accepts everything has mis-recovered a branch.
6. **Dead-block accounting.** The number of removed blocks must equal the number of constant
   predicates found. Explain every difference.
7. **Independent re-derivation.** Have the script-based recovery and the manual edge list agree.
   Two independent derivations that match are strong evidence; one that matches a plausible-looking
   output is not evidence.

## Pitfalls

- **The dispatcher is not always the biggest block.** A compare-chain dispatcher has one successor
  per `je`, which counts as many edges, but a helper function can have more. Confirm the
  candidate by checking that it reads the state variable.
- **The state slot changes between builds.** `-4` in one version, `-0x14` in the next. Re-derive
  it every time; never carry the offset over.
- **The pre-header store.** The dispatcher writes the state variable once on entry. Exclude that
  store when building the edge set, or the entry block gets a spurious predecessor.
- **Fall-through edges.** A block that ends without a state store continues into the next address.
  Include those edges or the graph loses paths.
- **Loops.** A back edge produces a cycle. A topological sort fails on a cycle, so use a DFS
  preorder or strongly connected components instead.
- **The switch is not the only switch.** A flattened function can contain a genuine switch in one
  of its blocks. Distinguish the dispatcher by checking which one reads the state variable.
- **Decompiler output can be misleading.** Ghidra may hoist the state variable into a register and
  show a `while (true)` with a `switch`, which hides the fact that the blocks are separate. Read
  the listing, not just the decompilation.
- **Patching changes the byte offsets.** Overwriting a state store with a jump moves the following
  bytes and invalidates every offset gathered so far. Prefer flow overrides, or patch from the
  end of the function backwards.
- **Obfuscated builds carry a checksum.** Editing the flattened code breaks the checksum. See
  [integrity-self-checks](./integrity-self-checks.md).
- **Scale.** A flattened function with 500 cases is not a manual job. Write the recovery script
  once and run it on every function in the binary.

## References

- ollvm `fla` and `bcf` passes — https://github.com/obfuscator-llvm/obfuscator
- Ghidra 12.2 — https://github.com/NationalSecurityAgency/ghidra/releases
- Ghidra Script Manager — https://github.com/NationalSecurityAgency/ghidra
- Binary Ninja Python API — https://binary.ninja/python-api/
- `angr` documentation — https://angr.readthedocs.io/
- `miasm` — https://github.com/cea-sec/miasm
- Capstone — https://www.capstone-engine.org/
- radare2 — https://rada.re/n/
- `networkx` — https://networkx.org/documentation/stable/
