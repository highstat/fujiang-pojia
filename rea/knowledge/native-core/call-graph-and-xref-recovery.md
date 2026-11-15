---
id: "call-graph-and-xref-recovery"
title: "Call graph and cross-reference recovery"
domain: "native-core"
kind: "technique"
platforms: "-"
arch: "x86, x86-64, arm64"
difficulty: "advanced"
tools: "radare2, r2pipe, Ghidra, LIEF, readelf, objdump"
verified: false
updated: "2026-11-15"
summary: "Rebuilds a call graph and locates the licence-validation chain in a stripped binary using entry-point walks, RTTI and vtable reconstruction on ELF, PE and Mach-O, and ObjC/Swift metadata discovery."
---

## Summary

A stripped binary has no function names, but it still has structure: an entry point, constructor
lists, type metadata, vtables and class metadata. This entry reconstructs that structure into a
usable call graph, then walks it from a concrete artefact — a string, a registry key, an HTTP
host — up to the decision point.

Three metadata systems carry most of the structure:

- ELF: the Itanium C++ ABI's `typeinfo` and vtable layout.
- PE: MSVC RTTI, where the complete object locator points at the class descriptor and the type
  descriptor.
- Mach-O: Objective-C class lists and method lists, plus Swift's type metadata sections.

## Recognition

- `rabin2 -s` prints a handful of dynamic symbols (`_start`, `__libc_start_main`) and no
  application symbols.
- A read-only data region holding an array of pointers, each pointing at a run of code: a vtable.
- Strings of the form `.?AVClassName@@` in a PE, or `_ZN4Name3Ev` mangled names in an ELF: the
  type descriptors are present.
- Mach-O sections `__objc_classlist`, `__objc_methname`, `__objc_selrefs`, `__swift5_types`.
- A `__mod_init_func` array in Mach-O, an `.init_array` section in ELF, or a PE TLS directory:
  constructors that run before `main`.

## Method

### Step 1 — Anchor the walk at the entry point and the constructors

ELF: `e_entry` at file offset `0x18` (64-bit) or `0x18` (32-bit). Constructors live in
`.init_array` and `.init`; the dynamic linker calls `DT_INIT` and every entry of
`DT_INIT_ARRAY`.

```
rabin2 -I target.elf | grep -i entry
readelf -SW target.elf | grep -E 'init_array|\.init\b'
objdump -s -j .init_array target.elf
r2 -q -c 'aaa; afl~entry; afl~init' target.elf
```

PE: `AddressOfEntryPoint` is an RVA in the optional header; constructors run from the TLS
directory (data directory index 9) and from `.CRT$XCU`/`_initterm` in `.CRT`.

```
rabin2 -I target.exe | grep -i entry
rabin2 -S target.exe | grep -i -E 'CRT|TLS'
r2 -q -c 'iE' target.exe | head -20      # exports, if any survive
```

Mach-O: `LC_MAIN` carries `entryoff` relative to `__TEXT`; constructors live in
`__DATA_CONST,__mod_init_func` (or `__DATA,__mod_init_func`).

```
otool -l target.macho | grep -A5 LC_MAIN
otool -l target.macho | grep -A10 __mod_init_func
rabin2 -I target.macho | grep -i entry
```

In radare2, `afl` lists the functions the analyser found and `agC` prints the call graph in
JSON. `aaa` runs the full analysis; `aa` is the quick pass.

```
r2 -q -c 'aaa; agC @ entry0' target.elf
```

In Ghidra, the *Defined Strings* and *Function Call Trees* windows give the same graph; set
*Analysis → One Shot → Aggressive Analyzer* for better recovery on stripped code.

### Step 2 — Recover function boundaries without symbols

Boundary heuristics that work across compilers and are cheap to check by hand:

- A prologue: `55 48 89 e5` (`push rbp; mov rbp, rsp`) on x86-64, `55 89 e5` on x86,
  `fd 7b ...` (`stp x29, x30, [sp, #-N]!`) on ARM64.
- An epilogue: `c3` (`ret`), `c2 10 00` (`ret 0x10`), `cb` (`leave; ret`), or ARM64 `c0 03 5f d6`
  (`ret`).
- Padding between functions: `90` on x86, `00 00 00 aa` (`mov x10, x10`) or `1f 20 03 d5` (`nop`)
  on ARM64.
- Thunks: `b <imm26>` on ARM64, `jmp rel32` on x86 — a one-instruction function that is a tail
  call.

radare2 applies these automatically:

```
r2 -q -c 'aaa; afl~fcn.' target.elf | head -40
```

Ghidra applies a fuller rule set under *Analysis → Auto Analyze*; check the result in the
*Listing* view where the "function" entries are highlighted.

### Step 3 — ELF: Itanium ABI vtables and typeinfo

An Itanium C++ vtable in a read-only data section is laid out as:

```
[0]  offset-to-top  (intptr, usually 0 for the primary vtable)
[1]  pointer to __class_type_info / __si_class_type_info / __vmi_class_type_info
[2]  virtual function pointer 0
[3]  virtual function pointer 1
...
```

The `typeinfo` object the second slot points to:

| RTTI kind | Layout |
| --- | --- |
| `__class_type_info` | `[vptr to __class_type_info vtable][name pointer]` |
| `__si_class_type_info` | `[vptr][base typeinfo pointer][name pointer]` |
| `__vmi_class_type_info` | `[vptr][flags][base count][base info array pointer][name pointer]` |

The `name` pointer leads to a NUL-terminated mangled name such as `_ZN6Licence7CheckerD2Ev`.

Recovery procedure:

1. Find the mangled names in `.rodata`:

   ```
   r2 -q -c 'izz~_ZN' target.elf
   ```

2. Take the cross-reference to the name: in an Itanium layout the name pointer sits at the end
   of the `typeinfo` object, so the referencing instruction is inside `typeinfo` itself. The
   typeinfo object starts 8 bytes before that on x86-64 (16 bytes for the vptr + spare
   combination varies). Cross-check by reading the first word of the typeinfo: it must point
   into `.data.rel.ro` at the address of the `__class_type_info` vtable.

3. The `typeinfo` pointer itself sits at vtable slot `[1]`. The vtable start is therefore at
   `typeinfo_address - 8` (x86-64, where the pointer is 8 bytes) and the virtual function
   pointers start at `typeinfo_address + 8`.

4. Confirm with the relocation table. In a PIE the vtable entries are filled by dynamic
   relocations, so `readelf -r` shows `R_X86_64_RELATIVE` entries against the `.data.rel.ro`
   offsets:

   ```
   readelf -rW target.elf | grep -i relative | head -20
   readelf -SW target.elf | grep -E 'data.rel.ro|rodata'
   ```

5. Rebuild the class hierarchy from the `__vmi_class_type_info` base array: the array holds
   `base_count` records of two pointers each (`base typeinfo`, `offset flags`).

LIEF makes the same data reachable without hand-walking:

```
python3 - <<'PY'
import lief
b = lief.ELF.Binary("target.elf")
for s in b.sections:
    if s.name in (".data.rel.ro", ".rodata", ".data"):
        print(s.name, hex(s.virtual_address), hex(s.offset), hex(s.size))
# relocations that populate the relro tables
for r in b.relocations:
    if r.address and "data.rel.ro" in str(r.symbol):
        print(hex(r.address), r.type, r.symbol)
PY
```

### Step 4 — PE: MSVC RTTI and the vftable

MSVC x64 lays out the RTTI as:

```
vftable[-1]  -> pointer to the Complete Object Locator (COL)
COL           -> signature (1), offset, cdOffset, pTypeDescriptor, pClassDescriptor, pSelf
typeDescriptor-> pVftable (its own RTTI vtable), spare, name (".?AVClassName@@")
classDesc     -> signature (1), attributes, numBaseClasses, pBaseClassArray
baseClassArray-> numBaseClasses entries of {pTypeDescriptor, pMFCR offset}
```

The name encoding is `.?AV` + the class name with `::` replaced by `@` + `@@`; e.g.
`std::vector<int>` becomes `.?AV?$vector@V<int>@std@@`.

Recovery procedure:

1. Locate the RTTI names:

   ```
   r2 -q -c 'izz~.?AV' target.exe
   ```

2. The type descriptor is the object whose last field is the name pointer. Read 4 bytes at
   `name_pointer - 4` — that is the `spare` field — and 4 bytes at `name_pointer - 8`, the
   `pVftable` field, which must point into `.rdata`. The type descriptor therefore starts at
   `name_pointer - 8`.

3. The vftable is the array that contains the type descriptor's *own* address? No — the vftable
   of the class is found through the COL. Search the relocation table or `.rdata` for a pointer
   to the type descriptor; that pointer is either `COL.pTypeDescriptor` or, in the single-inheritance
   layout, the vftable's `[-1]` slot holds the COL.

   The reliable route: find the pointer to the type descriptor. It appears in
   `COL.pTypeDescriptor` and in the base class array. Read the word 4 bytes before the
   candidate: `COL` starts with `signature = 1` at offset 0 and `offset` at offset 4, so a
   candidate COL begins with `01 00 00 00`.

4. The vftable pointer is the COL's `pSelf` field at offset 20 (0x14) — it points to the COL
   itself, so it locates the owning object. From the COL, the class hierarchy descriptor is at
   offset 16 (0x10).

5. In the vftable, the slot at index `-1` holds the COL pointer; virtual function pointers
   start at index `0`.

Ghidra ships an RTTI analyser for this layout: *Window → Defined Data → RTTI*, or enable the
*Windows RTTI* analyzer in *Analysis → Auto Analyze*. It produces `vftable` structures in the
Data Type Manager.

### Step 5 — Mach-O: Objective-C class and method lists

The Objective-C runtime metadata is a set of dedicated sections:

| Section | Content |
| --- | --- |
| `__objc_classlist` | array of pointers to `class_ro_t` objects |
| `__objc_metaclasslist` | array of pointers to metaclass `class_ro_t` objects |
| `__objc_catlist` | array of pointers to category objects |
| `__objc_protolist` | array of protocol objects |
| `__objc_methname` | pool of selector name strings |
| `__objc_selrefs` | array of pointers into `__objc_methname` |
| `__objc_classrefs` | array of pointers to classes referenced from code |
| `__objc_nlclslist` / `__objc_nlcatlist` | non-lazy lists, populated at load time |

The `class_ro_t` structure (32-bit and 64-bit differ only in pointer size) carries
`flags`, `instanceStart`, `instanceSize`, `ivarLayout`, `name`, `baseMethods`, `baseProtocols`,
`ivars`, `baseClasses`.

`baseMethods` points to a `method_list_t`: `entsize_and_flags`, `count`, then `count` entries of
`{name (SEL), types (char*), imp (IMP)}`. The `name` is a pointer into `__objc_methname`, and
`imp` is the function address.

radare2 exposes the class structure directly:

```
rabin2 -c target.macho                 # list classes
rabin2 -c target.macho | head -30
r2 -q -c 'ic' target.macho              # interactive class list
r2 -q -c 'icq' target.macho             # quiet class list
r2 -q -c 'icc' target.macho             # class methods
r2 -q -c 'icg' target.macho             # class graph
```

Ghidra's Objective-C analyzer populates the *Symbol Tree → Classes* and the *Program
Information → Classes* views.

### Step 6 — Mach-O: Swift metadata

Swift emits its own sections, all in `__TEXT,__swift5_*`:

| Section | Content |
| --- | --- |
| `__swift5_types` | descriptors for nominal types (structs, classes, enums) |
| `__swift5_reflstr` | reflection strings — field and protocol names |
| `__swift5_fieldmd` | field metadata |
| `__swift5_assocty` | associated type metadata |
| `__swift5_proto` | protocol descriptors |
| `__swift5_protos` | protocol conformance records |
| `__swift5_capture` | capture descriptors |
| `__swift5_typeref` | mangled type references |
| `__swift5_entrypoints` | entry point functions |

A Swift type descriptor begins with a relative pointer to the nominal type descriptor, a
relative pointer to the mangled name, and flags. The mangled names live in `__TEXT,__swift5_reflstr`
or in the `__TEXT,__const` section.

Commands:

```
rabin2 -S target.macho | grep swift5
r2 -q -c 'izz~swift' target.macho
strings -a target.macho | grep -E '^4[0-9] ' | head
swift-demangle --compact "$4s8LicenceCheckerV"
```

Ghidra 11+ includes a Swift demangler for the symbol names it recovers; set the demangler in
*Options → Demangler → Swift*.

### Step 7 — Turn the structure into a call graph

radare2 builds and stores the graph:

```
r2 -q -c 'aaa; agCj @ entry0 > graph.json' target.elf
r2 -q -c 'aaa; agf @ fcn.check_licence' target.elf      # callees
r2 -q -c 'aaa; agx @ fcn.check_licence' target.elf      # xrefs to fcn
```

In r2pipe:

```
python3 - <<'PY'
import r2pipe, json
r = r2pipe.open("target.elf")
r.cmd("aaa")
nodes = json.loads(r.cmd("agCj @ entry0"))
print(len(nodes), "nodes")
for n in nodes[:20]:
    print(hex(n.get("offset", 0)), n.get("name", "fcn."))
r.quit()
PY
```

Ghidra: open the *Decompiler* on a candidate and use *Window → Decompiler → Graph* to see the
call graph; the *Function Call Trees* window gives the inverted tree from the entry point.

### Step 8 — Find the licence call chain from a concrete artefact

Pick one hard artefact — not a generic string:

- A server URL: `https://api.vendor-licensing.example/v2/activate`
- A registry key: `HKLM\SOFTWARE\Vendor\Product\License`
- A file path: `C:\ProgramData\Vendor\license.dat`
- A key fragment: `-----BEGIN LICENCE-----`

Then walk upward:

```
r2 -q -c 'aaa; iz~activate; axt @@ str.https_api_vendor' target.elf
r2 -q -c 'aaa; pdf @ 0x140002310' target.elf     # the xref site
r2 -q -c 'aaa; axt @ 0x140002310' target.elf     # who calls the function containing it
```

Repeat until the chain reaches the entry point or a UI callback. The chain typically looks
like:

```
[UI callback] -> [read license blob] -> [verify signature] -> [derive key] -> [compare]
```

Each link is a concrete function address that can be patched independently. This chain is also
the skeleton of the licence-reconstruction playbook; see
`license-crypto` entries for the algorithm side.

### Step 9 — Record the graph

Export it in a form that survives the session:

```
r2 -q -c 'aaa; agCj @ entry0' target.elf > calls.json
r2 -q -c 'afl~fcn.' target.elf | sed 's/^/FUNC /' > funcs.txt
```

Keep the addresses with the file's hash. A call graph is only meaningful against the exact
binary it was derived from.

## Variations

### Go binaries

Go keeps a `pclntab` (`.gopclntab`) with function names and file/line data even in stripped
binaries.

```
go tool nm target 2>/dev/null | head
r2 -q -c 'izz~go:func' target
```

`runtime.moduledata` in `.noptrdata` gives the module's text range; the function table is at
`pcHeader.funcnametab`.

### Rust binaries

Rust vtables carry no RTTI; a `Vec`/`Box` drop shim looks like a vtable slot in `.rodata`.
Panic messages are `core::panicking::panic_fmt` with a format string that identifies the
failing check:

```
r2 -q -c 'izz~panicked at' target
```

`rustfilt` demangles the remaining symbols when any survive.

### MSVC 64-bit RTTI variants

On x64 the COL is 24 bytes and the `pSelf` field holds the COL's own address; some compilers
place the type descriptor pointer directly in the vftable at index `-1` instead of a COL. Test
both layouts: read the 8 bytes at `vftable - 8` and check whether they look like a COL
(signature DWORD = 1) or like a pointer to a type descriptor (whose `pVftable` word points into
`.rdata`).

### Interposition as a shortcut

On ELF, a PLT call to an external symbol can be intercepted without any patching:

```
LD_PRELOAD=./intercept.so ./target
```

Interpose `strcmp`, `memcmp`, `time`, `getenv` and observe what the check compares. This yields
the licence algorithm faster than static recovery and needs no writes to the binary.

### .NET and Java

These have their own metadata (ECMA-335 tables, DEX `method_ids`); the native call-graph
technique applies only to the native runtime shim around them.

## Verification

1. Prove the function boundary set is sane: the count of recovered functions should be in the
   same order as the size of the executable section, and every entry should start with a
   plausible prologue or a plausible mid-function entry.

   ```
   r2 -q -c 'aaa; afl' target.elf | wc -l
   rabin2 -S target.elf | grep -E '\.text|\.text\.'
   ```

2. Prove the vtable recovery: the `typeinfo` object's first word must point into the same
   read-only section that holds the vtable, and the mangled name must demangle to a plausible
   class:

   ```
   python3 -c "print(__import__('subprocess').run(['c++filt','_ZN6Licence7CheckerD2Ev'],capture_output=True,text=True).stdout)"
   ```

3. Prove the ObjC recovery: every `IMP` in the recovered `method_list_t` entries must point
   inside a `__TEXT` segment and be preceded by a function prologue.

4. Prove the call graph: pick one leaf function and confirm the caller's instruction really is a
   `call` to that address, in both the disassembly and the raw bytes:

   ```
   r2 -q -c 'aaa; pd 3 @ 0x140001200' target.elf
   xxd -s 0x1200 -l 8 target.elf
   ```

   The `e8` displacement must resolve to the callee's address.

5. Negative test: confirm the graph is not an artefact of the analyser's heuristics. Disable
   recursion and re-run; the set of functions that disappears should be the ones that were only
   reached through a misidentified boundary.

6. Compare the recovered graph against the import list: every leaf that calls an imported
   function must name an import that actually exists in the import table. A mismatch means a
   boundary was misidentified.

## Pitfalls

- Trusting `rabin2 -s` output as the function list. In a stripped binary it lists only dynamic
  symbols, usually a handful.
- Assuming the ELF section header count equals the function count. Section headers describe
  data layout, not code.
- Mis-reading the Itanium vtable: slot `[0]` is `offset-to-top`, not a function pointer, and
  slot `[1]` is the typeinfo pointer. Reading slot `[0]` as a function gives a garbage
  address.
- Mis-reading the MSVC vftable: index `-1` is the COL pointer, not a virtual function.
- Assuming a mangled name in `.rodata` is referenced only by a type descriptor. The same name
  is often also referenced by the typeinfo's own vtable slot and by exception-handling tables.
- Assuming `__objc_methname` strings are reachable only through `__objc_classlist`; they are
  also referenced by `__objc_selrefs` and by protocol lists.
- Expecting Swift reflection strings to be plain class names. `__swift5_reflstr` holds field
  and protocol names; the type names are in `__swift5_typeref` and mangled.
- Analysing a packed image and concluding the graph is small. Unpack first.
- Assuming the caller of the licence check is the UI. A service, a background thread, or a
  second copy of the check often exists. Confirm by tracing every caller.
- Losing the graph when the binary is patched: addresses shift, and a graph keyed on absolute
  addresses becomes invalid. Re-derive it or key it on byte patterns.

## References

- Itanium C++ ABI, virtual table layout and RTTI: <https://itanium-cxx-abi.github.io/cxx-abi/abi.html#vtable>
- Microsoft PE/COFF spec, RTTI structures (`RTTICompleteObjectLocator`, `RTTITypeDescriptor`,
  `RTTIClassHierarchyDescriptor`): <https://learn.microsoft.com/windows/win32/debug/pe-format>
- Apple Objective-C runtime, type structures: <https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/ObjCRuntimeGuide/Articles/Types.html>
- Swift ABI, type metadata: <https://github.com/apple/swift/blob/main/docs/ABI/TypeMetadata.rst>
- LLVM `ItaniumDemangle` and `MicrosoftDemangle`: <https://llvm.org/docs/DemangleNodes.html>
- radare2 documentation: <https://r2.re>
- Ghidra documentation: <https://ghidra.re/ghidra_docs/GhidraClass/Programming.pdf>
- LIEF documentation: <https://lief.re/doc/latest/>
