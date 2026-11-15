---
id: "dotnet-obfuscator-deobfuscation"
title: ".NET obfuscator deobfuscation"
domain: "windows-dotnet"
kind: "playbook-ref"
platforms: "windows, macos, linux"
arch: "-"
difficulty: "advanced"
tools: "dnSpyEx,ILSpy,de4dot,dnlib,AsmResolver,ilspycmd"
verified: false
updated: "2026-11-15"
summary: "Identifies the obfuscator that protects a .NET assembly, removes its protection layer with de4dot or a scripted dnlib pass, and exposes the licence method that the obfuscation was hiding."
---

## Summary

An obfuscated assembly hides the licence check in three ways at once: control flow is flattened
into a `switch` dispatcher, strings are encrypted and decrypted by a delegate, and the module
initializer runs the protection on every load. The licence method still exists; it is simply
unreachable from the decompiled source without unwrapping the proxy calls first.

This entry is a playbook: identify the obfuscator, run the deobfuscator, fall back to a
scripted `dnlib` pass when the deobfuscator fails, and then locate the protected licence
method in the deobfuscated output.

Cross-reference: [il-licence-check-editing](il-licence-check-editing.md) for the IL edits that
follow, and [strong-name-and-authenticode](strong-name-and-authenticode.md) because every
deobfuscation pass rewrites the assembly and therefore invalidates the strong name.

## Recognition

Markers in the decompiled source or the metadata:

| Obfuscator | Marker |
| --- | --- |
| ConfuserEx | an assembly- or module-level attribute whose type name contains `Confuser` or `ConfuserEx`; a `<Module>::.cctor` (module initializer) that calls the protection setup |
| .NET Reactor | types in a `Reactor` / `Eziriz` namespace; a native stub section; IL method bodies that decrypt at runtime; a `<Module>::.cctor` |
| Dotfuscator | an assembly attribute `DotfuscatorAttribute` with `DotfuscatorVersion`; renamed identifiers; `<Module>::.cctor` |
| Eazfuscator.NET | an assembly attribute in the `Eazfuscator` namespace; string arrays holding encrypted blobs; control-flow flattening |
| ConfuserEx rename | every identifier escaped as `\u1234` style names |
| SmartAssembly | obfuscated names plus `SmartAssembly` attributes and a `.snk` embedded resource |

Structural tells that survive renaming:

- A method with hundreds of `case` labels and a single `switch` — the control-flow flattening
  dispatcher.
- A static method that takes an `int` and returns a `string`, called from everywhere — the
  string decryption delegate.
- A field initialised with a large `byte[]` or `int[]` literal — the encrypted string or
  constant table.
- A `<Module>::.cctor` (the module initializer) that is longer than a few instructions.

Confirm with a metadata dump:

```bash
ilspycmd -il target.exe > target.il
grep -n "custom instance" target.il | head -40
```

## Method

Working directory for every command below: the directory that contains the target assembly.

### 1. Identify the protection layer

```bash
ilspycmd target.exe > target.decompiled.cs
grep -nEi 'Confuser|Reactor|Dotfuscator|Eazfuscator|SmartAssembly|Obfuscator' target.decompiled.cs | head -40
```

In dnSpyEx, open the assembly and look at the assembly-level attributes and at the `<Module>`
type. The module initializer is the first thing that runs and it is where ConfuserEx installs
its runtime protections.

### 2. Run de4dot

de4dot handles ConfuserEx, Dotfuscator, Eazfuscator.NET, SmartAssembly, XConfuser and the
common string-encryption and control-flow protections.

```bash
# Windows
de4dot.exe target.exe -o target.deob.exe

# Cross-platform, via mono or dotnet depending on the build
mono de4dot.exe target.exe -o target.deob.exe
```

Read the log it writes next to the output. It names the protections it detected
(`Anti-tamper`, `Anti-debug`, `Control flow`, `Constants`, `Rename`) and the ones it could not
handle (`Failed to deobfuscate ...`).

```bash
ilspycmd target.deob.exe > target.deob.cs
grep -nEi 'Licens|Serial|Trial|Expire|Activate|Registered' target.deob.cs | head -40
```

If the log reports that anti-tamper or anti-debug could not be removed, use the fork that
supports the newer ConfuserEx versions (the de4dot-cex fork) or apply the manual steps below.

### 3. When de4dot fails: remove the module initializer first

ConfuserEx installs the anti-tamper and anti-debug code from the module initializer
(`<Module>::.cctor`). de4dot cannot rewrite an assembly whose initializer it cannot locate or
whose protections fight back.

In dnSpyEx:

1. Expand the `<Module>` type in the Assembly Explorer.
2. Open `.cctor` and switch to the IL view.
3. Select every instruction and delete them, leaving an empty body.

The empty module initializer is `ret` only, which in the method body is the absence of
instructions; dnSpyEx writes the method with a single `ret` (`2a`).

Alternatively do it with dnlib, in a small console project or with `dotnet script`:

```csharp
using dnlib.DotNet;
using System.Linq;

var mod = ModuleDefMD.Load("target.exe");

// 1. empty the module initializer
var moduleType = mod.Types.FirstOrDefault(t => t.Name == "<Module>");
if (moduleType is not null)
{
    foreach (var cctor in moduleType.Methods.Where(m => m.IsStaticConstructor).ToList())
    {
        cctor.Body.Instructions.Clear();
        cctor.Body.ExceptionHandlers.Clear();
    }
}

// 2. drop the protection attributes
foreach (var attr in mod.Assembly.CustomAttributes.ToList())
{
    if (attr.Type.FullName.Contains("Confuser") ||
        attr.Type.FullName.Contains("Dotfuscator") ||
        attr.Type.FullName.Contains("Eazfuscator") ||
        attr.Type.FullName.Contains("Reactor"))
        mod.Assembly.CustomAttributes.Remove(attr);
}
foreach (var attr in mod.CustomAttributes.ToList())
{
    if (attr.Type.FullName.Contains("Confuser") ||
        attr.Type.FullName.Contains("Obfuscator"))
        mod.CustomAttributes.Remove(attr);
}

mod.Write("target.stripped.exe");
Console.WriteLine("written");
```

The same trick works with AsmResolver:

```csharp
using AsmResolver.DotNet;
using AsmResolver.PE.DotNet.Metadata.Tables;

var module = ModuleDefinition.FromFile("target.exe");
var moduleType = module.GetModuleType();
foreach (var method in moduleType.Methods.ToList())
{
    if (method.Name == ".cctor")
    {
        method.Cil = new AsmResolver.PE.DotNet.Cil.CilBody();
        method.Cil.OpCodes.Clear();
    }
}
module.Write("target.stripped.exe");
```

Run de4dot again on `target.stripped.exe`.

### 4. Recover a control-flow-flattened method by hand

When de4dot leaves a method as a `switch` dispatcher, the real logic is still there, one case
per basic block. Recover it as follows.

1. In dnSpyEx, open the method and switch to the IL view. Locate the `switch` instruction
   (opcode `45`) and its jump table.
2. Identify the block that produces the method's result. In the flattened form it is usually the
   block that writes to the return-value local with `stloc`.
3. Rewrite the method by hand: replace the whole body with the straight-line sequence that the
   blocks represent. For a boolean result, the recovery is usually three instructions:

   ```text
   IL_0000: ldc.i4.1     // 17
   IL_0001: ret          // 2a
   ```

4. The block that writes the result is often reachable only through the dispatcher, so the
   rewrite must be done in the IL editor, not by patching a single opcode.

For an encrypted-string method, the decryption delegate is a single method that takes an
index and returns a string. Find it by searching for a method whose body indexes into a
`byte[]`/`int[]` field and returns a `string`. Call it directly from the licence method, or
replace each call site with the literal string.

### 5. Reach the protected licence method

After deobfuscation the licence check usually appears in one of these shapes:

- A method in a class named `License`, `Licensing`, `Registration`, `Protection`, or
  `Settings` that returns `bool`.
- A method whose name survived renaming because it was called from a resource or from a
  reflection-based lookup.
- A property setter that stores a `bool` into a static field.

Trace it from the UI:

1. Find the string `Invalid license key` (or equivalent) in the deobfuscated output.
2. Find the method that throws it or shows it in a message box.
3. Walk up one level: the caller is the branch that decides licensed vs unlicensed.
4. Open that method in the IL view and apply the edits from
   [il-licence-check-editing](il-licence-check-editing.md).

If the licence state is behind a proxy call, the call site looks like this:

```text
IL_0000: ldnull
IL_0001: ldftn      void <Module>::.cctor()
IL_0007: newobj     instance void System.Func`2<object, object>::.ctor(object, native int)
IL_000c: stloc.0
```

`ldftn` (opcode `fe 06`) followed by `newobj` of a delegate type is the ConfuserEx proxy
pattern. Replace the whole call sequence with the real implementation, or let de4dot rewrite
it, or call the delegate's target method directly from the licence method.

### 6. Re-sign after every pass

Each deobfuscation pass rewrites the metadata and therefore breaks the strong name:

```bat
sn -R target.deob.exe original.snk
sn -vf target.deob.exe
```

If the key is unavailable, strip the strong name instead and patch the references; see
[strong-name-and-authenticode](strong-name-and-authenticode.md).

### 7. NativeAOT as the terminal case

An obfuscated assembly compiled with NativeAOT has no IL to deobfuscate. The protection runs
in native code and the managed metadata is embedded read-only. Patch the native binary: locate
the licence function with the REA `inspect_binary_layout` view and Ghidra, and apply the native
patch patterns from
[win32-licence-ui-flow](../windows-native/win32-licence-ui-flow.md).

## Variations

- **ConfuserEx string encryption only**: the control flow is intact, only the literals are
  encrypted. Decrypting the string array in the deobfuscated output is enough; the licence
  method becomes readable.
- **ConfuserEx anti-tamper**: the assembly hash is checked at load. Removing the module
  initializer defeats it, but any subsequent edit invalidates the hash, so the tamper check
  must be gone before the licence patch.
- **ConfuserEx anti-debug**: the check runs in the module initializer and kills the process
  under a debugger. Removing the initializer, or running under ScyllaHide, resolves it.
- **.NET Reactor**: protection is split between a native stub and IL method-body encryption.
  Method bodies are decrypted at JIT time, so a static decompiler shows empty bodies. Use the
  .NET Reactor deobfuscator that runs the original assembly in a controlled process, or dump
  the decrypted IL from memory with a debugger attached to the CLR.
- **Dotfuscator**: the licence check is usually still readable after the rename protection is
  removed; the interesting part is the resource-based string decryption.
- **Eazfuscator.NET**: control-flow flattening plus encrypted strings plus a native
  `x86` helper; the module initializer again holds the setup.
- **Babel / Agile.NET**: resource-based obfuscation with a marker in the resources;
  `de4dot` covers Babel.
- **A "protector" that is really a licensing SDK**: some products ship a commercial licensing
  library (a wrapper around a signed token). The decision is in the SDK, and the application
  only reads a boolean; editing the application side is enough.
- **A packer around the assembly**: an executable that extracts and loads the real assembly at
  runtime. Extract the payload first; the protection inside is then a normal case.

## Verification

1. **Prove the deobfuscation actually happened.** Compare the decompiled output before and
   after:

   ```bash
   ilspycmd target.exe > before.cs
   ilspycmd target.deob.exe > after.cs
   wc -l before.cs after.cs
   ```

   After deobfuscation, the identifiers are readable and the string literals are plain text.

2. **Positive test.** Run the deobfuscated assembly and confirm the application still starts
   and reaches its main window. A deobfuscation that leaves a broken assembly is worse than
   none.

3. **Negative test on the protection.** Confirm the anti-debug and anti-tamper are gone: the
   binary must start identically with and without a debugger attached, and must not complain
   about a modified image after the licence patch.

4. **Negative test on the licence.** Restore the original protected assembly and confirm the
   failure returns. If the deobfuscated copy behaves the same as the original, the protection
   was not the gate and the real check is elsewhere.

5. **Strong-name check.** `sn -vf target.deob.exe` must report a valid assembly after
   re-signing, and any host that references it must still load it.

6. **Metadata sanity.** `ilspycmd target.deob.exe` must exit without an error, and
   `ildasm /text /nobar /out=check.il target.deob.exe` must produce a complete IL dump. A
   truncated dump means the metadata tables are inconsistent.

## Pitfalls

- **Anti-tamper fights the deobfuscator.** ConfuserEx computes a hash of the method bodies
  when the assembly loads; the editor's save changes the hash and the assembly refuses to
  initialise. Remove the module initializer before editing anything else.
- **The module initializer is not optional.** Some protections use it to decrypt the string
  table; removing it makes every string null and the decompilation useless. If the strings
  turn into empty strings after the removal, restore the initializer and use a runtime
  deobfuscator instead.
- **de4dot writes a new assembly, it does not patch the original.** The file names in the
  command must be kept straight; `target.deob.exe` is the artefact to work on.
- **de4dot output for .NET Reactor is partial.** It usually decrypts strings and removes
  anti-tamper but leaves the native stub; a separate tool is needed for the method-body
  encryption.
- **Removing the strong name changes the identity.** Referencing assemblies then fail to
  resolve it, and the error looks like a missing file rather than a signature problem.
- **Obfuscators rename the licence method too.** Searching only for `License` finds nothing;
  search the strings, and search for `bool` returns in the decompiled output.
- **A `switch` dispatcher with 200 cases is not a licence check by itself.** Many methods are
  flattened; identify the one that is reachable from the licence string.
- **The protection can be re-entrant.** A protection that decrypts on load and re-encrypts on
  exit means the assembly on disk always looks protected; always dump the decrypted state
  from memory, never from the file.
- **Obfuscated assemblies often crash on load in a debugger** because the anti-debug routine
  runs first. Use ScyllaHide or attach after the module initializer has run.
- **dnlib writes a new file with a new MVID** and, by default, without the original
  timestamp. Any integrity check that covers the whole file must be dealt with separately.

## References

- de4dot: <https://github.com/de4dot/de4dot>
- ConfuserEx: <https://github.com/mkghost/ConfuserEx>
- dnlib: <https://github.com/0xd4d/dnlib>
- AsmResolver: <https://github.com/Washi1337/AsmResolver>
- dnSpyEx releases: <https://github.com/dnSpyEx/dnSpy/releases>
- ILSpy: <https://github.com/icsharpcode/ILSpy>
- ECMA-335 Partition II, metadata format:
  <https://ecma-international.org/publications-and-standards/standards/ecma-335/>
- Cross-reference: [il-licence-check-editing](il-licence-check-editing.md)
