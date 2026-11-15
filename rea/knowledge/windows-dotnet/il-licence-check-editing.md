---
id: "il-licence-check-editing"
title: "IL licence check editing"
domain: "windows-dotnet"
kind: "technique"
platforms: "windows, macos, linux"
arch: "-"
difficulty: "intermediate"
tools: "dnSpyEx,ILSpy,ildasm,sn,ilspycmd"
verified: false
updated: "2026-11-15"
summary: "Locates the licence decision in a .NET assembly, rewrites the single IL instruction that decides it, and restores the strong name so the modified assembly still loads."
---

## Summary

A .NET licence check is a method that returns a boolean, a date, or a throw. The whole decision
usually collapses into one or two IL instructions: a `ldc.i4.0` that should be `ldc.i4.1`, a
`brfalse.s` that should be `br.s`, or a comparison whose operand is a date in the past.

This entry gives the search procedure in dnSpyEx 6.6.0, the exact opcode bytes for each edit,
the re-signing step that keeps the assembly loadable, and the extraction/repack route for
single-file deployments.

Cross-reference: [dotnet-obfuscator-deobfuscation](dotnet-obfuscator-deobfuscation.md) when the
assembly is obfuscated and the check cannot be read directly, and
[strong-name-and-authenticode](strong-name-and-authenticode.md) for the signing rules in detail.

## Recognition

The five shapes of a .NET licence check, with their observable traces:

| Shape | Where it lives | Trace |
| --- | --- | --- |
| Constant flag | `bool IsLicensed()` | method body is `ldc.i4.0`/`ldc.i4.1` + `ret`, no logic |
| Expiry date | `DateTime` comparison | `call DateTime::get_Now()`, `call op_GreaterThan`, a `brfalse.s` |
| Native call | `[DllImport]` | a `call` to a method with a `pinvokeimpl` flag |
| Signature check | `RSA.VerifyData` | `ldstr` blob, `RSA::Create()`, `callvirt VerifyData`, `brfalse.s` |
| Activation call | `HttpClient` | `HttpClient::GetAsync`, then a status-code compare |

Other traces in the decompiled source:

- Property or field names: `IsLicensed`, `IsRegistered`, `HasLicense`, `Licensed`, `TrialDays`,
  `ExpiryDate`, `ExpirationDate`, `Serial`, `SerialNumber`, `ProductKey`, `RegistrationKey`.
- Class names: `LicenseManager`, `LicenceService`, `RegistrationManager`, `ActivationService`,
  `SubscriptionManager`.
- Strings: `Invalid license key`, `License expired`, `Trial expired`, `This product is not
  registered`, `ERR_LICENSE_013`, `Enter your serial number`.
- An assembly-level attribute such as `AssemblyTitle` containing the vendor name, used to build
  the registry key `HKCU\Software\<Vendor>`.

## Method

Working directory for every command below: the directory that contains the target assembly.

### 1. Survey the assembly

```bash
# Batch decompile with the ILSpy command line
ilspycmd -p -o decompiled target.exe

# Or list what is inside without a GUI
ilspycmd target.exe > target.cs
```

In dnSpyEx 6.6.0: `File > Open` the assembly, then use `Search > Search in Text` (Ctrl+Shift+F)
with these terms, one at a time:

```text
Licens
Serial
Activate
Trial
Expire
Validat
Registered
Subscription
```

Each hit lands in the decompiled C# view. Switch to the IL view to confirm what the method
actually does: `Debug > Step Into` is not needed, use the view switcher in the lower-left
corner of the editor, or right-click the method in the Assembly Explorer and choose
`View in IL` (dnSpyEx shows the IL window for the selected method).

### 2. Read the opcode table you need

The opcodes used by licence checks, with their encodings:

| Instruction | Byte | Operand |
| --- | --- | --- |
| `nop` | `00` | — |
| `ldarg.0` / `ldarg.1` | `02` / `03` | — |
| `ldloc.0` … `ldloc.3` | `06` … `09` | — |
| `stloc.0` … `stloc.3` | `0a` … `0d` | — |
| `ldnull` | `14` | — |
| `ldc.i4.m1` … `ldc.i4.8` | `15` … `1e` | — |
| `ldc.i4.s` | `1f` | 1 byte signed |
| `ldc.i4` | `20` | 4 bytes signed |
| `ldc.i8` | `21` | 8 bytes signed |
| `pop` | `26` | — |
| `call` | `28` | 4-byte method token |
| `ret` | `2a` | — |
| `br.s` | `2b` | 1-byte signed delta |
| `brfalse.s` | `2c` | 1-byte signed delta |
| `brtrue.s` | `2d` | 1-byte signed delta |
| `beq.s` | `2e` | 1-byte signed delta |
| `bne.un.s` | `33` | 1-byte signed delta |
| `br` | `38` | 4-byte signed delta |
| `brfalse` | `39` | 4-byte signed delta |
| `brtrue` | `3a` | 4-byte signed delta |
| `switch` | `45` | count + N deltas |
| `add` / `and` / `or` / `xor` | `58` / `61` / `62` / `63` | — |
| `callvirt` | `6f` | 4-byte method token |
| `ldstr` | `72` | 4-byte string token |
| `newobj` | `73` | 4-byte method token |
| `ldfld` / `stfld` | `7b` / `7d` | 4-byte field token |
| `ldsfld` / `stsfld` | `7e` / `80` | 4-byte field token |
| `leave` / `leave.s` | `dd` / `de` | — |
| `ceq` / `cgt` / `clt` | `fe 01` / `fe 02` / `fe 04` | — |

### 3. Edit the constant flag

The simplest case, `bool IsLicensed()` returning a constant:

```text
IL_0000: ldc.i4.0        // 16
IL_0001: stloc.0         // 0a
IL_0002: br.s    IL_0004 // 2b 00
IL_0004: ldloc.0         // 06
IL_0005: ret             // 2a
```

Full method body bytes: `16 0a 2b 00 06 2a`.

Change the constant so the method returns `true`:

```text
   16   ldc.i4.0   ->   17   ldc.i4.1
```

The one-byte edit changes the method's return value and nothing else. If the method returns
`int` rather than `bool`, the same edit works (`ldc.i4.1` is a valid `int`).

The same trick applies to a static field initialised to false:

```text
IL_0000: ldc.i4.0        // 16
IL_0001: stsfld   ...    // 80 <token>
```

Change `16` to `17`.

### 4. Edit the branch

A licence check that reads a stored flag:

```text
IL_0000: ldsfld    bool App::licensed   // 7e <token>
IL_0005: brfalse.s IL_0010               // 2c 09
```

Make the "not licensed" path unreachable by turning the conditional jump into an unconditional
one. `brfalse.s` (`2c`) and `br.s` (`2b`) take the same one-byte delta operand, so the edit is
one byte and no offset is disturbed:

```text
   2c 09   brfalse.s IL_0010   ->   2b 09   br.s IL_0010
```

Other useful inversions, same operand size:

| Before | After | Effect |
| --- | --- | --- |
| `2c xx` `brfalse.s` | `2b xx` `br.s` | always take the branch |
| `2d xx` `brtrue.s` | `2b xx` `br.s` | always take the branch |
| `2c xx` `brfalse.s` | `2d xx` `brtrue.s` | invert the condition |
| `39 xx xx xx xx` `brfalse` | `3a xx xx xx xx` `brtrue` | invert a long branch |

Note that `br.s` is only correct when the jump should always be taken. If the branch leads to a
cleanup block that expects the value on the stack, use `ldc.i4.1` + `pop` instead of forcing
the jump.

### 5. Edit the expiry comparison

```text
IL_0000: call      instance class System.DateTime [mscorlib]System.DateTime::get_Now()
IL_0005: stloc.0
IL_0006: ldloc.0
IL_0007: ldsfld    class System.DateTime App::licenseExpiry
IL_000c: call      instance bool [mscorlib]System.DateTime::op_GreaterThan(class System.DateTime)
IL_0011: brfalse.s IL_0019
```

Three ways to neutralise it:

**Push a far-future date instead of the stored one.** Replace the `ldsfld` (`7e <token>`) with
an `ldc.i8` holding the tick count of a date past the expiry:

```text
IL_0007: ldc.i8 639343584000000000    // 21 00 c0 be 2d 9a 67 df 08
```

The operand is 100-nanosecond ticks since 0001-01-01. The values used most often:

| Date | Ticks | `ldc.i8` bytes |
| --- | --- | --- |
| 2027-01-01 | 639343584000000000 | `21 00 c0 be 2d 9a 67 df 08` |
| 2030-01-01 | 640290528000000000 | `21 00 c0 7c c2 d7 c4 e2 08` |

Compute any other value with `days * 864000000000`.

**Make the comparison return false.** Replace the 5-byte `call` to `op_GreaterThan` with
`pop` + `ldc.i4.0` + three NOPs. The `call` pops two `DateTime` arguments and pushes a
boolean; `pop` discards them and `ldc.i4.0` pushes `false`:

```text
   28 <token:4>   call op_GreaterThan   ->   26 16 90 90 90
```

The following `brfalse.s` is then taken, and the licence reads as valid.

**Remove the whole check.** Replace the body with `ldc.i4.1` + `ret` (`17 2a`) and delete the
rest. In the dnSpyEx IL editor, select the extra instructions and press Delete; the editor
recomputes the branch offsets.

### 6. Edit the signature check

```text
IL_0000: call      class System.Security.Cryptography.RSA [mscorlib]System.Security.Cryptography.RSA::Create()
IL_0005: stloc.0
IL_0006: ldloc.0
IL_0007: ldc.i4    0x0400        // SHA1
IL_000c: ldloc.1
IL_000d: ldstr     "-----BEGIN PUBLIC KEY-----..."      // 72 <token>
IL_0012: callvirt  instance bool [mscorlib]System.Security.Cryptography.RSA::VerifyData(byte[], byte[], byte[], int, int)
IL_0017: brfalse.s IL_0020
```

`callvirt` is 6 bytes (`6f` plus a 4-byte token). Replace it with three `pop`s (the `this`
reference plus the two byte arrays), a `ldc.i4.1` and two NOPs:

```text
   6f <token:4>   callvirt RSA::VerifyData   ->   26 26 26 17 90 90
```

The comparison then succeeds, and the `brfalse.s` is not taken.

The same pattern works for `ECDsa.VerifyData`, `SignedXml.CheckSignature`, or any
`bool`-returning verification call.

### 7. Edit a native call from the managed side

A P/Invoke appears in the decompiled source as:

```csharp
[DllImport("licensing.dll", EntryPoint = "CheckLicense", CallingConvention = CallingConvention.Cdecl)]
private static extern bool CheckLicenseNative(string productKey);
```

In the IL it is a `call` to a method whose flags include `pinvokeimpl`. Replace the *managed
stub's* body with a constant:

```text
IL_0000: ldc.i4.1        // 17
IL_0001: ret             // 2a
```

Bytes: `17 2a`. The native DLL is never called, the strong name of the managed assembly is
untouched, and the check is bypassed without editing a second file. See
[managed-native-interop-hybrid](managed-native-interop-hybrid.md) for the native-side route.

### 8. Edit in dnSpyEx

1. Open the assembly with `File > Open`.
2. Find the method with `Search > Search in Text`.
3. Switch the editor to the IL view.
4. Click the instruction to edit. dnSpyEx turns the line into an editable box.
5. Type the new instruction, for example `ldc.i4.1` or `br.s IL_0010`, and press Enter. The
   editor validates the operand and the stack effect.
6. To delete instructions, select them and press Delete.
7. `File > Save` (Ctrl+S) writes the assembly back to disk. dnSpyEx updates the MVID and the
   timestamp, which is expected.

The decompiled C# view is a read-only projection of the IL. Edits made in the IL view are
reflected in the C# view after a reload, and the other way round does not work.

### 9. Re-sign the assembly

Any IL edit invalidates the strong name. If the assembly is strong-named, re-sign it with the
original key:

```bat
sn -R target.exe original.snk
```

Check the result:

```bat
sn -T target.exe
sn -vf target.exe
```

`sn -vf` prints `Assembly 'target.exe' is valid` when the hash matches the key. If the
original private key is not available, the alternative is to strip the strong name, which
changes the assembly identity and therefore requires patching every referencing assembly; see
[strong-name-and-authenticode](strong-name-and-authenticode.md).

On .NET Core, .NET 5 and later the runtime does not validate strong names at load time, so an
edited strong-named assembly still loads; only a *public key mismatch* between the assembly and
its references breaks the load.

### 10. Handle a single-file deployment

A .NET 5+ single-file bundle stores the assemblies in a bundle appended to the host executable,
with a bundle header listing each file's offset and size. The assemblies are deflate-compressed
unless `EnableCompressionInSingleFile` is `false`.

Extract the bundle:

```bash
dotnet tool install -g Dotnet.BundleExtract
dotnet-bundle extract app.exe --output-dir extracted
```

ILSpy 8 and later detect a bundle and offer to extract it as well:

```bash
ilspycmd app.exe --outputdir decompiled
```

Patch the extracted assembly with dnSpyEx as above, then republish so that the bundle contains
the patched assembly:

```bash
dotnet publish -c Release -r win-x64 --self-contained true \
  -p:PublishSingleFile=true \
  -p:EnableCompressionInSingleFile=false \
  -p:IncludeNativeLibrariesForSelfExtract=true \
  -o publish
```

Patching bytes inside the bundle in place is not practical: the assembly is compressed, and
the bundle header stores the compressed size of each file, so a changed assembly changes the
layout. Rebuilding the bundle from the patched sources is the reliable route.

## Variations

- **Release builds with inlining**: the licence check may be inlined into its caller, leaving
  no method to edit. Look for the field write instead (`stfld`) and edit the initialiser.
- **A field, not a method**: `stfld` of `false` into the licence field. Patch the `ldc.i4.0`
  that feeds it.
- **An exception instead of a boolean**: `throw new LicenseException("...")`. Replace the
  5-byte `newobj` + `throw` sequence with `pop; pop; ldc.i4.0; ret`, or set the exception
  message string to empty.
- **A `switch` dispatch**: the licence state selects a branch through a `switch` (opcode `45`).
  Rewriting the dispatch table is more work; see
  [dotnet-obfuscator-deobfuscation](dotnet-obfuscator-deobfuscation.md).
- **A WinForms / WPF UI gate**: the check feeds `menuItem.Enabled = false`. Patch the boolean
  in the method that produces it; the UI follows.
- **A background timer or service**: the licence is re-verified on a timer. The same edit
  applies, and the timer re-reads the patched method each tick.
- **A signed licence blob**: the licence file is a PKCS#7 or a custom signed structure. The
  local check is the RSA verification; the patch is the same as in step 6.
- **NativeAOT**: there is no IL. The assembly is a native binary with embedded metadata; patch
  the native code instead. See
  [managed-native-interop-hybrid](managed-native-interop-hybrid.md).
- **WASM / browser**: the IL is compiled to WebAssembly; patch the IL and rebuild, or patch
  the `.wasm` bytes.

## Verification

1. **Confirm the edit landed.** Re-dump the IL and read the method back:

   ```bat
   ildasm /text /nobar /tokens /out=target.after.il target.exe
   ```

   Search the dump for the method and confirm the new opcode is present.

2. **Positive test.** Run the application and exercise the licensed feature. The premium
   feature must be enabled and the licence dialog must not appear.

3. **Negative test.** Restore the original assembly (`target.original.exe`) and confirm the
   failure returns: the licence dialog reappears, the exit code is the original one, and the
   premium feature is disabled again. A patch whose effect cannot be observed when reverted was
   never the gate.

4. **Negative test for the cache.** Delete the licence cache the program writes (registry
   values, `%APPDATA%` files, a local database), restart the process, and repeat. A licence
   decision that is cached in a file will keep the old answer.

5. **Strong-name check.** After re-signing, `sn -vf target.exe` must report the assembly as
   valid, and any referencing application must still start. `FileLoadException` with a message
   about strong name validation means the re-sign did not take effect or used a different key.

6. **Loading check.** Load the patched assembly in a fresh host and exercise it:

   ```bash
   dotnet exec patched-host.dll
   ```

   A `BadImageFormatException` or `FileLoadException` at load means the strong name or the
   metadata is broken, not the licence logic.

## Pitfalls

- **The decompiled C# view cannot be edited.** dnSpyEx edits IL. Editing the C# text has no
  effect on the saved file.
- **The strong name hash covers the metadata**, so any IL edit invalidates it. On .NET
  Framework the failure appears as `FileLoadException` ("Strong name signature validation
  failed") when a strong-named referencing assembly loads it, or as a missing-assembly error
  when the public key changed.
- **Changing the public key changes the identity.** Stripping the strong name without patching
  the references turns a verification error into a "reference not resolved" error, which is
  harder to trace.
- **`ldc.i4.1` in a non-boolean method is still valid** but changes the semantics. Check the
  declared return type before assuming `true`.
- **Forcing a branch can break the stack.** A branch that skips a block which leaves a value on
  the stack produces invalid IL; dnSpyEx reports the mismatch. Prefer replacing the
  condition with a constant.
- **`call` and `callvirt` have different lengths** (5 and 6 bytes). A replacement must match the
  length, or the offsets after it shift and every branch target breaks.
- **Optimised builds inline the check.** A search for the method name finds nothing; search for
  the string instead, then work backwards from its use site.
- **Trimming removes unused licence code**, which changes the decompiled surface between
  builds and can make a patched method unreachable.
- **ReadyToRun images contain native code** compiled from the IL. Editing the IL does not change
  the native code unless the image is regenerated with crossgen.
- **Single-file bundles compress the assemblies**, so an in-place byte edit of a DLL inside the
  bundle is impossible; extract and repack.
- **The MVID changes on save.** Any code that pins a specific MVID (some DRM systems) will
  notice.
- **Two copies of the assembly.** The patched copy in the output folder may be shadowed by a
  copy in the GAC, in a publisher policy directory, or in another probing path. Check which
  file is actually loaded.

## References

- ECMA-335 Partition III, CIL instruction set:
  <https://ecma-international.org/publications-and-standards/standards/ecma-335/>
- C# language specification, expressions and statements:
  <https://learn.microsoft.com/dotnet/csharp/language-reference/>
- dnSpyEx releases: <https://github.com/dnSpyEx/dnSpy/releases>
- ILSpy command line (`ilspycmd`): <https://github.com/icsharpcode/ILSpy>
- `sn.exe` tool: <https://learn.microsoft.com/dotnet/standard/tools/sn-tool>
- `ildasm` and `ildasm /tokens`:
  <https://learn.microsoft.com/dotnet/standard/assembly/ildasm-command>
- Single-file deployment: <https://learn.microsoft.com/dotnet/core/deploying/single-file/>
- Cross-reference: [strong-name-and-authenticode](strong-name-and-authenticode.md)
