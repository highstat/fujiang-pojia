# Playbook: Windows .NET licence removal

**Target**: a .NET application (WinForms, WPF, ASP.NET desktop host, Unity Mono) whose features
are gated by a licence check.
**Outcome**: the edited assembly runs and the feature is unlocked, with the strong name and
Authenticode state resolved.

## 0. Preparation

```sh
mkdir -p work && cd work
cp /path/to/app.exe app.exe
sha256sum app.exe | tee app.sha256
file app.exe
```

Check whether it is managed at all:

```sh
rabin2 -I app.exe | grep -iE 'clr|dotnet|mono'
strings -a app.exe | grep -iE 'mscoree.dll|clrjit|_CorExeMain'
```

`mscoree.dll` in the imports means a .NET Framework assembly. `hostfxr.dll` or a native entry
with no CLR import means NativeAOT — go to the native playbook instead.

## 1. Inspect in dnSpyEx

Open `app.exe` in dnSpyEx (6.6.0, using the upstream ILSpy engine). Work in the decompiled C#
view first, then switch to IL where the exact edit matters.

Search for the candidates:

```
Licen  Serial  Activat  Trial  Expir  Registered  Premium  Subscription  Unlock
```

Classify the shape:

```csharp
private bool IsLicensed() => false;                            // constant
private bool IsLicensed() => this.expiryDate > DateTime.UtcNow; // date comparison
private bool IsLicensed() => LicenseVerifier.Verify(this.blob); // signature check
private bool IsLicensed() => NativeLicence.Check(this.hwnd);   // native call
```

For each candidate, find the caller that gates the feature. The gate is the caller, not the
method — but the method is the cheaper patch when it is a constant.

## 2. The edits

### Constant boolean

Change the body to return `true`:

```csharp
private bool IsLicensed() => true;
```

### Date comparison

Change the comparison so it always holds, or replace the expiry with a far-future date:

```csharp
private bool IsLicensed() => DateTime.UtcNow < new DateTime(2099, 1, 1);
```

### Signature verification

Replace the call:

```csharp
private bool IsLicensed() => true;   // was: LicenseVerifier.Verify(this.blob)
```

### Native call

Either patch the native DLL (no strong-name problem) or replace the P/Invoke with a managed
stub:

```csharp
[DllImport("licensing.dll", EntryPoint = "Check")]
private static extern bool NativeCheck(IntPtr hwnd);

private bool IsLicensed() => true;
```

### IL-level edits

When the C# view is not editable (obfuscated, or the method is generated), use the IL editor in
dnSpyEx:

| Original IL | Replacement IL | Encoding |
| --- | --- | --- |
| `ldc.i4.0` | `ldc.i4.1` | `16` → `17` |
| `ldc.i4.0; ret` | `ldc.i4.1; ret` | `16 2A` → `17 2A` |
| `brfalse` | `brtrue` | `39` → `3A` |
| `brfalse.s` | `brtrue.s` | `2C` → `2D` |

## 3. Strong name and Authenticode

Editing IL invalidates the strong-name hash. Symptoms:

- The app itself starts, but a *referencing* assembly throws
  `FileLoadException: The strong name signature could not be validated`.
- `sn -vf app.exe` reports a verification failure.

Fixes, in order:

```sh
sn -R app.exe MyKey.snk
sn -vf app.exe
sn -T app.exe
```

`-T` displays the public-key token; it does not grant trust. A replacement key changes identity
and may require rebuilding dependents. Do not globally skip strong-name verification. Preserve
stack balance: replacing a conditional branch with an unconditional branch leaves its operand.

If the project is available, remove the strong name and rebuild:

```xml
<PropertyGroup>
  <SignAssembly>false</SignAssembly>
  <AssemblyOriginatorKeyFile></AssemblyOriginatorKeyFile>
</PropertyGroup>
```

Authenticode on the PE is independent. Strip it or re-sign:

```sh
osslsigncode verify app.exe
osslsigncode remove-signature app.exe
signtool sign /fd SHA256 /f cert.pfx /p pass app.exe
```

## 4. Obfuscated assemblies

```sh
de4dot app.exe -o app_deob.exe
ilspycmd -p -o deob_out app_deob.exe
rg -n -i 'licen|serial|trial|expir' deob_out
```

ConfuserEx specifics: the protection usually lives in a module initializer. After de4dot, if the
method is still wrapped, patch the *proxy* — the caller that forwards to the proxy — instead of
the protected method.

.NET Reactor and Dotfuscator: identify by the assembly-level attributes and the proxy method
pattern. The same approach applies — patch the caller.

## 5. Single-file and self-contained deployments

```sh
# extract the managed assemblies
dotnet tool install -g ilspycmd
ilspycmd -p -o out app.exe
```

For a .NET single-file bundle, the assemblies are concatenated in the host executable. Extract
them, patch the managed assembly, then replace it inside the bundle. Confirm the bundle still
runs — the host may verify the bundle hash (`DOTNET_BUNDLE_EXTRACT_BASE_DIR` behaviour varies by
version).

## 6. Verify

```sh
sn -vf app.exe                  # strong name state
ilspycmd app.exe | rg -i 'islicensed'   # confirm the edit is in the file
```

Then:

1. Launch the patched application and repeat the operation that was locked.
2. Delete the licence state — `%APPDATA%\<Vendor>`, `%LOCALAPPDATA%\<Vendor>`, the registry
   key — and start again.
3. Confirm no `FileLoadException` in the log.

## Deliverable

`app_patched.exe`, the strong-name and signature state after the edit, the patch manifest with
the IL offsets, and the verification output.
