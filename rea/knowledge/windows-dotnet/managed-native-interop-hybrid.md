---
id: "managed-native-interop-hybrid"
title: "Managed and native interop hybrid"
domain: "windows-dotnet"
kind: "pattern"
platforms: "windows"
arch: "x86, x86-64, arm64"
difficulty: "intermediate"
tools: "dnSpyEx,ILSpy,rabin2,r2,LIEF,Ghidra,Frida,dumpbin"
verified: false
updated: "2026-11-15"
summary: "Handles the .NET applications that delegate the licence decision to native code, covering the DllImport declaration, the native export it resolves to, and the two patching routes with a managed stub example."
---

## Summary

A .NET application that calls into a native DLL for its licence decision is a common shape:
the managed code holds the UI and the state, and a small native helper performs the actual
verification. The helper is usually harder to inspect than the managed code, which is why it is
there in the first place.

Two patching routes exist and they are not equivalent. Patching the **native** side leaves the
managed assembly's strong name intact, so the application still loads and no re-signing is
needed. Patching the **managed** side removes the P/Invoke but requires re-signing a strong-named
assembly.

Cross-reference: [pe-section-and-entry-analysis](../windows-native/pe-section-and-entry-analysis.md)
for the native PE analysis, and [il-licence-check-editing](il-licence-check-editing.md) for the
managed-side IL edits.

## Recognition

Traces of an interop licence decision:

- The decompiled C# contains a declaration like:

  ```csharp
  [DllImport("licensing.dll", EntryPoint = "ValidateLicense", CharSet = CharSet.Unicode)]
  private static extern int ValidateLicenseNative(string productKey, [MarshalAs(UnmanagedType.LPWStr)] string machineId);
  ```

- A `Marshal` block: `Marshal.PtrToStringUni`, `Marshal.Copy`, `Marshal.AllocHGlobal`,
  `Marshal.GetDelegateForFunctionPointer`, `delegate* unmanaged<...>` (function pointers, .NET
  7 and later).
- `NativeLibrary.Load`, `NativeLibrary.GetExport`, `NativeLibrary.SetDllImportResolver`.
- `System.Runtime.InteropServices.SafeHandle` subclasses (`SafeHandle`, `SafeBuffer`,
  `Microsoft.Win32.SafeHandles.SafeFileHandle`) used around the native handle.
- The `CAPICOM`, `CERT*` or `WINHTTP` style "Capi" declarations, e.g.
  `System.Security.Cryptography.X509Certificates` P/Invoke into `crypt32.dll`.
- A native DLL shipped next to the executable with a name that matches the product:
  `licensing.dll`, `keycheck.dll`, `protector.dll`, `hasp_dll.dll`, `aladdin_user_*.dll`.
- The managed code holds a `bool` field that is written from the native call's return value.

## Method

Working directory for every command below: the directory that contains the target application.

### 1. Enumerate the P/Invoke surface

In the decompiled source:

```bash
ilspycmd -p -o decompiled target.exe
grep -rn "DllImport" decompiled/ | head -40
grep -rn "NativeLibrary\.\|GetDelegateForFunctionPointer\|Marshal\." decompiled/ | head -40
```

In dnSpyEx, open the assembly and search for `DllImport`, `extern`, `NativeLibrary`. Each
`[DllImport]` declaration is a method with the `pinvokeimpl` flag; the IL view shows the
target module and entry point.

Note the P/Invoke calling convention, because it decides the byte patch:

| Declaration | Convention | Native return register |
| --- | --- | --- |
| `CallingConvention.Cdecl` (the default on Windows for `DllImport`) | callee cleans the stack | `eax` on x86, `rax` on x64 |
| `CallingConvention.StdCall` (`Winapi` on Windows) | callee cleans the stack | same |
| `CallingConvention.ThisCall` / `FastCall` | register-based on x86 | `eax` |

### 2. Find the native export

Map the module name and entry point to a file and a symbol:

```bash
# The imported DLL must be next to the target
ls -la *.dll

# List the exports of the candidate DLL
rabin2 -E licensing.dll
rabin2 -i licensing.dll          # its own imports
dumpbin /exports licensing.dll
```

Match the entry point name against the export list, for example
`ValidateLicense` or `ValidateLicenseA` / `ValidateLicenseW`. The `A`/`W` suffix selects the
ANSI or the wide-character variant; both are usually exported.

Confirm the calling convention from the export's undecorated name: `__stdcall` builds on x86
decorate the symbol with a trailing `@n` (`ValidateLicense@12`), while `cdecl` exports keep the
plain name. On x64 there is a single calling convention and the decoration is absent.

```bash
rabin2 -E licensing.dll | grep -i valid
```

### 3. Locate the decision point in the native code

```bash
rabin2 -i licensing.dll | grep -Ei 'strcmp|wcscmp|memcmp|GetVolumeInformation|CryptVerify|Crypt'
```

The typical native licence routine:

1. Read the licence blob from a file or from a registry value.
2. Compare it with an embedded constant, or verify a signature with
   `CryptVerifySignature`/`BCryptVerifySignature`.
3. Return `BOOL`/`int`.

With Ghidra, open the DLL, find the export, and decompile it. With radare2:

```bash
r2 -q -c 'aaa; s sym.imp.strcmp; axt' licensing.dll
```

A small helper like this:

```text
   xor     eax, eax          ; 31 c0     return FALSE
   ret                        ; c3
```

is the shape to look for in the licence routine.

### 4. Patch the native side

The native DLL is not strong-named and usually carries no Authenticode signature, so patching
it does not disturb the managed assembly at all. Two patch shapes:

**Return a constant.** For a `BOOL` return in `eax`:

```text
   31 c0 c3            xor eax, eax ; ret        (return FALSE)
   b8 01 00 00 00 c3  mov eax, 1 ; ret           (return TRUE)
   b0 01 c3            mov al, 1 ; ret            (return TRUE, 1-byte form)
```

Find the exact prologue of the target function before overwriting it, so the write does not
destroy the stack frame that the callers expect:

```bash
r2 -q -c 'aaa; pdf @ sym.ValidateLicense' licensing.dll
```

If the function sets up a stack frame, replace the body after the prologue instead of the first
bytes, or restore the frame in the stub.

**Force the branch.** Inside the routine, the comparison is usually a `memcmp`/`strcmp`
followed by a conditional jump:

```text
   74 12   je  loc_ok      ->   75 12   jne loc_ok
```

Apply the patch with a script:

```bash
python3 - <<'PY'
import shutil
shutil.copy("licensing.dll", "licensing.patched.dll")
with open("licensing.patched.dll", "r+b") as f:
    f.seek(0x1234)
    f.write(bytes.fromhex("75 12"))
print("patched je -> jne at 0x1234")
PY
```

Then check the PE checksum of the patched DLL:

```bash
rabin2 -I licensing.patched.dll | head -20
```

The checksum in the optional header is advisory for a plain DLL, but recomputing it keeps
signing and loader paths quiet; the recomputation script is in
[windows-integrity-and-tamper-checks](../windows-native/windows-integrity-and-tamper-checks.md).

### 5. Patch the managed side instead

Replace the P/Invoke call with a managed stub. In dnSpyEx, open the calling method, switch to
the IL view, and replace the `call` to the P/Invoke stub with a constant.

For a method that returns `bool`, the whole body becomes:

```text
IL_0000: ldc.i4.1     // 17
IL_0001: ret          // 2a
```

Bytes: `17 2a`.

A managed stub in C#, used when the call site cannot be edited (for example the call is in a
generic helper):

```csharp
using System;
using System.Runtime.InteropServices;

internal static class LicenseInterop
{
    [DllImport("licensing.dll", EntryPoint = "ValidateLicense",
        CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
    private static extern int ValidateLicenseNative(
        [MarshalAs(UnmanagedType.LPWStr)] string productKey,
        [MarshalAs(UnmanagedType.LPWStr)] string machineId);

    private static bool s_forced = true;

    internal static bool ValidateLicense(string productKey, string machineId)
    {
        if (s_forced)
            return true;
        return ValidateLicenseNative(productKey, machineId) != 0;
    }
}
```

The same idea without a P/Invoke at all, using a delegate over a function pointer (.NET 7 and
later):

```csharp
[UnmanagedCallersOnly]
internal static bool ForcedLicenseResult() => true;
```

For a runtime-only override that leaves the files untouched, intercept the export with
Frida 17.x:

```javascript
'use strict';

const lic = Process.getModuleByName('licensing.dll');
const fn = lic.getExportByName('ValidateLicense');

Interceptor.replace(fn, new NativeCallback(function (keyPtr, machinePtr) {
  console.log('[blocked] ValidateLicense called');
  return 1;
}, 'int32', ['pointer', 'pointer']));
```

The native DLL may not be loaded when the script starts; load it explicitly or wait for the
module observer:

```javascript
const lic = Module.load('licensing.dll');
```

### 6. Handle the `SafeHandle` and `NativeLibrary` shapes

A modern .NET application may not use `[DllImport]` at all:

```csharp
IntPtr handle = NativeLibrary.Load("licensing.dll");
IntPtr fn = NativeLibrary.GetExport(handle, "ValidateLicense");
var delegate = Marshal.GetDelegateForFunctionPointer<ValidateLicenseFn>(fn);
```

In this case there is no P/Invoke stub in the metadata, so the "replace the stub body" patch
does not apply. Two options:

- Patch the native export (step 4), which is unchanged by the interop style.
- Redirect the load at runtime with `NativeLibrary.SetDllImportResolver`, registered before the
  assembly's first P/Invoke call:

  ```csharp
  internal static class NativeRedirect
  {
      internal static void Register()
      {
          NativeLibrary.SetDllImportResolver(typeof(NativeRedirect).Assembly, (name, asm, path) =>
          {
              if (name.Equals("licensing.dll", StringComparison.OrdinalIgnoreCase))
                  return NativeLibrary.Load("licensing.stub.dll");
              return IntPtr.Zero;
          });
      }
  }
  ```

  where `licensing.stub.dll` exports the same entry point and returns success.

A `SafeHandle` in the signature means the native side owns a resource; a stub must still
return a valid handle, because the managed code will call `ReleaseHandle` on it. The stub must
therefore export a matching `Dispose`/`Close` entry point.

### 7. NativeAOT: no IL at all

A NativeAOT application has no editable IL. The compiled binary is native, with the managed
metadata embedded as a read-only blob that the runtime does not use for execution. The licence
decision is native code.

Workflow:

```bash
rabin2 -I app.exe
rabin2 -S app.exe
rabin2 -i app.exe | grep -Ei 'license|valid|check|verify'
rabin2 -E app.exe | head -40
```

Then open the binary in Ghidra (12.2), locate the string `Invalid license key` and take the
cross-reference to the function that uses it, or import the binary into the REA workspace and
use the `inspect_binary_layout` view for the section and import inventory before switching to
the decompiler. For a managed-metadata view of the same binary, REA's
`inspect_managed_artifact` reports the embedded metadata tables.

The patch is the native one from step 4, applied to the NativeAOT binary:

```text
   b8 01 00 00 00 c3   mov eax, 1 ; ret
```

NativeAOT binaries are often signed and sometimes contain an integrity check over their own
image; see [windows-integrity-and-tamper-checks](../windows-native/windows-integrity-and-tamper-checks.md).

## Variations

- **x86 versus x64**: the return value is in `eax` on both, but the calling convention for
  arguments differs, and the decorated export names on x86 (`ValidateLicense@12`) reveal the
  convention.
- **`SetDllImportResolver` versus editing metadata**: the resolver is runtime-only and needs
  no re-signing; the metadata edit is permanent but breaks the strong name.
- **A COM component**: the licence check is behind a CLSID and an interface method; the patch
  target is the exported vtable slot in the DLL that implements the component.
- **A Java or Python wrapper**: the .NET assembly is loaded by the host through a reverse-P/Invoke
  layer; the native side is still the patch target.
- **The native DLL is signed**: patching it breaks the signature and triggers SmartScreen; the
  managed route avoids touching the signed file.
- **The native DLL is downloaded on demand**: a runtime override or a managed stub is the only
  stable route, since the file is replaced on each run.
- **Hardware-bound licences**: the native code derives the machine id from
  `GetVolumeInformationW`; the check cannot be satisfied by patching the comparison alone if
  the payload itself is encrypted per machine. The runtime override is then the cleanest path.
- **The native side calls back into managed code**: the P/Invoke is bidirectional, and the
  native side may hold the decision. Patch the native export, not the managed stub.

## Verification

1. **Positive test.** Run the patched application and confirm the licensed features are
   enabled and the licence dialog does not appear.

2. **Negative test on the native patch.** Restore the original DLL and confirm the failure
   returns: the licence dialog reappears or the application exits with the original code. If
   nothing changes, the patched function is not the one being called — check the export name
   and the `A`/`W` suffix.

3. **Negative test on the managed patch.** Restore the original assembly and confirm the
   failure returns, then confirm that the native DLL is still called (break on the export in
   x64dbg, or check the `Console` output of the Frida hook).

4. **Proof the native DLL is loaded and patched.** In x64dbg, break on the export:

   ```
   bp licensing.dll!ValidateLicense
   ```

   and confirm the patched bytes are in memory at that address:

   ```
   db licensing.dll+0x1234
   ```

   The bytes must read `b8 01 00 00 00 c3` or the flipped branch, not the original.

5. **Strong-name check for the managed route.** After editing the assembly:

   ```bat
   sn -vf target.exe
   ```

   A valid result means the assembly still loads from a strong-named host.

6. **For the Frida route.** Confirm the hook logs a call each time the licence is evaluated,
   and that the application behaves the same as the statically patched build.

## Pitfalls

- **The exported name is not the declared name.** `DllImport("licensing.dll")` with
  `EntryPoint = "Check"` and `CharSet.Unicode` may resolve to `CheckW`; with
  `ExactSpelling = false` (the default) the runtime tries `Check` first and then `CheckW`.
  Patch the symbol the runtime actually binds.
- **The calling convention mismatch corrupts the stack.** A `cdecl` native function called as
  `stdcall` (or the other way round) leaves the stack unbalanced; the crash appears far from
  the call site. Confirm the convention before patching a function that cleans the stack.
- **Patching the first bytes of a function that sets up a frame destroys the frame.** The
  callee may expect to pop arguments; a `ret` without `ret 0x0c` on x86 stdcall corrupts the
  caller's stack.
- **The native DLL may be verified by the managed side.** A checksum of `licensing.dll`
  stored in the managed assembly breaks when the native DLL is patched; look for a hash
  comparison in the decompiled source.
- **The managed route requires re-signing** a strong-named assembly; see
  [strong-name-and-authenticode](strong-name-and-authenticode.md).
- **The DLL is loaded by name, not by path.** Windows resolves the module name through the
  search order; a second copy in the working directory or in `PATH` may be loaded instead of
  the patched one. Verify which file is mapped.
- **A `SafeHandle` stub must release the handle.** Returning a non-null fake handle and
  omitting the matching release export causes a crash in `SafeHandle.Dispose`.
- **`NativeLibrary.SetDllImportResolver` can be called only once per assembly.** A second
  registration throws `InvalidOperationException`.
- **NativeAOT has no `Assembly.Load` and no runtime patching of IL.** Everything there is a
  native patch.
- **A `SafeHandle` for the module handle** (`NativeLibrary` uses an internal safe handle) is
  freed when the assembly unloads; replacing the module with a stub that has a different
  lifetime causes use-after-free.

## References

- P/Invoke documentation:
  <https://learn.microsoft.com/dotnet/standard/native-interop/pinvoke>
- `DllImportAttribute`:
  <https://learn.microsoft.com/dotnet/api/system.runtime.interopservices.dllimportattribute>
- `NativeLibrary`: <https://learn.microsoft.com/dotnet/api/system.runtime.interopservices.nativelibrary>
- `Marshal.GetDelegateForFunctionPointer`:
  <https://learn.microsoft.com/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer>
- `SafeHandle`: <https://learn.microsoft.com/dotnet/api/microsoft.win32.safehandles.safehandle>
- Function pointers in C#: <https://learn.microsoft.com/dotnet/csharp/language-reference/unsafe-code>
- NativeAOT: <https://learn.microsoft.com/dotnet/core/tools/native-aot/>
- Frida JavaScript API: <https://frida.re/docs/javascript-api/>
- Cross-reference: [pe-section-and-entry-analysis](../windows-native/pe-section-and-entry-analysis.md)
