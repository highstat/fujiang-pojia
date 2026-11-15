---
id: "win32-licence-ui-flow"
title: "Win32 licence UI flow"
domain: "windows-native"
kind: "pattern"
platforms: "windows"
arch: "x86, x86-64"
difficulty: "intermediate"
tools: "x64dbg,ScyllaHide,r2,rabin2,dumpbin,LIEF,Frida"
verified: false
updated: "2026-11-15"
summary: "Traces a native Windows licence gate from its modal dialog and WM_COMMAND handler through the registry or volume-serial check to the branch that gates the premium features."
---

## Summary

Most native Windows licence checks are not hidden in crypto. They are a modal dialog, a message
box, and a boolean that decides whether a menu entry is greyed out. The gate is a state machine
spread over four places: the dialog resource, the dialog procedure, the key source (registry,
file, or machine id), and the caller that branches on the result.

This entry gives the order of work: find the dialog, find the procedure that owns the failure
branch, find the source of the key, and patch the branch that decides. Every step names the
exact API and the exact breakpoint.

Cross-reference: [native-exception-based-control-flow](native-exception-based-control-flow.md)
for the variant where the branch is not a normal `je` but an exception dispatch, and
[pe-section-and-entry-analysis](pe-section-and-entry-analysis.md) for locating the resource
section that holds the dialog templates.

## Recognition

Concrete artefacts of a Win32 licence gate:

- A modal window that appears before or on top of the main window, with buttons such as
  `OK`, `Cancel`, `Register`, `Buy`, `Continue`, `Trial`.
- A message box with the caption `Registration`, `Licence`, `License Error`, `Evaluation`, or
  the body text `Invalid license key`, `Serial number is not registered`, `Your trial has
  expired`, `ERR_LICENSE_013`, `This copy is not registered`.
- A registry key under `HKCU\Software\<Vendor>\<Product>` holding a serial, a `Registered`
  DWORD, or a `LicenseKey` string.
- A file such as `%ProgramData%\<Vendor>\licence.dat`, `%APPDATA%\<Vendor>\license.key`,
  `%LOCALAPPDATA%\<Vendor>\settings.dat`.
- Premium menu items or toolbar buttons that are disabled until registration.
- A machine fingerprint that changes when the disk is replaced: a volume serial number from
  `GetVolumeInformationW`, plus the `MachineGuid` value under
  `HKLM\SOFTWARE\Microsoft\Cryptography`.
- An exit code, e.g. the program exits with `0x1e` or `0x2a` when the licence is missing.

## Method

Working directory for every command below: the directory that contains the target binary.

### 1. Confirm the UI is native Win32

```bash
rabin2 -i target.exe | grep -Ei 'MessageBox|DialogBox|CreateWindow|SetWindowText|EnableMenu|RegOpenKey|RegQueryValue|GetVolumeInformation'
```

The presence of `user32.dll` symbols (`MessageBoxW`, `DialogBoxIndirectParamW`,
`CreateWindowExW`, `SetWindowTextW`, `EnableWindow`, `EnableMenuItem`) plus `advapi32.dll`
registry symbols identifies the shape. Absence of these imports means the UI is drawn by a
framework (WinForms, WPF, Qt, MFC) and the native trace is not the first place to look.

### 2. Find the dialog templates in `.rsrc`

Dialog templates are resources of type `RT_DIALOG` (5), string tables `RT_STRING` (6), version
info `RT_VERSION` (16), manifests `RT_MANIFEST` (24).

```bash
# List resources with LIEF 1.0.0
python3 - <<'PY'
import lief
pe = lief.PE.parse("target.exe")
res = pe.resources_manager
if res is None:
    print("no resources")
else:
    for r in res.resources:
        print("type", r.id, "name", r.name)
        for n in r.ids:
            for lang in n.ids:
                print("   ", lang.id, hex(lang.rva), lang.size)
PY
```

```bash
# Or with the Resource Hacker-style external tools
wrestool -x --type=5 --name=100 target.exe   # icoutils, extracts RT_DIALOG
wrestool -l target.exe
```

The dialog template text in the resource holds the static labels and the control IDs. The
control ID of the "OK/Register" button is the number that reaches the dialog procedure as
`wParam` low word with `WM_COMMAND`.

### 3. Locate the dialog procedure

Two entry points create the dialog.

**`DialogBoxIndirectParamW`** (also `DialogBoxParamW`, `DialogBoxIndirectW`):

```c
INT_PTR WINAPI DialogBoxIndirectParamW(
  HINSTANCE hInstance,      // rcx / [esp+0x04]
  LPCDLGTEMPLATE lpTemplate,// rdx / [esp+0x08]
  HWND hWndParent,          // r8  / [esp+0x0c]
  DLGPROC lpDialogFunc,     // r9  / [esp+0x10]
  LPARAM lParamInit,        // [rsp+0x20] / [esp+0x14]
  LPARAM lParam);           // [rsp+0x28] / [esp+0x18]
```

Break on it and read the procedure pointer:

```
bp kernel32.dll!DialogBoxIndirectParamW
```

- x64: `r9` holds `lpDialogFunc`.
- x86: `[esp+0x10]` holds `lpDialogFunc`.

Then set the breakpoint on that address and continue. On modern Windows the export resolves to
`kernelbase.dll`, so the module name in the breakpoint may read `kernelbase.dll!DialogBoxIndirectParamW`.

**`CreateWindowExW`** with a registered class: the class is registered with `RegisterClassExW`
or `RegisterClassW`, whose `WNDCLASSEXW.lpfnWndProc` field (offset `0x18` inside the struct)
holds the window procedure. Break on `RegisterClassExW`, read the third argument (`r8` on x64,
`[esp+0x0c]` on x86), and dump the struct:

```
bp kernel32.dll!RegisterClassExW
px 80 @ r8
```

The `WNDCLASSEXW` layout: `cbSize` (4), `style` (4), `lpfnWndProc` (4), `cbClsExtra` (4),
`cbWndExtra` (4), `hInstance` (4), `hIcon` (4), `hCursor` (4), `hbrBackground` (4),
`lpszMenuName` (4), `lpszClassName` (4), `hIconSm` (4). The procedure pointer is at offset
`0x08` of the struct.

### 4. Find the failure branch by its strings

Take the message text from the dialog or the message box and search the binary for it:

```bash
r2 -q -c 'izz~Invalid license key' target.exe
```

Then take the cross-reference to the string's use site:

```bash
r2 -q -c 'axt @@ str.*Invalid*' target.exe
```

In the disassembly, the string is loaded with `lea rdx, [rip+0x...]` (x64) or
`push offset str.Invalid_license_key` (x86), immediately before a call to `MessageBoxW`. The
caller of `MessageBoxW` is the function that owns the failure branch; step back from the call
and look for the compare that selected it:

```text
   call    [MessageBoxW]
   ...
   test    eax, eax          ; 85 c0
   je      short loc_fail     ; 74 0a
```

The `je`/`jne` that follows the message box call is the branch that decides "invalid licence".

### 5. Trace the branch at runtime with x64dbg

Break on the message box and read its arguments. `MessageBoxW(HWND, LPCWSTR lpText,
LPCWSTR lpCaption, UINT uType)`:

- x64: `rcx` = hwnd, `rdx` = lpText, `r8` = lpCaption, `r9` = uType.
- x86: `[esp+0x04]`, `[esp+0x08]`, `[esp+0x0c]`, `[esp+0x10]`.

```
bp kernelbase.dll!MessageBoxW
```

On break, dump the UTF-16 strings:

```
du rdx
du r8
```

For a conditional breakpoint on the exact caption, compare the pointer with the address found
in the static dump. The x64dbg break condition field uses the expression evaluator:

```
bp kernelbase.dll!MessageBoxW "r8==0x00007ff6a1b0a1c0"
```

For x86 the equivalent is `"[esp+0x0c]==0x00401000"`. Two further tricks narrow the trace:

- `bp kernelbase.dll!MessageBoxW "0"` with a log: `bp kernelbase.dll!MessageBoxW "du rdx"`.
- Set the breakpoint on the *branch* instead: `bp <addr of the je>` and inspect `EAX`, which
  holds the return value of the licence routine.

Enable the ScyllaHide plugin before the run so that the check does not simply see the debugger:
ScyllaHide hides the debugger from `NtQueryInformationProcess`, `IsDebuggerPresent`,
`NtQuerySystemInformation` and the timing APIs. See
[windows-integrity-and-tamper-checks](windows-integrity-and-tamper-checks.md) for the exact
queries and for the runtime override that replaces them.

### 6. Find the key source

Registry read, x64 style:

```
bp kernel32.dll!RegQueryValueExW
```

On break, `rdx` is the value name (UTF-16) and the data pointer is the fifth argument
(`[rsp+0x28]` on x64, `[esp+0x10]` on x86). Dump:

```
du rdx
```

The key path arrives in `rcx` (the `HKEY` handle), so to see the path itself break on
`RegOpenKeyExW` and note the `hKey` result, or set a breakpoint on the `HKEY_CURRENT_USER`
constant read.

The two common sources:

- **Registry**: `RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Vendor\\Product", 0,
  KEY_READ | KEY_WOW64_64KEY, &hKey)` followed by `RegQueryValueExW(hKey, L"LicenseKey", ...)`.
- **File**: `CreateFileW`/`ReadFile` on a path under `%ProgramData%` or `%APPDATA%`.

Machine fingerprint, `GetVolumeInformationW`:

```
bp kernel32.dll!GetVolumeInformationW
```

`rcx` is the root path (`L"C:\\"`), and the volume serial number comes back in the 5th argument
(`[rsp+0x28]` on x64, `[esp+0x14]` on x86). A licence key derived from it looks like
`4C4F-1A2B` (the low and high 16-bit halves of the serial).

Combined with the `MachineGuid` under `HKLM\SOFTWARE\Microsoft\Cryptography`, this is the
"hardware-bound" shape: the key is only valid on the machine that generated it. Patching the
comparison is still the cheapest route.

### 7. Patch the branch

The candidates, in order of preference:

**Patch the boolean test.** A licence routine usually ends with `test eax, eax` (`85 c0`)
followed by a conditional jump. Flip the short jump:

```text
   74 0a   je  loc_locked      ->   75 0a   jne loc_locked
   85 c0                     ->   85 c0   (unchanged)
```

**Patch the call to the failure path.** Replace a call to the dialog routine with NOPs. A
near call is `e8 <rel32>`, 5 bytes:

```text
   e8 7a 1f 00 00   call sub_dialog     ->   90 90 90 90 90   nop x5
```

**Patch the licence routine's return value.** For a `BOOL` return in `eax`, write `mov eax, 1`
(`b8 01 00 00 00`) followed by `ret` (`c3`) over the function's first bytes.

Apply the patch with a script rather than by hand, so the change is reviewable:

```bash
python3 - <<'PY'
import shutil
shutil.copy("target.exe", "target.patched.exe")
with open("target.patched.exe", "r+b") as f:
    f.seek(0x1234)
    f.write(bytes.fromhex("75 0a"))
print("patched je -> jne at 0x1234")
PY
```

Any edit invalidates the PE checksum and the Authenticode signature; recompute or re-sign
before running the patched binary on a machine with signature enforcement.

### 8. Patch at runtime instead of on disk

When the file is signed, self-checking, or downloaded fresh every run, override the API in
memory with Frida 17.x:

```javascript
'use strict';

const k32 = Process.getModuleByName('kernel32.dll');

Interceptor.replace(k32.getExportByName('MessageBoxW'), new NativeCallback(function (hwnd, text, caption, type) {
  console.log('[blocked] ' + (caption ? caption.readUtf16String() : '') + ' / ' +
              (text ? text.readUtf16String() : ''));
  return 1;   // IDOK, and the dialog never appears
}, 'uint32', ['pointer', 'pointer', 'pointer', 'uint32']));
```

For a `bool IsLicensed()`-style native export, replace the function itself:

```javascript
Interceptor.replace(Module.getGlobalExportByName('IsLicensed'),
  new NativeCallback(function () { return 1; }, 'bool', []));
```

Frida 17 removed the static `Module.findExportByName`; use
`Process.getModuleByName('kernel32.dll').getExportByName('MessageBoxW')` as above, and call
`module.ensureInitialized()` before touching exports of a module that may not be loaded yet.

## Variations

- **WinForms / WPF**: the modal is `MessageBox.Show` in managed code and the gate is a managed
  boolean. See [il-licence-check-editing](../windows-dotnet/il-licence-check-editing.md).
- **MFC**: the dialog procedure is a method of a class, `afx_msg`-style handlers are found via
  the message map in `.rdata`; the command IDs are the `ID_*` resource values.
- **Delphi**: the dialog procedure is a VMT entry, and string literals are `UnicodeString`
  constants in the code section, not `.rdata`.
- **Qt**: the gate is in `qApp` code; the native trace starts at `QMessageBox::information`.
- **Console programs**: the licence gate is a `printf`/`WriteConsoleW` path and a
  `return 1` from `main`; the same branch patch applies.
- **Server-side activation**: the registry or file holds only an activation token, and the real
  decision is an HTTP response (`403` without a valid licence). The local gate is only a UI
  state; the server call has to be intercepted with the same Frida `Interceptor.replace` pattern.
- **Per-feature gating**: several independent checks, one per premium feature, each with its own
  branch. Patching the shared licence routine covers all of them; patching one `je` covers one.

## Verification

1. **Happy path.** Run the patched binary with no licence present. The dialog must not appear,
   the premium menu items must be enabled, and the exit code must be the same as the licensed
   run.

2. **Negative test, part one — the gate is really gone.** Restore the licence state the program
   uses (delete the registry value, delete the licence file, restore the original file) and run
   again. A patch that only hides the dialog but leaves the feature disabled is not a patch.

3. **Negative test, part two — the patched branch is the one that mattered.** Revert the patch
   and confirm the original behaviour returns: the message box with the exact original text
   appears, and the menu items are greyed out again. If the behaviour does not change, the
   patched branch was not the gate; keep tracing.

4. **Second run from a clean process.** Close the process, start it again, and repeat. In-memory
   patches and cached licence state must not be mistaken for a file patch.

5. **Tool consistency.** Confirm that the same branch is taken in all three views: the static
   disassembly (`r2 -q -c 'pd 20 @ 0x401234' target.patched.exe`), the debugger trace, and the
   observable UI. If the debugger disagrees with the file, the file was not saved or the
   checksum/signature blocked the load.

## Pitfalls

- **Greying out is not the check.** `EnableWindow(hWnd, FALSE)` and `EnableMenuItem(hMenu,
  MF_BYCOMMAND | MF_GRAYED)` are consequences of the decision. Disabling the greying call
  leaves the feature unreachable if the code path is still guarded.
- **Two checks, two paths.** Many programs check the licence once for the UI and again in a
  worker thread or a service. Patching the dialog path alone leaves the worker refusing.
- **The message box is not the branch.** The `MessageBoxW` call may be in a helper
  (`ShowError()`) called from several places; the compare that produced the argument is one
  level up.
- **Conditional breakpoints on strings are fragile.** x64dbg's expression evaluator compares
  memory, not wide strings, in most builds; compare the pointer value instead, or use
  `du` after an unconditional breakpoint.
- **MessageBoxW is forwarded.** The export lives in `kernelbase.dll` on current Windows; a
  breakpoint on `kernel32.dll!MessageBoxW` may not resolve until `kernel32.dll` is loaded, and
  the module name shown in the call stack is `kernelbase.dll`.
- **Anti-debug inside the dialog procedure.** A "the debugger must not be present" check right
  before the message box changes behaviour under x64dbg. ScyllaHide must be active before the
  process starts.
- **Editing the file breaks the checksum and the signature.** A patched EXE with a stale
  checksum is refused by the loader in some contexts; a patched EXE with a broken Authenticode
  signature triggers SmartScreen and UAC warnings.
- **Writing the registry under HKCU affects the wrong user.** The check runs in the user
  context of the interactive session; a value written by an elevated process under a different
  account is not seen.
- **x86 argument offsets are wrong on x64.** `[esp+0x10]` for `lpDialogFunc` is x86 only; on
  x64 the fourth argument is `r9` because the first three are passed in registers.

## References

- `MessageBoxW`: <https://learn.microsoft.com/windows/win32/api/winuser/nf-winuser-messageboxw>
- `DialogBoxIndirectParamW`:
  <https://learn.microsoft.com/windows/win32/api/winuser/nf-winuser-dialogboxindirectparamw>
- `CreateWindowExW`:
  <https://learn.microsoft.com/windows/win32/api/winuser/nf-winuser-createwindowexw>
- `RegQueryValueExW`:
  <https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-regqueryvalueexw>
- `GetVolumeInformationW`:
  <https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationw>
- Windows message codes (`WM_COMMAND`, `WM_INITDIALOG`):
  <https://learn.microsoft.com/windows/win32/winmsg/window-messages>
- x64dbg documentation: <https://help.x64dbg.com/>
- ScyllaHide: <https://github.com/x64dbg/ScyllaHide>
- Frida JavaScript API: <https://frida.re/docs/javascript-api/>
- Cross-reference: [windows-integrity-and-tamper-checks](windows-integrity-and-tamper-checks.md)
