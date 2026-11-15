---
id: "debugger-detection-techniques"
title: "Debugger detection techniques"
domain: "anti-analysis"
kind: "technique"
platforms: "windows, macos, linux, android, ios"
arch: "x86, x86-64, arm64"
difficulty: "intermediate"
tools: "x64dbg,ScyllaHide,Frida,radare2,Ghidra"
verified: false
updated: "2026-11-15"
summary: "Catalogue of the Win32, POSIX and Mach-O probes used to detect an attached debugger, with the disassembly signature of each probe and the byte-level or hook-level way to neutralise it."
---

## Summary

A debugger probe is a value the program computes that differs between "debugger attached" and
"debugger attached". The probe result is reduced to a single boolean, and that boolean drives the
decision: show the licence dialog, refuse to decrypt, exit with a code, or corrupt the payload.

This entry lists the probes in detection order of cost to the author, from the cheapest API call to
the most expensive exception or timing measurement. For each probe it gives the exact API, the
disassembly signature that identifies it in a binary (import table entry, inline PEB read, or inline
syscall stub), and the neutralisation: a byte-level patch of the decision point, a Frida 17
`Interceptor.replace` that returns a fixed value, or the ScyllaHide hook that covers it.

Reach for it when a target exits immediately under x64dbg, when a licence check succeeds only
without a debugger, or when a program behaves differently when `lldb`/`gdb` is attached.

Related entries: [timing-based-anti-debug](./timing-based-anti-debug.md) covers the clock-based
probes in detail, [anti-anti-debug-tooling](./anti-anti-debug-tooling.md) covers ScyllaHide and
Frida concealment, [integrity-self-checks](./integrity-self-checks.md) covers the image-validation
probes that run alongside debugger detection.

## Recognition

Probe imports visible in the import table. On Windows, run from the directory holding the target:

```
rabin2 -i target.exe
```

Filter for the probe set:

```
rabin2 -i target.exe | grep -Ei 'IsDebuggerPresent|CheckRemoteDebugger|NtQueryInformationProcess|NtSetInformationThread|NtQuerySystemInformation|OutputDebugString|DebugActiveProcess|SetUnhandledExceptionFilter|FindWindow|EnumWindows|GetTickCount|QueryPerformanceCounter|NtQueryObject|ZwQueryInformationProcess'
```

On ELF and Mach-O the equivalent probes are `ptrace`, `sysctl`, `task_info`, `isatty`, and
`/proc/self/status` string literals:

```
rabin2 -z target | grep -Ei 'TracerPid|/proc/self/status|PT_DENY_ATTACH|P_TRACED|SIMULATOR_'
```

The probe is frequently inlined rather than imported. Two PEB fetches cover most inlined cases:

| Architecture | Instruction | Bytes |
| --- | --- | --- |
| x86 | `mov eax, fs:[0x30]` | `64 a1 30 00 00 00` |
| x64 | `mov rax, gs:[0x60]` | `65 48 8b 04 25 60 00 00 00` |
| arm64 | `mrs x0, tpidr_el0` then `ldr x0, [x0, #0x60]` | `d53bd040` / `f9400c00` |

Direct PEB field reads that follow the fetch:

| Field | x86 PEB offset | x64 PEB offset | Meaning |
| --- | --- | --- | --- |
| `BeingDebugged` | `0x02` | `0x02` | `1` under a debugger |
| `NtGlobalFlag` | `0x68` | `0xbc` | `0x70` under a classic debugger |
| `ProcessHeap` | `0x18` | `0x28` | base for the heap flag probe |
| `Heap.Flags` | `processHeap + 0x10` | `processHeap + 0x10` | `HEAP_TAIL_CHECKING_ENABLED` |
| `Heap.ForceFlags` | `processHeap + 0x14` | `processHeap + 0x14` | `HEAP_TAIL_CHECKING_ENABLED` (0x10) |

The inline-syscall variant uses the ntdll stub instead of an import. On x64 the stub prefix is
`4c 8b d1` (`mov r10, rcx`) followed by `b8 xx xx xx xx` (`mov eax, <syscall number>`):

```
4c 8b d1 b8 50 00 00 00   mov r10, rcx ; mov eax, 0x50   (NtQueryInformationProcess)
```

Syscall numbers are build-specific. Read the number out of the ntdll stub in the same process
instead of hardcoding it.

Window-class and tool-name strings that appear in `.rdata`:

```
OllyDbg
x64dbg
x32dbg
WinDbg
IDA
Wireshark
ProcessHacker
FridaGadget
```

Runtime artefacts that give the game away even when the boolean is masked:

| Artefact | Where |
| --- | --- |
| `frida-agent-64.so`, `libfrida-gadget.so` | `/proc/self/maps`, `/proc/self/status` |
| `TracerPid:\t<n>` with `n != 0` | `/proc/self/status` |
| Listening socket on port `27042` | `/proc/net/tcp` |
| `frida-server` process | `ps -A` |

## Method

### 1. Decide whether to patch or to hook

Patching the file is durable but visible: the file hash changes, and any self-integrity check fails
(see [integrity-self-checks](./integrity-self-checks.md)). Hooking at runtime is invisible to the
file but depends on the injection mechanism surviving.

Start with a hook to locate the decision point, then decide. A hook on the probe API tells which
probe fired and how often; a breakpoint on the *consumer* of the probe tells where the boolean
lands.

### 2. Probe catalogue and neutralisation

Each entry below is `API — signature — neutralisation`.

#### 2.1 `IsDebuggerPresent`

- API: `BOOL IsDebuggerPresent(void)` in `kernel32.dll` (forwarded to `ntdll!RtlIsDebuggerPresent`).
- Signature: an import entry named `IsDebuggerPresent`, or the inlined PEB read
  `64 a1 30 00 00 00` / `65 48 8b 04 25 60 00 00 00` followed by a read of offset `0x02`.
- Typical inline x64 body: `8a 40 02` (`mov al, byte [rax+2]`) then `c3` (`ret`).
- Neutralise:
  - Byte level: overwrite the return path. `c3` → `31 c0 c3` (`xor eax, eax; ret`) makes the
    function return 0. At the call site, replace the call with `xor eax, eax` (`31 c0`).
  - Hook: Frida `Interceptor.replace` returning 0 (snippet below).

#### 2.2 `CheckRemoteDebuggerPresent`

- API: `BOOL CheckRemoteDebuggerPresent(HANDLE hProcess, BOOL *pbDebuggerPresent)` in `kernel32.dll`.
- Signature: import entry `CheckRemoteDebuggerPresent`, or the two-argument call with the second
  argument a stack slot that is tested immediately after the call.
- Neutralise: `Interceptor.replace` with `('int', ['pointer', 'pointer'])`, write 0 into the out
  pointer and return 0. At byte level, force the out parameter to 0 by writing `31 c0` over the
  post-call test.

#### 2.3 `NtQueryInformationProcess`

- API: `NtQueryInformationProcess(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG)` in `ntdll.dll`.
- Relevant classes: `ProcessDebugPort` (`0x07`), `ProcessDebugObjectHandle` (`0x1e`),
  `ProcessDebugFlags` (`0x1f`), `ProcessDebugStack` (`0x19`), `ProcessDebuggingFlags` (`0x1f`).
- Signature: import entry `NtQueryInformationProcess`, or the inline stub
  `4c 8b d1 b8 50 00 00 00` (x64). The class selector is pushed as `07 00 00 00` (DebugPort),
  `1e 00 00 00` (DebugObjectHandle) or `1f 00 00 00` (DebugFlags) right before the call.
- Result interpretation: `ProcessDebugPort` returns a non-zero port when a debugger is attached;
  `ProcessDebugFlags` returns `0` (SCDBG_CONTINUE) under a debugger; `ProcessDebugObjectHandle`
  returns a handle to the debug object.
- Neutralise: `Interceptor.replace` that forwards every class except `0x07`, `0x1e` and `0x1f`,
  and zeroes the output buffer for those classes.

#### 2.4 `NtSetInformationThread` (ThreadHideFromDebugger)

- API: `NtSetInformationThread(HANDLE, THREADINFOCLASS, PVOID, ULONG)`.
- Relevant class: `ThreadHideFromDebugger` (`0x11`).
- Signature: import entry `NtSetInformationThread`; inline stub `4c 8b d1 b8 0d 00 00 00` on
  Windows 10 x64. The class selector appears as `11 00 00 00`.
- Role: this is a *hide* primitive rather than a detect primitive. A target calls it so the thread
  is invisible to the debugger. Detect it by searching for the constant `11 00 00 00` near a call
  to `NtSetInformationThread`.
- Neutralise: make the call fail so the thread stays visible. `Interceptor.replace` returning
  `0xC0000001` (`STATUS_UNSUCCESSFUL`) makes the target treat the hide as failed, and many targets
  then abort — a good marker for a debugger-visible branch.

#### 2.5 `OutputDebugString` exception trick

- API: `BOOL OutputDebugStringA(LPCSTR)` in `kernel32.dll`.
- Mechanism: with no debugger attached, the string is processed in-process; a format string that
  contains `%s` with no matching argument dereferences garbage and raises an access violation,
  which is delivered to the target's own structured exception handler. With a debugger attached the
  `DBG_PRINTSTRING` message is consumed by the debugger first and no exception occurs.
- Signature: import entry `OutputDebugStringA` or `OutputDebugStringW`; the call is preceded by a
  push of a format string containing `%s` or `%d`, and the function is wrapped in an SEH frame
  (`push handler; push fs:[0]; mov fs:[0], esp` on x86; `.seh` in x64 unwind data).
- Detection: the target sets an SEH handler and records whether the handler ran. Handler ran means
  "no debugger".
- Neutralise:
  - The probe inverts the conclusion, so the patch target is the handler. Change the SEH handler to
    always take the "debugger present" branch, or NOP the `mov fs:[0], esp` install so the
    exception is never handled locally.
  - Hook: `Interceptor.replace` on `OutputDebugStringA` that returns 1 without raising the fault.
    That changes the exception path so the target's "handler ran" flag stays false — the opposite
    of the usual case. Adjust the expectation accordingly: on a hooked build the target sees the
    "debugger present" path.

#### 2.6 `NtQuerySystemInformation`

- API: `NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG)`.
- Relevant class: `SystemKernelDebuggerInformation` (`0x23` = 35). The returned `ULONG` is non-zero
  when a kernel debugger (KD) is attached.
- Signature: import entry `NtQuerySystemInformation`; the class constant appears as `23 00 00 00`.
- Neutralise: `Interceptor.replace` returning a zeroed 4-byte buffer for class `0x23`.

#### 2.7 `DebugActiveProcess`

- API: `BOOL DebugActiveProcess(DWORD dwProcessId)`.
- Mechanism: a process cannot debug itself. `DebugActiveProcess(GetCurrentProcessId())` succeeds
  when no debugger owns the process and fails with `ERROR_ACCESS_DENIED` (5) when one does. The
  target then calls `DebugActiveProcessStop` to undo the self-attach.
- Signature: import entries `DebugActiveProcess` and `DebugActiveProcessStop` appearing together.
- Neutralise: `Interceptor.replace` on `DebugActiveProcess` returning 0 and `ERROR_ACCESS_DENIED`
  semantics preserved — that is, return 0 and set the last error to 5 so the target concludes a
  debugger is present. Conversely, returning 1 mimics a clean machine.
  Patch level: replace the call with `xor eax, eax` and set `fs:[0x30]` last-error via
  `SetLastError(5)` stub.

#### 2.8 `SetUnhandledExceptionFilter` and the debug-object handle

- API: `ULONG_PTR SetUnhandledExceptionFilter(LONG_EXCEPTION_FILTER)`.
- Mechanism: the debugger replaces the target's unhandled exception filter with `NULL` when it
  attaches, so the function returns a `NULL` previous filter. The target sets a fresh handler and
  inspects the returned previous value.
- Signature: import entry `SetUnhandledExceptionFilter`; the returned value is tested immediately
  (`test rax, rax` / `85 c0`).
- Debug-object handle variant: `NtQueryInformationProcess(ProcessDebugObjectHandle)` returns a
  handle to the debug object. The target calls `CloseHandle` on it and checks for
  `ERROR_INVALID_HANDLE` (6). Under a debugger the handle is real and `CloseHandle` succeeds, so
  the probe inverts the conclusion.
- Neutralise: `Interceptor.replace` on `SetUnhandledExceptionFilter` that installs the handler and
  returns a non-zero sentinel (for example the handler pointer itself) so the "previous filter was
  NULL" test fails. For the handle variant, `Interceptor.replace` on `CloseHandle` that returns
  `ERROR_INVALID_HANDLE` for handles opened with `PROCESS_ALL_ACCESS` against the current process.

#### 2.9 `FindWindow` / `EnumWindows` class scans

- APIs: `FindWindowA(LPCSTR, LPCSTR)`, `FindWindowW`, `EnumWindows(BOOL (CALLBACK *)(HWND, LPARAM),
  LPARAM)`, `GetClassNameA`, `GetWindowTextA`.
- Signature: import entries `FindWindowA`/`EnumWindows`; the class names are literals in `.rdata`
  — `OllyDbg`, `x64dbg`, `x32dbg`, `WinDbg`, `IDA`, `Wireshark`, `ProcessHacker`, `Immunity
  Debugger`, `Cheat Engine`, `Fiddler`, `x64dbg`, `ProcessHacker`, `FridaGadget`.
- Neutralise:
  - Hook `FindWindowA`/`FindWindowW` to return `NULL` for the known class names and
    `EnumWindows` to never invoke the callback for those windows.
  - Byte level: replace the `call` with `xor eax, eax` (5-byte NOP `90 90 90 90 90` for a direct
    call, or `31 c0` plus a NOP when the call is a 6-byte near call `e8 xx xx xx xx` → `31 c0 90
    90 90 90`).
  - String level: patch the class-name literal to an unused string of the same length. Patching the
    literal in place keeps the code unchanged and defeats the string scan. Same length is required
    because the length is embedded in the `push` of the address.

#### 2.10 Timing probes

Covered in [timing-based-anti-debug](./timing-based-anti-debug.md). In short:
`GetTickCount`, `GetTickCount64`, `QueryPerformanceCounter`, `rdtsc`, `clock_gettime`,
`mach_absolute_time`. Neutralise by freezing the clock source with `Interceptor.replace`, or by
patching the threshold compare.

#### 2.11 Linux: `TracerPid` and `ptrace`

- Artefact: `/proc/self/status` contains a `TracerPid:` line; a non-zero value means a tracer
  (gdb, lldb, strace, `ptrace`) is attached.
- API: `ptrace(PTRACE_TRACEME, ...)` returns `-1` with `errno == EPERM` when already traced.
- Signature: string `TracerPid` in `.rodata`, or the `ptrace` import.
- Neutralise: `Interceptor.replace` on `ptrace` returning `0`; patch the `/proc/self/status` read
  by hooking `open`/`read` and rewriting the `TracerPid` value to `0`; or mount a private
  `/proc` (requires privileges).

#### 2.12 macOS: `sysctl` `P_TRACED` and `PT_DENY_ATTACH`

- API: `sysctl` with `CTL_KERN, KERN_PROC, KERN_PROC_PID, pid` fills a `struct kinfo_proc`; the
  `p_flag` field holds `P_TRACED` (`0x00000800`).
- API: `ptrace(PT_DENY_ATTACH, 0, 1, 0)` returns `-1` with `EPERM` when a debugger is attached.
- Neutralise: `Interceptor.replace` on `sysctl` that zeroes `p_flag` for the `KERN_PROC` class; or
  `Interceptor.replace` on `ptrace` returning `0`.

### 3. Frida 17 hooks

Frida 17 removed the static `Module.findExportByName`. Use the module instance.

Use the [scoped Windows helper](../../scripts/frida/bypass-anti-debug.js) instead of
redeclaring NT signatures. It preserves unrelated results, writes pointer-sized ports and
handles, writes a 32-bit 1 for ProcessDebugFlags, and leaves timing changes opt-in.
CheckRemoteDebuggerPresent reports API success separately from its BOOL out-parameter.
Changing NTSTATUS is not equivalent to changing an output flag.

Linux and macOS variants:

```javascript
// frida 17.x — Linux: hide TracerPid and pretend ptrace(PTRACE_TRACEME) succeeds.
const libc = Process.getModuleByName('libc.so.6');
Interceptor.replace(libc.getExportByName('ptrace'),
    new NativeCallback(function () { return 0; }, 'int', ['int', 'int', 'pointer', 'pointer']));

// frida 17.x — macOS: zero p_flag so P_TRACED is not visible.
const libSystem = Process.getModuleByName('libSystem.B.dylib');
Interceptor.replace(libSystem.getExportByName('sysctl'),
    new NativeCallback(function (mib, mibLen, oldp, oldlenp, newp, newlen) {
        const rc = origSysctl(mib, mibLen, oldp, oldlenp, newp, newlen);
        // struct kinfo_proc: kp_proc.p_flag sits at offset 0x10 within the struct on macOS.
        if (rc === 0 && oldp && mib[0] === 1 && mib[1] === 14) {   // CTL_KERN, KERN_PROC
            oldp.writeU32(0);
        }
        return rc;
    }, 'int', ['pointer', 'uint32', 'pointer', 'pointer', 'pointer', 'uint32']));
```

A `sysctl` replacement that zeroes the wrong offset is worse than none: confirm the layout of
`struct kinfo_proc` for the target SDK before trusting it.

### 4. Locate the decision point

The probes only feed a boolean. The patch that matters is the branch that consumes it.

In x64dbg, set a breakpoint on the *consumer*, not the probe:

1. Put a hardware breakpoint on the return address of the probe.
2. Run to the hit, note the caller.
3. Single-step to the conditional jump that tests the probe result and note the offset.

In Frida, trace the probe and print the return address of the caller:

```javascript
// frida 17.x — print who calls IsDebuggerPresent.
const kernel32 = Process.getModuleByName('kernel32.dll');
const isDebuggerPresent = kernel32.getExportByName('IsDebuggerPresent');
Interceptor.attach(isDebuggerPresent, {
    onEnter() {
        console.log('IsDebuggerPresent called from ' + this.returnAddress);
    },
    onLeave(retval) {
        console.log('IsDebuggerPresent returned ' + retval);
    }
});
```

With the caller known, patch the branch. The x64 conditional-jump opcodes to flip:

| Original | Neutralised | Meaning |
| --- | --- | --- |
| `74 xx` | `75 xx` | `JE` → `JNE` |
| `75 xx` | `74 xx` | `JNE` → `JE` |
| `0f 84 xx xx xx xx` | `0f 85 xx xx xx xx` | `JE` rel32 → `JNE` rel32 |
| `0f 85 xx xx xx xx` | `0f 84 xx xx xx xx` | `JNE` rel32 → `JE` rel32 |
| `83 f8 01` | `83 f8 00` | `cmp eax, 1` → `cmp eax, 0` |
| `85 c0` | `31 c0 90` | `test eax, eax` → `xor eax, eax; nop` |

Note the direction: the neutralising patch depends on the polarity of the test. Read the
surrounding code before applying the table.

### 5. ScyllaHide

ScyllaHide hooks the API-level probes in-process, which covers every probe in section 2.1 to 2.9
that goes through the API. It does not cover an inlined PEB read.

For x64dbg: open the plugin options (`Plugins` → `ScyllaHide` → `Options`), pick the profile that
matches the target, and enable the hook set. The shipped profiles include `VMProtect x86` and
`VMProtect x64`.

For a direct PEB read, clear the fields in the debuggee PEB from the debugger. On x64dbg:

```
dd gs:[0x60]
```

`gs:[0x60]` is the x64 PEB. Then:

```
db gs:[0x60]+0xbc      ; NtGlobalFlag
db gs:[0x60]+0x02      ; BeingDebugged
```

Set both to `00`. On x86 the PEB is at `fs:[0x30]`:

```
db fs:[0x30]+0x68
db fs:[0x30]+0x02
```

Run this from the module entry point, before the target's own check executes. Configuration and
profile details are in [anti-anti-debug-tooling](./anti-anti-debug-tooling.md).

## Variations

- **x86 versus x64 PEB offsets.** `BeingDebugged` is at `0x02` in both. `NtGlobalFlag` is `0x68` on
  x86 and `0xbc` on x64. `ProcessHeap` is `0x18` on x86 and `0x28` on x64. A patch written for one
  architecture silently reads the wrong field on the other.
- **Managed code.** A .NET or JVM target cannot read the PEB directly, so the probe is usually a
  P/Invoke or JNI call into the native runtime, or a managed anti-debug library that wraps
  `IsDebuggerPresent`. Hook the P/Invoke target rather than the managed wrapper.
- **Android.** `ApplicationInfo.FLAG_DEBUGGABLE` in the manifest is a weak signal (a debuggable
  build is not a debugger). The real signals are `Debug.isDebuggerConnected()`,
  `Debug.waitingForDebugger()`, the `/proc/self/status` `TracerPid` line, and the presence of
  `frida-server` or `re.frida.server` in `/proc`. Hook `Debug.isDebuggerConnected` with the Frida
  Java bridge to return `false`.
- **iOS.** The classic probe is `sysctl` with `P_TRACED` and `ptrace(PT_DENY_ATTACH)`. A jailbroken
  device adds `ptrace` returning `0` regardless, so the absence of a debugger is not evidence of
  integrity.
- **Runtime-only targets.** When the check lives in a downloaded or decrypted blob, only a hook
  works; there is no file to patch.
- **Self-integrity coupling.** A program that hashes its own `.text` and compares against a stored
  digest will detect the byte patch. Patch the branch and then recompute the digest, or hook the
  digest function instead.
- **Hardware watchpoints.** A debugger that uses a debug register to watch the PEB byte at
  `PEB+0x02` triggers a single-step trap that the target can detect by reading the trap flag in
  `EFLAGS`. Clear `TF` before the check.

## Verification

Prove the probe no longer fires, then prove the original behaviour is restored.

1. **Positive probe test.** With the hook set applied, run the target under the debugger and confirm
   it starts normally. A target that exits with code `1` or shows a "debugger detected" dialog
   before the patch is the negative baseline.
2. **Probe-level verification.** Instrument the probe and read the return value:

   ```javascript
   // frida 17.x — assert the probe now returns the neutral value.
   const kernel32 = Process.getModuleByName('kernel32.dll');
   Interceptor.attach(kernel32.getExportByName('IsDebuggerPresent'), {
       onLeave(retval) {
           console.log('IsDebuggerPresent -> ' + retval + ' (expected 0)');
       }
   });
   ```

   Expected output on a neutralised target: `IsDebuggerPresent -> 0 (expected 0)`.
3. **Branch-level verification.** Break on the consumer branch and confirm it is not taken. Change
   the flag in the debugger (`eflags` -> clear `ZF`/`CF` as appropriate) and confirm the target
   reacts, proving the branch is the live decision point and not a dead copy.
4. **Negative test — the check must be gone, not masked.** Remove the hook or restore the original
   bytes and confirm the target again refuses to run. If it still runs, the check was already
   bypassed by something else and the probe was not the gate.
5. **Restart test.** Restart the process completely. A hook applied in the previous session is not
   evidence; the check must be neutralised on every launch, so encode it in a launch script:

   ```
   frida -f com.example.app -l neutralize-debugger.js
   ```

6. **File-level test for a byte patch.** Recompute the PE checksum and any self-integrity digest
   after patching, re-sign where the format requires it, then launch the patched file from disk
   with no debugger attached.

## Pitfalls

- **Wrong polarity.** The tables in section 4 assume a specific branch direction. `74` → `75` in
  one place and `75` → `74` in another is the most common patch mistake. Read the consumer.
- **The probe is not the decision.** Several checks compute a boolean, then a second function
  decides what to do with it. Patching only the probe function leaves the second stage intact.
- **Multiple copies of the check.** One in the UI thread and one in a worker thread or a service.
  Hook the API and confirm zero calls remain after the patch by counting the hook's `onEnter`.
- **`OutputDebugString` inversion.** The exception trick reports "debugger present" when the
  exception does *not* occur. A hook that stops the fault flips the conclusion and the target
  takes the opposite branch. Verify the direction against the target's own logic.
- **Frida 17 API drift.** `Module.findExportByName` no longer exists and throws. Use
  `Process.getModuleByName(...).getExportByName(...)`. On iOS and macOS the module name differs
  (`libSystem.B.dylib`, `libc.so.6` on Linux, `ntdll.dll` and `kernel32.dll` on Windows).
- **Frida itself is detectable.** The agent leaves strings in `/proc/self/maps`, a socket on port
  `27042`, and a `TracerPid` entry. See [anti-anti-debug-tooling](./anti-anti-debug-tooling.md).
- **Calling the original after `Interceptor.replace`.** Create the `NativeFunction` for the
  original *before* the `Interceptor.replace` call, and call that object from inside the
  replacement. Calling the replaced address directly recurses.
- **32-bit helper processes.** A 64-bit target frequently spawns a 32-bit helper that carries its
  own copy of the check. Inject into both.
- **Checksums.** Patching a PE invalidates the Optional Header checksum and the Authenticode
  signature. Recompute or re-sign, or the loader and the target itself will reject the file.
- **Debugger presence is not the only trigger.** A suspended thread, a hardware breakpoint, a
  `PAGE_GUARD` page, or a debug register left set also changes the observable state.

## References

- `IsDebuggerPresent` — https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-isdebuggerpresent
- `CheckRemoteDebuggerPresent` — https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-checkremotedebuggerpresent
- `NtQueryInformationProcess` — https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-ntqueryinformationprocess
- `NtSetInformationThread` — https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-ntsetinformationthread
- `OutputDebugStringA` — https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-outputdebugstringa
- `DebugActiveProcess` — https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-debugactiveprocess
- `SetUnhandledExceptionFilter` — https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-setunhandledexceptionfilter
- `FindWindowA` — https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-findwindowa
- `EnumWindows` — https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-enumwindows
- Frida JavaScript API (17.x) — https://frida.re/docs/javascript-api/
- ScyllaHide — https://github.com/x64dbg/ScyllaHide
- `procfs` `TracerPid` — https://man7.org/linux/man-pages/man5/proc.5.html
- `ptrace(2)` — https://man7.org/linux/man-pages/man2/ptrace.2.html
- `sysctl(3)` and `kinfo_proc` — https://man.freebsd.org/cgi/man.cgi?query=sysctl&sektion=3
- System Informer (formerly SystemInformer), for inspecting the debug object, thread state and loaded modules — https://github.com/winsiderss/systeminformer
