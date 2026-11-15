---
id: "native-exception-based-control-flow"
title: "Native exception-based control flow"
domain: "windows-native"
kind: "pattern"
platforms: "windows"
arch: "x86, x86-64"
difficulty: "advanced"
tools: "x64dbg,ScyllaHide,r2,rabin2,LIEF,Frida,Ghidra"
verified: false
updated: "2026-11-15"
summary: "Explains how licence logic and anti-analysis hide inside SEH and VEH dispatch, how the debugger-versus-handler split changes the program's behaviour, and how to observe and neutralise the exception path."
---

## Summary

A structured exception handler is a branch that costs nothing to hide: the guarded code
executes an instruction that faults, and the handler decides whether to continue, skip, or
abort. Static analysis sees two unrelated pieces of code. Under a debugger the split between
"the debugger sees the exception" and "the program handles the exception" can invert the
intended logic, which is exactly how the "the debugger must not be present" pattern works.

This entry covers how to recognise exception-driven control flow, how to observe it in x64dbg
without letting the debugger steal the dispatch, and how to neutralise it: patch the handler
registration, patch the filter comparison, or force the intended handler to run.

Cross-reference: [windows-integrity-and-tamper-checks](windows-integrity-and-tamper-checks.md)
for the anti-debug queries that usually sit inside the handler.

## Recognition

Signals that the licence decision is behind an exception:

- The import table contains `AddVectoredExceptionHandler`, `SetUnhandledExceptionFilter`,
  `RtlAddFunctionTable`, `RtlDeleteFunctionTable`, `RtlLookupFunctionEntry`, or the statically
  linked MSVC helpers `__except_handler3`, `__except_handler4_common`, `__CxxFrameHandler3`,
  `__CxxFrameHandler4`.

  ```bash
  rabin2 -i target.exe | grep -Ei 'Vectored|UnhandledException|except_handler|CxxFrame|RtlAddFunctionTable|RtlDispatchException'
  ```

- The code section contains functions with no normal exit: a `jmp` into the middle of another
  function, an `int 3` (`cc`) or `ud2` (`0f 0b`) with no plausible handler, or a `div`/`idiv`
  by a value that is usually zero.

- A function that installs a handler, then deliberately faults:

  ```text
     call    [AddVectoredExceptionHandler]   ; install the filter
     xor     ecx, ecx
     div     ecx                              ; 0xf7 f1 -> divide by zero
     ; ... normally unreachable
  ```

- The `.pdata` of a PE32+ image is large and references runtime functions whose unwind codes
  point into a handler table, and the binary has `IMAGE_DLLCHARACTERISTICS_NO_SEH` (`0x0400`)
  clear.

- The program behaves differently under a debugger: the licence dialog appears under the
  debugger but not without it, or the program exits cleanly under the debugger while it fails
  when launched normally.

- `OutputDebugString`-based probes: `OutputDebugStringA` raises exception
  `0x40010006` (`DBG_PRINTEXCEPTION_C`) when a debugger is attached, and the code branches on
  whether that exception was raised.

## Method

Working directory for every command below: the directory that contains the target binary.

### 1. Map the exception machinery

x64 uses the x64 unwind tables: data directory index 3 (Exception Table) holds an array of
`RUNTIME_FUNCTION` (12 bytes each: `BeginAddress`, `EndAddress`, `UnwindData` RVAs). Each
`UNWIND_INFO` can carry a `UNWIND_FLAG_EXCEPTION_HANDLER` (0x1) or
`UNWIND_FLAG_CHAININFO` (0x4) and an exception-handler pointer, which is how a `__except`
block is wired on x64.

```bash
python3 - <<'PY'
import lief
pe = lief.PE.parse("target.exe")
for r in pe.exceptions:
    print(hex(r.begin), hex(r.end), "unwind", hex(r.unwind))
print("count", len(pe.exceptions))
PY
```

MSVC `__try/__except` on x86 compiles to a scope table plus a call to `__except_handler3`:

```text
     push    ebp
     mov     ebp, esp
     push    -1
     push    offset ___except_handler3
     push    dword ptr fs:[0]
     mov     dword ptr fs:[0], esp
     ...
     mov     eax, offset scope_table
     push    eax
     call    ___except_handler3
```

The scope table holds, per protected range, the filter expression address and the handler
address. The filter is called first; if it returns nonzero the handler runs. Break on
`__except_handler3` and the filter address is the first argument (`[esp+4]` on x86, `rcx` on
x64) — read it, set a breakpoint there, and the filter's return value is the branch.

### 2. Find the registration calls

```bash
r2 -q -c 'aaa; axt @@ sym.imp.*VectoredExceptionHandler*' target.exe
```

Set breakpoints on the registration APIs:

```
bp ntdll.dll!RtlAddVectoredExceptionHandler
bp kernel32.dll!AddVectoredExceptionHandler
bp kernel32.dll!SetUnhandledExceptionFilter
```

The `AddVectoredExceptionHandler(First, Handler)` arguments:

- x64: `rcx` = `First` (1 = prepend, 0 = append), `rdx` = `Handler`.
- x86: `[esp+4]` = `First`, `[esp+8]` = `Handler`.

`SetUnhandledExceptionFilter(Handler)` returns the previous filter. The classic anti-debug
trick is to call it twice and compare the two results: under a debugger the first call returns
the debugger's filter, so the two values differ; without a debugger the second call returns
the program's own handler. The compare is usually `test eax, eax` (`85 c0`) or `cmp eax, ecx`
(`39 c8`).

`RtlAddFunctionTable(RUNTIME_FUNCTION *FunctionTable, DWORD Length, ULONG_PTR Base)` adds
unwind information for code that is not covered by the image's own `.pdata`, and
`RtlDeleteFunctionTable` removes it. Its presence means the program builds its own unwind
table at runtime.

### 3. Observe the dispatch

The dispatch chain on x64 is:

```text
    KiUserExceptionDispatcher
      -> RtlDispatchException
        -> RtlLookupFunctionEntry        (find the frame)
        -> RtlVirtualUnwind              (walk to the handler)
        -> handler / filter
```

Break on the dispatcher:

```
bp ntdll.dll!RtlDispatchException
```

Windows user-mode code cannot replace `RtlDispatchException` (it lives in ntdll and is called
from the kernel-raised user-mode dispatcher), so the practical instrumentation point is the
handler itself and the filter.

To see the filter's decision, break on the handler address taken from the registration call and
inspect the return value:

```
bp <handler address>
```

Under x64 the filter receives the `EXCEPTION_POINTERS*` in `rcx` and returns
`EXCEPTION_CONTINUE_EXECUTION` (`0xffffffff`), `EXCEPTION_CONTINUE_SEARCH` (`0`), or
`EXCEPTION_EXECUTE_HANDLER` (`1`) in `eax`.

### 4. Configure the debugger so the program keeps control

This is the part that decides whether the trace is useful. When the debugger is configured to
break on the exception, it consumes the first-chance notification and the program's own filter
may never see the same exception the way it expects.

In x64dbg:

- `Debug → Windows Exception Handling` (or `Options → Debugging → Windows Exception Handling`).
- Untick "Break on first chance" for the exception codes the program raises
  (`EXCEPTION_INT_DIVIDE_BY_ZERO` = `0xc0000094`, `EXCEPTION_ACCESS_VIOLATION` = `0xc0000005`,
  `EXCEPTION_BREAKPOINT` = `0x80000003`, `EXCEPTION_ILLEGAL_INSTRUCTION` = `0xc000001d`).
- Keep "Second chance" breaks on for unexpected faults.

ScyllaHide does not change exception handling configuration; it only hides the debugger from
the queries listed in
[windows-integrity-and-tamper-checks](windows-integrity-and-tamper-checks.md). Use both: the
handler usually calls `NtQueryInformationProcess` or `IsDebuggerPresent`, and the debugger
configuration decides who sees the exception.

The net effect to aim for: the program raises the exception, the program's own filter returns
`EXCEPTION_CONTINUE_EXECUTION` (or `EXCEPTION_EXECUTE_HANDLER`), and execution resumes at the
faulting instruction with the handler's context restored. That is the state in which the
guarded code runs normally.

### 5. Neutralise the exception path

Three patch sites, in order of preference.

**Patch the registration.** Replace the `call AddVectoredExceptionHandler` with a stub that
returns a non-null dummy and never installs anything. A near call is `e8 <rel32>` (5 bytes);
replace it with `xor eax, eax` + `ret` (`31 c0 c3`) so the handler is never installed:

```text
   e8 44 11 00 00   call [AddVectoredExceptionHandler]   ->   31 c0 c3
```

For `SetUnhandledExceptionFilter`, the same replacement makes the program believe there is no
previous filter, which defeats the "compare the two return values" trick:

```text
   e8 88 22 00 00   call [SetUnhandledExceptionFilter]   ->   31 c0 c3
```

**Patch the filter's decision.** If the filter ends with `xor eax, eax` (`31 c0`) and `ret`
(`c3`) returning "not handled", change it to return `EXCEPTION_CONTINUE_EXECUTION`:

```text
   31 c0            xor eax, eax     ->   b8 ff ff ff ff   mov eax, 0xffffffff
   c3               ret
```

**Force the intended handler to run.** Set the handler address into the state the program
reads. If the program stores the filter pointer in a global and compares it, patch the compare
instead of the call:

```text
   39 05 00 30 40 00   cmp [rip+0x403000], eax   ->   90 90 90 90 90 90
```

At runtime, with Frida 17.x, remove the registration instead of patching the file:

```javascript
'use strict';

const k32 = Process.getModuleByName('kernel32.dll');

Interceptor.replace(k32.getExportByName('AddVectoredExceptionHandler'),
  new NativeCallback(function (first, handler) {
    console.log('[blocked] AddVectoredExceptionHandler handler=' + handler);
    return ptr(1);          // non-zero, but nothing is installed
  }, 'pointer', ['uint32', 'pointer']));

Interceptor.replace(k32.getExportByName('SetUnhandledExceptionFilter'),
  new NativeCallback(function (handler) {
    console.log('[blocked] SetUnhandledExceptionFilter handler=' + handler);
    return ptr(0);
  }, 'pointer', ['pointer']));
```

Returning `1` from `AddVectoredExceptionHandler` keeps the program's own "did the registration
succeed" logic happy while removing the handler from the chain.

For a filter that is called directly (not through the OS), hook the handler address instead:

```javascript
Interceptor.attach(ptr(handlerAddress), {
  onEnter(args) { this.ex = args[0]; },
  onLeave(retval) { retval.replace(ptr(0xffffffff)); }   // EXCEPTION_CONTINUE_EXECUTION
});
```

### 6. Neutralise the "no debugger" test inside the handler

Most handlers check for a debugger before they decide. Two options:

- Patch the check in the handler the same way as any other branch: `74 xx` to `75 xx`, or
  replace the call to `IsDebuggerPresent` (`e8 <rel32>`) with `xor eax, eax` (`31 c0`) plus NOPs
  to keep the length:

  ```text
   e8 1a 0f 00 00   call [IsDebuggerPresent]   ->   31 c0 90 90 90
  ```

- Override the API process-wide with Frida:

  ```javascript
  const k32 = Process.getModuleByName('kernel32.dll');
  Interceptor.replace(k32.getExportByName('IsDebuggerPresent'),
    new NativeCallback(function () { return 0; }, 'bool', []));
  ```

### 7. Confirm the guarded code now runs

Set a breakpoint on the code that is only reachable through the exception path. If it is never
hit, either the handler was not the one that matters, the filter returned the wrong value, or
the debugger configuration is stealing the dispatch.

## Variations

- **VEH vs SEH**: a vectored handler runs first for every exception, before the stack-based
  handler. A VEH-based licence check therefore fires even for exceptions raised inside a
  `__try` block. Patch the VEH registration, not the `__except_handler3` call.
- **Unwind-based (`RtlAddFunctionTable`)**: the program builds its own function table so that
  `RtlVirtualUnwind` can find a handler for code the image's `.pdata` does not describe. Break on
  `RtlAddFunctionTable` and read the `RUNTIME_FUNCTION` array in `rcx`; the third entry
  (`UnwindData`) points at the handler table.
- **x86 vs x64 handler model**: x86 SEH frames live on the stack and are installed by writing to
  `fs:[0]`; x64 uses unwind tables in `.pdata` and the handler is reached through the
  `UNWIND_INFO`. The x86 registration is a plain `mov dword ptr fs:[0], esp`, which is easy to
  spot in the disassembly.
- **Hardware-breakpoint / single-step traps**: `int 1` (`f1`) and `int 3` (`cc`) used as a
  control-transfer trick; the debugger intercepting them changes the flow.
- **`OutputDebugString` as a probe**: under a debugger, `OutputDebugStringA` raises
  `DBG_PRINTEXCEPTION_C` (`0x40010006`) and the code checks whether it was delivered. Replace
  `OutputDebugStringA`/`OutputDebugStringW` with a no-op at runtime to make the non-debugger
  path the only path.
- **Exception inside a JIT-compiled or generated code region**: the handler resolves the target
  by address, and the generated code is not in `.pdata`; this is the classic managed-protection
  (`.NET Reactor`, ConfuserEx anti-tamper) shape. See
  [dotnet-obfuscator-deobfuscation](../windows-dotnet/dotnet-obfuscator-deobfuscation.md).
- **ARM64**: exception handling is table-based with `BRK` (`0xd4200000`) as the trap
  instruction; the same reasoning applies with different encodings.

## Verification

1. **Establish the baseline.** Run the target twice, once with the debugger attached and
   configured to break on first chance, once with the debugger attached but with first-chance
   breaks disabled. If the behaviour differs, the exception path is load-bearing.

2. **Positive test.** After the neutralisation, the guarded code must be reached. Set a
   breakpoint on the code after the faulting instruction and confirm it hits. If it never hits,
   the filter's return value is wrong.

3. **Negative test — the debugger is not what made it work.** Detach and relaunch with the
   patched binary outside the debugger. The licence gate must behave the same as it does under
   the debugger. A patch that only holds under x64dbg is a debugger configuration, not a patch.

4. **Negative test — the handler was really bypassed.** Re-enable first-chance breaks and
   re-run: the program must not now take a different path because a handler was removed. If it
   does, the removal broke a legitimate error path and a more targeted patch (the filter's
   return value, or the compare inside the handler) is needed.

5. **Stability.** Run the patched binary at least ten times through the licence path. Exception
   control flow is timing- and address-sensitive; an unstable patch usually means the handler
   was reached through a different route than assumed.

## Pitfalls

- **"Break on first chance" changes the program's semantics.** The debugger gets first crack at
  the exception; a program that relies on its own filter sees a different world under x64dbg.
  Configure the exception handling before drawing conclusions.
- **`EXCEPTION_CONTINUE_EXECUTION` is not "continue the search".** The filter must return
  `0xffffffff` to resume at the faulting instruction. Returning `0` (`EXCEPTION_CONTINUE_SEARCH`)
  hands the exception to the next handler, which is usually the crash reporter.
- **The exception handler may be reached through a different path than the registration.**
  Static call graphs rarely show the edge, because the edge is created at runtime by the
  dispatcher.
- **Patching the registration with `xor eax, eax` breaks code that checks the return value.**
  A program that treats a null handler as "registration failed" then takes its failure path.
  Return a non-null dummy instead (`mov eax, 1`).
- **Handler addresses are per-load.** ASLR moves the image; a hard-coded handler address from
  one run is invalid in the next. Break on the registration and read the address at runtime.
- **`__except_handler3` is statically linked in most MSVC binaries**, so it does not appear in
  the import table. Search for the symbol name in the strings and in the `.text` section.
- **An exception-based check can be a red herring.** Genuine crash handling also uses SEH. The
  discriminator is whether the handler's outcome depends on licence state, not on the fault
  itself.
- **Unloading a module with an installed VEH leaves a dangling pointer.** Patching the
  registration is safer than installing a replacement handler that the program never removes.

## References

- Structured Exception Handling:
  <https://learn.microsoft.com/windows/win32/debug/structured-exception-handling>
- Vectored Exception Handlers:
  <https://learn.microsoft.com/windows/win32/debug/vectored-exception-handlers>
- `AddVectoredExceptionHandler`:
  <https://learn.microsoft.com/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler>
- `SetUnhandledExceptionFilter`:
  <https://learn.microsoft.com/windows/win32/api/errhandlingapi/nf-errhandlingapi-setunhandledexceptionfilter>
- x64 exception handling and unwind data:
  <https://learn.microsoft.com/windows/win32/debug/exception-handling-x64>
- `RtlAddFunctionTable`: <https://www.vergiliusproject.com/kernels/x64/windows-11/22h2/ntoskrnl-ex-rtladdfunctiontable>
- x64dbg exception handling settings: <https://help.x64dbg.com/en/latest/introduction/Exception-Handling.html>
- ScyllaHide: <https://github.com/x64dbg/ScyllaHide>
- Frida JavaScript API (`Interceptor`): <https://frida.re/docs/javascript-api/>
- Cross-reference: [windows-integrity-and-tamper-checks](windows-integrity-and-tamper-checks.md)
