---
id: "anti-anti-debug-tooling"
title: "Anti-anti-debug tooling"
domain: "anti-analysis"
kind: "tooling"
platforms: "windows, macos, linux, android, ios"
arch: "x86, x86-64, arm64"
difficulty: "intermediate"
tools: "ScyllaHide,Frida,x64dbg,Frida Gadget,Magisk"
verified: false
updated: "2026-11-15"
summary: "The available countermeasures against debugger detection — ScyllaHide profiles and hooks, Frida 17 Interceptor.replace, PEB field clearing, and the concealment of the injection tooling itself — with the limits of each and a first-response checklist."
---

## Summary

Anti-debug tooling exists on both sides. ScyllaHide hides the debugger from a debuggee's API
calls; Frida replaces the functions the debuggee's checks depend on. Both are incomplete, and both
are themselves detectable: ScyllaHide leaves the debugger's side effects on the process, and
Frida leaves an agent, a socket and a tracer in the target.

This entry maps the tooling landscape and its limits, gives the ScyllaHide configuration, the
Frida 17 hook pattern, the PEB-field clearing procedure, the concealment techniques for a Frida
server and Frida Gadget, and a checklist to work through when a target refuses to run under a
debugger.

Related entries: [debugger-detection-techniques](./debugger-detection-techniques.md) for the probe
catalogue that these tools answer to, [timing-based-anti-debug](./timing-based-anti-debug.md) for
the clock hooks.

## Recognition

Signs that a target has detected the instrumentation rather than the analyst:

| Sign | Source |
| --- | --- |
| The process exits within milliseconds of the injection | early probe |
| A dialog or a log line naming the tool | "debugger detected", "Frida detected" |
| `/proc/self/maps` contains `frida-agent` | Frida agent |
| `/proc/self/maps` contains `libfrida-gadget.so` | Frida Gadget |
| `/proc/self/task/*/status` shows a non-zero `TracerPid` | any tracer |
| `/proc/net/tcp` shows a listener on port `27042` | Frida server, default port |
| `/proc/self/status` shows `TracerPid` different from the pid of the injected helper | `ptrace` based injection |

Port 27042 in hex is `0x6972`, so a listener appears in `/proc/net/tcp` as a local address ending
in `:6972`.

```bash
grep -i frida /proc/self/maps
grep TracerPid /proc/self/status
grep -i ':6972' /proc/net/tcp
```

## Method

### 1. ScyllaHide

ScyllaHide is a plugin for x64dbg, IDA and Binary Ninja. It patches the debuggee's view of the
process rather than the analyst's, by hooking the API functions that report debugger state.

#### 1.1 What it covers

ScyllaHide hooks, among others:

| Hook | Covers |
| --- | --- |
| `NtQueryInformationProcess` | `ProcessDebugPort`, `ProcessDebugObjectHandle`, `ProcessDebugFlags`, `ProcessDebugStack` |
| `NtSetInformationThread` | `ThreadHideFromDebugger` |
| `NtQuerySystemInformation` | `SystemKernelDebuggerInformation` |
| `NtQueryObject` | the debug object |
| `RtlQueryProcessHeapInformation` | the heap debug flags |
| `RtlQueryProcessDebugInformation` | the debug information buffer |
| `RtlCreateQueryDebugBuffer` | the debug buffer |
| `NtClose` | closing the debug object handle |
| `IsDebuggerPresent` | the Win32 wrapper |
| `CheckRemoteDebuggerPresent` | the Win32 wrapper |
| `OutputDebugStringA` / `W` | the exception trick |
| `QueryPerformanceCounter` / `NtQueryPerformanceCounter` | timing |
| `GetTickCount` / `GetTickCount64` | timing |
| `QueryPerformanceFrequency` | timing |
| `SetUnhandledExceptionFilter` | the filter probe |
| `NtQueryInformationThread` | thread-level reports |
| `NtProtectVirtualMemory` | breakpoint detection through page permissions |

#### 1.2 Limits

ScyllaHide does not cover:

- An inlined read of `PEB->BeingDebugged` or `PEB->NtGlobalFlag`. There is no API call to hook.
- A direct read of the heap flags through `PEB->ProcessHeap`.
- A check of the debug registers (`DR0`–`DR7`) or the trap flag in `EFLAGS`.
- Timing that is measured with `rdtsc` rather than an API.
- Detection of the injection method itself (a `CreateRemoteThread`, an injected section, a
  modified thread context).

#### 1.3 Configuration

The plugin reads `ScyllaHide.ini` from its own directory. The shipped file lists every option with
its default; option names follow the `EnableHookX` convention and the file is the authority for
the installed version. The relevant sections look like this:

```ini
[Settings]
EnableDebuggingOfThisProcess=1
EnableDebuggingOfChildProcesses=0

[Plugins]
EnableHookNtQueryInformationProcess=1
EnableHookNtSetInformationThread=1
EnableHookNtQuerySystemInformation=1
EnableHookNtQueryObject=1
EnableHookRtlQueryProcessHeapInformation=1
EnableHookRtlQueryProcessDebugInformation=1
EnableHookNtClose=1
EnableHookIsDebuggerPresent=1
EnableHookCheckRemoteDebuggerPresent=1
EnableHookOutputDebugString=1
EnableHookSetUnhandledExceptionFilter=1
EnableHookQueryPerformanceCounter=1
EnableHookGetTickCount=1
EnableHookGetTickCount64=1
EnableHookQueryPerformanceFrequency=1
EnableHookNtQueryInformationThread=1
EnableHookNtProtectVirtualMemory=1

[HookedDlls]
kernel32.dll=1
ntdll.dll=1
user32.dll=1

[HookedProcesses]
```

The `EnableHook...` names and the section names vary between ScyllaHide versions; read the shipped
`ScyllaHide.ini` rather than trusting the list above.

Profiles: the plugin options dialog (`Plugins` → `ScyllaHide` → `Options` in x64dbg) exposes a
profile dropdown. The shipped profiles include `VMProtect x86` and `VMProtect x64`, plus generic
ones. A profile is a saved combination of the `EnableHook...` flags, so selecting the profile that
matches the target's protection is the fastest starting point.

```ini
; profile section for a VMProtect x64 target
[Profile_VMProtect_x64]
EnableHookNtQueryInformationProcess=1
EnableHookNtSetInformationThread=1
EnableHookNtQuerySystemInformation=1
EnableHookNtQueryObject=1
EnableHookRtlQueryProcessHeapInformation=1
EnableHookNtClose=1
EnableHookIsDebuggerPresent=1
EnableHookCheckRemoteDebuggerPresent=1
EnableHookOutputDebugString=1
EnableHookSetUnhandledExceptionFilter=1
EnableHookQueryPerformanceCounter=1
EnableHookGetTickCount=1
EnableHookGetTickCount64=1
EnableHookNtProtectVirtualMemory=1
```

#### 1.4 Clearing the PEB fields directly

The checks that ScyllaHide cannot hook read the PEB directly. Clear the fields from the debugger
before the target's check runs.

On x64dbg, the PEB is at `gs:[0x60]`. Set a breakpoint at the module entry point, then:

```
dd gs:[0x60]
db gs:[0x60]+0xbc      ; NtGlobalFlag
db gs:[0x60]+0x02      ; BeingDebugged
```

Set both to `00`. On x86 the PEB is at `fs:[0x30]`:

```
db fs:[0x30]+0x68      ; NtGlobalFlag
db fs:[0x30]+0x02      ; BeingDebugged
```

The heap flags are one level deeper: `PEB->ProcessHeap` is at `+0x18` on x86 and `+0x28` on x64,
and the heap flags are at `heap + 0x10` (`Flags`) and `heap + 0x14` (`ForceFlags`). The
`HEAP_TAIL_CHECKING_ENABLED` bit (`0x10`) in `ForceFlags` is the tell. Clearing the heap flags
requires writing through the pointer, which x64dbg can do with a dereference expression.

### 2. Frida 17 as the universal answer

Frida replaces the functions the check calls, which covers every probe that goes through the API
and works on every platform with the same pattern.

```javascript
// frida 17.x — the universal anti-anti-debug agent.
const HIDE = true;

function hookExport(moduleName, exportName, replacement, returnType, argTypes) {
    const mod = Process.getModuleByName(moduleName);
    const target = mod.getExportByName(exportName);
    Interceptor.replace(target, new NativeCallback(replacement, returnType, argTypes));
}

if (Process.platform === 'windows') {
    const kernel32 = Process.getModuleByName('kernel32.dll');
    const ntdll = Process.getModuleByName('ntdll.dll');

    hookExport('kernel32.dll', 'IsDebuggerPresent', function () { return 0; }, 'int', []);
    hookExport('kernel32.dll', 'CheckRemoteDebuggerPresent', function (h, pb) {
        if (!pb.isNull()) { pb.writeU8(0); }
        return 0;
    }, 'int', ['pointer', 'pointer']);
    hookExport('kernel32.dll', 'OutputDebugStringA', function () { return 1; }, 'int', ['pointer']);

    const origNqip = new NativeFunction(ntdll.getExportByName('NtQueryInformationProcess'),
        'uint32', ['uint32', 'uint32', 'pointer', 'uint32', 'uint32']);
    hookExport('ntdll.dll', 'NtQueryInformationProcess', function (h, cls, buf, len, retLen) {
        if (cls === 0x07 || cls === 0x1e || cls === 0x1f) {
            if (!buf.isNull() && len >= 4) { buf.writeU32(0); }
            return 0;
        }
        return origNqip(h, cls, buf, len, retLen);
    }, 'uint32', ['uint32', 'uint32', 'pointer', 'uint32', 'uint32']);

    hookExport('ntdll.dll', 'NtSetInformationThread', function (h, cls, buf, len) {
        if (cls === 0x11) { return 0xc0000001; }   // refuse ThreadHideFromDebugger
        return 0;
    }, 'uint32', ['uint32', 'uint32', 'pointer', 'uint32']);
} else if (Process.platform === 'linux') {
    hookExport('libc.so.6', 'ptrace', function () { return 0; },
        'int', ['int', 'int', 'pointer', 'pointer']);
} else if (Process.platform === 'darwin') {
    hookExport('libSystem.B.dylib', 'ptrace', function () { return 0; },
        'int', ['int', 'int', 'pointer', 'pointer']);
}
```

`Interceptor.replace` with a `NativeCallback` requires the argument types to match exactly. A
mismatched `argTypes` list shifts the arguments and corrupts the call, so check the prototype of
every function before replacing it.

Frida 17 removed the static `Module.findExportByName`. `Process.getModuleByName(name)` throws if
the module is not loaded, so call `Process.ensureInitialized()` or wait for the module to load
when the target loads it late.

### 3. The detection surface of the tooling

#### 3.1 Frida

| Artefact | Detail |
| --- | --- |
| `/proc/self/maps` | contains `frida-agent-64.so`, `frida-agent-32.so`, `frida-helper-64.so` |
| `/proc/self/task/*/status` | `TracerPid` is non-zero while the agent is attached |
| `/proc/net/tcp` | a listener on port `27042` when a server is used |
| Thread names | the injected threads are named `frida-*` |
| Memory | the strings `frida-agent`, `gum-js-loop`, `LINUX` and the agent's own symbols are in the process memory |
| Files | `/data/local/tmp/frida-server`, `/data/local/tmp/.cache/frida`, `/tmp/frida-*` |

Concealment options:

- **Rename the server binary.** Copy it to an innocuous name and delete the original:

  ```
  adb push frida-server /data/local/tmp/svchost
  adb shell "chmod 755 /data/local/tmp/svchost"
  adb shell "/data/local/tmp/svchost -l 0.0.0.0:27043 &"
  ```

  The process name in `ps` then matches the disguise. The `-l` option sets the listen address and
  port.

- **Use a non-default port.** The default 27042 is scanned for. Any other port avoids the naive
  check:

  ```
  frida -H 127.0.0.1:27043 -f com.example.app -l neutralize.js
  ```

- **Use Frida Gadget instead of a server.** Gadget is a shared library that is loaded into the
  target itself. It needs no root, no server, and no listening port when configured in script
  mode. The configuration file sits next to the library:

  ```json
  {
    "interaction": {
      "type": "script",
      "path": "frida-agent.js",
      "on_change": "reload"
    }
  }
  ```

  Place it as `lib/arm64-v8a/libfrida-gadget.config.json` in the APK's library directory, next to
  `libfrida-gadget.so`. With `interaction.type: "listen"` it opens a port instead, which is the
  mode to avoid when ports are scanned.

  The Gadget path is detectable by the library name. Rename the library and update the loader
  accordingly, or use a loader that maps it under a different name.

- **Rename the agent library.** The agent is loaded as `frida-agent-<arch>.so` into the target's
  memory. On a rooted device the file can be replaced, but the mapping still shows the name. The
  reliable concealment is to remove the detection rather than the agent.

#### 3.2 iOS

On iOS the server connects through the `usbmuxd` daemon, which proxies the USB tunnel. A target
can look for the tunnelled connection, for the `com.apple.mobile.dt.remote` service, or for the
presence of `frida-server` in the process list.

Concealment:

- Use `frida-gadget` embedded in the IPA rather than `frida-server`. The Gadget is loaded by the
  target itself and leaves no server process.
- On a jailbroken device, rename the server binary and use a non-default port.
- On a non-jailbroken device, Gadget plus `frida-compile` is the only route.

#### 3.3 Android

- **Magisk.** MagiskHide was removed in Magisk 24.0. The successor is the Zygisk denylist:
  enable Zygisk, then add the target's package to the denylist so the denylist is not visible to
  it. The setting is `Settings` → `Zygisk` → `Configure denylist`, or from the command line:

  ```
  magisk --denylist add com.example.app
  ```

- **Root detection.** A rooted device is detected by the presence of `su`, `magisk`, the
  `magisk` mount points, and the denylist configuration itself. These are separate checks from
  the Frida check and need separate handling.

### 4. Hiding the debugger's own side effects

Some checks exist purely to detect that the process is being debugged, with no API involved:

| Check | Response |
| --- | --- |
| `PEB->BeingDebugged` | clear the byte, see section 1.4 |
| `PEB->NtGlobalFlag` | clear the dword |
| `PEB->ProcessHeap` flags | clear `heap + 0x14` |
| Debug registers `DR0`–`DR7` | avoid hardware breakpoints, or clear `DR7` before the check |
| `EFLAGS` trap flag | clear `TF` before the check |
| `NtQueryInformationProcess(ProcessDebugStack)` | covered by ScyllaHide |
| Thread suspend count | `NtSuspendThread` count per thread |

In x64dbg, the debug registers are visible in the `dreg` view; clear the enable bits of `DR7`
(`0x00` for no breakpoints) before the target checks them.

## Variations

- **Hooking vs patching.** A hook leaves the file unmodified, so an integrity check stays happy. A
  patch is durable but changes the file hash. Prefer hooks while mapping the checks, then decide
  per check.
- **Per-platform differences.** The Windows probe set is API-heavy and ScyllaHide covers most of
  it. On Linux and macOS the probes are few (`ptrace`, `/proc/self/status`, `sysctl`), so a
  handful of Frida hooks is enough.
- **Managed wrappers.** A .NET or JVM target reaches the native API through a P/Invoke or JNI
  layer. Hook the native function, not the managed wrapper.
- **Anti-hook detection.** A target can detect an `Interceptor.replace` by checking the function
  prologue for a jump, by timing the call, or by checking the length of the function. ScyllaHide
  avoids this by patching the target's memory rather than by detouring the code, but it is also
  detectable in principle.
- **Stalker-based hiding.** Frida's `Stalker` can rewrite the `cpuid` and `in` instructions as
  they execute, which covers the checks that no API hook can reach.
- **Checking the loader.** A target can enumerate its own loaded modules and reject unknown ones.
  On Linux and macOS the Frida agent appears in the list; on Windows it usually does not. See
  [integrity-self-checks](./integrity-self-checks.md).
- **Gadget versus server.** Gadget is harder to detect but requires repackaging the application;
  the server is easier to set up but leaves a process and a port.
- **Hardware-assisted anti-debug.** A target that reads `DR7` or checks for a `PAGE_GUARD` page
  needs a different response than an API hook.

## Verification

1. **Establish the baseline.** Run the target without any instrumentation and confirm it works.
   Without this baseline there is no way to tell a successful bypass from a target that was
   already broken.
2. **Detect the failure.** Run under the debugger and record exactly how the target fails: exit
   code, message, or a hang. The exit code identifies the check to work on.
3. **Count the hooks.** Print every hook that fires, so the probe surface is known:

   ```javascript
   // frida 17.x — count the debugger probes that fire.
   const kernel32 = Process.getModuleByName('kernel32.dll');
   const counts = {};
   ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'OutputDebugStringA'].forEach(function (name) {
       const addr = kernel32.getExportByName(name);
       counts[name] = 0;
       Interceptor.attach(addr, {
           onEnter() { counts[name]++; }
       });
   });
   setInterval(function () {
       console.log(JSON.stringify(counts));
   }, 2000);
   ```

   Expected on a neutralised target: the counters stay at zero, or at a value consistent with the
   target's normal behaviour.

4. **Verify the concealment.** From inside the target, check the artefacts that would expose the
   tooling:

   ```javascript
   // frida 17.x — self-audit of the injection surface.
   const fs = require('fs');
   const maps = fs.readFileSync('/proc/self/maps', 'utf8');
   console.log('frida in maps: ' + /frida/i.test(maps));
   console.log('TracerPid: ' + (/TracerPid:\s*(\d+)/.exec(fs.readFileSync('/proc/self/status', 'utf8')) || [])[1]);
   console.log('tcp 6972: ' + fs.readFileSync('/proc/net/tcp', 'utf8').includes('6972'));
   ```

   Expected: all three report false or zero. Any `true` is a detection surface that must be
   addressed before the target's own checks matter.

5. **Negative test.** Remove the hooks, or run the target without ScyllaHide, and confirm the
   failure returns. A target that passes both with and without the tooling was never detecting
   the debugger.

6. **Restart test.** Every launch must be protected. Encode the tooling in the launch command:

   ```
   frida -H 127.0.0.1:27043 -f com.example.app -l neutralize.js
   x64dbg -p target.exe
   ```

7. **Cross-platform check.** The same product often ships a Windows binary and an Android build
   with different protections. Verify each separately.

## Pitfalls

- **The hook is installed too late.** A target that checks in its initialiser runs before a
  script that spawns the process can attach. Use `-f` so the script is in place
  before the first instruction, or use Frida Gadget with `interaction.type: "script"`.
- **A wrong `argTypes` list.** `Interceptor.replace` does not validate the prototype. A mismatch
  shifts the arguments and corrupts the target in ways that look like a different bug.
- **Calling the replaced address.** Create the `NativeFunction` for the original before the
  `Interceptor.replace` call, and call that object from inside the replacement.
- **Frida 17 API changes.** `Module.findExportByName` and the static `Module.getExportByName` are
  gone. Use `Process.getModuleByName(...).getExportByName(...)` or
  `Module.getGlobalExportByName(...)`.
- **ScyllaHide does not hook inline PEB reads.** The most common reason a target still detects
  x64dbg despite ScyllaHide. Clear the PEB fields manually, section 1.4.
- **ScyllaHide version drift.** The `EnableHook...` names and the ini sections change between
  versions. Read the shipped `ScyllaHide.ini`; do not copy a configuration from a write-up.
- **Hooking `OutputDebugString` flips the conclusion.** The exception trick reports "debugger
  present" when the exception does *not* occur. Confirm the polarity against the target's own
  logic before assuming the hook helped.
- **The port check is trivial.** Any target can connect to `127.0.0.1:27042` and read a
  handshake. Moving to a non-default port defeats the naive scan but not a target that enumerates
  all listening sockets.
- **Renaming the binary is not enough.** The maps entry, the thread names and the agent's memory
  still say "frida". Renaming is one layer.
- **Gadget repackaging breaks the signature.** A modified APK needs re-signing, and the package
  manager refuses an APK whose signature does not match the installed one.
- **MagiskHide no longer exists.** It was removed in Magisk 24.0; the Zygisk denylist replaced it.
- **Freezing the clock breaks other logic.** See
  [timing-based-anti-debug](./timing-based-anti-debug.md) for the side effects.
- **Anti-debug and integrity are independent.** A target can pass the debugger checks and still
  detect the byte patch. Handle both.
- **Over-hooking causes false positives.** Replacing a function that the target also uses for
  legitimate purposes introduces behaviour changes that look like analysis errors.

## References

- ScyllaHide — https://github.com/x64dbg/ScyllaHide
- x64dbg — https://x64dbg.com/
- Frida 17 release notes — https://frida.re/news
- Frida JavaScript API (17.x) — https://frida.re/docs/javascript-api/
- Frida Gadget configuration — https://frida.re/docs/gadget/
- Frida `Interceptor` — https://frida.re/docs/javascript-api/#interceptor
- Magisk and the Zygisk denylist — https://github.com/topjohnwu/Magisk
- `objection` (Gadget embedding for APK) — https://github.com/sensepost/objection
- `process_vm_readv` and `/proc/<pid>/maps` — https://man7.org/linux/man-pages/man5/proc_pid_maps.5.html
- `ptrace(2)` — https://man7.org/linux/man-pages/man2/ptrace.2.html
- Windows `PEB` layout and `NtGlobalFlag` — https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-ntqueryinformationprocess
- `usbmuxd` — https://github.com/libimobiledevice/usbmuxd
