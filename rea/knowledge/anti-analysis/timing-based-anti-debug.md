---
id: "timing-based-anti-debug"
title: "Timing-based anti-debug"
domain: "anti-analysis"
kind: "technique"
platforms: "windows, macos, linux, android, ios"
arch: "x86, x86-64, arm64"
difficulty: "intermediate"
tools: "Frida,x64dbg,radare2,Ghidra"
verified: false
updated: "2026-11-15"
summary: "How elapsed-time checks detect a debugger, how to observe the two timestamps and the threshold, and how to neutralise the measurement by freezing the clock source or patching the compare."
---

## Summary

A timing probe measures how long a piece of code takes and treats a long measurement as evidence
of a debugger. The pattern is always the same: read the clock, run the code, read the clock again,
subtract, compare against a hardcoded threshold. The threshold is the whole check.

This entry gives the clock sources on each platform, the threshold pattern with the exact
instructions to look for, the `cpuid` serialisation trick that makes `rdtsc` trustworthy, the
procedure to observe the measurement live, and three ways to neutralise it: patch the threshold
constant, patch the comparison, or freeze the clock API with a Frida 17 `Interceptor.replace`.

Reach for it when a target behaves correctly until a breakpoint is set, or when the licence dialog
appears only after the user clicks through a slow code path.

Related entries: [debugger-detection-techniques](./debugger-detection-techniques.md) for the wider
probe catalogue, [anti-anti-debug-tooling](./anti-anti-debug-tooling.md) for ScyllaHide's timing
hooks and Frida concealment.

## Recognition

Clock API imports:

| Platform | API | Unit | Notes |
| --- | --- | --- | --- |
| Windows | `GetTickCount` | ms | 32-bit, wraps every 49.7 days |
| Windows | `GetTickCount64` | ms | 64-bit |
| Windows | `QueryPerformanceCounter` | ticks | 100 ns nominal, frequency from `QueryPerformanceFrequency` |
| Windows | `QueryPerformanceFrequency` | — | divisor for the counter |
| Windows | `timeGetTime` | ms | `winmm.dll` |
| Linux | `clock_gettime(CLOCK_MONOTONIC)` | ns | `CLOCK_MONOTONIC` = `1` |
| Linux | `clock_gettime(CLOCK_MONOTONIC_RAW)` | ns | `CLOCK_MONOTONIC_RAW` = `4` |
| Linux | `gettimeofday` | µs | subject to NTP steps |
| macOS | `mach_absolute_time` | ticks | scale from `mach_timebase_info` |
| macOS | `mach_continuous_time` | ns | counts sleep, unlike `mach_absolute_time` |
| macOS | `clock_gettime(CLOCK_UPTIME_RAW)` | ns | `CLOCK_UPTIME_RAW` = `12` |
| Android | `System.nanoTime()` | ns | Java, `libart` |
| Android | `SystemClock.uptimeMillis()` | ms | Java, `SystemClock` |
| Android | `clock_gettime` | ns | native layer |

Detect the imports and the `rdtsc` opcode:

```
rabin2 -i target.exe | grep -Ei 'GetTickCount|QueryPerformance|timeGetTime|clock_gettime|gettimeofday|mach_absolute_time|mach_continuous_time'
rabin2 -d target.exe | grep -i 'rdtsc'
```

`rdtsc` is `0f 31` on x86 and x64. On arm64 the system register read is `mrs x0, cntvct_el0`
(`d53b40a0`) for a virtual counter, or `cntpct_el0` (`d53b40a1`) for a physical counter.

The threshold pattern. The two clock reads and the compare are usually within one function:

```
; x64, QueryPerformanceCounter variant
ff 15 xx xx xx xx     call qword [rip + ...]   ; QueryPerformanceCounter -> t0
48 89 c5              mov  rbp, rax            ; save t0
...                                     ; measured block
ff 15 xx xx xx xx     call qword [rip + ...]   ; QueryPerformanceCounter -> t1
48 2b c5              sub  rax, rbp           ; delta = t1 - t0
48 3d xx xx xx xx     cmp  rax, 0x100000       ; threshold
77 xx                 ja   <debugger detected>
```

`GetTickCount` variant, 32-bit:

```
ff 15 xx xx xx xx     call dword [rip + ...]   ; GetTickCount -> t0
89 c5                 mov  ebp, eax
...
ff 15 xx xx xx xx     call dword [rip + ...]   ; GetTickCount -> t1
29 c5                 sub  ebp, eax            ; delta = t0 - t1 (note the direction)
81 f9 xx xx xx xx    cmp  ecx, 0x1000
```

`rdtsc` variant:

```
0f 31                 rdtsc
48 c1 e2 20           shl  rdx, 32
48 0f 0b c0           or   rax, rdx            ; t0 as 64-bit
48 89 c5              mov  rbp, rax
...
0f 31                 rdtsc
48 c1 e2 20           shl  rdx, 32
48 0f 0b c0           or   rax, rdx            ; t1
48 2b c5              sub  rax, rbp
48 3d xx xx xx xx     cmp  rax, <threshold>
```

A large immediate in a `cmp` that follows a clock call is the signature. In radare2:

```
r2 -q -c 'aaa; axt @ sym.imp.QueryPerformanceCounter' target.exe
r2 -q -c 'aaa; pdf @ sym.imp.GetTickCount' target.exe
```

Threshold values seen in the wild: `0x100000` (1 048 576 QPC ticks ≈ 100 ms), `0x1000` (4096
ticks ≈ 0.4 ms), `1000` (1 second in `GetTickCount` milliseconds), `0xFFFFFF` and `0x2710`
(10 000).

## Method

### 1. Locate the two clock reads

Instrument the clock API rather than hunting for the compare. The caller of the clock function is
the measured region.

```javascript
// frida 17.x — log every clock read and the caller.
const kernel32 = Process.getModuleByName('kernel32.dll');
const qpc = kernel32.getExportByName('QueryPerformanceCounter');
const tick = kernel32.getExportByName('GetTickCount');

Interceptor.attach(qpc, {
    onEnter() { console.log('QPC from ' + this.returnAddress); },
    onLeave(rv) { console.log('  t = ' + rv); }
});

Interceptor.attach(tick, {
    onEnter() { console.log('GetTickCount from ' + this.returnAddress); },
    onLeave(rv) { console.log('  t = ' + rv); }
});
```

Two reads from the same caller address mean the timing check. Note the caller address — the
threshold constant is in the same function.

### 2. Read the threshold and the comparison

In x64dbg, break on the second clock call and step to the `cmp`:

```
bp kernel32!QueryPerformanceCounter
```

After the second hit, single-step until the `cmp`/`sub` sequence. Note the immediate operand of
the `cmp` — that is the threshold.

In Ghidra, use the decompiler on the caller function; the threshold appears as a constant in the
branch condition.

### 3. Measure the real delta

The threshold is meaningless without the observed delta. Compute it:

```javascript
// frida 17.x — print the delta and the threshold neighbourhood.
const kernel32 = Process.getModuleByName('kernel32.dll');
const qpc = kernel32.getExportByName('QueryPerformanceCounter');
const freq = new NativeFunction(kernel32.getExportByName('QueryPerformanceFrequency'), 'uint64', [])();

let last = null;
Interceptor.attach(qpc, {
    onLeave(rv) {
        if (last !== null) {
            const delta = rv.sub(last);
            console.log('delta = ' + delta + ' ticks = ' + (delta.toNumber() * 1e7 / freq.toNumber()).toFixed(3) + ' ms');
        }
        last = rv;
    }
});
```

Expected output on a target measured under a debugger with a breakpoint inside the region:
`delta = 8123456 ticks = 812.346 ms`. On an undebugged run the same region yields a delta in the
single-digit millisecond range. The gap between the two is the detection margin.

### 4. Neutralise

#### 4.1 Freeze the clock with Frida (recommended)

Freezing makes every delta zero, which is below any sane threshold. Keep the counter monotonic so
code that checks for "time went backwards" does not trip.

```javascript
// frida 17.x — freeze QueryPerformanceCounter so every measured delta is 1 tick.
const kernel32 = Process.getModuleByName('kernel32.dll');
const qpcAddr = kernel32.getExportByName('QueryPerformanceCounter');

// QPC is a 64-bit little-endian value written into the caller's buffer.
const slot = Memory.alloc(8);
let counter = 0x1000;

function writeU64LE(dst, value) {
    const buf = new Uint8Array(8);
    let v = value;
    for (let i = 0; i < 8; i++) {
        buf[i] = v & 0xff;
        v = Math.floor(v / 256);
    }
    dst.writeByteArray(buf);
}

Interceptor.replace(qpcAddr, new NativeCallback(function (lpPerformanceCount) {
    counter += 1;                       // monotonic, delta of exactly 1 tick per read
    writeU64LE(slot, counter);
    if (!lpPerformanceCount.isNull()) {
        lpPerformanceCount.writeByteArray(slot.readByteArray(8));
    }
    return 1;
}, 'int', ['pointer']));
```

`GetTickCount` and `GetTickCount64` freeze the same way, returning a fixed 64-bit value:

```javascript
// frida 17.x — freeze GetTickCount64 and GetTickCount.
const kernel32 = Process.getModuleByName('kernel32.dll');

Interceptor.replace(kernel32.getExportByName('GetTickCount64'),
    new NativeCallback(function () { return 0x1122334455667788; }, 'uint64', []));

Interceptor.replace(kernel32.getExportByName('GetTickCount'),
    new NativeCallback(function () { return 0x55667788; }, 'uint32', []));
```

macOS and Linux:

```javascript
// frida 17.x — macOS: freeze mach_absolute_time and mach_continuous_time.
const libSystem = Process.getModuleByName('libSystem.B.dylib');
let macCounter = 0;

Interceptor.replace(libSystem.getExportByName('mach_absolute_time'),
    new NativeCallback(function () { macCounter += 1000; return macCounter; }, 'uint64', []));

Interceptor.replace(libSystem.getExportByName('mach_continuous_time'),
    new NativeCallback(function () { macCounter += 1000; return macCounter; }, 'uint64', []));

// frida 17.x — Linux: freeze clock_gettime with CLOCK_MONOTONIC (1) and CLOCK_MONOTONIC_RAW (4).
const libc = Process.getModuleByName('libc.so.6');
const origClockGettime = new NativeFunction(libc.getExportByName('clock_gettime'),
    'int', ['int', 'pointer', 'pointer']);

const tsBuf = Memory.alloc(16);
Interceptor.replace(libc.getExportByName('clock_gettime'),
    new NativeCallback(function (clockId, tp) {
        if (clockId === 1 || clockId === 4) {
            writeU64LE(tsBuf.add(0), 1000000000);   // tv_sec
            writeU64LE(tsBuf.add(8), 0);            // tv_nsec
            tp.writeByteArray(tsBuf.readByteArray(16));
            return 0;
        }
        return origClockGettime(clockId, tp);
    }, 'int', ['int', 'pointer', 'pointer']));
```

#### 4.2 Patch the threshold constant

The smallest reversible change. Find the `cmp`/`sub` immediate and lower it so any plausible delta
passes.

```
; x64: cmp rax, 0x100000
48 3d 00 00 10 00    ->    48 3d ff ff ff 7f
```

```
; x86: cmp eax, 0x1000
81 f8 00 10 00 00    ->    81 f8 ff ff ff 7f
```

Keep the original bytes. The threshold lives inside the file, so a self-integrity check will notice
the change (see [integrity-self-checks](./integrity-self-checks.md)).

#### 4.3 Patch the comparison

Neutralise the branch so the measurement never matters.

```
; x64: cmp rax, imm32 ; ja rel32
48 3d 00 00 10 00    77 xx             ->    48 3d 00 00 10 00    90 90
```

```
; x86: cmp eax, imm32 ; ja rel32
81 f8 00 10 00 00    77 xx             ->    81 f8 00 10 00 00    90 90
```

Replace the conditional jump with NOPs, or invert it (`74`↔`75`, `0f 84`↔`0f 85`) depending on
which side is the "debugger detected" path. For a `sub`/`cmp` sequence, a single-byte patch of the
`ja` opcode to `90` (NOP) keeps the flags computation intact.

#### 4.4 Neutralise `rdtsc`

`rdtsc` is two bytes (`0f 31`), so it can be replaced in place with an equally long instruction
that returns a constant.

```
; 0f 31  rdtsc  ->  31 c0  xor eax, eax
```

```
; x64, 3-byte variant that clears the high half too:
0f 31 0f 31  ->  31 c0 31 d2
```

`31 c0` (`xor eax, eax`) and `31 d2` (`xor edx, edx`) give a zero timestamp, so every delta is
zero. This patch is inline and unaffected by API hooks.

### 5. The `cpuid` serialisation trick

`rdtsc` is not a serialising instruction: on an out-of-order core, the read can execute early and
report a timestamp from before the preceding instructions. Compilers therefore insert a serialising
instruction before `rdtsc` when the result must be trustworthy.

The canonical serialiser is `cpuid`:

```
0f a2                 cpuid
0f 31                 rdtsc
```

`cpuid` drains the pipeline and its side effects are globally visible, so the following `rdtsc`
cannot have executed early. `cpuid` also clobbers `eax`, `ebx`, `ecx` and `edx`, so the compiler
saves them around it.

Two consequences for the analysis:

- A target that measures time with `rdtsc` and also wants a trustworthy value inserts `cpuid`
  before each read. Finding `0f a2` immediately before `0f 31` tells you the measurement is
  deliberate rather than incidental.
- `cpuid` is itself a hypervisor-detection vector, because the hypervisor intercepts it. See
  [vm-and-emulator-detection](./vm-and-emulator-detection.md).

Frida cannot hook `rdtsc` through the API surface. Use the byte patch in 4.4, or replace the
*enclosing function* with `Interceptor.replace` and reimplement it without the measurement.

### 6. How a breakpoint inflates the measurement

Setting a software breakpoint writes an `int3` (`cc`) into the code byte. Every hit traps into the
debugger, saves the full register context, and the debugger decides whether to single-step the
original instruction and restore the byte. The cost is tens to hundreds of microseconds per hit on
a modern debugger, and far more when the debugger is stepping slowly or when the trap causes the
OS to schedule out the thread.

Two practical effects:

- A breakpoint *inside* the measured region inflates the delta by the trap cost. A breakpoint
  *outside* the region does not.
- Hardware breakpoints and debug registers are much cheaper, but a target that reads `DR7` or
  checks the trap flag in `EFLAGS` after the measurement detects them.

The same effect applies to a single-step: the check measures the debugger, not the code.

## Variations

- **Per-context clock.** A GUI application measuring its own message loop measures the wall time
  between user actions. Debugging makes the loop slow for the same reason a breakpoint does.
- **Anti-sleep check.** The inverse form measures how long a `Sleep(100)` call took. A debugger
  that patches `Sleep` to return immediately is detected. Patch `Sleep` to sleep the full duration
  instead of removing it.
- **Instruction-count timing.** `GetTickCount` around a loop that runs N iterations measures the
  loop, and the check detects an emulator that fast-forwards it. The same freeze hooks apply.
- **`CLOCK_MONOTONIC` versus `CLOCK_REALTIME`.** `CLOCK_REALTIME` (`0`) can jump backwards on an
  NTP step, which a paranoid target treats as tampering. `CLOCK_MONOTONIC` (`1`) does not.
- **Android ART.** `System.nanoTime()` maps to `art::System::NanoTime()` in `libart.so`. Hook the
  ART symbol, or hook the Java method with the Frida Java bridge:

  ```javascript
  // frida 17.x — Android: make System.nanoTime() return a constant.
  Java.perform(function () {
      const System = Java.use('java.lang.System');
      System.nanoTime.implementation = function () {
          return Java.use('long').valueOf(1000000);
      };
  });
  ```

- **iOS `mach_absolute_time` scale.** `mach_absolute_time` returns ticks, not nanoseconds. The
  conversion uses `mach_timebase_info`. A target that compares raw ticks against a nanosecond
  threshold has a scaled threshold; read the threshold, not the assumed unit.
- **Hybrid checks.** A target that measures time *and* checks the PEB has two gates. Neutralising
  only the timing leaves the PEB gate.
- **Virtualised time.** A VM's clock is subject to host scheduling. Under CPU contention a
  legitimate run can exceed the threshold, producing false positives. Treat a marginal delta as
  inconclusive.

## Verification

1. **Baseline without a debugger.** Run the instrumented target normally and record the delta.
   Expected: a small, stable value in the millisecond range that does not grow with runtime.
2. **Positive detection.** Set a breakpoint inside the measured region and re-run. Expected: the
   delta jumps by at least the trap cost, typically two to three orders of magnitude above the
   baseline. The target now takes the "debugger detected" branch.
3. **Neutralisation proof.** Apply the freeze hook and re-run with the breakpoint still set.
   Expected output: `delta = 1 ticks = 0.000 ms` on every measurement, and the target runs its
   normal path.
4. **Negative test.** Remove the hook and confirm the target is detected again. Without this step a
   coincidental pass looks like a successful bypass.
5. **Threshold sanity.** Compare the patched threshold against the observed baseline. A threshold
   below the baseline is a broken patch — the target now fails on a clean machine.
6. **Clock monotonicity.** Confirm the replacement never returns a smaller value than the previous
   one. A decreasing clock trips a different check (see the anti-sleep variant).
7. **Multiple sites.** Confirm the hook fired for every clock call site. Count the hook's `onEnter`
   calls and compare with the number of clock call sites found in the binary. A missed site is a
   missed check.

## Pitfalls

- **Unit confusion.** `QueryPerformanceCounter` counts ticks, not nanoseconds; `mach_absolute_time`
  counts scaled ticks; `GetTickCount` counts milliseconds. Comparing a raw counter against a
  nanosecond threshold makes the check always pass or always fail, and hides the real intent.
- **Resolution.** `GetTickCount` advances every 10 to 16 ms. A threshold below 20 ms cannot be
  measured with it reliably, so the target uses it only for coarse, long regions. Two reads of a
  fast region return the same value and the delta is 0 — the check then depends on a different
  signal.
- **Threshold too low.** A threshold of a few hundred nanoseconds flags any machine under load.
  Expect false positives on a busy host and on a VM with a contended scheduler.
- **Freezing the clock breaks other logic.** Licence timers, session timeouts, retry backoff and
  animation code all read the same clock. A frozen clock can hang a target in a retry loop or make
  a timeout never fire. Freeze only the specific function the check uses, or only during the
  measured region.
- **Patching `rdtsc` to `xor eax, eax` changes the high half only in the x64 build.** In 64-bit
  code `rdtsc` writes `edx:eax`; zeroing only `eax` leaves the upper 32 bits of `rax` unchanged.
  Use the two-instruction form `31 c0 31 d2` and confirm the surrounding code does not depend on
  `edx`.
- **Out-of-order execution.** A target that reads `rdtsc` without a serialiser may be measuring
  noise rather than the debugger. Do not chase a false positive: verify that the two reads are
  separated by real work.
- **The breakpoint is on the wrong side.** A breakpoint in the setup code before the first clock
  read does not inflate the measured delta. Move it inside the region.
- **Debugger slows the whole process.** Beyond the explicit check, a debugger reduces the
  application's throughput, which can trip independent watchdog logic.
- **`QueryPerformanceFrequency` is not constant across machines.** A threshold expressed in ticks
  derived from a frequency assumption breaks on hardware with a different frequency. Read the
  frequency from the target rather than assuming 10 MHz.

## References

- `QueryPerformanceCounter` — https://learn.microsoft.com/en-us/windows/win32/api/profileapi/nf-profileapi-queryperformancecounter
- `QueryPerformanceFrequency` — https://learn.microsoft.com/en-us/windows/win32/api/profileapi/nf-profileapi-queryperformancefrequency
- `GetTickCount` — https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-gettickcount
- `GetTickCount64` — https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-gettickcount64
- `clock_gettime(2)` — https://man7.org/linux/man-pages/man2/clock_gettime.2.html
- `mach_absolute_time` — https://developer.apple.com/documentation/mach/mach_absolute_time
- `System.nanoTime()` — https://developer.android.com/reference/java/lang/System#nanoTime()
- `SystemClock.uptimeMillis()` — https://developer.android.com/reference/android/os/SystemClock#uptimeMillis()
- Intel `RDTSC` and serialising instructions — https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
- Frida JavaScript API (17.x) — https://frida.re/docs/javascript-api/
- ScyllaHide timing hooks — https://github.com/x64dbg/ScyllaHide
- `cpuid` instruction and serialisation semantics — https://wiki.osdev.org/CPUID
