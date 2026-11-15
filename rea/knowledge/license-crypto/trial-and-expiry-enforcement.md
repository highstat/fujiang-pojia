---
id: "trial-and-expiry-enforcement"
title: "Trial and expiry enforcement"
domain: "license-crypto"
kind: "technique"
platforms: "windows, macos, linux, android, ios"
arch: "x86, x86-64, arm64"
difficulty: "intermediate"
tools: "Frida, radare2, Python"
verified: false
updated: "2026-11-15"
summary: "Locate where an application stores its trial state, identify the clock-rollback defences it relies on, and neutralise the expiry decision by forcing the trial boolean, rewriting the stored start time, or freezing the clock the comparison reads."
---

## Summary

Trial enforcement is a comparison between a stored timestamp and a current timestamp, plus
the branch that follows. Three things have to be found, and only the first is obvious:

1. **Where the state lives** — a registry value, a preferences file, a SQLite row, a counter
   file. Find it by observing what the application writes on first run.
2. **How the clock is read** — wall clock (`time`, `GetSystemTime`, `System.currentTimeMillis`)
   or monotonic (`GetTickCount64`, `mach_absolute_time`, `CLOCK_BOOTTIME`). Monotonic clocks
   cannot be moved by changing the system date, so patching them is required.
3. **The decision point** — the compare and the conditional branch that produces the
   "trial valid" boolean.

The three patch strategies correspond to those three finds: force the boolean, rewrite the
stored start into the past, or freeze/shift the clock. Patching the clock is the most
general because it also defeats the monotonic-counter defence.

## Recognition

**Where trial state lives.**

| Platform | Location | Typical content |
| --- | --- | --- |
| Windows | `HKCU\Software\<Vendor>\<App>` | `FirstRun`, `InstallDate`, `TrialDays`, `LicenseKey` (REG_DWORD / REG_QWORD / REG_BINARY) |
| Windows | `%APPDATA%\<Vendor>\<App>\` | `settings.json`, `config.dat`, `app.db` |
| Windows | `%LOCALAPPDATA%\`, `%PROGRAMDATA%\` | per-user state, machine-wide state |
| macOS | `~/Library/Preferences/<bundle-id>.plist` | `NSUserDefaults` keys: `FirstRunDate`, `TrialEndDate` |
| macOS | `~/Library/Application Support/<Vendor>/<App>/` | SQLite database, JSON state |
| macOS | `~/Library/Containers/<bundle-id>/Data/Library/Preferences/` | sandboxed apps |
| Linux | `~/.config/<app>/` | `config.json`, `state.db`, `*.conf` |
| Linux | `~/.local/share/<app>/`, `~/.cache/<app>/` | activation data, caches |
| Android | `/data/data/<pkg>/shared_prefs/<name>_prefs.xml` | `first_run`, `expiry`, `license` |
| Android | `/data/data/<pkg>/databases/<name>.db` | SQLite `license` table |
| iOS | app container `Library/Preferences/<bundle-id>.plist` | `NSUserDefaults` |

**File names that give it away:** `license.dat`, `licence.bin`, `activation.dat`,
`trial.state`, `state.json`, `first_run`, `.license`, `*.reg`, `prefs.xml`.

**Strings and UI text.**

```bash
r2 -q -c 'izz~trial' target.exe
r2 -q -c 'izz~expired' target.exe
r2 -q -c 'izz~evaluation' target.exe
```

Common messages: `Your trial period has expired`, `Evaluation version`, `Please purchase a
licence`, `Expires in %d days`, `Trial expired on %s`.

**Time-related imports** — the first place to look for the clock:

```bash
rabin2 -i target.exe | grep -iE 'GetSystemTime|GetTickCount|QueryPerformance|time@|gettimeofday|clock_gettime|mach_absolute'
```

`GetTickCount64`, `QueryPerformanceCounter`, `mach_absolute_time` and `clock_gettime` with
`CLOCK_BOOTTIME` are the monotonic clocks; their presence means the application defends
against clock rollback and the wall-clock hook alone will not be enough.

## Method

### Step 1 — Capture the state the application writes

Before the application ever shows the expiry dialog, it writes its state. Diff the state
directory across two runs.

```bash
# Linux
mkdir -p /tmp/state-before /tmp/state-after
cp -a ~/.config/vendor-app/. /tmp/state-before/ 2>/dev/null
# run the application once, then:
diff -r /tmp/state-before ~/.config/vendor-app
```

```bash
# macOS
ls -la ~/Library/Preferences/ | grep -i vendor
defaults read com.vendor.app
```

```powershell
# Windows
reg query "HKCU\Software\Vendor\App" /s
Get-ChildItem "$env:APPDATA\Vendor" -Recurse | Select-Object FullName, LastWriteTime
```

The file or value whose timestamp changes on the first launch is the trial state. Its
content shows the structure.

### Step 2 — Read the structure

```bash
# JSON state
python3 -c "import json;print(json.dumps(json.load(open('$HOME/.config/vendor-app/state.json')),indent=2))"

# SQLite state
sqlite3 ~/.config/vendor-app/app.db ".tables"
sqlite3 ~/.config/vendor-app/app.db "SELECT key, value FROM settings;"
sqlite3 ~/.config/vendor-app/app.db ".schema license"
```

```bash
# macOS defaults
defaults read com.vendor.app
plutil -p ~/Library/Preferences/com.vendor.app.plist
```

```bash
# Android
adb shell su -c 'cat /data/data/com.vendor.app/shared_prefs/vendor_prefs.xml'
```

Typical structures:

```json
{ "first_run": 1654641600, "trial_days": 14, "install_id": "8f2c...", "launch_count": 3 }
```

```xml
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <long name="first_run" value="1654641600" />
    <int name="launch_count" value="3" />
</map>
```

```sql
CREATE TABLE license (id INTEGER PRIMARY KEY, key TEXT, expiry INTEGER, machine TEXT);
```

An encrypted blob (DPAPI on Windows, a keychain item on macOS) shows up as a fixed-length
opaque file; the artefact is described in
[Symmetric licence blob formats](symmetric-license-blob-formats.md).

### Step 3 — Find the decision point

Search for the failure message and cross-reference:

```bash
r2 -q -c 'aaa; axt @@ str.*' target.exe | grep -i -B3 -A3 'expired'
r2 -q -c 'aaa; s 0x140003100; pdf' target.exe
```

The compare that matters is between the current time and the stored deadline:

```asm
0x140002700  mov  rax, [rbp-0x18]           ; stored expiry (from file/registry)
0x140002704  mov  rcx, r14                 ; current time
0x140002707  cmp  rax, rcx
0x14000270a  jbe  0x140002790              ; stored <= now -> expired
0x14000270c  mov  byte [rbp-0x40], 1       ; trial_valid = true
0x140002713  jmp  0x1400027a0
```

Patch the branch so the success path is always taken:

```
0F 86 82 00 00 00   ->   90 90 90 90 90 90      ; JBE -> six NOPs
```

or invert it:

```
0F 86 82 00 00 00   ->   0F 87 82 00 00 00      ; JBE -> JA (always expired, wrong direction)
```

The correct inversion depends on the operand order; when unsure, replace the conditional
jump with NOPs rather than guessing the flag sense.

### Step 4 — Rewrite the stored start time

The least invasive patch when the state is a plain file or value.

```bash
# JSON
python3 - <<'PY'
import json, os, pathlib, time
p = pathlib.Path(os.environ["HOME"]) / ".config/vendor-app/state.json"
d = json.loads(p.read_text())
past = 1654641600          # 2022-06-08T00:00:00Z, well before any plausible install date
d["first_run"] = past
if "install_date" in d:
    d["install_date"] = past
p.write_text(json.dumps(d))
print("state rewritten:", d)
PY
```

```bash
# Windows registry
reg query "HKCU\Software\Vendor\App"
reg add "HKCU\Software\Vendor\App" /v FirstRun /t REG_DWORD /d 0x62a00000 /f
```

```bash
# SQLite
sqlite3 ~/.config/vendor-app/app.db "UPDATE settings SET value='1654641600' WHERE key='first_run';"
sqlite3 ~/.config/vendor-app/app.db "UPDATE license SET expiry=4102444800;"
```

```bash
# macOS defaults (kill cfprefsd so the change is not cached)
defaults write com.vendor.app FirstRunDate -int 1654641600
killall cfprefsd
```

For an Android `shared_prefs` XML:

```bash
adb shell su -c "sed -i 's/value=\"1755[0-9]*\"/value=\"1654641600\"/' /data/data/com.vendor.app/shared_prefs/vendor_prefs.xml"
adb shell su -c "am force-stop com.vendor.app"
```

### Step 5 — Neutralise the expiry comparison

When the state is encrypted or server-supplied, patch the comparison instead. Locate it by
finding the two values being compared and the branch that follows:

```bash
r2 -q -c 'aaa; pdf @ fcn.00401200' target.exe
```

Look for the sequence `mov reg, [stored]` … `cmp` … `jcc`. Two common encodings:

```asm
; unsigned compare of two timestamps
48 39 C8              cmp rax, rcx
0F 82 6A 00 00 00     jb  expired
```

```asm
; signed compare after subtracting the trial length
48 83 E8 00 00 00 78  sub rax, 0x78000000     ; 120 days in seconds
48 39 C8              cmp rax, rcx
7C 40                 jl  expired
```

Patch either to `NOP` the branch (six NOPs for the rel32 form, two for the rel8 form) or to
force the "valid" flag byte to 1:

```
48 85 C0   ->   B0 01 90      ; test rax,rax  ->  mov al,1 ; nop
```

### Step 6 — Handle the monotonic clock defence

An application that stores `GetTickCount64()` at install and compares elapsed monotonic time
against the trial length ignores the wall clock entirely. Patching the wall clock has no
effect. Three ways forward.

**6a. Patch the monotonic source.** `GetTickCount64` returns the milliseconds since boot.
Hook it and subtract the elapsed trial time:

```javascript
// freeze_clock.js — Frida 17.x
//   frida -f target.exe -l freeze_clock.js
const DAY_MS = 86400000;

function hookWin(name, shiftMs, argIndex) {
  const k32 = Process.getModuleByName("kernel32.dll");
  Interceptor.attach(k32.getExportByName(name), {
    onLeave(retval) {
      const v = retval.sub(shiftMs);   // NativePointer arithmetic on a 64-bit value
      retval.replace(v);
      console.log("[hook] " + name + " shifted by " + shiftMs + " ms");
    }
  });
}

hookWin("GetTickCount64", 14 * DAY_MS);        // pretend the trial started 14 days ago
hookWin("GetTickCount", 14 * DAY_MS);
```

**6b. Patch the comparison against the stored monotonic value.** Same procedure as Step 5:
the stored counter and the current counter are compared; find the branch and neutralise it.

**6c. Rewrite the stored monotonic value.** If the stored counter is a file, registry value
or database row, subtract the elapsed time from it so the difference is larger than the
trial length.

### Step 7 — Freeze or shift the wall clock

```javascript
// clock_hooks.js — Frida 17.x
// Hooks the wall-clock and monotonic sources across Windows, macOS and Linux.
// SHIFT is applied in seconds; a negative value moves time into the past.
const SHIFT_SECONDS = -14 * 86400;

// --- Windows: GetSystemTimeAsFileTime writes a FILETIME (100 ns since 1601-01-01) ---
const k32 = Process.getModuleByName("kernel32.dll");
Interceptor.attach(k32.getExportByName("GetSystemTimeAsFileTime"), {
  onEnter(args) { this.ft = args[0]; },
  onLeave() {
    if (this.ft.isNull()) return;
    const cur = this.ft.readU64().toNumber();
    const shifted = cur + SHIFT_SECONDS * 10000000;
    this.ft.writeU64(shifted);
    console.log("[hook] GetSystemTimeAsFileTime shifted");
  }
});

// Windows: GetSystemTime fills a SYSTEMTIME structure
Interceptor.attach(k32.getExportByName("GetSystemTime"), {
  onEnter(args) { this.st = args[0]; },
  onLeave() {
    if (this.st.isNull()) return;
    // SYSTEMTIME: wYear(0) wMonth(2) wDay(4) wHour(6) wMinute(8) wSecond(10) wMilliseconds(12)
    const year = this.st.add(0).readU16();
    if (year >= 2000) {
      // move back 14 days by walking the calendar backwards
      this.st.add(0).writeU16(year);
      const day = this.st.add(4).readU16();
      if (day > 14) {
        this.st.add(4).writeU16(day - 14);
      } else {
        this.st.add(4).writeU16(1);
        const month = this.st.add(2).readU16();
        this.st.add(2).writeU16(month > 1 ? month - 1 : 12);
        if (month === 1) this.st.add(0).writeU16(year - 1);
      }
      console.log("[hook] GetSystemTime shifted");
    }
  }
});

// --- POSIX: time(), gettimeofday(), clock_gettime() ---
const libc = Process.getModuleByName("libc.so.6");

// time_t time(time_t *tloc)
Interceptor.attach(libc.getExportByName("time"), {
  onEnter(args) { this.tloc = args[0]; },
  onLeave(retval) {
    const shifted = retval.sub(SHIFT_SECONDS);      // 64-bit epoch seconds
    retval.replace(shifted);
    if (!this.tloc.isNull()) this.tloc.writeU64(shifted.toString());
    console.log("[hook] time() shifted");
  }
});

// int gettimeofday(struct timeval *tv, struct timezone *tz)
Interceptor.attach(libc.getExportByName("gettimeofday"), {
  onEnter(args) { this.tv = args[0]; },
  onLeave() {
    if (this.tv.isNull()) return;
    const sec = this.tv.readU64().toNumber() + SHIFT_SECONDS;
    this.tv.writeU64(sec);
    console.log("[hook] gettimeofday() shifted");
  }
});

// int clock_gettime(clockid_t clk_id, struct timespec *tp)
Interceptor.attach(libc.getExportByName("clock_gettime"), {
  onEnter(args) { this.tp = args[1]; this.id = args[0].toInt32(); },
  onLeave() {
    if (this.tp.isNull()) return;
    // CLOCK_REALTIME(0), CLOCK_MONOTONIC(1), CLOCK_BOOTTIME(7)
    const sec = this.tp.readU64().toNumber();
    const shift = (this.id === 0) ? SHIFT_SECONDS : SHIFT_SECONDS;
    this.tp.writeU64(sec + shift);
    console.log("[hook] clock_gettime(" + this.id + ") shifted");
  }
});
```

**macOS.** `mach_absolute_time` and `CFAbsoluteTimeGetCurrent` are the native clocks:

```javascript
// clock_macos.js — Frida 17.x
const SHIFT_NS = -14 * 86400 * 1000000000;
const libSystem = Process.getModuleByName("libSystem.B.dylib");

// uint64_t mach_absolute_time(void)
Interceptor.attach(libSystem.getExportByName("mach_absolute_time"), {
  onLeave(retval) {
    retval.replace(retval.sub(SHIFT_NS));
    console.log("[hook] mach_absolute_time shifted");
  }
});

// CFTimeInterval CFAbsoluteTimeGetCurrent(void) -> double seconds since 2001
const cfMod = Process.enumerateModules().find(m => m.path.indexOf("CoreFoundation") !== -1);
if (cfMod) {
  const cf = Process.getModuleByName(cfMod.path);
  Interceptor.attach(cf.getExportByName("CFAbsoluteTimeGetCurrent"), {
    onLeave(retval) {
      const v = retval.toDouble() + SHIFT_SECONDS;
      retval.replace(ptr(v));     // double return in xmm0
      console.log("[hook] CFAbsoluteTimeGetCurrent shifted");
    }
  });
}
```

**Java.** Since Frida 17.0.0 the Java bridge is a separate package; bundle it with
`frida-compile`:

```typescript
// clock_java.ts
const FIXED_MS = 1654641600000;   // 2022-06-08T00:00:00Z
const PAST_NANOS = 14 * 86400 * 1000000000;

Java.perform(() => {
  const System_ = Java.use("java.lang.System");
  System_.currentTimeMillis.overload().implementation = function () {
    return FIXED_MS;
  };
  System_.nanoTime.overload().implementation = function () {
    return 1000000000;
  };

  const Instant = Java.use("java.time.Instant");
  Instant.now.overload().implementation = function () {
    return Instant.ofEpochMilli(FIXED_MS);
  };

  const Clock = Java.use("java.time.Clock");
  if (Clock.systemUTC) {
    Clock.systemUTC.overload().implementation = function () {
      return Clock.fixed(Instant.ofEpochMilli(FIXED_MS), Java.use("java.time.ZoneOffset").UTC);
    };
  }
});
```

**.NET.** In dnSpyEx 6.6.0, patch the properties or the helper that reads the clock:
`DateTime.Now`, `DateTime.UtcNow`, `DateTimeOffset.UtcNow`, `Environment.TickCount64`,
`Stopwatch.GetTimestamp`. Replacing the property body with a constant return is the
equivalent of the native patch.

### Step 8 — Handle the launch counter

A counter file incremented once per launch bounds the number of runs, independent of the
clock. Examples: `launch_count` in the JSON state, a file `~/.config/vendor-app/count`
holding an integer, an `HKCU` `Runs` value.

Two options:

- Reset the counter to zero (or to a large number) before each run.
- Patch the increment: find `add dword [mem], 1` / `inc dword [mem]` and NOP it out.

```bash
# reset a counter file
printf '0' > ~/.config/vendor-app/count
# Windows
reg add "HKCU\Software\Vendor\App" /v Runs /t REG_DWORD /d 0 /f
```

## Variations

**Expiry computed from an activation date plus a duration.** The stored value is
`first_run` and the deadline is computed as `first_run + trial_days * 86400`. Patching the
stored value (Step 4) is enough; the comparison is never against a stored deadline.

**Licence expiry stored separately from the trial.** The application has both a trial counter
and a licence expiry. Patching the trial boolean does not touch the licence expiry, and a
stored licence with a past expiry keeps the app in evaluation mode. Find both compares.

**Server-enforced expiry.** The deadline comes from the server response and is cached
locally. Patch the cached value, or patch the response as described in
[Licence server protocol analysis](license-server-protocol-analysis.md).

**Anti-rollback with a monotonic file.** The state file stores both a wall-clock timestamp
and a boot-time counter. Comparing the two detects tampering. Patch the *comparison* rather
than either value, since the two values must stay mutually consistent.

**Time-zone and locale traps.** A trial that expires at local midnight shifts with the
time zone, and `localtime`/`tzset` change the result. Set `TZ=UTC` when testing so the
behaviour is reproducible, and hook `localtime` if the application converts through it.

**JavaScript/Electron targets.** The state lives in `app.getPath('userData')` and the clock
is `Date.now()`. Hook `Date.now` in the renderer, or patch the JS bundle directly:

```bash
rg -n "expiresAt|trialEnd|firstRun" app.asar.unpacked/resources/app/ 2>/dev/null | head -40
```

**Unity/IL2CPP.** The trial state is often in `PlayerPrefs`, stored as a registry key
(`HKCU\Software\<Company>\<Product>`) or a file next to the save game. IL2CPP code is
compiled to native code, so the same native patch procedure applies.

**Android.** `System.currentTimeMillis` inside the DEX is called through ART; the Java
bridge hook works. The `AlarmManager`/`JobScheduler` may also carry the expiry; clear
pending alarms with `adb shell dumpsys alarm | grep vendor` to see what is scheduled.

## Verification

1. **State located.** The file, registry value or database row identified in Step 1 changes
   when the application runs, and its content is the timestamp that the expiry logic uses.
2. **Decision point reached.** Set a breakpoint on the compare identified in Step 3 and
   confirm it executes with the expected operand values.
3. **Positive test.** Apply the chosen patch, start the application, and confirm the
   licensed/extended state appears: no expiry dialog, the remaining trial days increases,
   the "Upgrade" banner is gone.
4. **Negative test — the patch is not merely cosmetic.** Restore the original state file (or
   revert the byte patch), restart the application, and confirm the expiry dialog returns.
   If the application still shows the extended state, the state is cached elsewhere and the
   patch did nothing.
5. **Negative test — the clock is not simply wrong.** With the clock hook active, check that
   unrelated time-dependent behaviour is unaffected, or that you can identify the shift as
   intentional. A global clock shift can break TLS (certificate validity), cookie expiry and
   update checks.
6. **Reboot test.** Restart the machine and re-check. A trial that reverts after a reboot
   was restored from a second store — usually a registry mirror or a per-boot regenerated
   file.
7. **Counter test.** Run the application several times and confirm the run counter does not
   trigger a separate limit.

## Pitfalls

- **Patching the wall clock while the app uses a monotonic clock.** The patch appears to do
  nothing, and the developer concludes the trial cannot be extended. Check the imports for
  `GetTickCount64`, `QueryPerformanceCounter`, `mach_absolute_time`, `clock_gettime`.
- **The state is written by a helper process.** A launcher or updater writes the state
  before the main UI starts. Patching the UI's decision point is not enough; patch the
  comparison in the helper.
- **The state is stored twice.** A file under `%APPDATA%` and a registry value under
  `HKCU` frequently mirror each other; the application reads one and the other is used by
  the uninstaller.
- **cfprefsd caches preferences.** On macOS, `defaults write` does not always reach the
  application. Kill `cfprefsd` or write the plist with `plutil` while the app is not running.
- **The stored value is not a plain timestamp.** It may be a FILETIME (100 ns since 1601), a
  Windows `SYSTEMTIME` structure, a base-36 string, or a byte-reversed integer. Read the
  parsing code before writing a value.
- **The comparison is signed.** Timestamps stored as signed 32-bit integers compare
  differently near the 2038 boundary; a patch that assumes unsigned behaviour produces a
  different result after 2038.
- **The licence expiry is separate.** Extending the trial does not extend a purchased
  licence's expiry, and vice versa.
- **A global clock shift breaks TLS.** Certificate validity is checked against the system
  clock; shifting the clock by weeks makes every HTTPS connection fail. Prefer patching the
  comparison over shifting the global clock.
- **The application re-reads the state on every launch.** A patch applied to a running
  process is lost on restart. Use a file-level or binary-level patch for permanence.
- **Time-zone dependence.** Expiry at "local midnight" means the same stored timestamp
  yields different remaining days depending on `TZ`. Set `TZ=UTC` while testing.

## References

- Windows `GetSystemTime`, `GetSystemTimeAsFileTime`, `GetTickCount64`,
  `QueryPerformanceCounter` — <https://learn.microsoft.com/windows/win32/api/sysinfoapi/>
  and <https://learn.microsoft.com/windows/win32/api/timeapi/>
- macOS `mach_absolute_time`, `CFAbsoluteTimeGetCurrent` —
  <https://developer.apple.com/documentation/kernel/mach_absolute_time>
- Linux `clock_gettime` and the clock identifiers —
  <https://man7.org/linux/man-pages/man3/clock_gettime.3.html>
- Java `System.currentTimeMillis`, `java.time.Instant` —
  <https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/lang/System.html>
- .NET `DateTime.UtcNow`, `Environment.TickCount64` —
  <https://learn.microsoft.com/dotnet/api/system.datetime.utcnow>
- Frida 17.x JavaScript API — <https://frida.re/docs/javascript-api/>
- Sibling entries: [Offline activation and machine binding](offline-activation-and-machine-binding.md),
  [Licence server protocol analysis](license-server-protocol-analysis.md),
  [Hardware fingerprint binding](hardware-fingerprint-binding.md)
