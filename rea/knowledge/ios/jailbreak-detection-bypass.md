---
id: "jailbreak-detection-bypass"
title: "Jailbreak detection bypass"
domain: "ios"
kind: "technique"
platforms: "ios"
arch: "arm64"
difficulty: "advanced"
tools: "Frida, frida-objc-bridge, frida-compile, r2, otool, cycript"
verified: false
updated: "2026-11-15"
summary: "Enumerate the filesystem, process, environment, code-signature and loaded-image signals that iOS apps use to detect a jailbreak, then neutralise each signal at the syscall and Objective-C layer or defeat the aggregate decision instead."
---

## Summary

Jailbreak detection is a collection of small probes, not a single check. Each probe asks the
same question in a different way: does a path exist that should not exist, can a process be
created that the sandbox forbids, is a URL scheme registered that the App Store cannot
register, is a file writable that the sandbox forbids, is a dynamic library loaded that the
App Store cannot load.

Each probe can be neutralised individually at the layer it uses — `stat`, `access`, `open`,
`fork`, `dlopen`, `getenv`, `ptrace`, `canOpenURL:`, `_dyld_get_image_name`. A stronger
approach is to find the function that aggregates the probes into a boolean and force that
one function to return `false`.

## Recognition

### Filesystem and URL probes

- `stat("/Applications/Cydia.app", …)` — the classic Cydia.app probe.
- `access("/usr/sbin/sshd", F_OK)` — the sshd probe.
- `stat("/bin/bash", …)`, `stat("/usr/libexec/cydia", …)`,
  `stat("/private/var/lib/cydia", …)`, `stat("/Library/MobileSubstrate", …)`.
- `canOpenURL([NSURL URLWithString:@"cydia://"])` — the URL scheme probe. The App Store
  cannot register `cydia://`, `sileo://`, `zbra://`, `undecimus://`, `filza://`.
- `[[NSBundle bundleWithPath:@"/Applications/Cydia.app"] bundleIdentifier] != nil`.
- `[[NSFileManager defaultManager] fileExistsAtPath:@"/private/var/lib/cydia"]`.
- A write probe: `open("/private/jailbreak_probe.txt", O_CREAT | O_WRONLY)` succeeds on a
  jailbroken device because the process is not sandboxed, and fails on a stock device.
- `statfs("/", …)` and a check of the mount flags of the system volume.

### Process, environment and debugger probes

- `fork()` returning `0` — the sandbox forbids `fork` on iOS.
- `getenv("DYLD_INSERT_LIBRARIES")` returning a non-NULL string.
- `ptrace(PT_DENY_ATTACH, 0, 0, 0)` succeeding — the app denies debugging, and a debugger
  being attached changes the outcome.
- `sysctl(CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid(), …)` and a check of the `P_TRACED`
  bit (`0x800`) in `kp_proc.p_flag`.
- `isatty`, `ioctl`, or `getppid()` changes under a debugger.

### Code-signature and loaded-image probes

- `SecStaticCodeCheckValidityWithErrors` on the app bundle, used to detect a re-signed
  binary.
- `dlopen("/usr/lib/libsubstrate.dylib", RTLD_LAZY)` returning a handle.
- `_dyld_image_count` / `_dyld_get_image_name` scanning the loaded images for
  `MobileSubstrate`, `SubstrateLoader`, `SubstrateInserter`, `Substrate`, `TweakInject`,
  `libhooker`, `CydiaSubstrate`, `frida`, `cynject`, `libcycript`.
- `NSBundle.allBundles` or `allFrameworks` scanned for the same names.

### Aggregate decision

Most apps do not return the first probe result. They score the probes:

```java
private int jailbreakScore() {
    int score = 0;
    if (hasCydiaPath()) score++;
    if (canOpenCydiaUrl()) score++;
    if (forkSucceeds()) score++;
    if (hasSubstrateImage()) score++;
    if (writesOutsideSandbox()) score++;
    return score;
}

private boolean isJailbroken() {
    return jailbreakScore() >= 2;
}
```

The decision point is the method that returns the final boolean. Patching it defeats every
probe at once.

## Method

### 1. Identify the probes

Static analysis of the decrypted binary:

```bash
cd /path/to/work
r2 -qc 'iz~Cydia' App.decrypted
r2 -qc 'iz~cydia://' App.decrypted
r2 -qc 'iz~MobileSubstrate' App.decrypted
r2 -qc 'ic~jailbreak' App.decrypted
strings -a App.decrypted | grep -iE 'cydia|jailbreak|substrate|sileo|zebra|frida'
```

Cross-references to the path strings:

```bash
r2 -qc 'aaa; axt @@ str.*Cydia.app' App.decrypted
```

### 2. Write one interposer for the filesystem probes

The three functions that matter are `stat`, `access` and `open`. The pattern is the same for
all three: return the "not found" result for paths that only exist on a jailbroken device.

```js
// jailbreak_fs.js — Frida 17.x, iOS
'use strict';

const ENOENT = 2;
const EACCES = 13;

const JAILBREAK_PATHS = [
  '/Applications/Cydia.app',
  '/Applications/Cydia.app/',
  '/Applications/Sileo.app',
  '/Applications/Zebra.app',
  '/Applications/Filza.app',
  '/Library/MobileSubstrate',
  '/Library/PreferenceBundles/Liberty.prefBundle',
  '/usr/sbin/sshd',
  '/usr/libexec/sshd',
  '/usr/libexec/cydia',
  '/usr/lib/libsubstrate.dylib',
  '/usr/libexec/substrate',
  '/etc/apt',
  '/private/var/lib/apt',
  '/private/var/lib/cydia',
  '/private/var/cache/apt',
  '/private/var/stash',
  '/var/lib/cydia',
  '/var/stash',
  '/var/mobile/Library/SBSettings',
  '/bin/bash',
  '/bin/sh',
  '/usr/bin/ssh',
];

// Resolve a libc symbol without the removed static Module.findExportByName.
function resolve(names) {
  for (const name of names) {
    try {
      const p = Module.getGlobalExportByName(name);
      if (p !== null && !p.isNull()) return p;
    } catch (e) {
      /* try the next name */
    }
  }
  return null;
}

// Darwin keeps errno in thread-local storage behind __error().
let setErrno = null;
try {
  const kmod = Process.getModuleByName('libsystem_kernel.dylib');
  const errorPtr = kmod.getExportByName('__error');
  const errorFn = new NativeFunction(errorPtr, 'pointer', []);
  setErrno = function (value) {
    errorFn().writeS32(value);
  };
} catch (e) {
  console.log('[-] __error not found, errno will not be set');
}

function readPath(ptr) {
  if (ptr === null || ptr.isNull()) return null;
  try {
    return ptr.readUtf8String();
  } catch (e) {
    return null;
  }
}

function isJailbreakPath(path) {
  if (path === null) return false;
  if (path.startsWith('cydia://') || path.startsWith('sileo://') ||
      path.startsWith('zbra://') || path.startsWith('undecimus://') ||
      path.startsWith('filza://')) {
    return true;
  }
  if (path.startsWith('file://')) {
    const p = path.substring('file://'.length);
    return JAILBREAK_PATHS.some(function (j) { return p.indexOf(j) === 0; });
  }
  return JAILBREAK_PATHS.some(function (j) { return path === j || path.indexOf(j + '/') === 0; });
}
```

The `stat` interposer, using `Interceptor.replaceFast` so the original implementation stays
callable:

```js
const statPtr = resolve(['stat', '_stat', 'stat$INODE64']);
if (statPtr === null) {
  console.log('[-] stat not found');
} else {
  const original = new NativeFunction(
    Interceptor.replaceFast(statPtr, new NativeCallback(function (path, buf) {
      const p = readPath(path);
      if (isJailbreakPath(p)) {
        console.log('[hook stat] ' + p);
        if (setErrno !== null) setErrno(ENOENT);
        return -1;                       // ENOENT
      }
      return original(path, buf);
    }, 'int', ['pointer', 'pointer'])),
    'int', ['pointer', 'pointer']);
  console.log('[+] stat hooked');
}
```

`Interceptor.replaceFast` returns a pointer to the original implementation, so the
replacement can forward the normal case to it. When `replaceFast` is unavailable, the same
effect is obtained with `Interceptor.attach` and by overwriting the return value on leave:

```js
const statPtr = resolve(['stat']);
if (statPtr !== null) {
  Interceptor.attach(statPtr, {
    onEnter(args) {
      this.blocked = isJailbreakPath(readPath(args[0]));
    },
    onLeave(retval) {
      if (this.blocked) {
        retval.replace(-1);
        if (setErrno !== null) setErrno(ENOENT);
      }
    }
  });
}
```

`access` and `open` follow the same shape:

```js
const accessPtr = resolve(['access', '_access']);
if (accessPtr !== null) {
  const originalAccess = new NativeFunction(
    Interceptor.replaceFast(accessPtr, new NativeCallback(function (path, mode) {
      const p = readPath(path);
      if (isJailbreakPath(p)) {
        console.log('[hook access] ' + p);
        if (setErrno !== null) setErrno(ENOENT);
        return -1;
      }
      return originalAccess(path, mode);
    }, 'int', ['pointer', 'int'])),
    'int', ['pointer', 'int']);
}

const openPtr = resolve(['open', '_open', 'open$NOCANCEL']);
if (openPtr !== null) {
  const originalOpen = new NativeFunction(
    Interceptor.replaceFast(openPtr, new NativeCallback(function (path, flags) {
      const p = readPath(path);
      if (isJailbreakPath(p)) {
        console.log('[hook open] ' + p);
        if (setErrno !== null) setErrno(ENOENT);
        return -1;
      }
      return originalOpen(path, flags);
    }, 'int', ['pointer', 'int'])),
    'int', ['pointer', 'int']);
}
```

The write probe uses `open` with `O_CREAT` on a path the sandbox forbids. Blocking it with
`ENOENT` is the right answer for a path probe; a probe that writes to `/private/` and
expects `EACCES` needs `EACCES` (`13`) instead. Adjust the errno per probe.

Important: the path matcher must not block the app's own container. The sandbox lives under
`/private/var/mobile/Containers/Data/Application/<uuid>`, which starts with `/private`, so a
naive "block everything under `/private`" rule breaks the app. Block only the specific
jailbreak paths listed above.

### 3. The remaining native probes

```js
// fork(): the iOS sandbox forbids it, so a successful fork means no jailbreak.
const forkPtr = resolve(['fork']);
if (forkPtr !== null) {
  const originalFork = new NativeFunction(
    Interceptor.replaceFast(forkPtr, new NativeCallback(function () {
      console.log('[hook fork] pretending to fail');
      if (setErrno !== null) setErrno(35);      // EAGAIN
      return -1;
    }, 'int', [])),
    'int', []);
}

// dlopen(): refuse to load the substrate libraries.
const dlopenPtr = resolve(['dlopen']);
if (dlopenPtr !== null) {
  const originalDlopen = new NativeFunction(
    Interceptor.replaceFast(dlopenPtr, new NativeCallback(function (path, mode) {
      const p = readPath(path);
      if (p !== null && p.toLowerCase().indexOf('substrate') !== -1) {
        console.log('[hook dlopen] ' + p);
        return ptr(0);                        // NULL
      }
      return originalDlopen(path, mode);
    }, 'pointer', ['pointer', 'int'])),
    'pointer', ['pointer', 'int']);
}

// getenv(): hide the injection variable.
const getenvPtr = resolve(['getenv']);
if (getenvPtr !== null) {
  const originalGetenv = new NativeFunction(
    Interceptor.replaceFast(getenvPtr, new NativeCallback(function (name) {
      const n = readPath(name);
      if (n === 'DYLD_INSERT_LIBRARIES' || n === 'DYLD_LIBRARY_PATH') {
        console.log('[hook getenv] ' + n);
        return ptr(0);
      }
      return originalGetenv(name);
    }, 'pointer', ['pointer'])),
    'pointer', ['pointer']);
}

// ptrace(): the app denies debugging and treats a success as "not debugged".
const ptracePtr = resolve(['ptrace']);
if (ptracePtr !== null) {
  const originalPtrace = new NativeFunction(
    Interceptor.replaceFast(ptracePtr, new NativeCallback(function (request, pid, addr, data) {
      if (request === 0 /* PT_DENY_ATTACH */) {
        console.log('[hook ptrace] PT_DENY_ATTACH -> 0');
        return 0;
      }
      return originalPtrace(request, pid, addr, data);
    }, 'int', ['int', 'int', 'pointer', 'pointer'])),
    'int', ['int', 'int', 'pointer', 'pointer']);
}
```

`ptrace` needs a variadic-safe signature. Frida's `NativeCallback` supports the fixed
four-argument form for `ptrace` on Darwin; if the call misbehaves, use
`Interceptor.attach` on `ptrace` and replace the return value on leave instead.

### 4. The loaded-image probe

Hide the injected images from the image list:

```js
const BLOCKED_IMAGES = [
  'MobileSubstrate',
  'SubstrateLoader',
  'SubstrateInserter',
  'Substrate',
  'TweakInject',
  'CydiaSubstrate',
  'libhooker',
  'frida',
  'frida-agent',
  'frida-gadget',
  'cynject',
  'libcycript',
];

const dyldImageName = resolve(['_dyld_get_image_name']);
if (dyldImageName !== null) {
  const originalName = new NativeFunction(
    Interceptor.replaceFast(dyldImageName, new NativeCallback(function (index) {
      const name = originalName(index);
      if (name.isNull()) return name;
      const s = name.readUtf8String();
      if (s !== null && BLOCKED_IMAGES.some(function (b) { return s.indexOf(b) !== -1; })) {
        console.log('[hook dyld] hiding ' + s);
        return ptr(0);
      }
      return name;
    }, 'pointer', ['int'])),
    'pointer', ['int']);
  console.log('[+] _dyld_get_image_name hooked');
}
```

Returning `NULL` for a blocked index is enough for the common loop shape, which tests the
pointer for `NULL` before reading the name. A loop that counts the images and indexes them
consecutively still sees the blocked entry as a hole; the robust version is to intercept the
app's own scanning method instead.

### 5. The Objective-C probes

The URL-scheme probe and the bundle/file probes are Objective-C calls:

```js
// hook_objc.ts — Frida 17.x, needs frida-objc-bridge bundled with frida-compile
import ObjC from 'frida-objc-bridge';

const JAILBREAK_BUNDLES = [
  '/Applications/Cydia.app',
  '/Applications/Sileo.app',
  '/Applications/Zebra.app',
  '/Library/MobileSubstrate',
];

ObjC.schedule(function () {
  // canOpenURL:
  const canOpenURL = ObjC.classes.UIApplication['-canOpenURL:'];
  canOpenURL.implementation = function (url) {
    const s = url.absoluteString().toString();
    if (s.indexOf('cydia://') === 0 || s.indexOf('sileo://') === 0 ||
        s.indexOf('zbra://') === 0 || s.indexOf('undecimus://') === 0 ||
        s.indexOf('filza://') === 0) {
      console.log('[hook canOpenURL] ' + s + ' -> NO');
      return false;
    }
    return this.canOpenURL_(url);
  };

  // bundleWithPath:
  const bundleWithPath = ObjC.classes.NSBundle['+bundleWithPath:'];
  bundleWithPath.implementation = function (path) {
    const p = path.toString();
    if (JAILBREAK_BUNDLES.some(function (b) { return p.indexOf(b) !== -1; })) {
      console.log('[hook bundleWithPath] ' + p + ' -> nil');
      return NULL;
    }
    return this.bundleWithPath_(path);
  };

  // fileExistsAtPath:
  const fileExists = ObjC.classes.NSFileManager['-fileExistsAtPath:'];
  fileExists.implementation = function (path) {
    const p = path.toString();
    if (JAILBREAK_BUNDLES.some(function (b) { return p.indexOf(b) !== -1; })) {
      console.log('[hook fileExistsAtPath] ' + p + ' -> NO');
      return false;
    }
    return this.fileExistsAtPath_(path);
  };
});
```

Frida 17 does not bundle the Objective-C bridge. Install it and bundle the script:

```bash
npm install frida-objc-bridge
npx frida-compile hook_objc.ts -o hook_objc.js
```

A `NSURL.canOpenURL:` query for a scheme that is not in the app's `LSApplicationQueriesSchemes`
returns `NO` even on a jailbroken device. When the app's detection depends on the scheme
being registered, the URL scheme must be listed in `Info.plist`
(`LSApplicationQueriesSchemes`) — check that first, because a missing entry makes the whole
probe useless.

### 6. Defeat the aggregate decision

Patching the scoring function is one change instead of ten. Find the method that returns
the final boolean and replace it:

```js
ObjC.schedule(function () {
  const AppDelegate = ObjC.classes.AppDelegate;
  if (AppDelegate['-isJailbroken'] !== undefined) {
    AppDelegate['-isJailbroken'].implementation = function () {
      console.log('[+] -[AppDelegate isJailbroken] forced to false');
      return false;
    };
  }
  const Security = ObjC.classes.SecurityManager;
  if (Security !== undefined && Security['-jailbreakScore'] !== undefined) {
    Security['-jailbreakScore'].implementation = function () {
      console.log('[+] -[SecurityManager jailbreakScore] forced to 0');
      return 0;
    };
  }
});
```

For a Swift implementation the selector is mangled. Find it with
`nm -m App.decrypted | grep -i jail` or `r2 -qc 'ic~jail' App.decrypted`, then hook it by
its mangled name:

```js
ObjC.schedule(function () {
  const cls = ObjC.classes.SecurityManager;
  const sel = '-s5App11SecurityManagerr14jailbreakScore';
  if (cls[sel] !== undefined) {
    cls[sel].implementation = function () { return 0; };
  }
});
```

### 7. Static variant

The same decision can be patched in the binary. In arm64, a `BOOL` return is `mov w0, #0`
(`00 00 80 52`) followed by `ret` (`c0 03 5f d6`); changing the constant to
`mov w0, #1` (`20 00 80 52`) is wrong for this case, and the "no jailbreak" answer is the
`0` variant. The scoring function is patched by forcing the comparison to always take the
"not jailbroken" branch. See
[`ios-native-licence-patching.md`](ios-native-licence-patching.md) for the offset arithmetic
and [`fairplay-decrypted-binary-handling.md`](fairplay-decrypted-binary-handling.md) for
getting a readable binary in the first place.

### 8. Run the hooks

```bash
frida -U -f com.vendor.app -l jailbreak_fs.js
frida -U -f com.vendor.app -l hook_objc.js
```

Spawning with `-f` is required: a check that runs during launch has already passed by the
time an attached session starts. Frida 16 and later resume the spawned process automatically.

## Variations

### Hiding the injected images from the app

The loaded-image probe also looks at `NSBundle.allBundles` and
`NSBundle.allFrameworks`. Hook those:

```js
ObjC.schedule(function () {
  const allBundles = ObjC.classes.NSBundle['+allBundles'];
  allBundles.implementation = function () {
    const list = this.allBundles_();
    const out = ObjC.classes.NSMutableArray.array();
    const n = list.count();
    for (let i = 0; i < n; i++) {
      const b = list.objectAtIndex_(i);
      const p = b.bundlePath().toString();
      if (p.indexOf('MobileSubstrate') === -1 && p.indexOf('frida') === -1 &&
          p.indexOf('TweakInject') === -1) {
        out.addObject_(b);
      }
    }
    return out;
  };
});
```

### The sandbox receipt check

Some apps validate their own code signature to detect a re-signed binary. Neutralise the
system call:

```js
const secCheck = resolve([
  'SecStaticCodeCheckValidityWithErrors',
  '_SecStaticCodeCheckValidityWithErrors',
]);
if (secCheck !== null) {
  const originalCheck = new NativeFunction(
    Interceptor.replaceFast(secCheck, new NativeCallback(function (code, flags, errors) {
      console.log('[hook SecStaticCodeCheckValidityWithErrors] -> errSecSuccess');
      return 0;                       // errSecSuccess
    }, 'int', ['pointer', 'int', 'pointer'])),
    'int', ['pointer', 'int', 'pointer']);
}
```

This only hides the signature check; the app still runs the modified binary.

### `statfs` on the system volume

Some apps check the mount flags of the root volume. Hook `statfs` and `statvfs` and clear
the `f_flags` field, which on Darwin's 64-bit `struct statfs` sits at offset `0x48`
(confirm against the SDK header for the target version):

```js
const statfsPtr = resolve(['statfs', 'statfs64', 'statvfs']);
if (statfsPtr !== null) {
  const originalStatfs = new NativeFunction(
    Interceptor.replaceFast(statfsPtr, new NativeCallback(function (path, buf) {
      const r = originalStatfs(path, buf);
      if (r === 0 && buf !== null && !buf.isNull()) {
        const flags = buf.add(0x48).readU32();
        buf.add(0x48).writeU32(flags & ~0x1);   // clear MNT_RDONLY
      }
      return r;
    }, 'int', ['pointer', 'pointer'])),
    'int', ['pointer', 'pointer']);
}
```

### The `sysctl` debugger probe

The `P_TRACED` flag (`0x800`) is in the `kinfo_proc` buffer that `sysctl` fills. Clear it
on the way out:

```js
const sysctlPtr = resolve(['sysctl']);
if (sysctlPtr !== null) {
  const originalSysctl = new NativeFunction(
    Interceptor.replaceFast(sysctlPtr, new NativeCallback(function (name, oldp, oldlenp, newp, newlen) {
      const r = originalSysctl(name, oldp, oldlenp, newp, newlen);
      if (r === 0 && oldp !== null && !oldp.isNull() && oldlenp !== null && !oldlenp.isNull()) {
        const len = oldlenp.readU32();
        // kinfo_proc.kp_proc.p_flag is at offset 0x200 on 64-bit Darwin
        const flagOffset = 0x200;
        if (len > flagOffset + 4) {
          const flags = oldp.add(flagOffset).readU32();
          oldp.add(flagOffset).writeU32(flags & ~0x800);   // clear P_TRACED
        }
      }
      return r;
    }, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer'])),
    'int', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']);
}
```

The struct offsets are SDK-dependent; verify against the headers before relying on them.

### An anti-hook check

Apps that detect Frida look for the injected image in the loaded-image list, for a thread
whose name contains `gum-js-loop`, or for the presence of the `frida` agent. The same hooks
that hide the images also hide the agent, but a detection that uses
`sysctl(KERN_PROC_ALL)` to enumerate processes needs the process list filtered as well.

### Rootless jailbreaks

A rootless jailbreak keeps its files under `/var/jb` and `/var/jb/…` prefixes rather than
`/Applications/Cydia.app`. Add those paths to the matcher:

```text
/var/jb
/var/jb/usr/sbin/sshd
/var/jb/Library/MobileSubstrate
/var/jb/usr/lib/TweakInject
```

### The `cydia://` scheme and `LSApplicationQueriesSchemes`

`canOpenURL:` returns `NO` for any scheme that is not listed in the app's
`LSApplicationQueriesSchemes`. If the app forgot to list `cydia`, the probe always returns
`NO` and there is nothing to bypass.

## Verification

1. Probe-level check. Each hook logs the path or symbol it intercepted. The log must show
   the jailbreak path being blocked (`[hook stat] /Applications/Cydia.app`), which proves
   the probe was reached and not merely that the aggregate was overridden.
2. Decision check. The app must not show the jailbreak warning, the "untrusted device"
   screen, or refuse to start. An aggregate override can hide the warning while the probes
   still fire, which is why both checks are needed.
3. Negative test. Stop the hooks, or spawn without them, and confirm the app *does*
   detect the jailbreak. A bypass that never had anything to bypass proves nothing.
4. Negative test for the aggregate patch. Remove the aggregate override but keep the
   per-probe hooks and confirm the app is still detected — that identifies which layer is
   actually doing the work.
5. Resilience check. The probes often run at launch and again on resume. Background the
   app and foreground it again and confirm the warning does not come back.
6. Crash check. `dlopen` returning `NULL` where the caller did not check the result causes
   a crash at the dereference. Read the device console after each change
   (`idevicesyslog | grep App`) and confirm no new exceptions appear.

## Pitfalls

- **The app's own container is blocked.** A matcher that blocks every path under
  `/private` breaks the app's data storage. Match specific paths.
- **`errno` is not set.** Returning `-1` without setting `errno` leaves `errno` at its
  previous value, and the probe may conclude the path exists with a different error. Set
  `ENOENT` (2) or `EACCES` (13) explicitly.
- **`dlopen` returning NULL where the result is dereferenced.** The app crashes instead of
  concluding "no jailbreak". Check the call site first.
- **The check runs before the hook is installed.** Attaching to a running process is too
  late for a launch-time check. Spawn with `frida -U -f <bundle-id>`.
- **The Objective-C bridge is missing.** Frida 17 does not bundle `ObjC`; the script throws
  `TypeError: undefined is not an object`. Install `frida-objc-bridge` and bundle it with
  `frida-compile`.
- **The static `Module.findExportByName` no longer exists.** Frida 17 removed it. Use
  `Module.getGlobalExportByName(name)` or
  `Process.getModuleByName(name).getExportByName(name)`.
- **`stat` has several symbol variants.** `stat$INODE64` and `fstatat` are separate
  symbols. Hooking only `stat` leaves `fstatat` probes working.
- **`canOpenURL:` needs the scheme in `Info.plist`.** Otherwise the probe never fires.
- **The device is not jailbroken.** On a stock device there is nothing to detect, so every
  bypass is untested. Verify on a jailbroken device or against a known-detection app.
- **The app re-checks on every foreground.** A one-shot hook attached to a running process
  misses the second check.
- **Detecting the hooks.** Some apps look for interposed functions by comparing the
  address of `stat` with the expected dyld address, or by checking whether the function
  prologue is intact. `Interceptor.replaceFast` rewrites the prologue; a check on the
  first bytes of the function gives the detection away.

## References

- Apple, "App Security Overview" and the sandbox model:
  <https://support.apple.com/guide/security/app-security-overview-sece2c66f4b1a/web>
- Apple, "Using the sandbox" and `stat`, `access`, `open`:
  <https://developer.apple.com/library/archive/documentation/Security/Conceptual/SandboxOverview/SandboxOverview.html>
- Frida 17.x JavaScript API (Interceptor, `replaceFast`, `Module.getGlobalExportByName`):
  <https://frida.re/docs/javascript-api/>
- Frida bridges: <https://frida.re/docs/bridges/>
- Darwin `ptrace(2)`, `sysctl(3)`, `statfs(2)` manual pages:
  <https://keith.github.io/xcode-man-pages/>
- `SecStaticCodeCheckValidityWithErrors`:
  <https://developer.apple.com/documentation/security/1398306-secstaticcodecheckvaliditywither>
- Sibling entries: [`ios-native-licence-patching.md`](ios-native-licence-patching.md),
  [`fairplay-decrypted-binary-handling.md`](fairplay-decrypted-binary-handling.md),
  [`ipa-repack-and-resign.md`](ipa-repack-and-resign.md)
