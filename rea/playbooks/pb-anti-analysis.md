# Playbook: removing anti-analysis from a protected target

**Target**: a binary that refuses to run under a debugger, refuses to run in a virtual machine,
detects instrumentation, or verifies its own code.
**Outcome**: a target that runs under an ordinary debugger, in the analysis environment, with
the protection removed or neutralised.

## 0. Preparation

```sh
mkdir -p work && cd work
cp /path/to/app app && chmod +x app
sha256sum app
file app
rabin2 -S app
rabin2 -I app
readelf -SW app | grep -iE 'upx|themida|vmp|aspack'      # packer section names
```

## 1. Identify the layer

| Layer | Symptom | Reference |
| --- | --- | --- |
| Packer | tiny import table, entry point outside `.text`, unreadable strings | `knowledge/anti-analysis/packers-and-unpacking.md` |
| Debugger detection | exits at once under a debugger | `knowledge/anti-analysis/debugger-detection-techniques.md` |
| Timing | exits after a delay under a debugger | `knowledge/anti-analysis/timing-based-anti-debug.md` |
| VM detection | refuses to run in VMware/QEMU | `knowledge/anti-analysis/vm-and-emulator-detection.md` |
| Integrity check | fails only after a file edit | `knowledge/anti-analysis/integrity-self-checks.md` |
| Obfuscation | the decompiler output is unreadable | `knowledge/anti-analysis/control-flow-flattening.md` |

## 2. Unpack first

```sh
# UPX
upx -d app -o app_unpacked

# generic PE
python3 -m unipacker app -o app_unpacked.exe
```

If a static unpacker does not exist for the protector, dump the running image instead:

```sh
# Windows: Scylla — dump the OEP and rebuild the imports
# Linux / macOS
gdb -p $(pgrep -n app) -batch \
    -ex 'dump binary memory /tmp/app.dump 0x400000 0x500000'
```

```js
// Frida, on any platform
const m = Process.mainModule;
const bytes = Memory.readByteArray(m.base, m.size);
```

Analysing the memory image in the debugger is often enough — no file reconstruction needed.

## 3. Remove debugger detection

### Under x64dbg

ScyllaHide handles the standard Windows API set in one place:

1. Install ScyllaHide into the x64dbg plugins directory.
2. Load it from the plugin menu and select a profile — `VMProtect x86/x64` when the target is
   protected with VMProtect.
3. Apply the profile before the target runs (it patches the process at attach time).

Manual PEB clearing, when a check reads `BeingDebugged` directly:

```
# in x64dbg
dpe [esp+10]      # PEB
dpe [dpe+2]       # BeingDebugged
dpe [dpe+68]      # NtGlobalFlag
```

Set `BeingDebugged` to 0 and clear `NtGlobalFlag`.

### With Frida

Use the [scoped helper](../scripts/frida/bypass-anti-debug.js) and inspect its actual
API set. ProcessDebugFlags is class 31 and reports 1 for not-debugged;
ProcessDebugObjectHandle is class 30 and uses a pointer-sized output. Preserve original
API status and unrelated queries. Script loading does not prove the check executed.

### Timing checks

```js
const k32 = Process.getModuleByName('kernel32.dll');
const cb = new NativeCallback(() => 1000, 'uint64', []);
hooks.push(cb);
Interceptor.replace(k32.getExportByName('GetTickCount64'), cb);

const qpc = new NativeCallback((out) => {
  out.writeU64(1000);
  return 1;
}, 'int', ['pointer']);
hooks.push(qpc);
Interceptor.replace(k32.getExportByName('QueryPerformanceCounter'), qpc);
```

A check that compares two reads taken far apart needs a constant *delta*, not a constant value:
track the call count and return `base` then `base + 1000`.

## 4. Remove VM and emulator detection

### CPUID hypervisor bit

The check is usually `cpuid` with EAX=1, then `bt ecx, 0x1F`. Patch the conditional jump that
follows it, or hook `cpuid` — Frida cannot hook an instruction directly, so patch the branch:

```sh
r2 -q -c 'aaa; /x 0f31c9; pd 6' app
```

### Android emulator properties

```js
const get = Process.getModuleByName('libc.so').getExportByName('__system_property_get');
const cb = new NativeCallback((name, value) => {
  const n = name.readUtf8String();
  if (n === 'ro.hardware')       return value.writeUtf8String('qcom');
  if (n === 'ro.product.device') return value.writeUtf8String('SM-G991B');
  if (n === 'ro.kernel.qemu')    return value.writeUtf8String('1');
  return 0;
}, 'int', ['pointer', 'pointer']);
hooks.push(cb);
Interceptor.replace(get, cb);
```

### MAC OUI check

The check reads the interface list and compares the first three octets against known VM
prefixes. Patch the comparison, or interpose `getifaddrs` and rewrite the address.

## 5. Remove integrity self-checks

Locate the digest:

```sh
python3 -c "
import math, collections, pathlib
d = pathlib.Path('app').read_bytes()
c = collections.Counter(d); n = len(d)
print('entropy', -sum((v/n)*math.log2(v/n) for v in c.values()))
"
r2 -q -c '/x edb88320' app        # the CRC-32 polynomial
r2 -q -c '/x 982f8a42' app        # a SHA-256 round constant
```

Two ways out:

**Patch the comparison.** The digest constant's use site leads to the compare; invert the
branch there.

**Recompute the digest.** When the expected digest lives in the same file:

```python
import binascii, struct
from pathlib import Path

data = bytearray(Path('app').read_bytes())
START, END = 0x1000, 0x5000
computed = binascii.crc32(bytes(data[START:END])) & 0xFFFFFFFF

old = struct.pack('<I', 0xDEADBEEF)          # the original stored digest
i = data.find(old)
if i != -1:
    data[i:i+4] = struct.pack('<I', computed)
    Path('app_patched').write_bytes(data)
    print('digest updated at', hex(i))
```

Do this as the last step — any later edit invalidates it again. Better still, patch the check
so the digest never matters.

## 6. Remove instrumentation detection

If the target detects Frida itself:

- Rename the server binary and run it on a non-default port.
- Use Frida Gadget embedded in the app instead of a server.
- On Android, use a Magisk/KernelSU module with a denylist for the target package.
- Hook the detection: the target usually reads `/proc/self/maps` or scans for the `frida-agent`
  string. Interpose `open`/`read` and strip the matches.

## 7. Verify

1. The target runs under the debugger without exiting.
2. The target runs in the analysis environment without refusing.
3. After a patch, the target still passes its own integrity check.
4. Each symptom is re-triggered: attach the debugger again, re-enter the VM, re-run the packed
   binary.

## 8. Pitfalls

- **Layered protections.** Removing one check exposes the next. Iterate.
- **The protection is inside the packer.** A packed VMProtect binary hides its checks; unpack
  first.
- **Over-hooking.** A stubbed API that returns a constant breaks unrelated behaviour. Return
  the correct value for the normal case.
- **Timing hook with the wrong shape.** A frozen clock fails a check that expects the clock to
  advance.
- **Detection of the debugger's side effects.** The PEB fields, `NtGlobalFlag` and the debug
  object handle are three separate signals; clearing one is not enough.

## Deliverable

The unpacked or patched target, the list of removed checks with the API or offset for each, and
the verification that each symptom no longer reproduces.
