---
id: "vm-and-emulator-detection"
title: "VM and emulator detection"
domain: "anti-analysis"
kind: "technique"
platforms: "windows, macos, linux, android, ios"
arch: "x86, x86-64, arm64"
difficulty: "advanced"
tools: "Frida,radare2,Ghidra"
verified: false
updated: "2026-11-15"
summary: "Catalogue of the hypervisor, MAC-address, firmware-table and build-property signals used to detect a virtual machine or mobile emulator, with the byte pattern of the CPUID check and the Frida 17 bypass for each."
---

## Summary

A virtual machine or an emulator is a different machine, not a debugger, and the signals are
different too. The cheap ones are firmware and hardware strings; the expensive ones are instruction
traps that only a hypervisor can service.

This entry lists the signals in ascending cost to the target: MAC OUI prefixes, DMI and ACPI
strings, Android build properties, the iOS simulator environment, and finally the CPUID-based
checks — the hypervisor brand string, the hypervisor-present bit, the VMware backdoor port, and
the VirtualBox and QEMU guest-driver probes.

For each signal it gives where the signal is read, what the value looks like on a real guest, and
the bypass: a byte patch of the boolean, a CPUID interception, a spoofed property, or a hooked
`sysctl`.

Related entries: [debugger-detection-techniques](./debugger-detection-techniques.md) for the
instruction-trap family in general, [timing-based-anti-debug](./timing-based-anti-debug.md) for
the timing family that virtualisation also perturbs.

## Recognition

CPUID import or inline opcode:

```
rabin2 -i target.exe | grep -Ei 'CPUID|GetAdaptersAddresses|GetAdaptersInfo|GetSystemFirmwareTable|RegOpenKey|SetupDiGetDeviceRegistryProperty'
rabin2 -d target.exe | grep -i 'cpuid'
```

`cpuid` is `0f a2`. The hypervisor-presence check is the standard leaf-1 sequence:

```
b8 01 00 00 00      mov  eax, 1
0f a2               cpuid
f7 c1 80 00 00 00   test ecx, 0x80000000
75 0c               jne  <hypervisor detected>
```

The equivalent written with a bit test:

```
b9 01 00 00 00      mov  ecx, 1
0f a2               cpuid
0f a3 d1            bt   ecx, 0x1F
73 0c               jnb  <no hypervisor>
```

`0f a3 d1` is `bt ecx, 0x1F`: bit 31 of ECX, which is the hypervisor-present flag in the leaf-1
feature bits. `73 0c` is `jnb`, taken when the bit is clear.

The hypervisor brand string is read from leaf `0x40000000`, whose EBX/ECX/EDX registers hold 12
bytes of ASCII:

```
b8 00 00 00 40      mov  eax, 0x40000000
0f a2               cpuid
```

Brand strings in the wild:

| Vendor | String |
| --- | --- |
| VMware | `VMwareVMware` |
| KVM / QEMU (TCG) | `KVMKVMKVM\0\0\0` |
| QEMU (modern) | `QEMU Virtual Machine` |
| Hyper-V | `Microsoft Hv` |
| Parallels | `Parallels` |
| Xen | `XenVMMXenVMM` |
| VirtualBox | `VBoxVBoxVBox` (also reported by `cpuid` leaf `0x40000000` in some builds) |

MAC OUI prefixes searched for in the adapter list:

| Vendor | OUI prefixes |
| --- | --- |
| VMware | `00:0c:29`, `00:50:56`, `00:05:69`, `00:1c:14`, `00:03:ff` |
| VirtualBox | `08:00:27`, `0a:00:27` |
| QEMU / KVM | `52:54:00` |
| Hyper-V | `00:15:5d` |
| Parallels | `00:1c:42` |
| Xen | `00:16:3e` |

Firmware and DMI strings:

| Source | String |
| --- | --- |
| `/sys/class/dmi/id/sys_vendor` | `VMware`, `innotek GmbH`, `QEMU`, `Microsoft Corporation`, `Parallels` |
| `/sys/class/dmi/id/product_name` | `VMware Virtual Platform`, `VirtualBox`, `Standard PC (Q35 + ICH9, 2009)`, `Virtual Machine` |
| `/sys/class/dmi/id/bios_vendor` | `SeaBIOS`, `American Megatrends`, `Phoenix Technologies LTD` |
| `/sys/class/dmi/id/chassis_type` | `1` (other) for many guests |
| SMBIOS type 0 strings | `VMware`, `VirtualBox`, `QEMU`, `KVM`, `Xen` |

Windows firmware tables via `EnumSystemFirmwareTables` / `GetSystemFirmwareTable`:

| Table | Guest value |
| --- | --- |
| ACPI `RSDT` | `VBOX`, `QEMU`, `VMW` |
| ACPI `FACP` | `VBOX`, `QEMU` |
| SMBIOS (`RSMB`) | `VMware`, `VirtualBox`, `QEMU` |
| ACPI `SPCR` | `Microsoft` on Hyper-V |

Windows registry:

```
HKLM\HARDWARE\DEVICEMAP\Scsi          ; values Scsi0..ScsiN contain "QEMU HARDDISK" / "VMware Virtual" / "Msft Virtual Disk"
HKLM\HARDWARE\DEVICEMAP\VideoScsi
HKLM\SYSTEM\CurrentControlSet\Services\VBoxGuest
HKLM\SYSTEM\CurrentControlSet\Services\VBoxSF
HKLM\SYSTEM\CurrentControlSet\Services\vmci
HKLM\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters
```

Android emulator build properties (`/system/build.prop`, `getprop`):

| Property | Emulator value | Physical value |
| --- | --- | --- |
| `ro.kernel.qemu` | `1` | absent |
| `ro.hardware` | `goldfish`, `ranchu` | `qcom`, `exynos`, `mtk` |
| `ro.product.device` | `generic`, `generic_x86`, `generic_x86_64` | vendor-specific |
| `ro.product.model` | `sdk`, `sdk_gphone64_x86_64`, `Android SDK built for x86_64` | vendor-specific |
| `ro.build.fingerprint` | contains `generic`, `sdk`, `emulator` | `google/.../user/release-keys` |
| `ro.boot.hardware` | `ranchu`, `goldfish` | vendor-specific |
| `ro.boot.qemu` | `1` | absent |
| `ro.build.description` | `sdk_phone_x86` | vendor string |
| `ro.serialno` | `unknown` | vendor serial |
| `init.goldfish.rc`, `init.ranchu.rc` | present | absent |

Android emulator artefacts: `/dev/socket/qemud`, `/dev/qemu_pipe`, `/dev/goldfish_pipe`,
`/sys/qemu_trace`, the `qemu.sf.fake_key` property.

iOS simulator signals:

| Signal | Value on the simulator |
| --- | --- |
| `TARGET_OS_SIMULATOR` | `1` (compile-time, from the SDK used) |
| `SIMULATOR_DEVICE_NAME` | `iPhone 15` |
| `SIMULATOR_UDID` | `1B2C3D4E-...` |
| `SIMULATOR_ROOT` | `/Users/<name>/Library/Developer/CoreSimulator/Devices/<udid>/data` |
| dyld shared cache path | `/Library/Developer/CoreSimulator/Volumes/iOS_*/.../RuntimeRoot/System/Library/Caches/com.apple.dyld` |
| `getenv("SIMULATOR_MODEL_IDENTIFIER")` | `iPhone15,2` |

## Method

### 1. Classify the signal by cost

A target that only reads DMI strings is cheap to defeat. A target that traps on
`in`/`out` to a VMware backdoor port is expensive. Establish which family is present before
choosing a bypass.

### 2. CPUID hypervisor-presence bit

The check reads leaf 1 and tests bit 31 of ECX.

Locate it in the binary:

```
r2 -q -c '/x 0fa2f7c180000000' target.exe
r2 -q -c '/x 0fa20fa3d1' target.exe
```

Two ways to defeat it.

**Byte patch.** The sequence is `b8 01 00 00 00 0f a2 f7 c1 80 00 00 00 75 0c`. Patch the `test`
so the flag is always clear, or patch the branch:

```
b8 01 00 00 00   0f a2   f7 c1 80 00 00 00   75 0c
-> b8 01 00 00 00   0f a2   81 e1 ff ff ff 7f   75 0c
```

Replacing `f7 c1 80 00 00 00` (`test ecx, 0x80000000`) with `81 e1 ff ff ff 7f` (`and ecx,
0x7fffffff`) clears the bit in place and preserves the 6-byte length. The following `75 0c` then
falls through.

**CPUID interception.** `cpuid` is an instruction, so no API hook reaches it. Two options:

- Patch the instruction sequence with `Memory.patchCode` in a Frida script, which is the same
  byte edit done at runtime.
- Use Frida `Stalker` to rewrite the `cpuid` block during execution, which handles a target that
  computes the check in more than one place.

```javascript
// frida 17.x — patch the CPUID hypervisor-bit test at runtime.
const f7c1 = [0xf7, 0xc1, 0x80, 0x00, 0x00, 0x00];   // test ecx, 0x80000000
const and7f = [0x83, 0xe1, 0x7f, 0x7f, 0xff, 0xff]; // and ecx, 0x7fffffff

Memory.scanSync(Process.mainModule.base, Process.mainModule.size, 'f7 c1 80 00 00 00')
    .forEach(function (match) {
        Memory.patchCode(match.address, 6, function (code) {
            // `code` is a writable pointer to the patched range.
            code.writeByteArray(new Uint8Array(and7f));
            console.log('patched CPUID hypervisor test at ' + match.address);
        });
    });
```

`Memory.patchCode` supplies a writable `code` pointer; the byte array is written through it with
`code.writeByteArray(...)`. A simpler variant that does not need `patchCode` is a direct write
when the page is already writable:

```javascript
// frida 17.x — direct in-memory patch of the CPUID hypervisor test.
Memory.scanSync(Process.mainModule.base, Process.mainModule.size, 'f7 c1 80 00 00 00')
    .forEach(function (match) {
        match.address.writeByteArray(new Uint8Array(and7f));
        console.log('patched at ' + match.address);
    });
```

### 3. Hypervisor brand string

Leaf `0x40000000` returns 12 bytes of vendor string in EBX, ECX, EDX. A target compares those
registers against known strings.

Bypass by patching the comparison:

```
; x64: cmp rax, rbx  (or a 4-byte immediate compare of the first dword)
48 39 c3   ->   31 c0 90
```

A more robust runtime bypass is to intercept the `cpuid` result at the level of the wrapper the
target calls. Many targets route the leaf through a helper function that returns the brand in a
buffer. Find that helper by following the cross-reference of the `cpuid` instruction and patch the
helper to write the string of a physical machine.

```javascript
// frida 17.x — neutralise a helper that returns the hypervisor brand string.
// The helper signature below is the common one: void brand(char out[13]).
const target = Process.mainModule.findExportByName('check_hypervisor_brand');
if (target !== null) {
    Interceptor.replace(target, new NativeCallback(function (out) {
        const physical = 'GENUINEINTEL';
        const bytes = [];
        for (let i = 0; i < 12; i++) {
            bytes.push(i < physical.length ? physical.charCodeAt(i) : 0);
        }
        out.writeByteArray(new Uint8Array(bytes));
    }, 'void', ['pointer']));
}
```

### 4. VMware backdoor port

VMware exposes a backdoor through the `in`/`out` I/O ports. The magic value is `VMXh`
(`0x564D5868`) and the classic command port is `0x5658` (`'VX'`). The probe reads a value from
port `0x5658` and checks the result against `VMXh`.

Instructions involved:

| Instruction | Bytes |
| --- | --- |
| `in eax, dx` | `ed` |
| `in eax, dx` (operand-size prefix form) | `66 ed` |
| `out dx, eax` | `ef` |
| `mov eax, 0x564D5868` | `b8 68 58 4d 56` |
| `mov dx, 0x5658` | `66 ba 58 56` |

Locate the probe:

```
r2 -q -c '/x b868584d56' target.exe
r2 -q -c '/x 66ba5856' target.exe
```

Bypass: patch the `in eax, dx` to produce a non-matching value. `ed` is one byte; replace it with
`31 c0` would be two bytes and change the length. A same-length replacement that clobbers `eax`
is not available in one byte. Options:

- Patch the comparison that follows the `in` instead: the target compares `eax` against
  `0x564D5868`, which is `3d 68 58 4d 56` (`cmp eax, imm32`). Replace with `83 f8 00` plus a NOP
  to preserve length: `3d 68 58 4d 56` -> `83 f8 00 90 90`.
- Under a hypervisor the `in` traps and the VM returns a value; under bare metal the `in` to an
  unassigned port is a fault. Either way the compare is the reliable patch point.

### 5. VirtualBox

Signals: the guest driver service `VBoxGuest`, the shared folder service `VBoxSF`, the file
`C:\Windows\System32\drivers\VBoxGuest.sys`, the `VBoxService` process, the "VBox" ACPI table, the
`VBoxSharedFolders` registry key, and the host-side window class.

Bypass:

```javascript
// frida 17.x — make the VirtualBox service registry lookup fail.
const advapi32 = Process.getModuleByName('advapi32.dll');
const origRegOpenKeyEx = new NativeFunction(advapi32.getExportByName('RegOpenKeyExA'),
    'int', ['pointer', 'pointer', 'uint32', 'uint32', 'pointer', 'pointer']);
Interceptor.replace(advapi32.getExportByName('RegOpenKeyExA'),
    new NativeCallback(function (hKey, subKey, options, samDesired, result) {
        const name = subKey.isNull() ? '' : subKey.readAnsiString();
        if (name.indexOf('VBox') !== -1 || name.indexOf('vmci') !== -1) {
            if (!result.isNull()) {
                result.writePointer(ptr(0));
            }
            return 2;      // FILE_NOT_FOUND
        }
        return origRegOpenKeyEx(hKey, subKey, options, samDesired, result);
    }, 'int', ['pointer', 'pointer', 'uint32', 'uint32', 'pointer', 'pointer']));
```

### 6. QEMU and KVM

Signals: SMBIOS strings `QEMU`, `Bochs`, `SeaBIOS`; the ACPI table `QEMU`; the PCI vendor
`0x1234` with device `0x1111`; the serial port `0x1f`; the DMI `sys_vendor` value `QEMU`; the
`/sys/bus/pci/devices/*/vendor` file containing `0x1234`.

Bypass the DMI read by hooking `fopen`/`read` and rewriting the content, or by patching the
comparison. A filesystem-level approach is to bind-mount a doctored `/sys/class/dmi/id`:

```
mount --bind /tmp/fake-dmi/sys_vendor /sys/class/dmi/id/sys_vendor
```

### 7. Hyper-V

Signals: the `Microsoft Hv` CPUID brand; the `Hv` ACPI table; the KVP GUID
`{3a2e4d0f-...}`; the registry key `HKLM\SYSTEM\CurrentControlSet\Services\vmicheartbeat`; the
`Microsoft Hv` string in the CPUID brand buffer.

### 8. MAC address OUI check

The target enumerates adapters and compares the first three octets against a table of known VM
OUIs. The bypass is to make the enumeration return a physical-looking address.

```javascript
// frida 17.x — rewrite the first adapter's MAC to a physical OUI.
const iphlpapi = Process.getModuleByName('iphlpapi.dll');
const origGetAdapters = new NativeFunction(iphlpapi.getExportByName('GetAdaptersInfo'),
    'uint32', ['pointer', 'pointer']);
Interceptor.replace(iphlpapi.getExportByName('GetAdaptersInfo'),
    new NativeCallback(function (adapterInfo, sizePtr) {
        const rc = origGetAdapters(adapterInfo, sizePtr);
        if (rc === 0 && !adapterInfo.isNull()) {
            // struct IP_ADAPTER_INFO: first adapter MAC at offset 0x20
            const mac = new Uint8Array([0x00, 0x1b, 0x63, 0x84, 0x45, 0xe6]);
            adapterInfo.add(0x20).writeByteArray(mac);
        }
        return rc;
    }, 'uint32', ['pointer', 'pointer']));
```

Confirm the offset of the MAC field in `IP_ADAPTER_INFO` against the SDK headers for the target
before relying on it.

### 9. Android emulator properties

```javascript
// frida 17.x — Android: make the emulator build properties look physical.
Java.perform(function () {
    const SystemProperties = Java.use('android.os.SystemProperties');
    const spoof = {
        'ro.kernel.qemu': '',
        'ro.boot.qemu': '',
        'ro.hardware': 'qcom',
        'ro.boot.hardware': 'qcom',
        'ro.product.device': 'sunfish',
        'ro.product.model': 'Pixel 5',
        'ro.build.fingerprint': 'google/sunfish/sunfish:13/TQ3A.230805.001/10316531:user/release-keys',
        'ro.build.description': 'sunfish-user 13 TQ3A.230805.001 release-keys',
        'qemu.sf.fake_key': ''
    };
    const origGet = SystemProperties.get;
    SystemProperties.get.implementation = function (key) {
        if (spoof.hasOwnProperty(key)) {
            return spoof[key];
        }
        return origGet.call(this, key);
    };
});
```

For a native read of `__system_property_get` in `libc`:

```javascript
// frida 17.x — Android native: intercept __system_property_get.
const libc = Process.getModuleByName('libc.so');
const origGetProp = new NativeFunction(libc.getExportByName('__system_property_get'),
    'int', ['pointer', 'pointer']);
Interceptor.replace(libc.getExportByName('__system_property_get'),
    new NativeCallback(function (name, value) {
        const n = name.readAnsiString();
        const fake = {
            'ro.hardware': 'qcom',
            'ro.product.device': 'sunfish',
            'ro.kernel.qemu': ''
        };
        if (fake.hasOwnProperty(n)) {
            const s = fake[n];
            for (let i = 0; i < s.length && i < 91; i++) {
                value.add(i).writeU8(s.charCodeAt(i));
            }
            value.add(s.length).writeU8(0);
            return s.length;
        }
        return origGetProp(name, value);
    }, 'int', ['pointer', 'pointer']));
```

Artefact checks need file-level handling: `/dev/qemu_pipe`, `/dev/socket/qemud`, `/dev/goldfish_pipe`
and `/sys/qemu_trace` are path probes. Hook `open`/`fopen` and make those paths fail with
`ENOENT`:

```javascript
// frida 17.x — hide emulator device nodes.
const libc = Process.getModuleByName('libc.so');
const blocked = ['/dev/qemu_pipe', '/dev/socket/qemud', '/dev/goldfish_pipe', '/sys/qemu_trace'];
const origOpen = new NativeFunction(libc.getExportByName('open'), 'int', ['pointer', 'int']);
Interceptor.replace(libc.getExportByName('open'),
    new NativeCallback(function (path, flags) {
        const p = path.readAnsiString();
        for (let i = 0; i < blocked.length; i++) {
            if (p === blocked[i]) {
                return -1;
            }
        }
        return origOpen(path, flags);
    }, 'int', ['pointer', 'int']));
```

### 10. iOS simulator

```javascript
// frida 17.x — iOS/macOS: report physical hardware to the simulator probe.
const libSystem = Process.getModuleByName('libSystem.B.dylib');
const origGetenv = new NativeFunction(libSystem.getExportByName('getenv'),
    'pointer', ['pointer']);

const hidden = ['SIMULATOR_DEVICE_NAME', 'SIMULATOR_UDID', 'SIMULATOR_ROOT',
                'SIMULATOR_MODEL_IDENTIFIER'];

Interceptor.replace(libSystem.getExportByName('getenv'),
    new NativeCallback(function (name) {
        const n = name.readAnsiString();
        for (let i = 0; i < hidden.length; i++) {
            if (n === hidden[i]) {
                return ptr(0);
            }
        }
        return origGetenv(name);
    }, 'pointer', ['pointer']));
```

The `TARGET_OS_SIMULATOR` macro is resolved at compile time, so a binary built for the simulator
SDK has the constant `1` embedded. Locate it by searching for the `TARGET_OS_SIMULATOR` comparison
or by inspecting the build settings. Patching the constant is a byte edit like any other.

### 11. macOS `sysctl` spoofing

The classic macOS virtualisation probe is `sysctlbyname("kern.hv_vmm_present")` or the
`hw.model` string. Hook `sysctlbyname`:

```javascript
// frida 17.x — macOS: spoof sysctlbyname answers.
const libSystem = Process.getModuleByName('libSystem.B.dylib');
const origSysctlbyname = new NativeFunction(libSystem.getExportByName('sysctlbyname'),
    'int', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'uint32']);

const spoof = {
    'kern.hv_vmm_present': 0,
    'hw.model': 'MacBookPro18,3',
    'kern.osproductversion': '14.6.1'
};

Interceptor.replace(libSystem.getExportByName('sysctlbyname'),
    new NativeCallback(function (name, oldp, oldlenp, newp, newlen) {
        const n = name.readAnsiString();
        if (spoof.hasOwnProperty(n)) {
            const value = spoof[n];
            const sizePtr = oldlenp.isNull() ? null : oldlenp;
            if (oldp.isNull() || sizePtr === null) {
                return 0;
            }
            if (typeof value === 'number') {
                oldp.writeU32(value);
                sizePtr.writeU32(4);
            } else {
                const buf = [];
                for (let i = 0; i < value.length; i++) {
                    buf.push(value.charCodeAt(i));
                }
                buf.push(0);
                oldp.writeByteArray(new Uint8Array(buf));
                sizePtr.writeU32(buf.length);
            }
            return 0;
        }
        return origSysctlbyname(name, oldp, oldlenp, newp, newlen);
    }, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'uint32']));
```

## Variations

- **Container vs virtual machine.** A Docker container shares the host kernel and passes most VM
  checks. Anti-analysis inside a container usually looks for container artefacts
  (`/.dockerenv`, `/proc/1/cgroup` containing `docker`, `container=` in `cgroup`) instead.
- **Nested virtualisation.** Running under a hypervisor on top of a hypervisor produces two brand
  strings. A check that compares the leaf `0x40000000` result against a *single* known vendor
  string passes on an unknown hypervisor.
- **Cloud instances.** EC2, GCE and Azure have known SMBIOS strings and ACPI table IDs of their
  own, and a target that only knows consumer hypervisor vendors will not detect them.
- **Hardware-assisted detection.** Some targets use the `RDSEED` instruction, or the
  `KVMKVMKVM` magic at port `0x5048`, or the "CPUID leaf `0x40000001`" vendor-specific register.
- **Timing and scheduling artefacts.** Virtualised environments show inflated and jittery clock
  deltas. A timing check sometimes catches a VM without any hypervisor query. See
  [timing-based-anti-debug](./timing-based-anti-debug.md).
- **Android emulator without QEMU.** The "Android Studio physical device" profile and the
  "Willow" / "Cuttlefish" images have different property sets than the classic `goldfish` build.
  Property spoofing must cover the whole set, not just `ro.kernel.qemu`.
- **Genymotion and other third-party emulators.** They keep the QEMU property set but change some
  values, and they often have no `goldfish` device.
- **iOS simulator with an attached debugger.** `lldb` attaches to the simulator's process the same
  way it attaches to a device, so simulator detection and debugger detection are independent and
  both must be handled.
- **Windows Sandbox and containers.** `C:\Windows\System32\vmcompute.exe` presence and the
  `Microsoft Corporation` DMI vendor indicate a Windows sandbox, not a classic VMware host.
- **ARM guests.** On arm64 hosts the equivalent of `cpuid` is the hypervisor identification
  register `MIDR_EL1` and the hypervisor traps. The `mrs x0, midr_el1` read is `d5380000`.
- **Managed runtimes.** .NET and JVM targets usually reach the same signals through a native
  helper library, so the helper is the patch target rather than the managed code.

## Verification

1. **Baseline on real hardware.** Confirm the target runs its normal path on a physical machine.
   Without this baseline a false positive on a virtualised test host is indistinguishable from a
   working bypass.
2. **Prove the detection fires.** Run the target under the emulator or hypervisor it checks for and
   confirm it takes the detection branch. Record the exact signal: with a debugger attached, break
   on the branch and read the compared value.
3. **Bypass proof.** Apply the bypass and re-run. Expected: the detection branch is not taken and
   the target behaves as on physical hardware.
4. **Negative test.** Remove the bypass and confirm the detection fires again. A bypass that
   appears to work may simply be a different emulator profile.
5. **Hook coverage.** Print every bypassed call:

   ```javascript
   // frida 17.x — count the calls that reach the emulator probe.
   const libc = Process.getModuleByName('libc.so');
   let hits = 0;
   const origOpen = new NativeFunction(libc.getExportByName('open'), 'int', ['pointer', 'int']);
   Interceptor.attach(libc.getExportByName('open'), {
       onEnter(args) {
           const p = args[0].readAnsiString();
           if (p.indexOf('/dev/qemu') !== -1 || p.indexOf('goldfish') !== -1) {
               hits++;
               console.log('emulator probe: ' + p);
           }
       },
       onLeave() {}
   });
   ```

   Expected: the count drops to zero after the bypass, and was non-zero before it.
6. **Property-level verification.** Dump the properties as the target sees them, not as the shell
   sees them:

   ```
   adb shell getprop | grep -Ei 'qemu|goldfish|ranchu|generic'
   ```

   Expected after the bypass: no `ro.kernel.qemu`, and `ro.hardware` reports the physical SoC.
7. **DMI verification.** Confirm the guest sees the spoofed strings:

   ```
   cat /sys/class/dmi/id/sys_vendor /sys/class/dmi/id/product_name
   ```

8. **False-positive check.** Run the bypassed target on physical hardware and confirm nothing
   breaks. A hook that changes global state (a wrong MAC, a spoofed model string) can break
   networking, licensing or telemetry.

## Pitfalls

- **The bit index.** The hypervisor-present flag is bit 31 of ECX after leaf 1. `bt ecx, 0x1F` is
  correct; `bt ecx, 0x1F` on the *input* ECX before `cpuid` is meaningless, because `cpuid`
  overwrites ECX.
- **`cpuid` clobbers registers.** `cpuid` overwrites EAX, EBX, ECX and EDX. A patch that replaces
  `cpuid` with `nop` corrupts the brand string even when the branch is right. Clear the specific
  bit instead of removing the instruction.
- **x86 PIC and EBX.** On 32-bit PIC code, `cpuid` clobbers EBX, so the compiler pushes and pops
  it around the instruction (`push ebx` / `pop ebx` = `53` / `5b`). Patching the instruction
  without restoring the stack breaks the frame.
- **The brand string is 12 bytes in four registers.** A comparison that only checks the first
  dword misses vendor names whose first dword differs.
- **`sysctlbyname` signature.** The real signature is
  `int sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen)`.
  Hooking it with the wrong arity corrupts the call.
- **Property names are cached.** On Android, `SystemProperties.get` returns a cached value on some
  API levels. Override the Java method and the native `__system_property_get` both.
- **`getenv` is used for more than the simulator.** Returning `NULL` for every `getenv` call
  breaks the process. Filter by the exact names.
- **DMI is a sysfs interface.** Files under `/sys/class/dmi/id` are read-only, and the values come
  from the firmware, so patching them requires root or a bind mount.
- **Hypervisor traps cost time.** A CPUID leaf the hypervisor does not implement is much slower
  than a native leaf. A target can measure the CPUID latency and detect a hypervisor even when the
  brand string is spoofed.
- **Enumerate everything.** A target usually checks several signals and treats any hit as
  detection. Neutralising one leaves the others armed.
- **Firmware tables need the right API.** `GetSystemFirmwareTable('ACPI')` returns the raw table
  blob; the provider string is at the start of the table. Parsing it requires the correct offsets
  for the table type.

## References

- `CPUID` instruction and hypervisor interception — https://wiki.osdev.org/CPUID
- `GetSystemFirmwareTable` — https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-getsystemfirmwaretable
- `EnumSystemFirmwareTables` — https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-enumsystemfirmwaretables
- `GetAdaptersInfo` — https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersinfo
- `SystemProperties.get` — https://developer.android.com/reference/android/os/SystemProperties
- Android emulator documentation — https://developer.android.com/studio/run/emulator
- `sysctlbyname` — https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/sysctlbyname.3.html
- `mach_absolute_time` and hypervisor detection on macOS — https://developer.apple.com/documentation/mach
- Frida JavaScript API (17.x) — https://frida.re/docs/javascript-api/
- Ghidra 12.2 — https://github.com/NationalSecurityAgency/ghidra/releases
