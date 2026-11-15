---
id: "hardware-fingerprint-binding"
title: "Hardware fingerprint binding"
domain: "license-crypto"
kind: "technique"
platforms: "windows, macos, linux, android, ios"
arch: "x86, x86-64, arm64"
difficulty: "advanced"
tools: "Frida, radare2, Python"
verified: false
updated: "2026-11-15"
summary: "Determine which machine identifiers an application folds into a licence digest, how to observe that digest's input at runtime, and how to force the collectors to fixed values so the fingerprint becomes reproducible."
---

## Summary

Hardware binding hashes a set of machine identifiers and stores the result in the licence.
The identifiers are usually stable, but not always, and the binding only works if the
application hashes exactly the same bytes in exactly the same order on every run.

The procedure has two halves that must be done together:

- **Identify the inputs.** Hook the digest function and dump its input buffer. The bytes
  reveal the fields, their order, the separators, and any normalisation.
- **Control the inputs.** Hook the collectors so each identifier returns a fixed value.
  The digest then becomes a pure function of the licence payload, and the licence can be
  produced for a machine that does not exist.

Doing only the second half without the first produces a digest that still varies, because
some unidentified field (a hostname, a user name, a timestamp) is still in the input.

## Recognition

**Identifiers by platform.**

| Platform | Identifier | Access path | Stability |
| --- | --- | --- | --- |
| Windows | Disk serial (WMI) | `Win32_DiskDrive.SerialNumber` (root\cimv2), `MSStorageDriver_FullDiskProperties.SerialNumber` (root\wmi) | stable until the disk is replaced or reformatted |
| Windows | Baseboard serial | `Win32_BaseBoard.SerialNumber` (root\cimv2) | stable, identical on identical OEM boards |
| Windows | BIOS serial | `Win32_BIOS.SerialNumber` | stable, often blank on desktops |
| Windows | SMART data | `DeviceIoControl` with `IOCTL_ATA_PASS_THROUGH` (0x4D02C) / `IOCTL_SCSI_PASS_THROUGH` (0x4D004), `SMART_RCV_DRIVE_DATA` (0x0BC802) | stable, ATA IDENTIFY DEVICE words 10-19 |
| Windows | Volume serial | `GetVolumeInformationW` | changes when the volume is reformatted |
| Windows | NIC MAC | `GetAdaptersInfo` → `PhysicalAddress` | changes with network randomisation |
| Windows | MachineGuid | `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` | stable per Windows installation |
| macOS | Platform UUID | `IOPlatformUUID` via IOKit | stable per machine, cloned in VM images |
| macOS | Platform serial | `IOPlatformSerialNumber` via IOKit | stable per machine |
| macOS | Disk serial | `IORegistryEntry` property `Device Serial Number` / `ApplePartition` | stable |
| macOS | USB serial | `IORegistryEntry` property `USB Serial Number` | stable per device, absent on many Macs |
| macOS | MAC | `getifaddrs` | changes with private Wi-Fi addressing |
| Linux | DMI UUID | `/sys/class/dmi/id/product_uuid` | stable, cloned in VM images |
| Linux | DMI serial | `/sys/class/dmi/id/product_serial` | stable |
| Linux | Machine ID | `/etc/machine-id` | stable per installation |
| Linux | NIC MAC | `/sys/class/net/<if>/address` | changes with randomisation |
| Linux | USB serial | `/sys/bus/usb/devices/*/serial` | stable per device |
| Android | ANDROID_ID | `Settings.Secure.getString(cr, "android_id")` | stable per app-signing-key and user since Android 8; reset on factory reset |
| Android | Build serial | `Build.SERIAL`, `Build.getSerial()` | restricted since Android 8, requires privileged permission |
| Android | Property serial | `getprop ro.serialno`, `ro.boot.serialno` | requires shell or root |

**Implementation signatures.**

```bash
rabin2 -i target.exe | grep -iE 'DeviceIoControl|GetVolumeInformation|GetAdaptersInfo|CoCreateInstance'
r2 -q -c 'izz~Win32_' target.exe
r2 -q -c 'izz~product_uuid' target.exe
```

A string list containing several of `Win32_DiskDrive`, `Win32_BaseBoard`, `SerialNumber`,
`ro.serialno`, `android_id` tells the collector is WMI/property based. A digest library in
the import table tells the fingerprint is hashed with a standard primitive.

**Symptoms.**

- The licence works on the original machine and not on a reinstall of the same machine —
  the fingerprint includes a software-side identifier.
- The licence stops working after a network change — a MAC address is included.
- The licence works on two cloned VM images — the identifiers are cloned with the image.
- The application asks the user to "allow access to hardware identifiers" — Android
  `Build.getSerial()` or a permissions dialog.

## Method

### Step 1 — Enumerate the candidates statically

Look for the strings and the API calls that produce identifiers:

```bash
r2 -q -c 'izz~serial' target.exe
r2 -q -c 'izz~uuid' target.exe
r2 -q -c 'izz~machine' target.exe
r2 -q -c 'aaa; axt @ sym.imp.DeviceIoControl' target.exe
r2 -q -c 'aaa; axt @ sym.imp.GetVolumeInformationW' target.exe
```

For a WMI-based collector the query strings are plain text in the binary:

```
SELECT SerialNumber FROM Win32_DiskDrive
SELECT SerialNumber FROM Win32_BaseBoard
```

For a Linux collector the file paths are plain text:

```
/sys/class/dmi/id/product_uuid
/sys/class/net/*/address
```

### Step 2 — Observe the digest input

This is the decisive step. The digest input buffer contains the fingerprint fields exactly as
the application assembles them.

```javascript
// dump_digest_input.js — Frida 17.x
//   frida -f target.exe -l dump_digest_input.js
function hex(p, n) {
  const b = new Uint8Array(p.readByteArray(n));
  let s = "";
  for (let i = 0; i < b.length; i++) {
    const c = b[i];
    s += (c >= 0x20 && c < 0x7f) ? String.fromCharCode(c) + "|" : ("0" + c.toString(16)).slice(-2) + " ";
  }
  return s.trim();
}
function ascii(p, n) {
  const b = new Uint8Array(p.readByteArray(n));
  let s = "";
  for (let i = 0; i < b.length; i++) {
    const c = b[i];
    s += (c >= 0x20 && c < 0x7f) ? String.fromCharCode(c) : ".";
  }
  return s;
}

function hookDigest(moduleName, exportName, dataArg, lenArg) {
  let mod;
  try {
    mod = Process.getModuleByName(moduleName);
  } catch (e) {
    console.log("[!] " + moduleName + " not loaded");
    return;
  }
  Interceptor.attach(mod.getExportByName(exportName), {
    onEnter(args) {
      const data = args[dataArg];
      const len = args[lenArg].toUInt32();
      if (len === 0 || len > 4096) return;
      console.log("[" + exportName + "] len=" + len);
      console.log("   ascii: " + ascii(data, len));
      console.log("   hex  : " + hex(data, len));
    }
  });
  console.log("[+] hooked " + moduleName + "!" + exportName);
}

// Windows CNG: NTSTATUS BCryptHash(hAlg, pbHashedData, cbHashedData, pbHashValue, cbHashValue, dwFlags)
hookDigest("bcrypt.dll", "BCryptHash", 1, 2);
// Windows CNG incremental: NTSTATUS BCryptHashData(hHash, pbInput, cbInput, dwFlags)
hookDigest("bcrypt.dll", "BCryptHashData", 1, 2);
// Windows CryptoAPI: BOOL CryptHashData(hHash, pbData, dwDataLen, dwFlags)
hookDigest("advapi32.dll", "CryptHashData", 1, 2);
// OpenSSL: int EVP_Digest(const EVP_MD *md, const void *data, size_t count, unsigned char *md_out, unsigned int *size, const EVP_MD *type, ENGINE *impl)
hookDigest("libcrypto.so.3", "EVP_Digest", 1, 2);
hookDigest("libcrypto.so.3", "EVP_DigestUpdate", 1, 2);
```

Expected output for a disk-serial-based fingerprint:

```
[BCryptHash] len=48
   ascii: 6E1C4A2B|WD-WCC4E1234567|11111111-2222-3333-4444-555555555555|
   hex  : 36 45 31 43 34 41 32 42 7c 57 44 2d 57 43 43 34 45 31 32 33 34 35 36 37 7c 31 31 31 31 ...
```

The separators are part of the input. Two fields separated by `|` means the concatenation is
`serial + "|" + baseboard + "|" + machineguid`.

If no library digest is called, the fingerprint uses a custom mixer. In that case hook the
consumer instead: the digest is compared against a stored value with `memcmp`. Log the
operands and pick the one that looks like a digest.

```javascript
// find_digest_compare.js — Frida 17.x
const libc = Process.getModuleByName("libc.so.6");
Interceptor.attach(libc.getExportByName("memcmp"), {
  onEnter(args) {
    const n = args[2].toUInt32();
    if (n === 16 || n === 20 || n === 32 || n === 64) {
      const a = ascii(args[0], n);
      const b = ascii(args[1], n);
      console.log("[memcmp " + n + "] a=" + a);
      console.log("[memcmp " + n + "] b=" + b);
    }
  }
});
```

The 16/32-byte operand that is *not* printable is the stored digest; the other operand is the
computed one. Its producer is the custom mixer, and the buffer that feeds it is the
fingerprint assembly buffer — dump it by breaking on the store into the mixer.

### Step 3 — Fix the collectors per platform

#### Windows: SMART and disk serial through `DeviceIoControl`

```javascript
// fix_windows_ids.js — Frida 17.x
const FIXED_DISK_SERIAL = "WD-WCC4E1234567";
const FIXED_VOLUME_SERIAL = 0x6E1C4A2B;

function hex(p, n) {
  const b = new Uint8Array(p.readByteArray(n));
  let s = "";
  for (let i = 0; i < b.length; i++) s += ("0" + b[i].toString(16)).slice(-2) + " ";
  return s.trim();
}

// DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned, lpOverlapped)
const k32 = Process.getModuleByName("kernel32.dll");
Interceptor.attach(k32.getExportByName("DeviceIoControl"), {
  onEnter(args) {
    this.ioctl = args[1].toUInt32();
    this.out = args[4];
    this.outLen = args[5].toUInt32();
  },
  onLeave(retval) {
    if (retval.toInt32() === 0) return;
    const code = this.ioctl;
    // IOCTL_ATA_PASS_THROUGH (0x4D02C) and IOCTL_SCSI_PASS_THROUGH (0x4D004):
    // the IDENTIFY DEVICE data lands in the DataBufferOffset area of the output buffer.
    if (code === 0x4D02C || code === 0x4D004) {
      console.log("[DeviceIoControl] IOCTL=0x" + code.toString(16) +
                  " out=" + hex(this.out, Math.min(this.outLen, 64)));
    }
    // IOCTL_DISK_GET_DRIVE_GEOMETRY_EX (0x700A0) returns DISK_GEOMETRY_EX
    if (code === 0x700A0 && this.outLen >= 0x28) {
      console.log("[DeviceIoControl] DISK_GEOMETRY_EX = " + hex(this.out, 0x28));
    }
  }
});

// Volume serial
Interceptor.attach(k32.getExportByName("GetVolumeInformationW"), {
  onEnter(args) { this.serial = args[3]; },
  onLeave(retval) {
    if (retval.toInt32() !== 0 && !this.serial.isNull()) {
      this.serial.writeU32(FIXED_VOLUME_SERIAL);
      console.log("[hook] GetVolumeInformationW serial -> 0x" + FIXED_VOLUME_SERIAL.toString(16));
    }
  }
});
```

Overwriting the serial *inside* the SMART buffer requires knowing the exact layout: for
`IOCTL_ATA_PASS_THROUGH`, the output buffer is an `ATA_PASS_THROUGH` structure whose
`DataBufferOffset` points at the 512-byte IDENTIFY DEVICE data, and the serial number is at
word offset 10 (byte offset 20), 20 bytes, space-padded, swapped byte order.

```javascript
// patch_identify_serial.js — Frida 17.x
// Runs after the SMART read, rewrites the ATA serial number in place.
const FIXED_SERIAL_ATA = "WD-WCC4E1234567";   // 20 chars, space padded

function patchIdentifySerial(dataPtr) {
  const raw = FIXED_SERIAL_ATA.padEnd(20, " ").split("");
  for (let i = 0; i < 20; i++) {
    const word = i >> 1;
    const hi = (i & 1) === 0 ? 0 : 1;
    const off = word * 2 + hi;
    const cur = dataPtr.add(off).readU8();
    const want = raw[i].charCodeAt(0);
    if (cur !== want) {
      dataPtr.add(off).writeU8(want);
    }
  }
}
```

The byte order of ATA IDENTIFY strings is swapped within each 16-bit word; the loop above
writes each character into the correct half-word position.

#### Windows: WMI

WMI results are returned as COM objects, which makes interception awkward. Two workable
techniques:

1. **Hook the string allocator.** Every WMI string property is allocated with
   `SysAllocStringLen` in `oleaut32.dll`. Logging strings of serial-like shape finds the
   value and its property name.

   ```javascript
   // hook_wmi_strings.js — Frida 17.x
   const ole = Process.getModuleByName("oleaut32.dll");
   Interceptor.attach(ole.getExportByName("SysAllocStringLen"), {
     onEnter(args) {
       const len = args[0].toUInt32();
       if (len >= 6 && len <= 40) {
         const p = args[1];
         if (p.isNull()) return;
         const b = new Uint8Array(p.readByteArray(len * 2));
         let s = "";
         for (let i = 0; i < b.length; i += 2) {
           const c = b[i] | (b[i + 1] << 8);
           s += (c >= 0x20 && c < 0x7f) ? String.fromCharCode(c) : ".";
         }
         if (/^[A-Za-z0-9._-]{6,40}$/.test(s)) {
           console.log("[SysAllocStringLen] len=" + len + " '" + s + "'");
         }
       }
     }
   });
   ```

2. **Enumerate the same values externally** and compare with the digest input, to confirm
   which property is which:

   ```powershell
   Get-CimInstance Win32_DiskDrive | Select-Object SerialNumber
   Get-CimInstance Win32_BaseBoard | Select-Object SerialNumber
   Get-CimInstance Win32_BIOS | Select-Object SerialNumber
   ```

#### macOS: IOKit properties

```javascript
// fix_macos_ids.js — Frida 17.x
const FIXED_UUID = "A1B2C3D4-E5F6-4711-8899-AABBCCDDEEFF";

function findModule(needle) {
  for (const m of Process.enumerateModules()) {
    if (m.path.indexOf(needle) !== -1) return m;
  }
  return null;
}

const ioKitMod = findModule("IOKit");
const cfMod = findModule("CoreFoundation");

if (ioKitMod && cfMod) {
  const io = Process.getModuleByName(ioKitMod.path);
  const cf = Process.getModuleByName(cfMod.path);
  const CFStringGetCStringPtr = new NativeFunction(
    cf.getExportByName("CFStringGetCStringPtr"), "pointer", ["pointer", "uint32"]);
  const CFStringCreateWithCString = new NativeFunction(
    cf.getExportByName("CFStringCreateWithCString"), "pointer",
    ["pointer", "pointer", "uint32", "uint32"]);
  const CFRelease = new NativeFunction(cf.getExportByName("CFRelease"), "void", ["pointer"]);
  const kCFStringUTF8Encoding = 0x08000100;

  const ioProperties = ["IOPlatformUUID", "IOPlatformSerialNumber",
                         "Device Serial Number", "USB Serial Number",
                         "ApplePartition", "IORegistryEntryName"];

  Interceptor.attach(io.getExportByName("IORegistryEntryCreateCFProperty"), {
    onEnter(args) { this.key = args[1]; },
    onLeave(retval) {
      if (retval.isNull() || this.key.isNull()) return;
      const cstr = CFStringGetCStringPtr(this.key, 0);
      if (cstr.isNull()) return;
      const key = cstr.readUtf8String();
      if (ioProperties.indexOf(key) === -1) return;
      const replacement = (key === "IOPlatformUUID") ? FIXED_UUID : "FIXEDSERIAL0001";
      CFRelease(retval);
      const buf = Memory.allocUtf8String(replacement);
      retval.replace(CFStringCreateWithCString(ptr(0), buf, kCFStringUTF8Encoding, 0));
      console.log("[hook] " + key + " -> " + replacement);
    }
  });
  console.log("[+] IOKit property hook installed");
}
```

`IOPlatformUUID` and `IOPlatformSerialNumber` on the host, for comparison:

```bash
ioreg -rd1 -c IOPlatformExpertDevice | grep -E 'IOPlatformUUID|IOPlatformSerialNumber'
ioreg -p IOUSB -l | grep -i 'USB Serial Number'
```

#### Linux: sysfs and netlink

```javascript
// fix_linux_ids.js — Frida 17.x
const FIXED_MACHINE_ID = "a1b2c3d4e5f60718293a4b5c6d7e8f90";
const FIXED_DMI_UUID = "A1B2C3D4-E5F6-4711-8899-AABBCCDDEEFF";
const FIXED_MAC = "02:11:22:33:44:55";

const REDIRECT = {
  "/etc/machine-id": "/tmp/fake-machine-id",
  "/var/lib/dbus/machine-id": "/tmp/fake-machine-id",
  "/sys/class/dmi/id/product_uuid": "/tmp/fake-product-uuid",
  "/sys/class/dmi/id/product_serial": "/tmp/fake-product-serial"
};

const libc = Process.getModuleByName("libc.so.6");

// open()/openat() redirection
["open", "openat"].forEach(function (name) {
  let fn;
  try { fn = libc.getExportByName(name); } catch (e) { return; }
  Interceptor.attach(fn, {
    onEnter(args) {
      const idx = (name === "openat") ? 1 : 0;
      let p = null;
      try { p = args[idx].readUtf8String(); } catch (e) { return; }
      if (p !== null && Object.prototype.hasOwnProperty.call(REDIRECT, p)) {
        args[idx] = Memory.allocUtf8String(REDIRECT[p]);
        console.log("[hook] " + name + " " + p + " -> " + REDIRECT[p]);
      }
    }
  });
});

// getifaddrs(): patch the MAC of the first non-loopback interface
const getifaddrs = libc.getExportByName("getifaddrs");
Interceptor.attach(getifaddrs, {
  onLeave(retval) {
    if (retval.toInt32() !== 0) return;
    let node = retval;
    for (let i = 0; i < 16; i++) {
      const next = node.readPointer();
      const addr = node.add(0x18).readPointer();   // struct ifaddrs: ifa_addr
      const flags = node.add(0x30).readU32();      // ifa_flags (offset varies by arch)
      if (!addr.isNull()) {
        const family = addr.readU16();
        if (family === 1 /* AF_UNIX */) { /* skip */ }
        if (family === 17 /* AF_PACKET */) {
          const mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
          addr.add(2).writeByteArray(mac);
          console.log("[hook] getifaddrs MAC -> " + FIXED_MAC);
          return;
        }
      }
      if (next.isNull()) break;
      node = next;
    }
  }
});
```

The `struct ifaddrs` field offsets differ between architectures; verify them on the host
before relying on the hook:

```bash
cat > /tmp/ifa.c <<'EOF'
#include <stdio.h>
#include <ifaddrs.h>
#include <stddef.h>
int main(void){
  struct ifaddrs *ifa; getifaddrs(&ifa);
  printf("sizeof(struct ifaddrs)=%zu ifa_addr=%zu ifa_flags=%zu ifa_data=%zu\n",
         sizeof(struct ifaddrs), offsetof(struct ifaddrs, ifa_addr),
         offsetof(struct ifaddrs, ifa_flags), offsetof(struct ifaddrs, ifa_data));
  return 0;
}
EOF
cc -o /tmp/ifa /tmp/ifa.c && /tmp/ifa
```

#### Android: properties and Settings.Secure

```typescript
// fix_android_ids.ts — Frida 17.x (JavaScript TypeScript for frida-compile)
Java.perform(() => {
  // Settings.Secure.ANDROID_ID
  try {
    const SettingsSecure = Java.use("android.provider.Settings$Secure");
    const getString = SettingsSecure.getString.overload(
        "android.content.ContentResolver", "java.lang.String");
    getString.implementation = function (cr, name) {
      const v = getString.call(this, cr, name);
      if (name === "android_id") {
        console.log("[hook] ANDROID_ID -> 1111111122222222");
        return "1111111122222222";
      }
      return v;
    };
  } catch (e) {
    console.log("[!] Settings.Secure unavailable: " + e);
  }

  // Build.getSerial() (API 26+)
  try {
    const Build = Java.use("android.os.Build");
    Build.getSerial.overload().implementation = function () {
      console.log("[hook] Build.getSerial -> FIXEDSERIAL0001");
      return "FIXEDSERIAL0001";
    };
  } catch (e) {
    console.log("[!] Build.getSerial unavailable");
  }

  // MessageDigest.update(byte[]) to observe the fingerprint input
  try {
    const MessageDigest = Java.use("java.security.MessageDigest");
    MessageDigest.update.overload("[B").implementation = function (data) {
      const s = Java.use("java.lang.String").$new(data);
      console.log("[MessageDigest.update] " + s);
      return this.update(data);
    };
  } catch (e) {
    console.log("[!] MessageDigest hook unavailable");
  }
});
```

For native Android code reading system properties, hook the property API:

```javascript
// hook_android_props.js — Frida 17.x
const libc = Process.getModuleByName("libc.so");
const get = libc.getExportByName("__system_property_get");
Interceptor.attach(get, {
  onEnter(args) {
    this.name = args[0].readCString();
  },
  onLeave(retval) {
    if (this.name === "ro.serialno" || this.name === "ro.boot.serialno") {
      const value = "FIXEDSERIAL0001";
      const buf = Memory.allocUtf8String(value);
      retval.replace(buf);
      console.log("[hook] " + this.name + " -> " + value);
    }
  }
});
```

`__system_property_get` writes into a caller-provided buffer and returns its length, so the
value must be written into `args[1]` rather than the return value. The code above is the
simplified form; for a correct implementation, write the value into the buffer the caller
supplied:

```javascript
Interceptor.attach(get, {
  onEnter(args) {
    this.name = args[0].readCString();
    this.buf = args[1];
    this.len = args[2].toInt32();
  },
  onLeave(retval) {
    if (this.name === "ro.serialno" || this.name === "ro.boot.serialno") {
      const value = "FIXEDSERIAL0001";
      this.buf.writeUtf8String(value);
      retval.replace(ptr(value.length));
      console.log("[hook] " + this.name + " -> " + value);
    }
  }
});
```

### Step 4 — Re-derive the fingerprint and forge the licence

With every collector fixed, the digest input becomes a known byte string. Reproduce it
offline:

```python
# fingerprint.py — reproduce the digest input observed in the dump_digest_input.js output
import hashlib

SEPARATOR = "|"
DISK_SERIAL = "WD-WCC4E1234567"
BASEBOARD = "FIXEDSERIAL0001"
MACHINE_GUID = "11111111-2222-3333-4444-555555555555"

def fingerprint_material() -> bytes:
    """Exactly the bytes fed to the digest function, in the observed order."""
    return SEPARATOR.join([DISK_SERIAL, BASEBOARD, MACHINE_GUID]).encode("utf-8")

def fingerprint() -> str:
    return hashlib.sha256(fingerprint_material()).hexdigest()

if __name__ == "__main__":
    print(fingerprint_material())
    print(fingerprint())
```

The application may hash the fingerprint together with the licence payload. Then the digest
input is `payload + fingerprint` and the licence has to be produced with the *fixed*
fingerprint value; the assembly routine in
[Keygen construction from a recovered algorithm](keygen-construction.md) applies unchanged.

## Variations

**Disk serial versus volume serial.** The volume serial changes on a reformat; the disk
serial does not. A vendor that wants a permanent binding uses the disk serial, obtained via
SMART or WMI, not `GetVolumeInformation`.

**Cloned virtual machines.** VM images clone the DMI UUID, the disk serial and often the
volume serial. A fingerprint built from these values is identical on every clone, which is
why many vendors mix in a machine-specific value such as the MachineGuid or an
`ANDROID_ID`.

**Randomised MAC addresses.** Windows 10 and later, and Android 9 and later, randomise MAC
addresses per network. A fingerprint that includes a MAC address can change when the
machine joins a different network. Vendors that want stability use the NIC's permanent
address, which on Windows requires reading the `NetworkAddress` registry value or the
adapter's `OID_802_3_PERMANENT_ADDRESS` through `GetAdaptersAddresses`.

**Android `ANDROID_ID` semantics.** Since Android 8 the value is scoped to the app's
signing key, the user and the device, so it survives app updates but changes on reinstall
with a different key or after a factory reset. Vendors that also embed the package name in
the hash keep the binding stable across reinstalls.

**iOS `identifierForVendor`.** Changes when all apps from a vendor are removed. It is not
suitable for a permanent binding, and App Store review rejects licences bound to it.

**Composite digests.** Some applications hash each identifier separately and concatenate the
digests, or use a Merkle-style construction. The dump of the digest input shows this
directly: 64 hex characters that are two 32-character halves point to SHA-256 of two
separate inputs.

**HMAC with a device secret.** Some products store a per-device secret in the TPM or the
keychain and use it as the HMAC key, so the fingerprint is not derivable from public
identifiers. Read the secret at runtime with the same digest-input technique.

**Anti-tamper on the fingerprint buffer.** A few products recompute the fingerprint twice
and compare, to detect hooks. Fixing the collector is still the cleaner route.

## Verification

1. **Digest input identified.** The `dump_digest_input.js` output shows printable ASCII
   containing the identifiers, with the separators visible. The field order is unambiguous.
2. **Collector override confirmed.** After the fix script is installed, the digest input
   shows the fixed constants instead of the host values. This is the key check: it proves
   every input field is controlled, including fields that were not obvious from the strings.
3. **Fingerprint stability.** Run the application twice, with a reboot in between, and
   confirm the digest input is byte-identical both times.
4. **Licence acceptance.** Apply a licence produced for the fixed fingerprint and confirm
   the licensed state appears.
5. **Negative test — the binding is real.** Remove the fix script and restore the original
   state, then apply the same licence. The application must reject it. If it still accepts,
   the fingerprint never entered the decision.
6. **Negative test — a different fingerprint is rejected.** Change one fixed constant and
   regenerate the licence. The previous licence must be rejected.
7. **Cross-check against the binary.** The separators and the concatenation order observed
   at runtime must appear as literals in the binary:
   `r2 -q -c '/x 7c' target.exe` and `r2 -q -c 'izz~|' target.exe`.

## Pitfalls

- **Only some fields are fixed.** The digest input still contains a hostname, a user name, a
  CPU count or a timestamp. Always read the dump output and fix every field, not only the
  ones the strings suggested.
- **The digest input is not the raw identifiers.** The application lowercases, truncates,
  strips separators or hashes each field individually before concatenating. The dump shows
  the *post-normalisation* bytes, so reproduce those bytes, not the collector output.
- **Order matters.** `a + "|" + b` and `b + "|" + a` produce different digests. The dump
  output is the only reliable source of the order.
- **UTF-16 vs UTF-8.** A Windows application that hashes wide strings produces a different
  digest than one that hashes UTF-8. The dump shows single-byte separators when the input is
  UTF-8; wide input shows `7c 00 7c 00`.
- **Hooking the wrong layer.** Overriding `GetVolumeInformationW` does not change a WMI
  `Win32_DiskDrive.SerialNumber` query; they are different sources with different values.
- **Property read restrictions.** On Android 8 and later `Build.SERIAL` is a placeholder and
  `Build.getSerial()` throws without the privileged permission. Hooking the Java method is
  the way around it.
- **The digest happens in two stages.** A first hash over the identifiers feeds a second
  hash with the payload. Hooking only the second stage misses the fingerprint fields; hook
  both and compare the inputs.
- **The fingerprint includes a timestamp.** A per-launch salt in the input makes the digest
  non-deterministic by design; find it in the dump and fix it too.
- **ARM64 struct offsets.** The `struct ifaddrs` and `PIP_ADAPTER_INFO` layouts differ by
  architecture; verify offsets on the host before trusting the hooks.
- **Hook timing.** The identifiers are collected very early, sometimes before the UI
  appears. Spawn the process (`frida -f ...`) so the first collection is caught.
- **Kernel-mode identifiers.** Some products read identifiers through a driver or through
  `SMART` on a raw device handle that requires administrator rights. Running the target
  elevated makes the read possible; without it the value may be all zeroes, which changes
  the digest.

## References

- Windows `DeviceIoControl`, `IOCTL_ATA_PASS_THROUGH`, `SMART_RCV_DRIVE_DATA`,
  `GetVolumeInformationW`, `GetAdaptersAddresses` —
  <https://learn.microsoft.com/windows/win32/api/ioapiset/>
- WMI `Win32_DiskDrive`, `Win32_BaseBoard`, `MSStorageDriver_FullDiskProperties` —
  <https://learn.microsoft.com/windows/win32/wmisdk/>
- Apple IOKit `IORegistryEntryCreateCFProperty`, `IOPlatformUUID` —
  <https://developer.apple.com/documentation/iokit>
- Linux DMI and sysfs identifiers —
  <https://www.kernel.org/doc/Documentation/arch/x86/boot/boot.txt>
- Android `Settings.Secure.ANDROID_ID`, `Build.getSerial` —
  <https://developer.android.com/reference/android/provider/Settings.Secure> ,
  <https://developer.android.com/reference/android/os/Build>
- Frida 17.x `Interceptor` API — <https://frida.re/docs/javascript-api/>
- Sibling entries: [Offline activation and machine binding](offline-activation-and-machine-binding.md),
  [Symmetric licence blob formats](symmetric-license-blob-formats.md),
  [Asymmetric licence signature verification](asymmetric-license-signature-verification.md),
  [Keygen construction from a recovered algorithm](keygen-construction.md)
