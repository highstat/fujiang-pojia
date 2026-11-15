---
id: "offline-activation-and-machine-binding"
title: "Offline activation and machine binding"
domain: "license-crypto"
kind: "playbook-ref"
platforms: "windows, macos, linux, android, ios"
arch: "x86, x86-64, arm64"
difficulty: "advanced"
tools: "Frida, radare2, Python"
verified: false
updated: "2026-11-15"
summary: "Reconstruct an offline activation handshake, collect and normalise the machine fingerprint it binds to, and satisfy that binding either by forcing the collected value to a constant or by neutralising the comparison."
---

## Summary

An offline activation flow has three artefacts:

1. **Request blob** — produced by the application, containing product, version, machine
   fingerprint, and often a nonce.
2. **Response blob** — returned by the vendor, containing the licence fields and a signature
   over them (see
   [Asymmetric licence signature verification](asymmetric-license-signature-verification.md)).
3. **Stored state** — where the application writes the accepted response, usually a file,
   registry key, or preferences database.

The machine fingerprint is the part that breaks offline transfers: a licence generated for one
machine is rejected on another because the response blob embeds the fingerprint and the
application recomputes it. Two ways to satisfy the binding:

- **Force the collected value.** Make the fingerprint collector return a constant you control,
  then produce a licence for that constant. The rest of the application stays untouched.
- **Neutralise the comparison.** Patch the branch that compares the collected fingerprint (or
  its digest) against the value inside the response blob.

The first is preferred: it keeps every other check intact and produces a licence that is
genuinely valid rather than a licence that merely slips past one branch.

## Recognition

**Handshake artefacts.**

- A "Request ID", "Activation request", "Offline request", or `*.req` file written on first
  run, containing base64 or hex text.
- An import/export pair in the UI: `Generate request file` / `Import license file`.
- Strings: `offline activation`, `activation request`, `machine id`, `device id`,
  `hardware id`, `fingerprint`, `request code`, `activation code`.
- A vendor page that asks for a "request code" or "system ID" and returns an activation code.

**Fingerprint sources and their distinguishing artefacts.**

| Platform | Source | Artefact / API |
| --- | --- | --- |
| Windows | MachineGuid | `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`, read with `RegGetValueA`/`RegQueryValueExA` |
| Windows | Volume serial | `GetVolumeInformationW` → `LPDWORD` serial, e.g. `6E1C-4A2B` |
| Windows | CPU | `CPUID` leaf 1 (processor signature) and leaf 3 (serial) |
| Windows | Computer name | `GetComputerNameW` |
| Windows | MAC | `GetAdaptersInfo` (iphlpapi.dll) → `PhysicalAddress` |
| macOS | Platform UUID | `IOPlatformUUID` via `IORegistryEntryCreateCFProperty` |
| macOS | Platform serial | `IOPlatformSerialNumber`, same mechanism |
| macOS | MAC | `getifaddrs` → `ifa_addr->sa_data` |
| macOS | Host name | `gethostname` / `SCDynamicStoreCopyComputerName` |
| Linux | Machine ID | `/etc/machine-id` or `/var/lib/dbus/machine-id` |
| Linux | DMI UUID | `/sys/class/dmi/id/product_uuid` |
| Linux | MAC | `getifaddrs`, or `/sys/class/net/<if>/address` |
| Android | ANDROID_ID | `Settings.Secure.getString(cr, "android_id")` |
| Android | Serial | `Build.SERIAL`, `getprop ro.serialno` |

**Static hints.**

```bash
rabin2 -i target.exe | grep -iE 'GetVolumeInformation|GetComputerName|GetAdaptersInfo|RegGetValue|RegQueryValue|CryptGenRandom'
rabin2 -z target.exe | grep -iE 'machine-id|product_uuid|IOPlatformUUID|MachineGuid'
r2 -q -c 'izz~Cryptography' target.exe     # Windows MachineGuid path
r2 -q -c 'izz~etc/machine' target.exe
```

A `hex` of the collected value (32 hex characters for a GUID, 16 for a volume serial) in the
binary usually means the expected fingerprint is embedded, which narrows the whole search to
one constant.

## Method

### Step 1 — Map the handshake

Find where the request blob is written and where the response is parsed.

```bash
r2 -q -c 'izz~activation_request' target.exe
r2 -q -c 'izz~license.dat' target.exe
r2 -q -c 'aaa; axt @ sym.imp.CreateFileW' target.exe
```

Record:

- Where the request is stored (path or registry key).
- Where the response is read from.
- Which function parses the response and which function validates it.

### Step 2 — Collect the fingerprint sources

Read each candidate source directly on the host to see the format the app will see.

```bash
# Linux
cat /etc/machine-id
cat /sys/class/dmi/id/product_uuid
cat /sys/class/net/*/address

# macOS
ioreg -rd1 -c IOPlatformExpertDevice | grep -E 'IOPlatformUUID|IOPlatformSerialNumber'
```

```powershell
# Windows PowerShell
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' | Select-Object MachineGuid
Get-Volume | Select-Object DriveLetter, UniqueId
Get-CimInstance Win32_BIOS | Select-Object SerialNumber
```

### Step 3 — Find the normalisation

The raw collector output is almost never what is compared. The usual normalisations:

| Normalisation | Implementation evidence |
| --- | --- |
| Lowercased | a `tolower`/`_tolower`/`toLowerCase` call in the loop over the string |
| Separators stripped | `-`/`:`/`-` removed by a `strchr`+`memmove` sequence or by skipping in the copy loop |
| Hex-decoded | `sscanf("%08x")`, `strtoul(s, NULL, 16)`, or `UInt32::from_str_radix` |
| Truncated to N characters | a `cmp` against a small constant length |
| First MAC only | a loop over the adapter list that breaks after the first entry |
| Digits only | `if (c >= '0' && c <= '9')` in the copy loop |

Locate the normalisation code:

```bash
r2 -q -c 'aaa; axt @ sym.imp.tolower' target.exe
r2 -q -c 'aaa; axt @ sym.imp.strtoul' target.exe
r2 -q -c 'izz~%08x' target.exe
```

Read the loop that builds the normalised string. A typical x64 normalisation loop:

```asm
0x140002500  xor  r10d, r10d             ; output length
0x140002503  mov  r11, rsi               ; source
0x140002506  movzx eax, byte [r11+r10]
0x14000250a  cmp  al, 0x2d               ; '-'
0x14000250d  je   0x140002520
0x14000250f  cmp  al, 0x3a               ; ':'
0x140002512  je   0x140002520
0x140002514  movzx edx, al
0x140002517  call qword [rip+0x1d80]      ; tolower
0x14000251d  mov  [rdi+r10], dl
0x140002521  inc  r10d
0x140002524  cmp  r10d, rdx_len
0x140002528  jne  0x140002506
```

Note that `tolower` is locale-sensitive: on Windows `CharLowerBuffW` is used for wide strings,
and `LCMapStringEx` with `LCMAP_LOWERCASE` is the modern path.

### Step 4 — Force the collected value to a constant

Pick the representation the application expects *after* normalisation. If the app lowercases
and strips separators, the constant you feed must be the already-normalised form.

#### Windows: volume serial, computer name, MachineGuid, MAC

```javascript
// fix_fingerprint_win.js — Frida 17.x
//   frida -f target.exe -l fix_fingerprint_win.js
const FIXED_VOLUME_SERIAL = 0x12345678;   // as returned in the LPDWORD out-parameter
const FIXED_MACHINE_GUID  = "11111111-2222-3333-4444-555555555555";
const FIXED_COMPUTER_NAME = "DESKTOP-AAAAAAA";
const FIXED_MAC           = "02:11:22:33:44:55";

function hex(p, n) {
  const b = new Uint8Array(p.readByteArray(n));
  let s = "";
  for (let i = 0; i < b.length; i++) s += ("0" + b[i].toString(16)).slice(-2) + " ";
  return s.trim();
}

// GetVolumeInformationW(root, name, nameLen, &serial, &maxComp, &flags, fsName, fsNameLen)
const k32 = Process.getModuleByName("kernel32.dll");
Interceptor.attach(k32.getExportByName("GetVolumeInformationW"), {
  onEnter(args) { this.serialPtr = args[3]; },
  onLeave(retval) {
    if (retval.toInt32() !== 0 && !this.serialPtr.isNull()) {
      this.serialPtr.writeU32(FIXED_VOLUME_SERIAL);
      console.log("[hook] GetVolumeInformationW serial -> 0x" + FIXED_VOLUME_SERIAL.toString(16));
    }
  }
});

// GetComputerNameW(buf, &size)
Interceptor.attach(k32.getExportByName("GetComputerNameW"), {
  onEnter(args) { this.buf = args[0]; },
  onLeave(retval) {
    if (retval.toInt32() !== 0) {
      const w = FIXED_COMPUTER_NAME + "\0";
      this.buf.writeUtf16String(FIXED_COMPUTER_NAME);
      console.log("[hook] GetComputerNameW -> " + FIXED_COMPUTER_NAME);
    }
  }
});

// RegGetValueA / RegQueryValueExA for the MachineGuid
try {
  const adv = Process.getModuleByName("advapi32.dll");
  Interceptor.attach(adv.getExportByName("RegGetValueA"), {
    onEnter(args) {
      this.data = args[5];
      this.size = args[6];
    },
    onLeave(retval) {
      if (retval.toInt32() === 0 && !this.data.isNull()) {
        const bytes = Array.from(new Uint8Array(0)).length; // placeholder, kept explicit
        const s = FIXED_MACHINE_GUID + "\0";
        this.data.writeUtf8String(FIXED_MACHINE_GUID);
        if (!this.size.isNull()) this.size.writeU32(s.length);
        console.log("[hook] RegGetValueA -> " + FIXED_MACHINE_GUID);
      }
    }
  });
} catch (e) {
  console.log("[!] advapi32 RegGetValueA not available");
}

// GetAdaptersInfo -> overwrite the MAC of the first adapter
try {
  const iph = Process.getModuleByName("iphlpapi.dll");
  Interceptor.attach(iph.getExportByName("GetAdaptersInfo"), {
    onEnter(args) { this.buf = args[0]; },
    onLeave(retval) {
      if (retval.toInt32() === 0xFFFFFFFE) return;   // ERROR_BUFFER_OVERFLOW
      // PIP_ADAPTER_INFO: Next(offset 0) Length(offset 8) PhysicalAddress(offset 0x14)
      const mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
      let node = this.buf;
      for (let i = 0; i < 8; i++) {
        const len = node.add(8).readU32();
        const physLen = node.add(0x11).readU32();
        if (physLen >= 6) {
          node.add(0x14).writeByteArray(mac);
          console.log("[hook] GetAdaptersInfo MAC -> " + FIXED_MAC);
          break;
        }
        if (len === 0) break;
        node = node.add(len);
      }
    }
  });
} catch (e) {
  console.log("[!] GetAdaptersInfo not available");
}
```

The `PIP_ADAPTER_INFO` layout used above is: `Next` (pointer, offset 0), `ComboIndex`
(offset 8), `AdapterName` (4 bytes), `Description` (128 bytes), `PhysicalAddressLength`
(offset 0x11), `PhysicalAddress` (offset 0x14). Confirm the offsets for the target SDK before
relying on them; the same hook works more robustly when the application formats the MAC with
`inet_ntoa`/`FormatAdapter`, so hooking `GetAdaptersInfo` plus reading the returned buffer
with `r2`-style struct knowledge is often faster than guessing.

#### macOS: IOPlatformUUID and IOPlatformSerialNumber

```javascript
// fix_fingerprint_macos.js — Frida 17.x
const FIXED_UUID   = "A1B2C3D4-E5F6-4711-8899-AABBCCDDEEFF";
const FIXED_SERIAL = "C02XXXXXABCD";

function findModule(needle) {
  const mods = Process.enumerateModules();
  for (const m of mods) {
    if (m.name.indexOf(needle) !== -1 || m.path.indexOf(needle) !== -1) return m;
  }
  return null;
}

const cfMod = findModule("CoreFoundation");
const cf = cfMod.getExportByName ? cfMod : null;
const CFStringGetCStringPtr = new NativeFunction(
  Process.getModuleByName(cfMod.path).getExportByName("CFStringGetCStringPtr"),
  "pointer", ["pointer", "uint32"]);
const CFStringCreateWithCString = new NativeFunction(
  Process.getModuleByName(cfMod.path).getExportByName("CFStringCreateWithCString"),
  "pointer", ["pointer", "pointer", "uint32", "uint32"]);
const CFRelease = new NativeFunction(
  Process.getModuleByName(cfMod.path).getExportByName("CFRelease"),
  "void", ["pointer"]);

const kCFStringUTF8Encoding = 0x08000100;

function makeCFString(s) {
  const buf = Memory.allocUtf8String(s);
  return CFStringCreateWithCString(ptr(0), buf, kCFStringUTF8Encoding, 0);
}

const ioKitMod = findModule("IOKit");
if (ioKitMod) {
  const io = Process.getModuleByName(ioKitMod.path);
  const IORegistryEntryCreateCFProperty = io.getExportByName("IORegistryEntryCreateCFProperty");
  Interceptor.attach(IORegistryEntryCreateCFProperty, {
    onEnter(args) {
      this.key = args[1];
      this.replaced = false;
    },
    onLeave(retval) {
      if (retval.isNull() || this.key.isNull()) return;
      const cstr = CFStringGetCStringPtr(this.key, 0);
      if (cstr.isNull()) return;
      const key = cstr.readUtf8String();
      if (key === "IOPlatformUUID" || key === "IOPlatformSerialNumber") {
        const replacement = (key === "IOPlatformUUID") ? FIXED_UUID : FIXED_SERIAL;
        CFRelease(retval);
        const out = makeCFString(replacement);
        retval.replace(out);
        console.log("[hook] " + key + " -> " + replacement);
      }
    }
  });
  console.log("[+] IOKit hook installed");
}
```

#### Linux: machine-id and DMI UUID by path redirection

```javascript
// fix_fingerprint_linux.js — Frida 17.x
// The redirection targets files that hold the identifiers, so both the C library
// and the raw syscalls are covered by hooking the libc wrappers.
const REDIRECT = {
  "/etc/machine-id": "/tmp/fake-machine-id",
  "/var/lib/dbus/machine-id": "/tmp/fake-machine-id",
  "/sys/class/dmi/id/product_uuid": "/tmp/fake-product-uuid",
  "/sys/class/dmi/id/product_serial": "/tmp/fake-product-serial"
};

const libc = Process.getModuleByName("libc.so.6");
function hookOpen(name) {
  let fn;
  try {
    fn = libc.getExportByName(name);
  } catch (e) {
    return;
  }
  Interceptor.attach(fn, {
    onEnter(args) {
      let p = null;
      try {
        p = args[name === "openat" ? 1 : 0].readUtf8String();
      } catch (e) { return; }
      if (p !== null && REDIRECT.hasOwnProperty(p)) {
        args[name === "openat" ? 1 : 0] = Memory.allocUtf8String(REDIRECT[p]);
        console.log("[hook] " + name + " " + p + " -> " + REDIRECT[p]);
      }
    }
  });
}
hookOpen("open");
hookOpen("openat");
```

Create the redirected files once:

```bash
printf 'a1b2c3d4e5f60718293a4b5c6d7e8f90\n' > /tmp/fake-machine-id
printf 'A1B2C3D4-E5F6-4711-8899-AABBCCDDEEFF\n' > /tmp/fake-product-uuid
printf 'C02XXXXXABCD\n' > /tmp/fake-product-serial
```

`getifaddrs` MAC selection is harder to redirect than a file, because the value is computed
in place. Two practical options: patch the MAC in the returned `struct ifaddrs` list
(`ifa_addr->sa_data` for `AF_LINK`), or leave the MAC alone and bind the licence to the MAC
that the target actually has — the fingerprint only needs to be *stable*, not fake.

### Step 5 — Neutralise the comparison instead

Find the compare between the collected (or digested) fingerprint and the value inside the
response blob:

```bash
r2 -q -c 'aaa; axt @ sym.imp.strcmp' target.exe
r2 -q -c 'aaa; axt @ sym.imp.memcmp' target.exe
```

Typical x64 shape:

```asm
0x140002600  mov  rdi, rax                 ; collected fingerprint
0x140002603  lea  rsi, [rbp-0x40]           ; fingerprint from the response blob
0x140002609  call qword [rip+0x1f70]       ; strcmp
0x14000260f  test eax, eax
0x140002611  jne  0x140002660              ; -> "this licence belongs to another machine"
```

Patch the branch to always continue:

```
0F 85 4f 00 00 00   ->   90 90 90 90 90 90      ; NOP out the JNE
```

or, smaller and safer, force the flag test:

```
48 85 C0   ->   B0 01 90                     ; test rax,rax -> mov al,1 ; nop
```

If the comparison is on a *digest* of the fingerprint (a 16/32-byte `memcmp`), the same
technique applies at the `memcmp` result test.

### Step 6 — Produce a licence for the controlled fingerprint

With the collector forced to a constant, the licence must be generated for that constant.
Reconstruct the normalised form the application produces, then feed it to the keygen:

```python
# normalise.py — reproduce the normalisation observed in the binary
import re

def normalise(raw: str) -> str:
    s = raw.lower()
    s = re.sub(r"[^0-9a-z]", "", s)      # strip separators
    return s

def fingerprint_hex(raw: str) -> str:
    """The 32-character hex form used when the value is parsed with %08x / from_str_radix."""
    digits = re.sub(r"[^0-9a-fA-F]", "", raw)
    return digits.lower()[:32]

if __name__ == "__main__":
    raw = "A1B2C3D4-E5F6-4711-8899-AABBCCDDEEFF"
    print(normalise(raw))
    print(fingerprint_hex(raw))
```

If the fingerprint enters a hash together with the other licence fields, the hash input is
the *normalised* string, not the raw collector output. Confirm the exact byte sequence the
application hashes (see
[Hardware fingerprint binding](hardware-fingerprint-binding.md) for hooking the digest
function).

## Variations

**Server-assisted activation with a device token.** Some products send the fingerprint to the
vendor and receive a device token that is stored locally; the offline check compares the
recomputed fingerprint against the token. Forcing the collector to a constant makes the token
check pass only if the token was issued for that constant — otherwise use Step 5.

**Request/response capture and replay.** Because the request blob is deterministic apart from
the nonce, a request captured on machine A can be answered once and the response replayed on
machine B, provided the fingerprint check is neutralised. Capture the request format by
hooking the file write:

```javascript
// dump_request.js — Frida 17.x
const k32 = Process.getModuleByName("kernel32.dll");
Interceptor.attach(k32.getExportByName("WriteFile"), {
  onEnter(args) {
    const len = args[2].toUInt32();
    if (len > 32 && len < 8192) {
      const b = new Uint8Array(args[1].readByteArray(len));
      let s = "";
      for (let i = 0; i < b.length; i++) s += ("0" + b[i].toString(16)).slice(-2);
      console.log("[WriteFile] " + s);
    }
  }
});
```

**Android.** `Settings.Secure.getString(cr, "android_id")` is available to any app since
Android 8 only for the app's own signing key and user, which makes the value stable per app
install. Hook it with the Frida Java bridge:

```typescript
Java.perform(() => {
  const SettingsSecure = Java.use("android.provider.Settings$Secure");
  const getString = SettingsSecure.getString.overload("android.content.ContentResolver", "java.lang.String");
  getString.implementation = function (cr, name) {
    const v = getString.call(this, cr, name);
    if (name === "android_id") {
      console.log("[hook] ANDROID_ID -> 1111111122222222");
      return "1111111122222222";
    }
    return v;
  };
});
```

**iOS.** `IOPlatformUUID` is available through `IOKit` without special entitlements;
`identifierForVendor` comes from `UIKit` and changes on every reinstall of all vendor apps.
The UUID is the stable choice, and the same IOKit hook from the macOS section applies
against `IOKit.framework` on iOS.

**Virtual machines.** Cloned VM images share the DMI UUID and the volume serial, so a
fingerprint built from those values is identical on every clone — which is both a binding
weakness and a source of false failures when the vendor's own server disagrees.

**Fingerprint in the request only.** Some products bind the licence to the fingerprint only at
activation time and never re-check it. In that case the binding is enforced by the vendor
server, not by the client, and the local patch is unnecessary.

## Verification

1. **Collector override confirmed.** With the hook installed, the request blob or the
   application log must contain the constant value, not the real one. Print the blob contents
   before and after the hook.
2. **Normalisation confirmed.** Feed the constant through the reconstructed normalisation and
   check it matches the string the application compares against — character for character,
   including case.
3. **Licence accepted.** Apply the generated licence and confirm the licensed state appears
   with no "licence belongs to another machine" message.
4. **Negative test — the binding is not merely bypassed.** Remove the hook and apply the
   same licence: the application must now reject it. If it still accepts, the licence was
   never bound to the fingerprint and the binding was cosmetic.
5. **Negative test — a foreign licence is still rejected.** Apply a licence generated for a
   different machine constant. It must be rejected. If it is accepted, the binding check was
   removed entirely rather than satisfied.
6. **Persistence test.** Restart the application and the machine, then re-check the licence
   state. A binding patched only in memory does not survive a reboot.

## Pitfalls

- **The fingerprint is hashed together with other fields.** Changing the collector changes the
  hash input, so the licence must be regenerated for the new value. Reusing the vendor's
  licence after patching the collector always fails.
- **The response blob embeds the fingerprint in the clear.** The application compares the
  collected value against the value inside the blob. Forcing the collector to a constant only
  works if that constant equals the embedded value — which is why the licence has to be
  regenerated, or the comparison patched instead.
- **Normalisation mismatch.** A constant with dashes where the app strips them (or vice
  versa) never matches. Derive the constant from the normalisation code, not from the
  collector's raw output.
- **Wide vs narrow strings.** `GetComputerNameW` returns UTF-16; the app may convert to
  UTF-8 or compare wide. Write the constant with the matching encoding.
- **Multiple fingerprint sources combined.** If the digest mixes the MachineGuid *and* the
  volume serial, patching one source is not enough.
- **`getifaddrs` order is not stable.** The "first" adapter changes with the routing table;
  the vendor's server may have hashed a different adapter. Prefer a source that does not
  move.
- **Hook timing.** `GetVolumeInformation` is called during very early initialisation. Spawn
  the process (`frida -f ...`) rather than attaching, or the first call is missed.
- **Writing wrong data into out-parameters.** `GetVolumeInformationW` writes a `DWORD` to
  `args[3]`; writing a 64-bit value there corrupts the neighbouring `DWORD` out-parameter
  and produces a volume serial of `0` on little endian. Use `writeU32`.
- **Writing a string into a fixed-size buffer.** `GetComputerNameW` requires the buffer to be
  at least `MAX_COMPUTERNAME_LENGTH + 1` UTF-16 units, and the length out-parameter must be
  consistent or the call fails.
- **Forged licence accepted for the wrong reason.** If the application never re-verifies the
  signature and only checks the presence of a file, any file works. Confirm the binding and
  signature checks are both present before concluding the licence is valid.

## References

- Windows `GetVolumeInformationW`, `GetComputerNameW`, `GetAdaptersInfo`, `RegGetValueA` —
  <https://learn.microsoft.com/windows/win32/api/>
- Apple `IORegistryEntryCreateCFProperty`, `IOPlatformUUID` —
  <https://developer.apple.com/documentation/iokit>
- systemd `machine-id` specification — <https://www.freedesktop.org/software/systemd/man/latest/machine-id.html>
- SMBIOS/DMI `product_uuid` — <https://www.dmtf.org/standards/smbios>
- Android `Settings.Secure.ANDROID_ID` —
  <https://developer.android.com/reference/android/provider/Settings.Secure>
- Frida 17.x `Interceptor` and JavaScript API — <https://frida.re/docs/javascript-api/>
- Sibling entries: [Hardware fingerprint binding](hardware-fingerprint-binding.md),
  [Trial and expiry enforcement](trial-and-expiry-enforcement.md),
  [Asymmetric licence signature verification](asymmetric-license-signature-verification.md),
  [Licence server protocol analysis](license-server-protocol-analysis.md)
