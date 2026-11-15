---
id: "fairplay-decrypted-binary-handling"
title: "FairPlay decrypted binary handling"
domain: "ios"
kind: "technique"
platforms: "ios"
arch: "arm64"
difficulty: "advanced"
tools: "Frida, LLDB, LIEF, otool, r2, frida-ios-dump, ipsw, dyld_info"
verified: false
updated: "2026-11-15"
summary: "Explain how FairPlay encrypts an App Store binary, dump the decrypted __TEXT image from a running process, patch it at the right file offset and produce an installable IPA whose encryption state is consistent."
---

## Summary

An App Store binary ships encrypted. The first pages of `__TEXT` are AES-CBC ciphertext,
the load command says so, and nothing readable exists on disk until the device's DRM
subsystem decrypts the pages as they are faulted in. Any analysis of the store binary — and
any patch of it — therefore has to happen on the decrypted in-memory image.

The decrypted image is not a file. It is a window into the process. Turning it back into
something installable means splicing the plaintext back over the encrypted region of the
original file, clearing the encryption flag, and re-signing the bundle.

## Recognition

The encryption load command:

```bash
otool -l App.app/App | grep -A6 LC_ENCRYPTION_INFO
```

```text
Load command 12
      cmd LC_ENCRYPTION_INFO_64
  cmdsize 24
  cryptoff 16384
 cryptsize 16384
   cryptid 1
     pad 0
```

- `cryptid` is `1` when the binary is encrypted and `0` when it is not.
- `cryptoff` is the file offset where the encrypted region starts, usually `0x4000`.
- `cryptsize` is the length of the encrypted region, usually `0x4000` (16 KB).
- The encrypted region is a run of 4096-byte pages. Each page is AES-128-CBC ciphertext and
  carries its own 16-byte initialisation vector in the first 16 bytes of the page.

Consequences visible to the analyst:

- `strings` on the store binary finds only ciphertext, not `license expired`.
- `otool -tvV` produces garbage in the first pages of `__TEXT`.
- The Objective-C class and method *names* are readable (they live in `__TEXT.__objc_methname`
  only when that section falls inside the encrypted region, otherwise they are plaintext),
  but the method bodies are not.
- The `__DATA` segment and `__LINKEDIT` are not encrypted. Metadata that points at code is
  therefore usable, while the code itself is not.

## Method

### 1. Determine the encrypted region

```bash
cd /path/to/work
otool -l App.app/App | grep -A6 -E 'LC_ENCRYPTION_INFO'
otool -l App.app/App | grep -A8 'segname __TEXT'
```

Record `cryptoff`, `cryptsize` and the `__TEXT` segment's `vmaddr`/`fileoff`. For the usual
build: `__TEXT` has `vmaddr 0x100000000` and `fileoff 0`, and the encrypted region is
`[0x4000, 0x8000)`.

### 2. Dump the decrypted image from a running process

The app must be running, and the pages must already be faulted in. Launch the app, navigate
to the screen that uses the licensed code so those pages are mapped and decrypted.

#### 2a. Frida memory read over the encrypted range

The in-memory image of the app's `__TEXT` sits at the module base plus the slide. The
file offset and the memory offset coincide for the `__TEXT` segment (`fileoff 0`), so the
encrypted range is at `module.base + cryptoff`.

```js
// dump_text.js — Frida 17.x, reads the decrypted __TEXT window
'use strict';

const fs = require('fs');
const APP = 'App';
const CRYPTOFF = 0x4000;      // from otool -l
const CRYPTSIZE = 0x4000;     // from otool -l

let mod = null;
for (const m of Process.enumerateModules()) {
  if (m.name === APP || m.path.endsWith('/' + APP)) {
    mod = m;
    break;
  }
}
if (mod === null) {
  console.log('[-] ' + APP + ' not loaded');
} else {
  const start = mod.base.add(CRYPTOFF);
  console.log('[+] base=' + mod.base + ' start=' + start);
  const buf = Memory.readByteArray(start, CRYPTSIZE);
  if (buf === null) {
    console.log('[-] read failed (page not mapped)');
  } else {
    const out = Buffer.from(buf);
    fs.writeFileSync('App.text.' + CRYPTOFF.toString(16) + '.bin', out);
    console.log('[+] wrote ' + out.length + ' bytes');
  }
}
```

Run it against a spawned process:

```bash
frida -U -f com.vendor.app -l dump_text.js
```

Pages that were never faulted in are not decrypted and not present; read a range that is
definitely touched, and touch the licensed screen first. Frida can also read unmapped pages
by triggering a fault, but the simplest approach is to launch the app and let it run.

#### 2b. LLDB core dump

```bash
lldb -p <pid>
(lldb) process save-core /path/to/work/App.core
(lldb) quit
```

`process save-core` writes a Mach-O core file that contains the mapped memory of the
process, including the decrypted `__TEXT`. The core is then parsed with LIEF:

```python
# extract_text.py — python3 extract_text.py App.core
import lief

core = lief.MachO.parse("App.core")
for segment in core.segments:
    if segment.name == "__TEXT":
        content = bytes(segment.content)
        open("App.text.bin", "wb").write(content)
        print(f"__TEXT vmaddr=0x{segment.virtual_address:x} size={len(content)}")
```

The core's segment has the same contents as the file's `__TEXT`, but the file's `__LINKEDIT`
(the symbol table, the string tables and the code signature) is not mapped and therefore
absent from the core. The file has to be merged with the original.

#### 2c. Purpose-built dumpers

- `frida-ios-dump` does the whole job: it reads the encrypted file, reads the decrypted
  memory, patches the encrypted region, clears `cryptid` and writes a new IPA.
- `Clutch` (jailbreak) performs the same dump from a crashing or running app.
- `ipsw` and `dyld_info` handle the dyld shared cache, which is where the *system* frameworks
  live. They are useful for reference, but the app's own binary is not in the shared cache.

#### 2d. Dumping without DYLD_INSERT_LIBRARIES

`DYLD_INSERT_LIBRARIES` is stripped from the launch environment on stock devices, and using
it changes the process environment, which some apps detect. The route that avoids it
entirely is to attach to an already running process:

```bash
# attach to the running app and dump from there
frida -U -n App -l dump_text.js
```

or use the debugserver that `lldb` talks to. Attaching after launch is enough as long as the
encrypted pages have been faulted in.

### 3. Splice the plaintext back into the file

The original file stays the base: it carries the `__LINKEDIT`, the symbol table and the
correct load commands. Only the encrypted range is replaced, and `cryptid` is cleared.

```python
#!/usr/bin/env python3
# fairplay_decrypt.py
# usage: python3 fairplay_decrypt.py App.encrypted App.text.bin App.decrypted
import struct
import sys

LC_ENCRYPTION_INFO = 0x21
LC_ENCRYPTION_INFO_64 = 0x2C
FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE


def slices(data):
    """Return [(slice_offset, slice_size, magic)] for a thin or fat Mach-O."""
    magic = struct.unpack(">I", data[:4])[0]
    if magic in (FAT_MAGIC, FAT_MAGIC_64):
        n = struct.unpack(">I", data[4:8])[0]
        out = []
        stride = 20 if magic == FAT_MAGIC else 32
        for i in range(n):
            fields = struct.unpack(">%dI" % (stride // 4),
                                   data[8 + i * stride: 8 + (i + 1) * stride])
            offset = fields[2]
            size = fields[3]
            out.append((offset, size, struct.unpack(">I", data[offset:offset + 4])[0]))
        return out
    return [(0, len(data), struct.unpack("<I", data[:4])[0])]


def find_encryption(data, slice_off):
    """Return (cmd_offset, cryptoff, cryptsize, cryptid_field_offset) inside one slice."""
    magic = struct.unpack("<I", data[slice_off:slice_off + 4])[0]
    if magic not in (MH_MAGIC_64, MH_CIGAM_64):
        raise SystemExit("only 64-bit Mach-O slices are handled")
    ncmds = struct.unpack("<I", data[slice_off + 16:slice_off + 20])[0]
    cmd = slice_off + 32
    for _ in range(ncmds):
        cmd_id, cmdsize = struct.unpack("<II", data[cmd:cmd + 8])
        if cmd_id == LC_ENCRYPTION_INFO_64:
            cryptoff = struct.unpack("<Q", data[cmd + 8:cmd + 16])[0]
            cryptsize = struct.unpack("<I", data[cmd + 16:cmd + 20])[0]
            cryptid_off = cmd + 20
            return cmd, cryptoff, cryptsize, cryptid_off
        if cmd_id == LC_ENCRYPTION_INFO:
            cryptoff = struct.unpack("<I", data[cmd + 8:cmd + 12])[0]
            cryptsize = struct.unpack("<I", data[cmd + 12:cmd + 16])[0]
            cryptid_off = cmd + 16
            return cmd, cryptoff, cryptsize, cryptid_off
        cmd += cmdsize
    return None


def main():
    src, plain, dst = sys.argv[1], sys.argv[2], sys.argv[3]
    data = bytearray(open(src, "rb").read())
    blob = open(plain, "rb").read()

    for slice_off, slice_size, _ in slices(bytes(data)):
        info = find_encryption(bytes(data), slice_off)
        if info is None:
            print(f"slice at 0x{slice_off:x}: no encryption command")
            continue
        _, cryptoff, cryptsize, cryptid_off = info
        print(f"slice at 0x{slice_off:x}: cryptoff=0x{cryptoff:x} "
              f"cryptsize=0x{cryptsize:x} cryptid={struct.unpack('<I', data[cryptid_off:cryptid_off+4])[0]}")
        if len(blob) < cryptsize:
            raise SystemExit("plaintext dump is shorter than the encrypted region")
        data[slice_off + cryptoff: slice_off + cryptoff + cryptsize] = blob[:cryptsize]
        struct.pack_into("<I", data, cryptid_off, 0)      # cryptid = 0

    open(dst, "wb").write(bytes(data))
    print("wrote", dst)


if __name__ == "__main__":
    main()
```

```bash
cd /path/to/work
python3 fairplay_decrypt.py App.encrypted App.text.bin App.decrypted
otool -l App.decrypted | grep -A6 LC_ENCRYPTION_INFO_64
```

The verification is `cryptid 0` and an unchanged `cryptoff`/`cryptsize`.

### 4. Patch the decrypted binary

The patch is applied to the decrypted file, at the file offset that backs the virtual
address of the instruction:

```text
file_offset = vmaddr - segment.vmaddr + segment.fileoff
```

For `__TEXT` (`vmaddr 0x100000000`, `fileoff 0`) the file offset is `vmaddr - 0x100000000`.

```bash
cd /path/to/work
r2 -qc 'ic~Licens' App.decrypted
r2 -qc 's 0x100001234; pd 8' App.decrypted
printf '\x20\x00\x80\x52' | dd of=App.decrypted bs=1 seek=$((0x1234)) conv=notrunc
```

The byte-level patching itself is described in
[`ios-native-licence-patching.md`](ios-native-licence-patching.md).

### 5. Put it back into the IPA and sign

```bash
cd /path/to/work
cp App.encrypted App.patched
# replace the binary inside the unpacked bundle
cp App.decrypted unpacked/Payload/App.app/App
# or rebuild the ipa from the unpacked tree
cd unpacked && zip -qry ../repacked.ipa Payload && cd ..

# strip the old signature and sign the nested binaries, then the app
codesign --remove-signature unpacked/Payload/App.app/App
rm -rf unpacked/Payload/App.app/_CodeSignature
codesign --force --sign - --timestamp=none --entitlements entitlements.plist \
  unpacked/Payload/App.app/Frameworks/Your.framework/Your
codesign --force --sign - --timestamp=none --entitlements entitlements.plist \
  unpacked/Payload/App.app
codesign --verify --verbose=4 unpacked/Payload/App.app
```

The full signing order is in [`ipa-repack-and-resign.md`](ipa-repack-and-resign.md).

### 6. Install

An IPA whose binary carries `cryptid 0` is a *decrypted* IPA. It installs on a jailbroken
device with an ad-hoc signature, and on a stock device when it is signed with a valid
development or distribution certificate and a matching provisioning profile.

```bash
ideviceinstaller -i repacked.ipa
```

An IPA that still has `cryptid 1` is re-encrypted by the App Store at install time, and any
patch made to the encrypted bytes is either impossible or destroyed.

## Variations

### The store re-encrypts on install

The FairPlay key used by the store is bound to the app and to the install. Consequences:

- A patched *encrypted* store binary is useless: the loader decrypts it at install and the
  patch is either overwritten by the decryption or corrupts the image.
- A patched *decrypted* binary (`cryptid 0`) must be side-loaded. Installing it from the
  App Store replaces it with the store's own encrypted build.
- A patched binary that is uploaded to a signing service is delivered decrypted, because
  the service re-signs whatever it is given.

### Shared cache versus the app binary

The system frameworks live in the dyld shared cache (`/System/Library/Caches/com.apple.dyld/`
on disk, mapped into every process). They are not encrypted, they are not part of the app
bundle, and they are not patched. `ipsw dyld` and `dyld_info` (`dyld_info -exports`,
`dyld_info -objc`) are the tools for that side of the problem.

### `__TEXT` remapping and the slide

- The app's `__TEXT` is mapped at `slide + 0x100000000`, where the slide is chosen at launch
  by ASLR. The file's virtual addresses are fixed at `0x100000000`.
- The memory image and the file therefore differ by exactly the slide, and the file offset
  is `vmaddr - segment.vmaddr + segment.fileoff`.
- Confirm the slide at runtime:
  `vmmap <pid> | grep -A2 App` — the first mapping's address minus `0x100000000` is the
  slide.

### Segments that are not in memory

`__LINKEDIT` holds the symbol table, the Objective-C selector and class reference strings in
some builds, and the code signature. It is a file-only segment: it is never mapped, so no
memory dump contains it. Any decryption pipeline must therefore start from the original
file, not from the dump.

### `__DATA` is writable

`__DATA` in memory holds the app's mutated state, not the initialised values from the file.
A memory dump of `__DATA` is not a valid `__DATA` segment for a file. Read `__TEXT` only.

### Multi-slice binaries

Each slice of a fat binary has its own `LC_ENCRYPTION_INFO_64` and its own encrypted range.
A decrypted IPA must have every slice cleared. The script above iterates the slices.

### No symbols in the store build

The App Store build has no symbol table and no dSYM. The Objective-C metadata survives
(`ic` in radare2, `otool -oV`), and that is what makes the class and method lookup work.

## Verification

1. Encryption check. `otool -l App.decrypted | grep -A6 LC_ENCRYPTION_INFO_64` must show
   `cryptid 0`. A file that still says `cryptid 1` will be decrypted again on install and
   the patch will be lost or the app will crash with an invalid-page error.
2. Content check. `strings -a App.decrypted | grep -i licen` finds the licence strings that
   were invisible in the encrypted file. This is the proof that the plaintext really was
   spliced in and not just zeros.
3. Disassembly check. `r2 -qc 's <method addr>; pd 8' App.decrypted` shows the patched
   instructions.
4. Signature check. `codesign --verify --verbose=4 unpacked/Payload/App.app` succeeds only
   after the re-signing step.
5. Runtime check. Install and launch; the licensed path must be reachable. The device
   console shows a crash with `mach_vm_protect` or `Invalid page` when the plaintext was not
   spliced correctly and the loader tried to decrypt it.
6. Negative test. Dump and decrypt the binary without patching it and confirm the licence
   gate still refuses. Then apply the patch to a fresh dump and confirm the gate opens. This
   separates "the dump worked" from "the patch worked".

## Pitfalls

- **Patching the encrypted file directly.** The bytes are ciphertext; the patch is
  destroyed by the decryption at install time.
- **Forgetting to clear `cryptid`.** The loader still tries to decrypt the now-plaintext
  region and the app dies on an invalid page.
- **Splicing at the wrong offset.** The file offset of the encrypted region is `cryptoff`,
  which is the offset inside the *slice*, and a fat binary adds the slice offset on top.
- **Reading memory before the pages are faulted in.** The unread pages read back as
  zero-filled or encrypted garbage. Touch the licensed screen first.
- **Using the memory dump as the new file.** It has no `__LINKEDIT`, so no symbol table and
  no code signature, and the load commands may not match. Start from the original file.
- **Dumping `__DATA`.** It is writable and its memory content differs from the file.
- **Assuming the store version matches the installed version.** The App Store binary on the
  device is a different build from the one downloaded for analysis. Compare the version
  code and the file hash.
- **The App Store overwrites the patch.** Installing from the App Store replaces the
  decrypted binary with the encrypted original.
- **Device with a different architecture.** The arm64e slice is a different file offset from
  the arm64 slice. Patch the slice the device loads.
- **FairPlay keys are device-bound.** A dump taken on one device is valid data, but a
  re-encrypted binary produced for another device will not decrypt.
- **`frida-ios-dump` output may still be partly encrypted** when the app was killed before
  the pages were touched. Check `cryptid` and the presence of readable strings before
  trusting the dump.

## References

- Apple, "Code Signing" and the `LC_ENCRYPTION_INFO` load command:
  <https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/CodeSigningGuide.html>
- Apple, "Mach-O Programming Topics":
  <https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/MachOOverview.html>
- FairPlay DRM overview (Apple Platform Security):
  <https://support.apple.com/guide/security/fairplay-drm-secb0694df1a/web>
- LIEF 1.0.0 Mach-O documentation: <https://lief.re/doc/latest/formats/macho.html>
- Frida 17.x JavaScript API: <https://frida.re/docs/javascript-api/>
- `frida-ios-dump`: <https://github.com/AloneMonkey/frida-ios-dump>
- `Clutch`: <https://github.com/KushagraDiggal/Clutch>
- `ipsw`: <https://github.com/blacktop/ipsw>
- `dyld_info`: <https://github.com/MobileNativeFoundation/dyld_info>
- Sibling entries: [`ipa-repack-and-resign.md`](ipa-repack-and-resign.md),
  [`ios-native-licence-patching.md`](ios-native-licence-patching.md),
  [`jailbreak-detection-bypass.md`](jailbreak-detection-bypass.md)
