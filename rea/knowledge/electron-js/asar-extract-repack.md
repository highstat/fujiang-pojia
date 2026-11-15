---
id: "asar-extract-repack"
title: "ASAR extraction and repacking"
domain: "electron-js"
kind: "format"
platforms: "windows, macos, linux"
arch: "-"
difficulty: "intro"
tools: "npx,node,python3,xxd,codesign"
verified: false
updated: "2026-11-15"
summary: "Documents the ASAR container layout, the @electron/asar commands for listing, extracting and repacking an archive, the integrity fuse that blocks a modified archive, and the signature consequences of repacking on macOS and Windows."
---

## Summary

ASAR is not an archive format with compression; it is a JSON header describing file offsets followed
by the raw file contents concatenated in one blob. That simplicity makes it easy to read and easy
to rewrite, and it is also the reason a modified archive breaks the application in exactly two
places: the code signature on macOS and Windows, and the Electron integrity fuse. This entry
describes the container layout, the command sequence for extract and repack, the fuse that enforces
the header hash, and a Python parser that lists every entry with its absolute file offset.

## Recognition

- The application directory contains `resources/app.asar` (a single large file) or `resources/app/`
  (an unpacked directory).
- `xxd -l 64 resources/app.asar` shows four little-endian 32-bit integers followed by a JSON blob
  starting with `{"files":`.
- `file resources/app.asar` reports `JSON text data` or `data`, not a zip.
- The archive is much larger than the sum of its compressed contents would suggest; the file
  contents are stored uncompressed.
- `resources/app.asar.unpacked/` exists when some files were excluded from the archive (native
  addons are commonly unpacked so they can be `dlopen`ed).
- The Electron binary contains the fuse string `EnableEmbeddedAsarIntegrityValidation`.
- `Contents/Info.plist` contains an `ElectronAsarIntegrity` dictionary.

## Method

### 1. Locate the archive

```bash
cd /path/to/App.app/Contents/Resources
ls -la
file app.asar
xxd -l 64 app.asar
```

On Linux the resources directory is next to the executable:

```bash
ls -la /opt/app/resources/
```

### 2. List, extract and repack with @electron/asar

```bash
cd /path/to/work
mkdir -p out

npx --yes @electron/asar list /path/to/App.app/Contents/Resources/app.asar
npx --yes @electron/asar extract /path/to/App.app/Contents/Resources/app.asar out/
npx --yes @electron/asar pack out/ app.asar
```

`list` prints one relative path per line, `extract` writes the tree into `out/`, and `pack` writes
a new archive from a directory.

The older, deprecated package name still works but pulls a different codebase:

```bash
npx --yes asar list app.asar          # deprecated
```

### 3. The node module API

```javascript
// asar-api.js
const asar = require('@electron/asar');
const path = require('path');

const archive = process.argv[2];

console.log('entries:', asar.listPackage(archive).length);
console.log('stat  :', asar.statFile(archive, 'package.json'));

const buf = asar.extractFile(archive, 'package.json');
console.log('main  :', JSON.parse(buf.toString('utf8')).main);

asar.extractAll(archive, path.join(process.cwd(), 'out'));
asar.createPackageWithOptions(path.join(process.cwd(), 'out'), 'app.asar', {
  unpack: '**/*.node',
  unpackDir: 'dist'
});
```

```bash
node asar-api.js /path/to/App.app/Contents/Resources/app.asar
```

`createPackageWithOptions` keeps `*.node` files outside the archive in an `.unpacked` directory, which
is what the official packagers do and what a native addon needs in order to be loaded.

### 4. Parse the header with Python

```python
#!/usr/bin/env python3
"""asar_header.py — list the entries of an ASAR archive with their file offsets.

Usage: python3 asar_header.py /path/to/app.asar
"""
import json
import os
import struct
import sys


def load_header(path):
    """Return (header_dict, data_base) for an ASAR archive."""
    with open(path, "rb") as f:
        blob = f.read()
    if len(blob) < 16:
        raise SystemExit("file too small to be an ASAR archive")

    # Layout:
    #   [0:4]   uint32 LE  payload size of the size pickle (normally 4)
    #   [4:8]   uint32 LE  H, the size of the header pickle
    #   [8:12]  uint32 LE  payload size of the header pickle
    #   [12:16] uint32 LE  N, the length of the JSON header string
    #   [16:]   the JSON header string, NUL padded to a 4-byte boundary
    # The file payload region starts at 8 + H.
    a, h, _payload, n = struct.unpack("<IIII", blob[:16])

    candidates = [(16, n)]
    idx = blob.find(b'{"files"')
    if idx >= 4:
        (fallback_n,) = struct.unpack("<I", blob[idx - 4:idx])
        candidates.append((idx, fallback_n))

    header = None
    used = None
    for off, length in candidates:
        if not length:
            continue
        try:
            header = json.loads(blob[off:off + length].decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            continue
        used = (off, length)
        break
    if header is None:
        raise SystemExit("could not decode the ASAR header")

    # Candidate data bases, most standard first; validated against the first entry.
    for base in (8 + h, 4 + a, 8 + used[0] + used[1]):
        if base > len(blob):
            continue
        if _first_entry_fits(header, base, len(blob)):
            return header, base
    raise SystemExit("could not determine the payload base offset")


def _first_entry_fits(header, base, total):
    for meta in _iter_files(header.get("files", {})):
        if meta.get("unpacked"):
            continue
        try:
            offset = int(meta.get("offset", "0"))
        except (TypeError, ValueError):
            continue
        size = int(meta.get("size", 0))
        return base + offset + size <= total
    return True


def _iter_files(files, prefix=""):
    for name, meta in files.items():
        path = f"{prefix}/{name}" if prefix else name
        if "files" in meta:
            yield from _iter_files(meta["files"], path)
        else:
            yield path, meta


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: asar_header.py <app.asar>")
    path = sys.argv[1]
    header, base = load_header(path)
    total = os.path.getsize(path)
    print(f"archive      : {path} ({total} bytes)")
    print(f"payload base : 0x{base:x} ({base})")
    print(f"{'offset':>10}  {'size':>9}  flags  path")
    for name, meta in _iter_files(header.get("files", {})):
        offset = int(meta.get("offset", "0")) if not meta.get("unpacked") else -1
        absolute = base + offset if offset >= 0 else -1
        flags = []
        if meta.get("executable"):
            flags.append("exec")
        if meta.get("unpacked"):
            flags.append("unpacked")
        if meta.get("integrity"):
            flags.append("sha256")
        print(f"{absolute:>10}  {int(meta.get('size', 0)):>9}  {','.join(flags) or '-':<6}  {name}")


if __name__ == "__main__":
    main()
```

```bash
python3 asar_header.py /path/to/App.app/Contents/Resources/app.asar
```

Expected: a table of every entry with its absolute file offset, plus the payload base address.

A single file can then be carved out directly:

```bash
python3 - <<'PY'
import sys
sys.path.insert(0, ".")
from asar_header import load_header, _iter_files

path = "/path/to/app.asar"
header, base = load_header(path)
want = "package.json"
for name, meta in _iter_files(header.get("files", {})):
    if name == want:
        off = base + int(meta["offset"])
        with open(path, "rb") as f:
            f.seek(off)
            data = f.read(int(meta["size"]))
        open("carved-package.json", "wb").write(data)
        print(f"{name}: 0x{off:x} ({meta['size']} bytes)")
PY
```

### 5. Repack and reinstall

```bash
cd /path/to/work

# 1. Extract, patch, repack.
npx --yes @electron/asar extract /path/to/App.app/Contents/Resources/app.asar out/
# ... edit out/ ...
npx --yes @electron/asar pack out/ app.asar

# 2. Replace the archive.
cp /path/to/App.app/Contents/Resources/app.asar app.asar.bak
cp app.asar /path/to/App.app/Contents/Resources/app.asar

# 3. macOS: the bundle seal covers Resources/, so re-sign the bundle.
codesign --force --sign - --timestamp=none /path/to/App.app
codesign -v --deep --strict --verbose=4 /path/to/App.app
```

On Windows the signature lives on the executable, not on `app.asar`:

```cmd
signtool sign /fd SHA256 /f cert.pfx /p password /tr http://timestamp.digicert.com "C:\path\to\App.exe"
signtool verify /pa "C:\path\to\App.exe"
```

### 6. The integrity fuse

`EnableEmbeddedAsarIntegrityValidation` makes the Electron binary hash the ASAR header and compare
it with a value embedded at build time. A repacked archive fails that comparison and the process
refuses to start the app.

```bash
npx --yes @electron/fuses read --app-path /path/to/App.app
```

Expected output:

```text
Fuse Version: v1
RunAsNode is Enabled
EnableCookieEncryption is Enabled
EnableNodeOptionsEnvironmentVariable is Enabled
EnableNodeCliInspectArguments is Enabled
EnableEmbeddedAsarIntegrityValidation is Enabled
OnlyLoadAppFromAsar is Disabled
LoadBrowserProcessSpecificV8Snapshot is Enabled
GrantFileProtocolExtraPrivileges is Disabled
```

Disable the fuse on a copy of the Electron framework:

```bash
cp -R /path/to/App.app/Contents/Frameworks/Electron\ Framework.framework /tmp/Electron.framework.bak
npx --yes @electron/fuses write --app-path /path/to/App.app \
  --version 1 --enable-embedded-asar-integrity-validation false
npx --yes @electron/fuses read --app-path /path/to/App.app
```

Expected: `EnableEmbeddedAsarIntegrityValidation is Disabled`.

The integrity data itself lives beside the binary:

- **macOS**: `Contents/Info.plist` carries an `ElectronAsarIntegrity` dictionary:

```xml
<key>ElectronAsarIntegrity</key>
<dict>
  <key>algorithm</key>
  <string>SHA256</string>
  <key>blockSize</key>
  <integer>4194304</integer>
  <key>hash</key>
  <string>BASE64_HASH_OF_THE_ASAR</string>
</dict>
```

- **Windows**: the hash is embedded in the executable's resources, and the fuse check compares
  against it.

Recomputing the macOS value is possible: the `hash` is the SHA-256 of the whole archive and
`blockSize` is the chunk size used for the per-block hashes. Use the fuse write tool to remove the
requirement rather than trying to reproduce the vendor's exact hashing parameters.

### 7. A header that does not decode

ASAR itself has no encryption. If `asar extract` fails with a JSON parse error, the header has been
rewritten by a protection tool, or the file is not an ASAR at all.

```bash
xxd -l 128 /path/to/app.asar
python3 asar_header.py /path/to/app.asar
```

If the first bytes are not the expected integers, the reader is custom. Find it in the Electron
binary or in a preload:

```bash
strings -a /path/to/App.app/Contents/Frameworks/Electron\ Framework.framework/Versions/A/Helpers/chrome_crashpad_handler 2>/dev/null | grep -i asar
r2 -qc 'aaa; iz~asar' /path/to/App.app/Contents/Frameworks/Electron\ Framework.framework/Versions/A/Electron\ Framework
```

The parsed header also exists in the process memory once the app is running. Dump it with Frida:

```javascript
// dump-asar-header.js — Frida 17.x
const fs = require('fs');
const base = Module.getGlobalExportByName('base::ReadFileToStringWithMaxSize');
console.log('[asar] base::ReadFileToStringWithMaxSize ->', base);
```

A more direct route is to intercept the JSON parse of the header and log the string. The Electron
binary links `base::JSONReader` and the ASAR reader in `electron::api::AsarArchive`; locating the
parse call site in the binary gives a single breakpoint on the header string.

## Variations

- **Unpacked directory instead of an archive.** `resources/app/` holds the files directly. Nothing
  to extract; edit in place and remove the archive, or leave the archive and rely on the
  `OnlyLoadAppFromAsar` fuse being off.
- **`asar` versus `@electron/asar`.** The original `asar` package is deprecated and unmaintained;
  `@electron/asar` is the maintained fork and is what Electron itself uses.
- **Fuse values in the packaged app.** The fuses live in the Electron framework inside the
  application, not in the app's own code. Reading them requires the framework path, and the path
  differs between macOS (`Contents/Frameworks/Electron Framework.framework`) and Linux
  (`resources/` plus the `electron` binary).
- **Windows packaging.** `electron-builder` can produce an `app.asar` inside a `resources`
  directory or a packed `.asar` inside an NSIS installer. The latter has to be unpacked before the
  archive is reachable.
- **AppImage.** A Linux AppImage embeds the Electron application in a SquashFS image; the asar is
  reached after `unsquashfs` or by running the AppImage with `--appimage-extract`.
- **Snapshot packaging.** A V8 snapshot (`v8_context_snapshot.bin`) embeds the JavaScript heap and
  can contain the licence logic; it must be dumped separately.

## Verification

Positive — the archive is well formed and the entries are readable:

```bash
npx --yes @electron/asar list /path/to/app.asar | wc -l
python3 asar_header.py /path/to/app.asar | head -5
```

Expected: a non-zero entry count and a table whose first entries correspond to the same paths.

Positive — the repacked archive works:

```bash
npx --yes @electron/asar list app.asar | diff - <(npx --yes @electron/asar list /path/to/App.app/Contents/Resources/app.asar)
```

Expected: no output, i.e. the same file list.

Negative — the signature check still fails on the unmodified original, proving the seal covers the
resources:

```bash
codesign -v --deep --strict /path/to/App.app ; echo "exit=$?"
printf 'X' | dd of=/path/to/App.app/Contents/Resources/app.asar bs=1 seek=0 count=1 conv=notrunc
codesign -v --deep --strict /path/to/App.app 2>&1 | head -3
```

Expected: `exit=0` before the change and `a sealed resource is missing or invalid` after it. Restore
the archive from `app.asar.bak` and re-sign.

Negative — the integrity fuse is really off:

```bash
npx --yes @electron/fuses read --app-path /path/to/App.app | grep -i asar
```

Expected: `EnableEmbeddedAsarIntegrityValidation is Disabled`. With the fuse enabled and a modified
archive the app exits immediately with an integrity error and no console output.

## Pitfalls

- ASAR stores files uncompressed. An archive larger than the sum of its contents is normal and is
  not a sign of a nested archive.
- `asar pack` does not preserve the executable bit by default for every entry; check the mode of
  any file that must be executed, and repack with `unpack` options if native addons are involved.
- Repacking on macOS without re-signing gives `kill: 9` and a `code object is not signed at all`
  message in the system log. See `../macos/codesign-and-entitlements.md`.
- Repacking on Windows invalidates the Authenticode signature over the executable, and the vendor's
  own updater refuses to install over a mismatched signature.
- The `ElectronAsarIntegrity` dictionary in `Info.plist` is part of the signed resource set; changing
  it also requires a re-sign.
- `@electron/asar extract` overwrites the destination. Always extract into an empty directory.
- A repacked archive with a different header size shifts every file offset. Tools that reference
  absolute offsets inside the archive break; re-run the offset scan after repacking.
- Disabling a fuse changes the Electron framework binary, which is signed on macOS; re-sign the
  whole bundle afterwards.
- `npx @electron/fuses` needs a Node.js toolchain and network access for the package download; the
  fuse wire can also be flipped by hand with a hex patch on the sentinel string
  `dL7pKGdnNz796uMpQ7g++E6uJnyxQ` in the Electron binary, but the tool is far safer.
- An ASAR inside a `.asar` (nested) is not extracted by the tool; it must be extracted separately
  with its own path.

## References

- `electron/asar` upstream repository and the `@electron/asar` npm package
- Electron documentation, *Application Security* and *Electron Fuses* — the
  `EnableEmbeddedAsarIntegrityValidation` fuse
- `electron/fuses` npm package — `read` and `write` command reference
- Chromium `base::Pickle` format — the framing used by the ASAR header
- Sibling entries: `electron-licence-flow.md`, `../macos/codesign-and-entitlements.md`
