---
id: "electron-licence-flow"
title: "Electron licence flow"
domain: "electron-js"
kind: "technique"
platforms: "windows, macos, linux"
arch: "-"
difficulty: "intermediate"
tools: "rg,npx,node,r2,frida,strings"
verified: false
updated: "2026-11-15"
summary: "Locates the licence decision point inside an Electron application across the four places it can hide — main process JavaScript, renderer bundle, native Node addon and Electron fuse — and gives the search commands plus the three patching routes and the ELECTRON_RUN_AS_NODE and --inspect probes."
---

## Summary

An Electron application is three programs in one: a Chromium browser process, a Node.js main
process, and renderer processes that run the bundled JavaScript. The licence check can live in any
of them, and the location determines the tool. This entry gives the search procedure across all
four hiding places, the patching route for each, and the two probes — `ELECTRON_RUN_AS_NODE` and
`--inspect` — that turn the application into something readable.

## Recognition

- The application directory contains `resources/app.asar` or `resources/app/`.
- `package.json` inside the archive has a `main` entry pointing at `dist/main.js`,
  `build/main/index.js` or `main.js`.
- `strings app.asar | grep -i licen` finds licence strings, and `rg -i 'licen' out/` finds them in
  the extracted tree.
- A `*.node` file exists in `resources/app.asar.unpacked/` or `resources/app/`; a native addon is
  loaded by `require('./build/xyz.node')` or through `process.dlopen`.
- The app shows a modal with `Activate`, `Enter license key`, `Subscription expired` or
  `Your trial has ended`.
- The Electron framework contains the fuse string `EnableEmbeddedAsarIntegrityValidation`, and
  `RunAsNode` is enabled.
- `package.json` contains `electron-updater` or a `publish` block, and the update feed carries the
  licence server URL.

## Method

### 1. Establish the application layout

```bash
cd /path/to/work
mkdir -p out
npx --yes @electron/asar extract /path/to/App.app/Contents/Resources/app.asar out/
ls -la out/
cat out/package.json | python3 -m json.tool | head -40
```

The `main` field names the entry point of the main process:

```bash
python3 -c "import json;print(json.load(open('out/package.json'))['main'])"
```

Expected: a path such as `dist/main.js`.

### 2. Find the licence strings

```bash
cd /path/to/work
rg -i --no-heading -n 'licen|licence|serial|trial|expire|subscription|activat|register' out/ | head -60
```

Common hits: `licenseKey`, `LICENSE_SERVER_URL`, `checkLicense`, `isLicensed`, `trialExpired`,
`activationStatus`.

Raw strings in the archive itself, for the case where the archive is not decodable:

```bash
strings -a /path/to/App.app/Contents/Resources/app.asar | grep -iE 'licen|trial|expire|serial' | head -40
```

### 3. Decide where the decision lives

Four candidates, in the order they should be checked:

1. **Main process JavaScript** — inside the asar, reachable from `package.json` `main`. The main
   process owns the window and the licence dialog, so the check is very often here.
2. **Renderer JavaScript** — a bundled file under `out/dist/` or `out/build/`, often minified into
   one line. The renderer asks the main process over IPC, so the renderer often only holds the
   display logic.
3. **Native Node addon** — a `*.node` file, a PE, Mach-O or ELF shared object loaded through
   `process.dlopen`. The check lives in native code when the vendor wants it out of reach of a
   casual reader.
4. **Electron fuse or feature flag** — a build-time switch in the Electron framework, or a flag in
   the app's own `package.json`/`config` file.

### 4. Inspect the main process entry point

```bash
cd /path/to/work
rg -i --no-heading -n -C2 'licen|trial|expire' out/dist/main.js | head -60
```

The typical shape in a bundled main process is a single boolean set from a validation call:

```javascript
let valid = false;
try {
  valid = await licenseService.validate(userData);
} catch (e) {
  valid = false;
}
mainWindow.webContents.send('license:status', valid);
```

The decision point is the assignment of `valid` or the branch that follows it.

### 5. Inspect a native addon

Find the addons and the code that loads them:

```bash
cd /path/to/work
find out -name '*.node' -print
rg -n --no-heading "require\(.*\.node|process\.dlopen" out/ | head -20
```

Then search the addon binary:

```bash
r2 -qc 'aaa; iz~licen' out/build/licence.node
r2 -qc 'aaa; ii~License' out/build/licence.node
```

Expected: symbols such as `LicenseManager::validate`, `CheckLicense` or `VerifyReceipt`, and
strings such as `License key is invalid` or `https://licence.vendor.example/validate`.

The verdict is returned as an integer or a boolean in the first return register. Force it:

```bash
rasm2 -a x86 -b 64 -d 'mov eax, 1'      # -> b8 01 00 00 00
rasm2 -a arm -b 64 -d 'mov w0, #1'      # -> 20 00 80 52
rasm2 -a x86 -b 32 -d 'mov eax, 1'      # -> b8 01 00 00 00
```

Apply the patch with radare2:

```bash
r2 -w -qc 'wx b801000000 @ 0xADDR; q' out/build/licence.node
```

### 6. Patch the JavaScript and repack

```bash
cd /path/to/work

# 1. Locate the decision.
rg -n --no-heading 'valid\s*=\s*' out/dist/main.js | head -20

# 2. Edit out/dist/main.js so the verdict is always true.

# 3. Repack.
npx --yes @electron/asar pack out/ app.asar

# 4. Install.
cp app.asar /path/to/App.app/Contents/Resources/app.asar

# 5. macOS: re-sign, the resource seal covers the archive.
codesign --force --sign - --timestamp=none /path/to/App.app
```

See `asar-extract-repack.md` for the container layout and the integrity fuse.

### 7. Patch the Electron integrity validation

When the fuse blocks a repacked archive, the check lives inside the Electron binary itself, not in
the application. Read and flip the fuse:

```bash
npx --yes @electron/fuses read --app-path /path/to/App.app
npx --yes @electron/fuses write --app-path /path/to/App.app \
  --version 1 --enable-embedded-asar-integrity-validation false
```

On macOS the framework binary is
`Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework`; the fuse wire is a
sentinel string followed by a byte per fuse:

```bash
r2 -qc '/ 644c37704b47446e4e7a37393675506d7107672b2b453655754a6e797851' \
  /path/to/App.app/Contents/Frameworks/Electron\ Framework.framework/Versions/A/Electron\ Framework
```

Expected: one hit at the fuse sentinel. The byte immediately after each fuse name is the state,
`0x72` (`r`) for enabled and `0x31` (`1`) for disabled.

### 8. Probe with ELECTRON_RUN_AS_NODE

With the `RunAsNode` fuse enabled, the Electron binary behaves as a plain Node.js interpreter:

```bash
cd /path/to/work
ELECTRON_RUN_AS_NODE=1 /path/to/App.app/Contents/MacOS/App --version
```

Expected: a Node.js version string such as `v20.18.1` instead of the Electron version. On Linux:

```bash
ELECTRON_RUN_AS_NODE=1 /opt/app/app --version
```

Run the application's own main script directly:

```bash
ELECTRON_RUN_AS_NODE=1 /path/to/App.app/Contents/MacOS/App \
  /path/to/work/out/dist/main.js 2>&1 | head -40
```

That runs the main-process code as Node, which prints the licence logic to stdout if the code
prints it, and more usefully lets the script be stepped through with the Node inspector.

If the `RunAsNode` fuse is disabled, flip it first:

```bash
npx --yes @electron/fuses write --app-path /path/to/App.app --version 1 --enable-run-as-node true
```

### 9. Live debugger on the main process

```bash
cd /path/to/work
/path/to/App.app/Contents/MacOS/App --inspect=9229 --inspect-brk out/dist/main.js
```

`--inspect-brk` breaks before the first line, so a breakpoint can be set on the licence function
before it runs. Attach with `chrome://inspect` in a Chromium browser, or with the Node inspector:

```bash
node --inspect=127.0.0.1:9229
```

For a packaged application the main process flag is `--inspect`, and the Node-level flag is only
available with `ELECTRON_RUN_AS_NODE`:

```bash
ELECTRON_RUN_AS_NODE=1 /path/to/App.app/Contents/MacOS/App --inspect-brk=127.0.0.1:9229 out/dist/main.js
```

The `--inspect` flag can be blocked by the `EnableNodeCliInspectArguments` fuse. Read it:

```bash
npx --yes @electron/fuses read --app-path /path/to/App.app | grep -i inspect
```

### 10. Dump the licence logic as executed

To see the decision as it runs, without a debugger, patch the boolean through the IPC channel.
Where the renderer is told the verdict, the message name is visible in the bundle:

```bash
rg -n --no-heading -i "ipcMain\.(handle|on)\(['\"]" out/dist/main.js | head -30
rg -n --no-heading -i "ipcRenderer\.(invoke|send|on)\(['\"]" out/ | head -30
```

An IPC channel named `license:check` or `check-license` is the seam. A small preload script can
override the renderer-side handler:

```javascript
// preload-override.js
const { contextBridge } = require('electron');
contextBridge.exposeInMainWorld('__licence', {
  isLicensed: () => Promise.resolve(true)
});
```

The renderer must consult it, which is not guaranteed; the main-process branch is the more
reliable patch point.

## Variations

- **Bundled and minified renderers.** A production renderer is a single minified line. Use
  `npx --yes prettier --write out/dist/renderer.js` or search with a fixed-string search for
  `licence` case-insensitively; the surrounding context is still recoverable.
- **Source maps.** A `*.js.map` next to the bundle turns the minified code back into readable
  modules and reveals the original file names, which is often enough to locate the licence module
  without touching the binary.
- **IPC-only checks.** The renderer never decides; it asks the main process. Patching the renderer
  then has no effect, and the main-process handler is the only seam.
- **Native addons.** The addon is a shared object and can also be interposed or patched with
  LIEF; see `../linux-elf/elf-patch-elf-toolchain.md` for the ELF side.
- **Renderer-side checks with obfuscation.** Obfuscated bundles may use string arrays and
  `eval`-based loaders. The strings are still in the file; `rg` finds them.
- **Service-side checks.** A vendor server decides. The local code caches the entitlement; the
  patch point is the JSON field the client trusts.
- **Packed with a different framework.** Tauri, Neutralino and Wails do not use ASAR and do not
  use Electron fuses; the licence logic sits in Rust, Go or C# and the methods in this entry do not
  apply.

## Verification

Positive — the licence logic is located and named:

```bash
cd /path/to/work
rg -i --no-heading -n 'licen|trial|expire' out/ | head -20
node -e "console.log(require('./out/package.json').main)"
```

Expected: a stable list of hits and the main entry point.

Positive — the modified archive loads and reports a valid licence:

```bash
npx --yes @electron/asar list /path/to/App.app/Contents/Resources/app.asar | wc -l
codesign -v --deep --strict /path/to/App.app ; echo "exit=$?"
```

Expected: the entry count matches the repacked archive and `exit=0`.

Negative — the check is really gone, not merely cached. Clear the application state and re-run:

```bash
rm -rf ~/.config/App ~/.config/app-name ~/Library/Application\ Support/App
rm -rf ~/Library/Caches/App
/path/to/App.app/Contents/MacOS/App
```

Expected: the app starts with the paid features enabled. If the licence state returns, the patch
did not change the decision point.

Negative — the probe path works, proving the JavaScript really runs in the main process:

```bash
ELECTRON_RUN_AS_NODE=1 /path/to/App.app/Contents/MacOS/App --version
```

Expected: a Node.js version string. If the Electron version is printed instead, the `RunAsNode`
fuse is off.

Negative — confirm the native addon patch is present:

```bash
r2 -qc 'aaa; s 0xADDR; p8 8' out/build/licence.node
```

Expected: the new bytes at the address, with the original file retained for rollback.

## Pitfalls

- `strings` on a compressed or packed archive finds noise. ASAR itself is uncompressed, but the
  JavaScript inside it may be minified into one long line, so `rg` prints an enormous match line.
  Use `-o` to print only the matched word.
- The `main` field may point at a file that only bootstraps; the licence code can be one import
  deeper. Follow the imports before concluding anything.
- `ELECTRON_RUN_AS_NODE` is ignored when the `RunAsNode` fuse is disabled, and the binary then
  starts the GUI instead of the script.
- `--inspect` is blocked by the `EnableNodeCliInspectArguments` fuse, and the app may also set
  `NODE_OPTIONS` restrictions through `EnableNodeOptionsEnvironmentVariable`.
- `--inspect-brk` breaks before the first line, which means the main window never appears and the
  app looks hung. That is expected.
- Repacking without re-signing on macOS gives `kill: 9`; the resource seal covers
  `Contents/Resources/app.asar`.
- A native addon is usually excluded from the asar into `app.asar.unpacked`; patching the copy
  inside the archive does nothing. Patch the unpacked file.
- `--allow-file-access-from-files` and `--no-sandbox` may be needed in a container, but they do not
  help with a fuse-enforced integrity check.
- DevTools are disabled in packaged apps unless the vendor left `devTools: true` in the
  `BrowserWindow` options or the app is started with `--remote-debugging-port=9222`.
- A licence check duplicated in the renderer and the main process means patching one leaves the
  other in place; check both before declaring success.

## References

- Electron documentation, *Process Model*, *Security*, *Electron Fuses* and *Inter-Process
  Communication*
- `electron/asar` and `@electron/asar` for the archive format and the CLI
- `electron/fuses` for reading and writing the fuse wire
- Node.js documentation, `process.dlopen`, the inspector protocol and `--inspect-brk`
- `chromium` DevTools protocol documentation for `--remote-debugging-port`
- Sibling entries: `asar-extract-repack.md`, `../linux-elf/elf-patch-elf-toolchain.md`,
  `../macos/hardened-runtime-and-library-validation.md`
