# Playbook: Electron app licence bypass

**Target**: an Electron application packaged with `app.asar`.
**Outcome**: the application launches with the licensed features unlocked, after the archive is
patched, repacked and — where required — re-signed.

## 0. Preparation

```sh
mkdir -p work && cd work
cp -R "/path/to/App.app" App.app          # macOS
# or: cp -R /path/to/App App              # Windows
find App.app -type f -exec shasum -a 256 {} \; | tee hashes.txt
ls App.app/Contents/Resources/            # macOS
ls App/resources/                         # Windows
```

Identify the archive:

```sh
npx @electron/asar list App.app/Contents/Resources/app.asar | head -40
```

## 1. Locate the licence logic

```sh
npx @electron/asar extract App.app/Contents/Resources/app.asar app_out
rg -n -i 'licen|serial|activat|trial|expir|purchas|premium|subscription' app_out/
```

The layers, in the order they gate the feature:

| Layer | Where | Notes |
| --- | --- | --- |
| Renderer | `app_out/dist/*.js`, `app_out/build/*.js` | shows the paywall; patching it hides the dialog but not the gate |
| Main process | `app_out/main.js`, `app_out/*.js` | owns the licence state and the IPC handlers — the real decision |
| Preload | `app_out/preload.js` | may cache a `licensed` flag the renderer trusts |
| Native addon | `app.asar.unpacked/**/*.node` | the actual check, in native code |

Find the IPC boundary:

```sh
rg -n "ipcMain\.(handle|on)" app_out/
rg -n "ipcRenderer\.(invoke|send)" app_out/
```

The handler that answers "am I licensed" is the gate.

## 2. Read the decision without a debugger

Run the app's own Node:

```sh
cd App.app/Contents/MacOS
ELECTRON_RUN_AS_NODE=1 ./App -e 'console.log(process.versions)'
ELECTRON_RUN_AS_NODE=1 ./App -e 'console.log(require("./app_out/main.js") ? "loaded" : "")'
```

Attach the inspector to the main process:

```sh
./App --inspect=9229
```

If the fuse `EnableNodeCliInspectArguments` is off, `--inspect` is ignored — check with
`npx @electron/fuses read --app ./App`.

## 3. Patch

### The IPC handler — the reliable target

```js
// before
ipcMain.handle('check-license', async () => {
  const key = store.get('licenseKey');
  return validateLicense(key);
});

// after
ipcMain.handle('check-license', async () => true);
```

### A minified bundle

Find the handler by its literal and force the result. Minifiers emit `!0` for `true` and `!1`
for `false`:

```js
// before
return 0 === t && (e = o("https://vendor/api/verify"), ...)
// after
return !0
```

### The renderer

Replace the paywall with the licensed view. Find the condition that selects the paywall
component and invert it.

### The preload cache

```js
// before
contextBridge.exposeInMainWorld('license', { isLicensed: () => ipcRenderer.invoke('check-license') });
// after
contextBridge.exposeInMainWorld('license', { isLicensed: () => true });
```

### The native addon

```sh
ls app_out/../app.asar.unpacked/node_modules/*/build/Release/*.node
r2 -q -c 'is~licen; ic~licen' app.asar.unpacked/node_modules/foo/build/Release/foo.node
```

Patched `.node` files live outside the archive and are stored verbatim — repack does not touch
them.

## 4. Repack

```sh
npx @electron/asar pack app_out App.app/Contents/Resources/app.asar
npx @electron/asar list App.app/Contents/Resources/app.asar | wc -l   # compare with the original
```

## 5. Electron fuses

If the app refuses to start, inspect the actual fuse state, archive errors and signature
diagnostics. A launch failure does not prove integrity validation is enabled:

```sh
npx @electron/fuses read --app ./App.app
npx @electron/fuses --help
```

Use the installed package's documented options/API for `EnableEmbeddedAsarIntegrityValidation`;
there is no generic `disable-code-integrity` fuse. `RunAsNode` and
`EnableNodeCliInspectArguments` are separate controls. Changing a fuse is not required for
static archive inspection.

Flipping a fuse modifies the Electron binary, which invalidates the app signature. Re-sign
afterwards:

```sh
codesign --force --deep --sign - ./App.app
codesign -v --deep --strict ./App.app
```

## 6. Verify

1. Launch the patched app and repeat the operation that was locked.
2. Clear the Electron state and repeat:
   ```sh
   rm -rf ~/Library/Application\ Support/AppName      # macOS
   rm -rf %APPDATA%\AppName                           # Windows
   ```
3. Confirm the repack is structurally identical to the original: compare the entry counts and
   the paths from `asar list` before and after.
4. If the app still refuses to start, check the fuse state and the signature before touching the
   patch again.

## 7. Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| The app does not start after repacking | the integrity fuse | flip the fuse, re-sign |
| The paywall is gone but the feature still fails | the gate is in the main process or the addon | patch the handler, not the renderer |
| The app is slower or errors on a missing module | the repack dropped a file | compare the `asar list` output |
| The patch is ignored | the app loads from `app.asar.unpacked` or from a different path | check `process.resourcesPath` at runtime |
| macOS refuses to launch | the signature is invalid after the fuse flip | re-sign the bundle |

## Deliverable

The repacked app, the patched files with their diffs, the fuse state before and after, and the
verification output.
