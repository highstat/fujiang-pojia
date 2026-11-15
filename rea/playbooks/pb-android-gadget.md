# Playbook: Android APK patch without root (Frida Gadget)

**Target**: an Android application that must be modified without root — a shared device, an
unrootable device, or a distribution where the user cannot run a Frida server.
**Outcome**: an APK that carries Frida Gadget and executes an autonomous hook script at launch,
so the licence decision is overridden without any host tooling.

## 0. Preparation

```sh
mkdir -p work && cd work
cp /path/to/app.apk app.apk
sha256sum app.apk | tee app.sha256
unzip -l app.apk | grep -E 'lib/|classes.*dex'
aapt2 dump badging app.apk | grep -E 'package|native-code'
```

Determine the ABI of the target device:

```sh
adb shell getprop ro.product.cpu.abi
```

`arm64-v8a` covers virtually all current devices. `armeabi-v7a` is the 32-bit fallback.

## 1. Obtain the Gadget

Frida 17 no longer bundles the bridges into the runtime. The Gadget is a standalone artefact:

```sh
pip install frida-tools
python3 -c "import frida; print(frida.__version__)"       # match the Gadget version

# download frida-gadget-<version>-android-<arch>.so.xz from the Frida release page
unxz frida-gadget-17.26.0-android-arm64.so.xz
cp frida-gadget-17.26.0-android-arm64.so libgadget.so
```

The Gadget and the host `frida` CLI should be the same version.

## 2. Write the hook script

The script runs inside the app with no host attached. It must be self-contained.

```js
/* gadget.js */
Java.perform(function () {
  var License = Java.use('com.vendor.LicenseManager');
  License.isValid.implementation = function (key) {
    console.log('[hook] isValid(' + key + ') -> true');
    return true;
  };

  // catch classes that are not yet loaded
  try {
    var Premium = Java.use('com.vendor.Premium');
    Premium.isUnlocked.implementation = function () { return true; };
  } catch (e) {}
});
```

The Java bridge must be bundled into the script — on Frida 17 `Java` is undefined in a raw
script:

```sh
npm install frida-java-bridge frida-compile
npx frida-compile gadget.js -o gadget.script.js
```

For a native hook, the Gadget script needs no bridge:

```js
const so = Process.getModuleByName('liblicense.so');
Interceptor.attach(so.getExportByName('Java_com_vendor_LicenseManager_isValid'), {
  onLeave(r) { r.replace(1); }
});
```

## 3. Embed into the APK

```sh
mkdir -p apk_work
cd apk_work
unzip -q ../app.apk
mkdir -p lib/arm64-v8a
cp ../libgadget.so lib/arm64-v8a/libgadget.so
cp ../gadget.script.js lib/arm64-v8a/libgadget.script.js
```

The Gadget config file sits next to the library and is named after it:

```json
{
  "interaction": {
    "type": "script",
    "path": "libgadget.script.js"
  }
}
```

Write it to `lib/arm64-v8a/libgadget.config.json`.

The Gadget loads when the app loads the library. Two ways to trigger that:

**a. Explicit load** — patch `Application.attachBaseContext` in smali:

```smali
.method protected attachBaseContext(Landroid/content/Context;)V
    .locals 1
    invoke-super {p0, p1}, Landroid/app/Application;->attachBaseContext(Landroid/content/Context;)V
    const-string v0, "gadget"
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
    return-void
.end method
```

**b. The app already loads a native library** — rename the Gadget to that library's name and
replace it. Simpler, but it replaces a library the app needs.

## 4. Rebuild and sign

```sh
cd apk_work
zip -q -r ../app_gadget.apk . -x '.*'
cd ..
zipalign -P 16 -f 4 app_gadget.apk app_gadget_aligned.apk
apksigner sign --ks my.keystore --ks-pass pass:android --key-pass pass:android \
               --out app_gadget_signed.apk app_gadget_aligned.apk
apksigner verify --verbose app_gadget_signed.apk
```

## 5. Install and check

```sh
adb uninstall com.vendor.app
adb install app_gadget_signed.apk
adb logcat -c
adb shell am start -n com.vendor.app/.MainActivity
adb logcat | grep -iE 'hook|gadget|frida|AndroidRuntime'
```

The `[hook]` line in logcat confirms the script ran and the method was replaced.

## 6. Making the distribution usable

For a shipped build, the script should be unobtrusive: no verbose logging, no `send()` calls to
a host that is not there, and it must fail silently if the target class does not exist.

```js
Java.perform(function () {
  try {
    var License = Java.use('com.vendor.LicenseManager');
    License.isValid.implementation = function (k) { return true; };
  } catch (e) { /* class absent in this build */ }
});
```

## 7. Limitations

- **Play Integrity.** A modified APK has a different signature and a modified package; attestation
  fails unless the device-side signals are also spoofed. Server-side entitlement checks are not
  affected by the client patch and remain the real gate.
- **Update path.** The store refuses to update a differently-signed package. The user must
  reinstall from the patched APK after each update.
- **Native hooks and early calls.** A hook installed after the library loads misses the calls
  made during startup. Use `Process.attachModuleObserver` when that matters:

```js
Process.attachModuleObserver({
  onAdded(module) {
    if (module.name === 'liblicense.so') {
      const fn = module.getExportByName('Java_com_vendor_LicenseManager_isValid');
      Interceptor.attach(fn, { onLeave(r) { r.replace(1); } });
    }
  }
});
```

- **Gadget detection.** An app that scans its own APK for known libraries can detect the
  Gadget. Remove the artefact names, or hook the scan.

## Deliverable

The signed APK, the Gadget and its config, the bundled script, and the logcat output proving the
hook executed.
