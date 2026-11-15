# Playbook: iOS IPA repack, patch and install

**Target**: an iOS application in IPA form whose features are gated by a licence check.
**Outcome**: a repacked IPA, re-signed and installed, with the check patched or bypassed.

## 0. Preparation

Needs a macOS host with the Xcode command line tools (`codesign`, `xcrun`), and for installation
either a developer certificate, a jailbroken device, or a signing service.

```sh
mkdir -p work && cd work
cp /path/to/app.ipa app.ipa
shasum -a 256 app.ipa
mkdir ipa && cd ipa && unzip -q ../app.ipa
ls -la Payload/
plutil -p Payload/App.app/Info.plist | head -40
codesign -dvvv Payload/App.app 2>&1 | head -20
```

Record the bundle identifier and the current signature state.

## 1. Locate the check

```sh
APP=Payload/App.app
otool -hv $APP/App
otool -L $APP/App
otool -oV $APP/App | grep -iA 12 'License\|Subscription\|IAP\|Pro'
nm -m $APP/App | grep -i licen
strings -a $APP/App | grep -iE 'licen|not activ|trial expir|purchase'
r2 -q -c 'izz~licen' $APP/App
```

If the app uses StoreKit, the entitlement arrives through a transaction. The local gate is still
a boolean somewhere.

## 2. Patch

### ObjC `BOOL`, arm64

```
00 00 80 52 C0 03 5F D6      mov w0, #0 ; ret   (false)
20 00 80 52 C0 03 5F D6      mov w0, #1 ; ret   (true)
```

### Conditional branch, arm64

```
40 00 00 54   b.eq +0x08   ->   41 00 00 54   b.ne +0x08
```

### arm64e

`arm64e` adds pointer authentication, which affects pointer values — not a plain boolean return.
The `mov w0, #1 ; ret` patch is unaffected.

### Dylib injection instead of a code patch

When the check is hard to reach statically, inject code:

```sh
cp frida-gadget.dylib $APP/Frameworks/
optool install -c load -p "@executable_path/Frameworks/frida-gadget.dylib" -t $APP/App
```

or with your own dylib that patches the decision at `+load` time.

## 3. FairPlay-encrypted binaries

App Store binaries are encrypted at rest (`LC_ENCRYPTION_INFO`, `cryptid != 0`) and decrypted by
the kernel at install. A file-level patch of the on-disk binary is impossible while encrypted.

Get the decrypted image from a running process:

```sh
# LLDB
(lldb) process attach --name App
(lldb) process save-core --output app.core
```

```js
// Frida
const m = Process.mainModule;
const text = m.enumerateSections().find(s => s.name === '__TEXT');
const bytes = Memory.readByteArray(text.address, text.size);
```

To patch the file, compute the offset of the instruction inside `__TEXT` and apply it to the
file's `__TEXT` segment — the loader maps that segment at a fixed relative position, so the
offset is stable:

```sh
otool -l $APP/App | grep -A 12 '__TEXT'
# segment file offset + (instruction address - segment vmaddr) = file offset
```

## 4. Re-sign

```sh
APP=Payload/App.app

# the entitlements must match what the app expects
codesign -d --entitlements :- $APP > entitlements.plist 2>/dev/null

# remove the old signature
rm -rf $APP/_CodeSignature $APP/Frameworks/*.framework/_CodeSignature

# sign nested code first, then the app
find $APP/Frameworks -name '*.framework' -maxdepth 1 | while read -r fw; do
  codesign --force --sign - "$fw"
done
codesign --force --sign - --entitlements entitlements.plist $APP

codesign -v --deep --strict --verbose=2 $APP
```

On a jailbroken device with `ldid`, the alternative is:

```sh
ldid -S $APP
ldid -S$entitlements.plist $APP
```

## 5. Repack and install

```sh
cd ipa
zip -qry ../resigned.ipa Payload
cd ..
shasum -a 256 resigned.ipa
```

Installation options:

```sh
# developer-signed, via USB
ios-deploy --bundle ipa/Payload/App.app --justlaunch

# jailbroken device
ideviceinstaller -i resigned.ipa

# signing service
zsign -a "your.p12" -m "provisioning.mobileprovision" -o out.ipa resigned.ipa
```

## 6. Verify

1. Launch the app and repeat the operation that was locked.
2. Terminate the app completely and relaunch — the state must survive a cold start.
3. Check the device log for loader problems:
   `idevicesyslog | grep -iE 'dyld|code signature|App'`.
4. Confirm the signature is valid on the host: `codesign -v --deep --strict $APP`.

## 7. Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| The app dies at launch | the signature is invalid | re-sign; nested code before the app |
| `Invalid Signature` on install | the provisioning profile does not match | re-sign with the right profile |
| The patch has no effect | the binary was still FairPlay-encrypted | dump the decrypted image and patch the file offset |
| `frida-gadget.dylib` missing at runtime | the load command path is wrong | use `@executable_path/Frameworks/...` |
| The app crashes in the patched path | the patch broke an invariant | patch the state rather than the boolean |
| The check runs in a helper app or extension | the check is not in the main binary | patch the extension too |

## Deliverable

`resigned.ipa`, the re-signing sequence, the patch manifest with the Mach-O offsets, and the
verification output.
