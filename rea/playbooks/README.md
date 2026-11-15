# Playbook index

Each playbook is a complete mission: a target shape, a symptom, an ordered procedure with real
commands, and the verification that proves the outcome. Read the matching one end to end before
starting; the steps are ordered by dependency.

| Playbook | Target | Outcome |
| --- | --- | --- |
| [`pb-windows-native.md`](pb-windows-native.md) | Windows PE (native) | Branch inverted or boolean forced, binary still loads |
| [`pb-windows-dotnet.md`](pb-windows-dotnet.md) | .NET assembly | IL edited, strong name and Authenticode resolved, app runs |
| [`pb-android-apk.md`](pb-android-apk.md) | Android APK | Smali or `.so` patched, rebuilt, aligned, signed, installed |
| [`pb-android-gadget.md`](pb-android-gadget.md) | Android APK without root | Frida Gadget embedded, autonomous hook script delivered |
| [`pb-ios-ipa.md`](pb-ios-ipa.md) | iOS IPA | Dylib injected or code patched, re-signed, installed |
| [`pb-macos-bundle.md`](pb-macos-bundle.md) | macOS app bundle | Code patched, re-signed, hardened runtime handled |
| [`pb-linux-elf.md`](pb-linux-elf.md) | Linux ELF | Patched in file, or interposed with `LD_PRELOAD` |
| [`pb-electron-asar.md`](pb-electron-asar.md) | Electron app | ASAR unpacked, patched, repacked, fuses handled |
| [`pb-license-keygen.md`](pb-license-keygen.md) | Any platform | Algorithm recovered, generator built and validated |
| [`pb-signed-blob-forgery.md`](pb-signed-blob-forgery.md) | App with signed licence | Blob forged or verification patched |
| [`pb-anti-analysis.md`](pb-anti-analysis.md) | Protected target | Unpacked, detection removed, target analysable |
| [`pb-patch-reporting.md`](pb-patch-reporting.md) | Any | Evidence, patch manifest and report produced |

## Cross-cutting rules

1. **Hash the target before everything.** The original hash is the anchor for every later claim.
2. **Work on a copy.** The original is the rollback.
3. **One change at a time.** A patched binary that fails tells you nothing about which change
   broke it.
4. **Re-verify after every stage**, not only at the end.
5. **Record offsets and bytes** as you go, using the manifest format from
   `skills/rea-patching-automation/SKILL.md`.

## Dependency order

```
triage ──► locate decision point ──► classify check ──► choose route
                                                      │
        ┌─────────────────────────────────────────────┼──────────────┐
        ▼                        ▼                    ▼              ▼
   file patch            runtime hook          forge input     protocol
        │                        │                    │              │
        └────────────┬───────────┘                    └──────┬───────┘
                     ▼                                       ▼
              re-verify target                       re-verify target
                     │                                       │
                     └──────────────► report ◄───────────────┘
```
