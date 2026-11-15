# REA knowledge index

[Corpus overview](../README.md) · [Schema](SCHEMA.md) · [Authoring guide](../references/AUTHORING.md) · [Tool matrix](../references/tool-matrix.md) · [Playbooks](../playbooks/README.md)

**49 entries across 10 domains.** Each entry is a self-contained technique: how the target
presents, the procedure with exact commands and byte values, the variations, and how to prove
the outcome.

## native-core — 8 entries

Format internals and patch mechanics, platform-neutral.

| Entry | Delivers |
| --- | --- |
| [`elf-pe-macho-layout.md`](native-core/elf-pe-macho-layout.md) | Virtual address to file offset in PE, ELF and Mach-O, with worked examples |
| [`conditional-branch-patching.md`](native-core/conditional-branch-patching.md) | Every branch-inversion and boolean-return encoding for x86, x64 and arm64 |
| [`call-graph-and-xref-recovery.md`](native-core/call-graph-and-xref-recovery.md) | Building a call graph without symbols; RTTI, vtables and ObjC metadata |
| [`string-and-symbol-recovery.md`](native-core/string-and-symbol-recovery.md) | Separating real strings from instruction bytes; stack strings and obfuscation |
| [`function-identification-fingerprints.md`](native-core/function-identification-fingerprints.md) | Recognising library and crypto functions from code shape when symbols are stripped |
| [`inline-hook-patching.md`](native-core/inline-hook-patching.md) | Trampolines, relative-call displacement maths, arm64 branch rewriting |
| [`import-table-and-plt-got-surgery.md`](native-core/import-table-and-plt-got-surgery.md) | Redirecting a call through the import table, the PLT/GOT or the Mach-O namespace |
| [`checksum-and-integrity-repair.md`](native-core/checksum-and-integrity-repair.md) | Identify checksum/signing layers and repair what can be recomputed or re-signed |

## license-crypto — 8 entries

Licence rules, keygens, signed blobs and activation.

| Entry | Delivers |
| --- | --- |
| [`serial-validation-algorithm-recovery.md`](license-crypto/serial-validation-algorithm-recovery.md) | The six common validation shapes and how to tell them apart |
| [`keygen-construction.md`](license-crypto/keygen-construction.md) | Turning a recovered rule into a generator, including the non-invertible case |
| [`asymmetric-license-signature-verification.md`](license-crypto/asymmetric-license-signature-verification.md) | Extracting the public key; swapping it or patching the verification |
| [`symmetric-license-blob-formats.md`](license-crypto/symmetric-license-blob-formats.md) | Recovering symmetric keys from memory and rebuilding the plaintext |
| [`offline-activation-and-machine-binding.md`](license-crypto/offline-activation-and-machine-binding.md) | The offline handshake and the machine-fingerprint sources per platform |
| [`license-server-protocol-analysis.md`](license-crypto/license-server-protocol-analysis.md) | The activation protocol, TLS interception and response rewriting |
| [`trial-and-expiry-enforcement.md`](license-crypto/trial-and-expiry-enforcement.md) | Trial state storage, clock-rollback defences and the patch points |
| [`hardware-fingerprint-binding.md`](license-crypto/hardware-fingerprint-binding.md) | Per-platform fingerprint collectors and how to stabilise them |

## windows-native — 4 entries

| Entry | Delivers |
| --- | --- |
| [`pe-section-and-entry-analysis.md`](windows-native/pe-section-and-entry-analysis.md) | PE layout, section characteristics, entry point, packer detection |
| [`win32-licence-ui-flow.md`](windows-native/win32-licence-ui-flow.md) | The modal-dialog licence gate and how to find its handler |
| [`native-exception-based-control-flow.md`](windows-native/native-exception-based-control-flow.md) | SEH/VEH-based checks and how to neutralise them |
| [`windows-integrity-and-tamper-checks.md`](windows-native/windows-integrity-and-tamper-checks.md) | Self-checks a Windows binary performs and their patch points |

## windows-dotnet — 4 entries

| Entry | Delivers |
| --- | --- |
| [`il-licence-check-editing.md`](windows-dotnet/il-licence-check-editing.md) | Finding and editing the licence method in IL, with opcode encodings |
| [`dotnet-obfuscator-deobfuscation.md`](windows-dotnet/dotnet-obfuscator-deobfuscation.md) | ConfuserEx, .NET Reactor and Dotfuscator: identification and unwrapping |
| [`strong-name-and-authenticode.md`](windows-dotnet/strong-name-and-authenticode.md) | What breaks on an IL edit and the exact repair for each layer |
| [`managed-native-interop-hybrid.md`](windows-dotnet/managed-native-interop-hybrid.md) | P/Invoke and NativeAOT hybrids — where the check really lives |

## android — 4 entries

| Entry | Delivers |
| --- | --- |
| [`apk-decode-rebuild-sign.md`](android/apk-decode-rebuild-sign.md) | The full decode → rebuild → align → sign round trip and why the order matters |
| [`dex-smali-licence-patching.md`](android/dex-smali-licence-patching.md) | Smali shapes of a licence check and the concrete rewrites |
| [`android-native-library-licence.md`](android/android-native-library-licence.md) | JNI entry points, arm64 return patches and replacing a `.so` in place |
| [`play-billing-entitlement-faking.md`](android/play-billing-entitlement-faking.md) | Entitlement caching, Play Integrity and the server-side limit |

## ios — 4 entries

| Entry | Delivers |
| --- | --- |
| [`ipa-repack-and-resign.md`](ios/ipa-repack-and-resign.md) | Injecting a dylib and re-signing an IPA in the correct order |
| [`ios-native-licence-patching.md`](ios/ios-native-licence-patching.md) | Finding and patching the entitlement in arm64 Mach-O code |
| [`fairplay-decrypted-binary-handling.md`](ios/fairplay-decrypted-binary-handling.md) | Dumping the decrypted image and mapping offsets back to the file |
| [`jailbreak-detection-bypass.md`](ios/jailbreak-detection-bypass.md) | Every detection signal and the exact call to hook for each |

## macos — 4 entries

| Entry | Delivers |
| --- | --- |
| [`app-bundle-analysis.md`](macos/app-bundle-analysis.md) | The bundle layout and where the licence strings actually live |
| [`codesign-and-entitlements.md`](macos/codesign-and-entitlements.md) | Signing order, `--preserve-metadata`, and what each flag does |
| [`hardened-runtime-and-library-validation.md`](macos/hardened-runtime-and-library-validation.md) | The three injection routes and the entitlement that unlocks them |
| [`mas-receipt-validation.md`](macos/mas-receipt-validation.md) | The store receipt and the three ways to satisfy its check |

## linux-elf — 3 entries

| Entry | Delivers |
| --- | --- |
| [`elf-interposition-ld-preload.md`](linux-elf/elf-interposition-ld-preload.md) | `LD_PRELOAD` interposition, symbol versioning, and why a hook silently fails |
| [`elf-patch-elf-toolchain.md`](linux-elf/elf-patch-elf-toolchain.md) | `patchelf` versus LIEF, and the structural repair after each |
| [`linux-desktop-licence-flow.md`](linux-elf/linux-desktop-licence-flow.md) | XDG state locations, keyrings, sandboxing and the machine id |

## electron-js — 2 entries

| Entry | Delivers |
| --- | --- |
| [`asar-extract-repack.md`](electron-js/asar-extract-repack.md) | The container format, extraction, repacking and the header parser |
| [`electron-licence-flow.md`](electron-js/electron-licence-flow.md) | Where the licence lives in an Electron app, layer by layer |

## anti-analysis — 8 entries

| Entry | Delivers |
| --- | --- |
| [`debugger-detection-techniques.md`](anti-analysis/debugger-detection-techniques.md) | The full detection catalogue per platform and the neutralisation for each |
| [`timing-based-anti-debug.md`](anti-analysis/timing-based-anti-debug.md) | Elapsed-time checks and how to defeat them with a constant delta |
| [`integrity-self-checks.md`](anti-analysis/integrity-self-checks.md) | Self-verification patterns and the digest recomputation route |
| [`vm-and-emulator-detection.md`](anti-analysis/vm-and-emulator-detection.md) | CPUID, device files, MAC prefixes and Android emulator properties |
| [`packers-and-unpacking.md`](anti-analysis/packers-and-unpacking.md) | Identification, static and dynamic unpacking, and rebuilding the image |
| [`obfuscation-llvm-mir.md`](anti-analysis/obfuscation-llvm-mir.md) | The ollvm transformations and how to recognise each |
| [`control-flow-flattening.md`](anti-analysis/control-flow-flattening.md) | The dispatcher recipe and the CFG recovery procedure |
| [`anti-anti-debug-tooling.md`](anti-analysis/anti-anti-debug-tooling.md) | ScyllaHide profiles, Frida's own detection surface and the counter-countermeasures |

## Where to start

| Situation | Read |
| --- | --- |
| A licence dialog blocks startup | `native-core/conditional-branch-patching.md`, then the platform entry |
| The serial format must be understood | `license-crypto/serial-validation-algorithm-recovery.md` |
| A keygen must be produced | `license-crypto/keygen-construction.md` |
| A licence file is signed | `license-crypto/asymmetric-license-signature-verification.md` |
| The target refuses to run under a debugger | `anti-analysis/debugger-detection-techniques.md` |
| The binary verifies itself | `anti-analysis/integrity-self-checks.md` |
| The app is packed | `anti-analysis/packers-and-unpacking.md` |
| A signature breaks after the edit | `native-core/checksum-and-integrity-repair.md` |

## Conventions

- `verified: false` means the procedure is documented but was not executed end to end by the
  author. It is a statement about the author, not about the technique.
- Every command is copy-pasteable and states its working directory.
- Offsets are written `0x1234`; byte sequences as spaced lowercase hex: `74 12 90 90`.
