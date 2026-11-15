# Tool matrix

Version targets below were recorded by the corpus author on **2026-11-15**. They do not prove
that those releases are installed, currently latest, or compatible with every example. Confirm
the exact release and API against the linked upstream documentation before use. Schema checks
do not validate engine execution or live application procedures.

## Core instrumentation

| Tool | Version | Source | Notes |
| --- | --- | --- | --- |
| Frida | 17.x | frida.re/news | Confirm exact client, server and Gadget releases locally; do not mix incompatible releases. |
| Frida bridges | 17.x | frida.re/docs/bridges | Since **17.0.0 bridges are not bundled** with the GumJS runtime. `frida-java-bridge`, `frida-objc-bridge`, `frida-swift-bridge` are separate packages, migrated to ESM for `frida-compile`. |
| Frida Gadget | 17.x | frida.re/docs/gadget | Config-file driven. `interaction.type: "script"` with `path` executes an autonomous agent inside the app with no host attached. |

### Frida 17 breaking changes that break older scripts

| Removed / changed | Replacement |
| --- | --- |
| Static `Module.findExportByName(module, name)` | `Process.getModuleByName(module).getExportByName(name)` or `Module.getGlobalExportByName(name)` |
| Static `Module.getExportByName(module, name)` | `Module.getGlobalExportByName(name)` (throws when absent) |
| Static `Module.ensureInitialized(module)` | `module.ensureInitialized()` on the instance |
| Bundled `Java` / `ObjC` / `Swift` bridges | Install the matching bridge package and bundle with `frida-compile` |
| `Interceptor.attach` on `Process.mainModule` paths without init | Call `module.ensureInitialized()` before touching exports |

`Module.load` is static, not an instance API. Other relevant APIs include `Process.enumerateModules`,
`Process.attachModuleObserver`, `Memory.scan` / `scanSync` / `findPointers`, `Memory.patchCode`,
`MemoryAccessMonitor`, `Interceptor`, `Stalker`, `CModule`, `RustModule`, `ApiResolver`
(`module` / `objc` / `swift`), `DebugSymbol`, `Java`/`ObjC`/`Swift` bridges when installed.

The Frida REPL and `frida-trace` provide bridges in their own agents; autonomous Gadget agents
must import and bundle the required bridge. Removing bridges from GumJS does not mean every
REPL script needs an extra build step. `ObjC.schedule` takes `(queue, work)`.

`Process.codeSigningPolicy` reports `optional` unless Gadget is configured to assume signing is
required; it tells the agent whether `Interceptor` and in-memory code modification are usable.

## Binary parsing and rewriting

| Tool | Version | Source | Notes |
| --- | --- | --- | --- |
| LIEF | 1.0.0 | pypi.org/project/lief | Released 2026-07-12. Python 3.9+. Handles ELF, PE, Mach-O, OAT, DEX, VDEX, ART. `patch_address()` exists on the Mach-O and PE surfaces; LIEF Extended adds DWARF, PDB, Objective-C metadata and dyld shared cache support. |
| radare2 | 6.2.6 | github.com/radareorg/radare2/releases | Latest tagged release. `master` tracks 6.2.7/6.2.8. `rabin2`, `r2`, `r2pipe`. |
| Ghidra | verify locally | github.com/NationalSecurityAgency/ghidra/releases | Use the exact release's installation guide for its JDK requirement. |
| Capstone / Unicorn | verify locally | — | Disassembly and emulation engines. Used for opcode-level patch construction and emulation-based verification. |
| patchelf | verify locally | github.com/NixOS/patchelf | `--replace-needed`, `--set-interpreter`, `--set-rpath`, `--remove-rpath`, `--add-needed`. |

## Managed code

| Tool | Version | Source | Notes |
| --- | --- | --- | --- |
| dnSpyEx | 6.6.0 | github.com/dnSpyEx/dnSpy/releases | First stable release in two years. Uses upstream ILSpy engine (ICSharpCode.Decompiler 11.2). Ships a `.NET 10` distribution (`dnSpy-net`, x64+x86, not self-contained). IL editor and metadata table editing. |
| ILSpy | verify locally | github.com/icsharpcode/ILSpy | Command-line `ilspycmd` for batch decompile; GUI for navigation. |
| jadx | 1.5.6 | github.com/skylot/jadx/releases | Java/Kotlin decompiler for DEX. `jadx-gui` for navigation, `jadx` CLI for batch export. |
| apktool | 2.12+ | github.com/iBotPeaches/apktool/releases | Ships smali/baksmali 3.0.8; 3.0.10 in the unreleased notes. Decode → rebuild → resource re-decode fidelity. |

## Debugging and anti-analysis

| Tool | Version | Source | Notes |
| --- | --- | --- | --- |
| x64dbg | verify locally | releases.x64dbg.com | x86/x64 Windows debugger with the plugin ecosystem. |
| ScyllaHide | verify locally | github.com/x64dbg/ScyllaHide | Anti-anti-debug plugin for x64dbg/IDA/Binary Ninja. Ships profiles including `VMProtect x86/x64`. |
| LLDB / GDB / lldb-server | platform built-in | — | Primary debuggers for Mach-O and ELF targets. |

## Mobile patching and instrumentation

| Tool | Version | Source | Notes |
| --- | --- | --- | --- |
| LSPatch | verify locally | github.com/lsposed/lspatch | Rootless Xposed-style module injection by inserting dex and native libraries into the target APK. |
| Play Integrity Fix | verify locally | github.com/KOWX712/PlayIntegrityFix | Magisk / KernelSU / APatch module. Requires root + Zygisk (Magisk built-in, ZygiskNext, NeoZygisk, ReZygisk). |
| optool | verify locally | github.com/aferrero2707/optool | Mach-O load-command surgery: `install -c load -p <path>`, strip code signatures, resign, remove ASLR. |
| objection | verify locally | github.com/sensepost/objection | Frida companion; its gadget-embedding mode injects Frida Gadget into an APK for non-root deployment. |

## Packaging and signing

| Tool | Platform | Notes |
| --- | --- | --- |
| `apksigner` | Android | Build Tools 24.0.3+. Verifies and produces v1/v2/v3/v3.1 signatures. |
| `uber-apk-signer` | Android | Batch `zipalign` + sign helper. |
| `zipalign` | Android | Page alignment for native libraries, required before signing. |
| `codesign` | macOS | `--force --deep --sign -` for ad-hoc; `--entitlements` to preserve or grant capabilities. |
| `ldid` | macOS / iOS | Alternative entitlement signer for jailbroken devices. |
| `lief` | all | Fallback when platform-native signing tools are unavailable. |

## REA integration

`REA` (github.com/morluto/rea) is the MCP server for artifact analysis. Pinned npm release used by
this repository's installer: `rea-agents@6.9.0`, which declares Node.js `^22.23.4 || ^24.22.1 ||
>=26.12.1`. Native analysis needs an existing engine (Ghidra, Hopper, IDA or Kuna); REA does not
install engines. Useful entry points for this corpus:

| Need | REA tool |
| --- | --- |
| Native executable, library or analysis database | `open_binary`, then focused analysis tools |
| Managed PE/CLI assembly | `inspect_managed_artifact` |
| Android package code, classes, methods | `inspect_android_package` |
| ASAR / extracted JavaScript tree | `analyze_javascript_application` |
| Archive member inventory (APK, IPA, ZIP, MSIX, DMG, PyInstaller) | `open_binary` with `detail: "summary"` |
| APK signature schemes and signers | `inspect_apk_signature` |
| PE imports, delay-load, TLS, load config, certificates | `inspect_pe_imports`, `inspect_pe_load_config`, `inspect_pe_certificates`, `inspect_pe_resources` |
| ELF notes, exported symbols | `inspect_elf_notes`, `inspect_native_exports` |
| Unity IL2CPP metadata | `inspect_il2cpp_metadata` |
| Recorded packet / web captures | `inspect_packet_capture`, `inspect_web_network_capture` |

## Verification sources

- Frida release notes: <https://frida.re/news>
- Frida JavaScript API: <https://frida.re/docs/javascript-api/>
- LIEF documentation: <https://lief.re/doc/latest/>
- Ghidra releases: <https://github.com/NationalSecurityAgency/ghidra/releases>
- radare2 releases: <https://github.com/radareorg/radare2/releases>
- dnSpyEx releases: <https://github.com/dnSpyEx/dnSpy/releases>
- jadx releases: <https://github.com/skylot/jadx/releases>
- apktool releases: <https://github.com/iBotPeaches/apktool/releases>
- REA upstream: <https://github.com/morluto/rea>
