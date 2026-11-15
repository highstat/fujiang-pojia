# REA structure and agent-instruction review

[Corpus guide](rea-corpus.md) · [Source overview](../rea/README.md)

Reviewed on 2026-11-15. This is a focused source/helper review, not an assertion that all
160,000 words or every platform-specific command were executed or independently verified.
The initial read-only request was superseded by the user's explicit request to fix findings.

## Fixed in this update

| Area | Finding and correction |
| --- | --- |
| Installation | `sh` invoked Bash-only features; the new POSIX launcher calls a Python installer. Skills previously copied without their referenced corpus; they now include a shared relocatable resource snapshot. |
| Updates | Replacements previously deleted existing skills without backup or rollback. Updates now stage content, preserve backups outside discovery, reject symlinks/source destinations and restore completed replacements on failure. |
| Agent files | Long duplicated code diverged from procedures and contained API/opcode mistakes. All 12 skills now have distinct frontmatter triggers and short workflows linking canonical resources. |
| Patch manifest | The helper accepted missing hashes, empty/overlapping/negative patches and existing output paths. It now validates those invariants, protects the input, writes exclusively and preserves executable permission bits without privilege bits. |
| Address mapping | PE VA/RVA confusion, incorrect header/BSS fallbacks and little-endian-only ELF parsing are corrected. Mach-O command sizes and universal slice bounds are checked; PE `--rva` and Mach-O `--slice` are explicit. |
| Candidate scanner | 64-bit Mach-O no longer implies ARM64. Near x86 branches, final instructions, ARM64 masks and universal-file offsets are corrected. Raw-byte hits remain candidates, not instruction proofs. |
| Frida examples | Fixed Objective-C queue/implementation handling, NT output widths and inverted flag semantics, optional counter writes and bounded capture reads. Removed obsolete spawn flags in commands and corrected bridge guidance using upstream docs. |
| Platform examples | Corrected reviewed ARM64 and smali encodings, strong-name commands, IL stack-preserving branch inversion, an ELF version-script example and LIEF dependency editing. Client changes no longer imply forging original asymmetric signatures. |
| Packaging | APK helper uses 16 KiB library alignment, environment password references and alignment verification. macOS traversal signs deep nested code and standalone Mach-O files, preserving per-component entitlements. These are not live signing tests. |
| C template | Added required types/includes, forwarded variadic `open` modes and made clock/machine-ID changes explicit options instead of unconditional global mutations. |
| Corpus tooling | Validator checks real dates, exact boolean types, duplicate keys/IDs, canonical vocabulary, skill frontmatter, links and fence structure. Normalizer rejects unknown values and retains arm64e as distinct from arm64. |

## What should still improve

1. Add per-platform fixture matrices and negative tests for SDK, loader and signing behavior.
   Mocks cannot validate Frida's real bridge/ABI behavior, and syntactically correct C is not
   evidence that an interposer is safe for every threaded application.
2. Keep machine-readable tool/version provenance with exact source URL, retrieval date and
   supported command/API version. Do not label a broad version table “latest” or “verified”
   without release-specific evidence. Frida/LIEF documentation was queried through Context7
   during this pass; no engine installation followed.
3. Add per-entry verification records before setting `verified: true`: target hash, platform,
   version, prerequisites, commands, expected/observed results and negative cases. Do not
   globally refresh `updated` just to satisfy a validator.
4. Expand application-semantic tests rather than only byte-pattern checks. Inverted branches
   swap paths; a modified client or displayed UI state does not establish a valid signature,
   backend authorization or a complete functional result.

## Evidence used here

- Python regressions use synthetic PE/ELF/Mach-O headers, byte arrays and temporary install
  trees; they never launch a supplied application or use a real license target.
- Node tests use Frida API mocks, not an injected agent. C coverage is a compiler syntax check.
- Corpus validation covers metadata and document structure; it cannot prove technical truth.
- No global host configuration, scanner, engine, signing identity or connected device is changed
  by these checks. The source prompt and plugin runtime are outside this update's fixes.

Relevant primary references: [Frida JavaScript API](https://frida.re/docs/javascript-api/),
[Frida bridges](https://frida.re/docs/bridges/),
[LIEF ELF tutorial](https://lief.re/doc/latest/tutorials/09_frida_lief.html),
[DEX bytecode](https://source.android.com/docs/core/runtime/dalvik-bytecode),
[zipalign](https://developer.android.com/tools/zipalign),
[Strong Name tool](https://learn.microsoft.com/en-us/dotnet/framework/tools/sn-exe-strong-name-tool),
and [Electron fuses](https://www.electronjs.org/docs/latest/tutorial/fuses).
