# REA knowledge schema

The REA corpus uses its own schema. It is deliberately lighter than the CVE-oriented schema in
`../../plugin/knowledge/SCHEMA.md`: REA entries describe techniques and procedures, not advisories.
The two corpora never mix; a file belongs to exactly one of them.

## Location

```text
rea/knowledge/<domain>/<entry-id>.md
```

Allowed domains:

| Domain | Covers |
| --- | --- |
| `native-core` | Formats, calling conventions, disassembly, cross-references, patch mechanics |
| `license-crypto` | Serial algorithms, keygens, signed licence blobs, activation protocols |
| `windows-native` | PE internals, Win32 API surface, native licensing flows |
| `windows-dotnet` | IL, metadata, obfuscators, .NET licensing |
| `android` | DEX, smali, APK packaging, signing, native libraries, Play flows |
| `ios` | Mach-O in iOS, FairPlay, jailbreak detection, IPA packaging |
| `macos` | App bundles, code signing, entitlements, hardened runtime, receipt validation |
| `linux-elf` | ELF layout, dynamic linking, interposition, distro specifics |
| `electron-js` | ASAR, bundles, licensing in JavaScript, Node/desktop packaging |
| `anti-analysis` | Anti-debug, integrity checks, VM detection, packers, obfuscators |
| `tooling` | Tool mechanics, script APIs, automation, reporting |

`native-core` and `tooling` are platform-neutral; everything else is platform-bound.

## Frontmatter

Flat `key: value`, `---` delimited, no nested structures, no sequences. String values are
double-quoted JSON scalars; numbers, booleans and `null` are typed.

| Field | Type | Meaning |
| --- | --- | --- |
| `id` | string | Lowercase hyphenated identifier, identical to the filename without `.md`. |
| `title` | string | Human-readable subject. |
| `domain` | string | One of the domains above. |
| `kind` | string | `technique`, `format`, `pattern`, `playbook-ref`, or `tooling`. |
| `platforms` | string | Comma-separated platform list, or `-` for platform-neutral entries. |
| `arch` | string | Comma-separated architecture list, or `-`. |
| `difficulty` | string | `intro`, `intermediate`, or `advanced`. |
| `tools` | string | Comma-separated primary tool list, or `-`. |
| `verified` | boolean | `true` only when the procedure was executed end to end. |
| `updated` | string | `YYYY-MM-DD` of the last substantive revision. |
| `summary` | string | One sentence stating what the entry delivers. |

`verified: true` requires that the described procedure ran to completion on a real target and the
expected result was observed. A technique that is theoretically correct but was never executed
keeps `verified: false`.

## Body

Sections appear in this order. Every section is required.

1. `## Summary` — what the entry teaches and when to reach for it.
2. `## Recognition` — how the technique presents: signatures, strings, error text, UI behaviour.
3. `## Method` — the procedure. Numbered steps, commands in fenced blocks, exact byte values.
4. `## Variations` — sibling approaches, alternative tool paths, platform deltas.
5. `## Verification` — how to prove the outcome, including the negative test.
6. `## Pitfalls` — failure modes, false positives, repair steps.
7. `## References` — upstream documentation, specifications, source of the technique.

Level-three subsections are allowed inside `## Method` and `## Variations`.

Code fences are opaque to the tooling and must be balanced. Do not nest triple backticks inside
fences; use a four-backtick fence when a sample itself contains a fence.

## Style

- Present tense, imperative, second person avoided. "Patch the byte", not "you should patch".
- Every command is copy-pasteable and states its working directory.
- Every offset is written as `0x1234` and every byte sequence as spaced hex: `74 12 90 90`.
- State the tool version the syntax depends on when the API is version-sensitive.
- No marketing adjectives. "Reverses the check" beats "powerfully defeats the check".
- Name the decision point precisely: function, offset, or field.
