# REA — Reverse Engineering & Application Patching Corpus

[Project overview](../README.md) · [Knowledge schema](knowledge/SCHEMA.md) · [Authoring guide](references/AUTHORING.md) · [Tool matrix](references/tool-matrix.md) · [Playbook index](playbooks/README.md)

A self-contained corpus for reverse engineering, license-validity reconstruction and binary
patching of desktop and mobile applications. Everything is written in English and organised so an
agent can route a target to the correct technique without re-deriving the method each time.

Scope of the corpus:

- **Static analysis** — format internals (PE, ELF, Mach-O, DEX, IL), disassembly, symbol recovery,
  string triage, cross-reference work.
- **Dynamic analysis** — debuggers, tracers, Frida 17 instrumentation, runtime behaviour capture.
- **Licence reconstruction** — recovering serial algorithms, keygen construction, signed-licence
  blob handling, offline-activation flows.
- **Patching** — byte-level patches, IL/smali source patches, load-command and import-table
  surgery, runtime hooks, re-signing and re-packaging chains per OS.
- **Countermeasures** — anti-debug, integrity self-checks, VM detection, packers and obfuscators,
  and the specific ways each is removed.

The corpus is a working library, not a lecture. Knowledge entries carry byte patterns, opcode
encodings, exact command sequences and verification criteria so the reader can move from
"this app refuses to start" to "this file, this offset, this byte" without re-research.

**49 knowledge entries across 10 domains, 12 agent skills and 12 playbooks.**
Every installed skill links to the [documentation-first workflow](references/agent-workflow.md):
read the applicable project instructions and relevant procedure before acting, check prerequisites,
preserve original inputs and report verification actually performed. Re-run `sh rea/install.sh`
from the repository root with the same destination to refresh existing skills and resources.
This changes instructions, not a model's capabilities or guaranteed behavior.

The 15 files under `scripts/` include platform helpers, Frida agents, a C interposition
template, validators and the skill installer. Not every file is a standalone program:
Frida agents need the matching runtime and the C template must be compiled.

## Layout

```text
rea/
├── README.md                 This file
├── knowledge/                Atomic technique entries, one subject per file
│   ├── SCHEMA.md             Frontmatter and body rules for knowledge entries
│   ├── SKILL.md              Index of the knowledge corpus — 49 entries
│   └── <domain>/             Entries grouped by platform or technique family
├── skills/                   12 agent skills (SKILL.md) for routing and execution
├── playbooks/                12 end-to-end missions per platform
├── scripts/                  Runnable helpers: patchers, Frida agents, build/sign chains
├── templates/                Report and session templates
├── references/               Tool matrix, authoring guide
├── tests/                    Offline helper and installation regressions
└── install.sh                POSIX launcher for the Python skill installer
```

## Routing

| Target | Start with |
| --- | --- |
| Windows PE, native | `skills/rea-windows-apps/`, `knowledge/windows-native/` |
| Windows .NET / managed | `skills/rea-windows-apps/`, `knowledge/windows-dotnet/` |
| Android APK | `skills/rea-android-apps/`, `knowledge/android/` |
| iOS IPA / Mach-O | `skills/rea-apple-apps/`, `knowledge/ios/` |
| macOS app bundle | `skills/rea-apple-apps/`, `knowledge/macos/` |
| Linux ELF | `skills/rea-linux-apps/`, `knowledge/linux-elf/` |
| Electron / ASAR / JS bundle | `skills/rea-electron-apps/`, `knowledge/electron-js/` |
| Licence algorithm or keygen | `skills/rea-license-crypto/`, `knowledge/license-crypto/` |
| Anti-debug, integrity, packers | `skills/rea-anti-analysis-bypass/`, `knowledge/anti-analysis/` |
| Programmatic binary editing | `skills/rea-patching-automation/` |
| Native binary analysis | `skills/rea-native-static/` |
| Runtime observation | `skills/rea-runtime-instrumentation/` |
| Artefact analysis through the REA MCP server | `skills/rea-mcp-artifact-analysis/` |
| Corpus index and routing | `skills/rea-knowledge-base/` |

## Install the skills

```sh
sh rea/install.sh --dry-run
sh rea/install.sh /path/to/project/.opencode/skills
```

Run from the repository root with Python 3.10+ available. Omitting the target selects
`${XDG_CONFIG_HOME:-$HOME/.config}/opencode/skills`. Windows can call
`python rea/scripts/install-skills.py PATH_TO_SKILLS --dry-run` directly.

The installer copies all 12 skills, packages a shared snapshot under
`rea-knowledge-base/references/`, rewrites the skill links, and saves replaced skills under
`fujiang-rea-backups/` beside the skills directory. Failed replacements roll back. Symlink
destinations and installation over the source corpus are rejected. Restart the host and verify
actual discovery; copying files does not connect REA MCP or install analysis engines.

The corpus itself needs no installation: point an agent at
[the routing skill](skills/rea-knowledge-base/SKILL.md). It remains separate from the Harness
plugin's 300-entry CVE/workflow corpus and the upstream REA MCP server.

## Validate

```sh
python3 rea/scripts/check-knowledge.py --strict
python3 rea/scripts/normalize-knowledge.py --check
python3 -B -m unittest discover -s rea/tests -v
node --test rea/tests/runtime.mjs
```

The validator checks entry metadata, calendar dates, canonical vocabulary, skill frontmatter,
Markdown links and balanced fences outside code examples. Helper tests use synthetic bytes
and temporary directories; they do not prove live-target or signing success. All 49 entries
retain `verified: false`. A schema pass is not an end-to-end procedure test.

Skills are short routing instructions; detailed examples live in `knowledge/` and `playbooks/`
rather than being duplicated into multiple agent instructions. Use the connected server's
advertised tools and schemas, not guessed tool names from older references.


## Working agreement

1. Fix the target identity first: hash, format, architecture, signature, packer state.
2. Locate the decision point before touching bytes. A patched symptom without the decision point
   produces a binary that fails elsewhere.
3. Prefer the smallest reversible change: one conditional branch, one return value, one string.
4. Re-verify after every mutation: recompute checksums, re-sign, re-run, then re-check the
   original failing behaviour.
5. Record the offset, the original bytes and the new bytes. A patch without a record is a patch
   without a rollback.

## Legal note

The techniques in this corpus apply to software the reader owns, has a licence for, or is
authorised to test. They are equally the technique set used for malware triage, compatibility
work, interoperability, and internal assessment. Use them on targets you are allowed to modify.
