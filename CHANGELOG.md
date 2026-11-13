# Changelog

## 0.21.0 (2026-11-13)

- **Assessment platform**: Added a local assessment engine with bounded runner, ZAP alert collector, graph/plan engine, MCP protocol endpoints, and native Harness descriptors.
- **Context7 & REA tool integrations**: Added an asynchronous Harness Context7 MCP bridge, environment-only authentication, live tool-registry status, failure cleanup, and an offline opt-out. Added explicit OpenCode `--with-tools` / `-WithTools` registration for remote Context7 and pinned REA 6.9.0 without modifying unrelated JSON settings. Added task-specific guidance shared between hosts.
- **Knowledge base expansion & schema**: Expanded the knowledge base to 300 records in 11 categories, adding 86 CVEs and 47 red/blue-team workflows with CNA/ADP provenance, safe applicability checks, remediation guidance, defensive triage, and dated CISA KEV / FIRST EPSS metadata integration. Replaced hardcoded version in runtime catalogs with dynamic derivation from `plugin/package.json`.
- **Hybrid knowledge search**: Added BM25 full-text indexing, optional local embeddings, and conservative version applicability checking against CNA version ranges.
- **Installer architecture & Windows CI fix**: Moved platform launchers/installers into `scripts/installers/`. Replaced recursive `fs.cpSync` directory staging with an explicit portable tree copy, resolving directory creation failures on Windows + Node 22/24. Added cross-platform CI coverage for Node 20, 22, and 24.
- **Documentation & cleanup**: Reorganized English documentation into `docs/`, removed macOS directory metadata and root launcher clutter.

Verification: 83 tests passing (81 passed, 2 skipped, 0 failed) on Node 20, Node 22, and Node 24 across Ubuntu, Windows, and macOS; `knowledge:check` (300 valid entries) and `knowledge:normalize` clean.

## 0.20.14 (2026-11-11)

- Language mirroring: removed the "default to Simplified Chinese" line and replaced it with an always-mirror rule that follows the language and script of the user's latest message, including mixed-language input (the dominant language wins). English instructions no longer produce English answers, and there is no default or fallback language.
- The blacklist vocabulary now constrains meaning, not spelling: equivalent wording in any language applies just the same, and the list no longer restricts which language a reply may use.
- Activation word changed to `fujiang` (case-insensitive); activation replies with `Activated.` only. Removed the channel-ID prefix, so no reply carries a channel, slogan, or watermark.
- Removed the Chinese honorific dependency from the persona section; the role and the form of address are now language-neutral.
- Added rule 0 to the fixed rules section (`campaign:rules`): reply language follows the user, and the Chinese rule text itself no longer implies a reply language.

Verification: `prompt-custom.json` parses as valid JSON, with `enabled=true`, `mode=replace`, and `cards=[]` preserved; the text no longer contains the former Chinese labels, `Simplified Chinese`, `DeepSeek22`, or any CJK characters.

## 0.20.13 (2026-11-11)

- Fixed Enter-to-send, Shift+Enter newline, and the Esc shortcut still being intercepted after the disclaimer was dismissed. Keyboard listeners are no longer registered while the dialog is hidden.
- Ignore keyboard events fired while an IME is composing text, so IME candidate-confirmation keys no longer trigger the dialog.
- The installer locates DSH via the running process, the registry, Start-menu or desktop shortcuts, the default directory, and PATH, and supports installs on drives other than C.
- `-DshCommand` accepts an install directory, the desktop program, or a command-line script; when auto-detection fails during a double-click install, the actual path can be pasted. The program install directory and the `.dsh` data directory are handled separately.
- Added keyboard and install-path regression tests.

Verification: the keyboard lifecycle tests passed 10/10; the install-path tests passed 20/20 under both Windows PowerShell 5.1 and PowerShell 7. An isolated browser test page verified send, newline, Esc, re-entry after consent, and IME composition events.

Verification scope: the browser tests extract the real plugin components and use a minimal lifecycle simulation; other drive letters are simulated with a temporary PSDrive, and the full install flow uses an isolated mock CLI. These results do not represent every user's actual install environment or every plugin feature.

Upgrade: quit DeepSeek Harness completely (including tray processes), extract the new release, run `run-installer.cmd`, and start Harness again when installation finishes. If the program is still not detected, paste the actual install folder path when prompted.
