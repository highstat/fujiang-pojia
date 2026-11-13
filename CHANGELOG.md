# Changelog

## Unreleased — Context7 and REA connections (2026-11-13)

- Added an asynchronous Harness Context7 MCP bridge, environment-only authentication, live tool-registry status, failure cleanup, and an offline opt-out. The existing on-demand REA connection remains independent.
- Added explicit OpenCode `--with-tools` / `-WithTools` registration for remote Context7 and pinned REA 6.9.0. Preserves unrelated JSON settings with backups; refuses JSONC, symlinks and conflicting server names. No model request or REA package execution occurs during installation.
- Added shared task-specific Context7/REA guidance as a disposable Harness section and an appended OpenCode section. The source prompt file and original persona text remain unchanged; the effective assembled instruction set is intentionally extended. This adds no content filter or guaranteed invocation.
- Added offline MCP/configuration regressions and integration documentation with actual runtime requirements and verification limits.

## Unreleased — red/blue expansion and installer layout (2026-11-13)

- Expanded the knowledge base to 300 records in 11 categories, adding 86 CVEs and 47 red/blue-team workflows. Added public-source provenance, safe applicability checks, remediation guidance, defensive triage and explicit verification limits.
- Moved all eight platform launcher/installer files from the repository root into `scripts/installers/`; updated relative source resolution, documentation, shell regression tests and Windows fixture layout. Old root-level launcher paths are intentionally no longer supported.
- Added scripts/knowledge navigation, source-audit documentation and offline expansion regressions. No source-prompt changes or model calls are part of this update.

## Unreleased — knowledge maintenance (2026-11-13)

- Reorganized the English documentation around this fork's version and host support; moved detailed features, screenshots, and the activation-word note into `docs/`. Kept all installer entry points at their existing root paths.
- Removed macOS directory metadata and added ignore rules for OS files, local environment files, logs, dependencies, and test artifacts.
- Added a typed knowledge schema, an idempotent normalization checker, canonical category tables, explicit severity policy and verification provenance.
- Preserved multi-CVE chains, workflow structure, source prompt and fenced PoC examples. Added optional CISA KEV / FIRST EPSS metadata refresh without target testing or implicit verification.
- Fixed stale live knowledge catalogs and derived the library version from `plugin/package.json` instead of a separate hardcoded version.
- Added offline knowledge regressions, root `npm test` commands and cross-platform CI. The browser fixture server remains manual and is not started by the test suite.
- See `plugin/knowledge/CHANGELOG.md` for the content/schema history. This is not a new upstream author release.

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
