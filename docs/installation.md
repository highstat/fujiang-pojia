# Cross-platform installation

Install the host application first. These scripts install this repository's local files; they do not install Harness, OpenCode, Node.js, or API credentials, and they do not automatically start or stop applications. Do not run them with sudo or Administrator privileges.

## DeepSeek Harness

### Windows

The existing Windows installer remains available and unchanged by the portability work:

```powershell
.\run-installer.cmd
.\install.ps1 -DryRun
.\install.ps1 -DshCommand 'D:\Apps\DeepSeek Harness' -DshHome 'E:\Data\.dsh'
```

Start Harness Desktop once to initialize its desktop profile, then quit it completely before installing. This installer uses Windows PowerShell and the CLI bundled with Harness; the new external Node.js requirement does not apply to it.

### macOS

Requires Node.js 20 or newer and an existing Harness installation. Double-click `run-installer.command`, or use Terminal:

```sh
sh ./install.sh harness --dry-run
sh ./install.sh harness
```

If the application is not discovered automatically:

```sh
sh ./install.sh harness \
  --dsh-command '/Applications/DeepSeek Harness.app' \
  --dsh-home "$HOME/.dsh"
```

Discovery checks `dsh` on PATH, the user's local bin, standard CLI locations, and the system/user Applications folders. An explicit invalid path fails rather than falling back to another installation.

If a ZIP extraction loses executable permissions, use the `sh` command above instead of double-clicking. If macOS blocks a downloaded launcher, review its contents and the download source before allowing it through the operating system's security UI.

### Linux

Requires Node.js 20 or newer and an existing executable DSH CLI. This script does not imply that a Harness Desktop build exists for every Linux distribution.

```sh
sh ./install.sh harness --profile my-profile --dry-run
sh ./install.sh harness --profile my-profile
```

Use your actual profile name. The default is `desktop`, which requires an already initialized Desktop profile. Nonstandard installations can specify both paths:

```sh
sh ./install.sh harness --profile my-profile \
  --dsh-command '/opt/deepseek-harness/resources/runtime/cli/bin/dsh' \
  --dsh-home "$HOME/.dsh"
```

### What the macOS/Linux installer changes

- Copies `plugin/` to `$DSH_HOME/local-plugins/dsh-prompt-custom`.
- Copies `prompt-custom.json` byte-for-byte to `$DSH_HOME/prompt-custom.json`.
- Registers that path with `dsh plugin --profile <profile> add <path>`.
- Uses `--dsh-home`, then `DSH_HOME`, then `~/.dsh` to select the data directory.
- Backs up replaced files under `$DSH_HOME/fujiang-backups/`.
- Refuses an actual install when the Harness Desktop process is detected; dry-run remains available.
- Restores copied plugin/prompt files if registration fails. Registration is a host CLI operation and may also modify the profile or resolve dependencies over the network; inspect the profile after a failed registration.

Dry-run validates paths and sources but does not copy files, create backups, or invoke registration. The installer neither kills nor restarts Harness. The original Windows installer retains its existing backup/rollback behavior described in the README.

## OpenCode with DeepSeek

### What is portable

OpenCode supports Markdown agents whose bodies supply the system prompt, and skill directories containing `SKILL.md` plus supporting files. This adapter targets those documented features, not the DeepSeek Harness Cordis plugin API.

It installs:

- `agents/fujiang.md`: a primary agent whose body is exactly the current `text` from `prompt-custom.json`.
- `skills/kb-*/`: all nine categories and all 167 supporting knowledge documents, copied without rewriting their contents.

The adapter does **not** port Harness settings tabs, prompt-card switching, its HTTP routes, `kb_match` / `campaign_upsert` / `finding_upsert` / `pipeline_next` tools, skill downloaders, or automatic task continuation. Any references to those Harness-only facilities in the preserved text remain references, not working OpenCode integrations. Ordinary OpenCode file/skill tools can load the copied knowledge documents.

The source prompt's `enabled`, `mode`, and `cards` settings do not map to a Markdown agent and are not imported. The agent takes effect only when selected in OpenCode. Re-run the installer after changing the source prompt or knowledge files; this is a snapshot, not a live link.

No API keys, provider settings, permission rules, default agents, default models, or existing `opencode.json` / `opencode.jsonc` files are edited. Installation does not guarantee identical answers, refusal behavior, or effectiveness of any prompt: provider behavior and other OpenCode instruction sources still apply. This portability change does not edit or revert the existing source prompt.

### Install globally

On macOS, double-click `install-opencode.command`, or use the same shell command as Linux:

```sh
sh ./install-opencode.sh --dry-run
sh ./install-opencode.sh
```

On Windows:

```powershell
.\install-opencode.cmd -DryRun
.\install-opencode.cmd
# Or call PowerShell directly:
.\install-opencode.ps1
```

The OpenCode adapter requires Node.js 20 or newer on every platform. Its default destination is `~/.config/opencode` (on Windows, under the user home directory, not AppData). `OPENCODE_CONFIG_DIR` takes precedence; otherwise `XDG_CONFIG_HOME/opencode` is honored when set. `--config-dir` / `-ConfigDir` explicitly selects a different configuration directory. Configure OpenCode to read that same directory when using a custom location.

This installer is offline and does not need an OpenCode executable or API key to copy files. OpenCode itself is required to use the agent. The documented adapter format targets OpenCode 2; compatibility with older releases must be checked separately.

### Install for one project only

```sh
sh ./install-opencode.sh --project '/path/to/project' --dry-run
sh ./install-opencode.sh --project '/path/to/project'
```

```powershell
.\install-opencode.ps1 -Project 'D:\Projects\My Project' -DryRun
.\install-opencode.ps1 -Project 'D:\Projects\My Project'
```

This creates `.opencode/agents/fujiang.md` and `.opencode/skills/kb-*` in that project instead of changing global configuration. Do not combine project and configuration-directory options.

### Connect DeepSeek and select the agent

1. Start or restart OpenCode after installation.
2. Use `/connect` and choose DeepSeek; enter your API key in OpenCode, not in these scripts.
3. Select an available DeepSeek model and the `fujiang` primary agent.

List the model IDs exposed by your installed OpenCode version:

```sh
opencode models deepseek
```

For an explicit per-agent model preference, pass its real `provider/model` ID using `--model` in the shell installer or `-Model` in PowerShell. Model IDs are intentionally not hardcoded because availability depends on the provider and installation. Selecting an agent does not necessarily replace a model already selected by an existing session; choose the DeepSeek model explicitly there.

From the CLI:

```sh
opencode run --agent fujiang --model 'deepseek/YOUR_MODEL_ID' 'Describe the available knowledge categories'
```

Replace `YOUR_MODEL_ID` with the actual ID from the model list. Normal model requests may incur provider charges. No model request is made during installation.

### Updates, backups, and removal

Re-run the same installer to update. Files that already match are left alone. Before replacing an agent or a knowledge category, the installer keeps its previous contents under `<config-dir>/fujiang-backups/<installation-id>/`, retaining the relative `agents/` and `skills/` paths. Unrelated agents and skills are left alone. Destination symlinks are rejected rather than followed. Backups can contain personal prompt text; keep them private.

To undo an update, close OpenCode and restore the affected paths from that backup. To remove a fresh install, remove only `agents/fujiang.md` and the nine `skills/kb-*` directories installed by this repository; do not delete the whole OpenCode configuration directory. If a same-named skill existed before installation, restore its backup instead of deleting it.

## Verification

Run from the repository root:

```sh
node --test tests/portable-installers.mjs tests/english-localization.mjs tests/keyboard-regression.mjs
```

The portable tests use isolated temporary directories and fake DSH commands. They cover prompt/content identity, model frontmatter, project/global destinations, dry-run, idempotent updates, backups, symlink protection, process protection, literal path arguments, and rollback after failed registration. Unix-specific cases are skipped on Windows. Run the existing `tests/install-paths.ps1` separately on Windows for the original Harness installer.

These tests do not perform a live model request, execute PoCs, or prove compatibility with every host release.

To additionally check agent discovery and exact system-text preservation using an installed OpenCode 2 binary, opt in to the isolated native test:

```sh
FUJIANG_OPENCODE_BIN="$(command -v opencode)" node --test tests/portable-installers.mjs
```

```powershell
$env:FUJIANG_OPENCODE_BIN = (Get-Command opencode).Source
node --test tests/portable-installers.mjs
```

That test redirects HOME and all OpenCode data/config/cache/state paths into a temporary fixture and runs only `debug agents --standalone`, not a model request. Without the opt-in variable, it is skipped.

## Official compatibility references

- [OpenCode agents](https://opencode.ai/docs/agents/): agent directories, primary agents, model selection, and system-prompt behavior.
- [OpenCode skills](https://opencode.ai/docs/skills/): skill discovery and supporting-file layout.
- [OpenCode configuration](https://opencode.ai/docs/config/): configuration locations and precedence.
- [DeepSeek's OpenCode integration guide](https://api-docs.deepseek.com/quick_start/agent_integrations/opencode/): connecting the DeepSeek provider.
