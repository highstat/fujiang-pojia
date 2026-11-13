<img width="1736" height="346" alt="CleanShot 2026-11-11 at 19 17 48@2x" src="https://github.com/user-attachments/assets/e9d9d347-f519-4b24-9168-86d097a9b193" />

# Fujiang Pojia

### English fork · Harness plugin · OpenCode adapter

Custom prompt controls, an offline security knowledge base, and assessment-workflow tools for DeepSeek Harness. The OpenCode adapter installs the preserved source prompt plus additive tool-use guidance and knowledge as a selectable agent and skills.

> **Fork version: 0.21.0**, based on upstream **0.20.13**. This version belongs to this fork; it is not a new release from the original author.

[Installation](docs/installation.md) · [Harness features](docs/features.md) · [Context7 / REA](docs/tool-integrations.md) · [Screenshots](docs/screenshots/README.md) · [Changelog](CHANGELOG.md) · [Disclaimer](DISCLAIMER.md)

## What this fork includes

- English interface text, documentation, and bundled knowledge.
- Installers for Windows, macOS, and Linux, with dry-run and backup support.
- A native Harness plugin and a separate OpenCode agent adapter.
- **300 knowledge entries across 11 categories**, with stable IDs and a validated metadata schema.
- **20 red-team/pentest and 27 blue-team/SOC playbooks**, covering identity, cloud, containers, CI/CD, detections and incident response.
- Explicit verification fields and dated CISA KEV / FIRST EPSS metadata.
- Context7 documentation MCP, REA artifact analysis, and task-specific tool-use guidance shared by both adapters.
- Offline regression tests and a cross-platform CI configuration.

The activation word in the bundled prompt is `fujiang` (case-insensitive). Review `prompt-custom.json` before installing or redistributing it: the installer copies your current local prompt, which may contain personal configuration.

## Choose your host

| Capability | DeepSeek Harness | OpenCode |
| --- | --- | --- |
| Custom prompt | Plugin settings and prompt configuration | Body of the selected `fujiang` agent |
| Offline knowledge | Eleven registered category skills | Eleven copied category skills |
| Settings UI and report browser | Native plugin panels | Not included |
| Fingerprint matching and workflow tools | Harness runtime integration | Not included |
| REA / AboutSecurity download controls | On-demand skill-library integration | Not included |
| Updates | Re-run the Harness installer and restart Harness | Re-run the adapter to refresh its snapshot |

By default, the adapter leaves API keys, permission rules, provider settings, default agents/models, and existing `opencode.json` / `opencode.jsonc` files unchanged. Optional `--with-tools` registration updates only MCP configuration as described below. Selecting the agent does not guarantee a particular response or bypass provider restrictions. Model requests may incur provider charges.

## Quick start

Download and extract this repository, or clone your copy. Run commands from the repository root. Install the host application first; these scripts do not install Harness, OpenCode, Node.js, or API credentials. Do not run them with elevated privileges.

### DeepSeek Harness

Initialize the intended Harness profile once, then **quit Harness completely**, including tray processes. The installer never closes or restarts the application for you.

| Platform | Launcher | Preview without changes |
| --- | --- | --- |
| Windows | Double-click [`scripts/installers/run-installer.cmd`](scripts/installers/run-installer.cmd) | `.\scripts\installers\install.ps1 -DryRun` |
| macOS | Double-click [`scripts/installers/run-installer.command`](scripts/installers/run-installer.command) | `sh ./scripts/installers/install.sh harness --dry-run` |
| Linux | `sh ./scripts/installers/install.sh harness --profile YOUR_PROFILE` | Add `--dry-run` to the same command |

For macOS or an initialized Desktop profile:

```sh
sh ./scripts/installers/install.sh harness --dry-run
sh ./scripts/installers/install.sh harness
```

The portable installer requires **Node.js 20+**. The original Windows [`scripts/installers/install.ps1`](scripts/installers/install.ps1) uses PowerShell and the CLI bundled with Harness, without requiring an external Node.js installation. Linux requires an existing DSH CLI and an explicitly selected profile; this repository does not provide a Linux Desktop build.

The plugin declares Harness / `dsh-system-prompt` compatibility `>=0.2.1-rc.5 <0.3.0` and Cordis compatibility `>=4.0.5 <5`. These are declared ranges, not proof that every host version has been tested. See [installation details](docs/installation.md) for custom paths, backups, and troubleshooting.

### OpenCode with DeepSeek

Requires **Node.js 20+**. The adapter targets OpenCode 2 agents and skills.

| Platform | Launcher |
| --- | --- |
| Windows | [`scripts/installers/install-opencode.cmd`](scripts/installers/install-opencode.cmd) or [`scripts/installers/install-opencode.ps1`](scripts/installers/install-opencode.ps1) |
| macOS | [`scripts/installers/install-opencode.command`](scripts/installers/install-opencode.command) or the shell command below |
| Linux | [`scripts/installers/install-opencode.sh`](scripts/installers/install-opencode.sh) |

For a project-local installation on macOS/Linux:

```sh
sh ./scripts/installers/install-opencode.sh --project '/path/to/project' --dry-run
sh ./scripts/installers/install-opencode.sh --project '/path/to/project'
```

On Windows:

```powershell
.\scripts\installers\install-opencode.ps1 -Project 'D:\Projects\My Project' -DryRun
.\scripts\installers\install-opencode.ps1 -Project 'D:\Projects\My Project'
```

Replace the example path with your project. Omit the project option for the default global destination. Add `--with-tools` (PowerShell: `-WithTools`) to register Context7 and pinned REA MCP servers in that scope; starting OpenCode can then download REA via npm. See [tool setup and runtime requirements](docs/tool-integrations.md). Installation makes no model request. In OpenCode, connect your DeepSeek provider, then explicitly select the `fujiang` agent and an available model. See the [OpenCode guide](docs/installation.md#opencode-with-deepseek) for model selection, isolated configuration, backups, and removal.

## Knowledge base

The knowledge ships in [`plugin/knowledge/`](plugin/knowledge/) and works offline. Categories cover Java components, Java web platforms, edge devices, Exchange / Active Directory, web CMSs, Linux privilege escalation, cloud / containers, business-site and API risks, triage / reporting, authorized red-team assessments, and blue-team operations. Start with the [knowledge index](plugin/knowledge/README.md) or the [expansion and source-policy guide](docs/knowledge-expansion.md).

Entries distinguish CVEs, implementation flaws, configuration issues, business logic, and workflows. Metadata preserves related CVEs, verification evidence, and source dates. Schema validation checks structure and consistency; public-feed enrichment does **not** establish that a vulnerability was reproduced or that an entry applies to your target.

| Guide | Purpose |
| --- | --- |
| [Knowledge schema](plugin/knowledge/SCHEMA.md) | Fields, entry kinds, severity policy, and verification rules |
| [Contributing and refreshing](plugin/knowledge/CONTRIBUTING.md) | Add entries, normalize metadata, and refresh public risk data |
| [Knowledge changelog](plugin/knowledge/CHANGELOG.md) | Content and schema changes |

CISA KEV / FIRST EPSS fields are dated snapshots, not live intelligence. Refreshing them is an explicit maintenance action; installation, runtime lookups, and the default tests do not refresh public feeds.

## Repository layout

```text
fujiang-pojia/
├── README.md                 Project overview and quick start
├── CHANGELOG.md              Fork history and unreleased work
├── DISCLAIMER.md             Usage boundaries
├── prompt-custom.json        Prompt configuration copied during installation
├── plugin/                   Native Harness package and its MIT license
│   ├── lib/                  Runtime integrations and knowledge schema
│   └── knowledge/            Offline entries, category skills, maintenance docs
├── scripts/                  Installation and maintenance tools
│   ├── installers/           Windows, macOS and Linux launchers
│   ├── install.mjs           Shared portable installation engine
│   └── *knowledge.mjs        Knowledge checks, normalization and enrichment
├── tests/                    Automated checks and manual keyboard fixtures
├── docs/                     Installation, features, activation note, screenshots
└── .github/workflows/        Cross-platform test configuration
```

All platform launchers now live in [`scripts/installers/`](scripts/installers/README.md); earlier instructions that use root-level launcher paths must be updated. The launchers resolve repository files relative to their own location, so they work from another current directory. Detailed documentation and images live under `docs/`; OS metadata, local environment files, logs, and generated test artifacts are excluded through `.gitignore`.

## Development and checks

Use Node.js 20 or newer. The workspace test commands require no additional npm dependencies:

```sh
npm test
npm run knowledge:check
npm run knowledge:normalize
```

These checks validate English localization, keyboard behavior, installer fixtures, knowledge metadata and runtime behavior, and documentation links. They do not execute PoCs or make model requests. The optional native OpenCode discovery test is opt-in; the default installer checks use isolated temporary directories and fake DSH commands.

`npm run knowledge:enrich` explicitly contacts CISA and FIRST and reports available metadata changes without writing files. Consult the [maintenance guide](plugin/knowledge/CONTRIBUTING.md) before applying an update.

Run `npm run test:windows` on Windows for the PowerShell installer tests. CI is configured for Node.js 20 and 22 on Linux, macOS, and Windows; configuration alone does not establish that remote checks have passed. Manual browser fixtures are documented in the [verification guide](docs/installation.md#verification) and are excluded from `npm test`.

## Screenshots

[View the four-panel Harness gallery](docs/screenshots/README.md). The original screenshots were cropped and localized into English; they are edited documentation images, not new runtime captures. OpenCode does not include these Harness panels.

<details>
<summary>Preview: custom prompt settings</summary>

![Custom prompt settings in the Harness plugin](docs/screenshots/01-custom-prompt.png)

</details>

## License and responsible use

The plugin carries an [MIT license](plugin/LICENSE). On-demand third-party skill libraries retain their own licenses. Use assessment tools only on systems you own or are authorized to test; read the [disclaimer](DISCLAIMER.md) before use. This fork is not an official DeepSeek product and makes no guarantee about model behavior, vulnerability coverage, or testing outcomes.
