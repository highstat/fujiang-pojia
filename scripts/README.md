# Installation and maintenance scripts

[Project overview](../README.md) · [Installation guide](../docs/installation.md) · [Knowledge guide](../docs/knowledge-expansion.md)

Run the following commands from the repository root. Platform launchers live in [`installers/`](installers/README.md); there are no root-level copies.

| Path | Purpose |
| --- | --- |
| [`installers/`](installers/README.md) | Double-click and shell/PowerShell launchers for Harness and OpenCode |
| [`install.mjs`](install.mjs) | Shared portable installation engine; `harness` or `opencode` target |
| [`tool-config.mjs`](tool-config.mjs) | Offline, conservative OpenCode MCP config merge used by `--with-tools` |
| [`check-knowledge.mjs`](check-knowledge.mjs) | Offline schema, category and table checks |
| [`normalize-knowledge.mjs`](normalize-knowledge.mjs) | Offline normalization check or reviewable patch output |
| [`enrich-knowledge.mjs`](enrich-knowledge.mjs) | Explicit public CISA/FIRST metadata refresh; network access required |

```sh
node scripts/install.mjs --help
npm test
npm run knowledge:check
npm run knowledge:normalize
```

Knowledge scripts never execute PoCs. The enrichment command is not an implicit installation or runtime step. Read the contribution guide before applying generated patches.
