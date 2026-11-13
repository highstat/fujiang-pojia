# Platform installers

[Project overview](../../README.md) · [Detailed installation guide](../../docs/installation.md) · [Maintenance scripts](../README.md)

All eight launchers now live in this directory. Update bookmarks and commands that previously referenced the repository root. Each launcher resolves its own path; changing the terminal's working directory does not change the source bundle.

| Host | Windows | macOS | Linux |
| --- | --- | --- | --- |
| Harness | [`run-installer.cmd`](run-installer.cmd) / [`install.ps1`](install.ps1) | [`run-installer.command`](run-installer.command) / [`install.sh`](install.sh) | [`install.sh`](install.sh), with an existing profile |
| OpenCode | [`install-opencode.cmd`](install-opencode.cmd) / [`install-opencode.ps1`](install-opencode.ps1) | [`install-opencode.command`](install-opencode.command) / [`install-opencode.sh`](install-opencode.sh) | [`install-opencode.sh`](install-opencode.sh) |

From the repository root:

```sh
sh ./scripts/installers/install.sh harness --dry-run
sh ./scripts/installers/install-opencode.sh --project '/path/to/project' --dry-run
```

```powershell
.\scripts\installers\install.ps1 -DryRun
.\scripts\installers\install-opencode.ps1 -Project 'D:\Projects\My Project' -DryRun
```

Remove the dry-run option only when the preview is correct. Quit Harness completely before a real install. The portable installers require Node.js 20+; the original Windows Harness installer uses the host's bundled CLI and PowerShell. These scripts do not install host applications, create API credentials, or make model requests. See the detailed guide for backup, rollback and host-compatibility limits.

For OpenCode MCP registration, append `--with-tools` on Unix or `-WithTools` in PowerShell. The installer only writes configuration; launching OpenCode can subsequently acquire the pinned REA package. Read [Context7 / REA setup](../../docs/tool-integrations.md) before enabling it.
