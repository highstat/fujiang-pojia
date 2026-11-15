# Application reverse-engineering corpus

[Project overview](../README.md) · [Corpus overview](../rea/README.md) · [Review and limitations](rea-review.md) · [MCP connections](tool-integrations.md)

## Three separate components

| Component | Contents | Installation |
| --- | --- | --- |
| `plugin/knowledge/` | 300 CVE, assessment and red/blue workflow entries in 11 categories | Main Harness/OpenCode installer |
| `rea/` | 49 technique entries in 10 domains, 12 skills and 12 application-analysis playbooks | Separate corpus installer, or read from checkout |
| Upstream REA MCP | Tools advertised by the connected `rea-agents` server and its available providers | On-demand Harness library or OpenCode `--with-tools` |

The local REA corpus is not a vendored copy of the upstream server. Installing one component
does not establish readiness of the others. The main installer does not automatically discover
`rea/` or add it to the plugin's CVE schema, catalogs, graph or search index.

## Layout and routing

- [Knowledge index](../rea/knowledge/SKILL.md): native-core, license-crypto, windows-native,
  windows-dotnet, android, ios, macos, linux-elf, electron-js and anti-analysis.
- [Agent routing skill](../rea/skills/rea-knowledge-base/SKILL.md): select a platform or technique.
- [Agent workflow](../rea/references/agent-workflow.md): read relevant documentation first, check prerequisites, preserve inputs and distinguish local checks from live verification. Each installed skill links to the shared copy.
- [Playbooks](../rea/playbooks/README.md): ordered target-to-verification workflows.
- [Manifest schema](../rea/templates/patch-manifest.schema.json), [patch report](../rea/templates/patch-report.md)
  and [working notes](../rea/templates/working-notes.md): reproducible artifact records.
- [Tool matrix](../rea/references/tool-matrix.md) and [authoring guide](../rea/references/AUTHORING.md):
  prerequisites and maintenance conventions.

Scripts include Python file-analysis and patch helpers, Frida agents, APK build/sign and macOS
signing chains, and a C interposition template. These have different runtime requirements;
they are not all standalone executables or tools installed by the skills installer.

## Install independently

Requires Python 3.10+. From the repository root:

```sh
sh rea/install.sh --dry-run
sh rea/install.sh '/absolute/path/to/project/.opencode/skills' --dry-run
sh rea/install.sh '/absolute/path/to/project/.opencode/skills'
```

Without an explicit destination, the installer selects
`${XDG_CONFIG_HOME:-$HOME/.config}/opencode/skills`. An explicit path can target another host's
supported skill directory; verify that host's discovery conventions rather than assuming
identical behavior. Do not use elevated privileges.

Windows can call the Python entry point without Bash:

```powershell
python .\rea\scripts\install-skills.py 'D:\Projects\My App\.opencode\skills' --dry-run
python .\rea\scripts\install-skills.py 'D:\Projects\My App\.opencode\skills'
```

The installer:

1. Checks destinations and sources, rejecting symlinks and installation over the corpus itself.
2. Stages all 12 skills and one shared knowledge/playbook/script/template snapshot under
   `rea-knowledge-base/references/`; installed skills link to that sibling resource bundle.
3. Backs up replaced skills under `<skills-parent>/fujiang-rea-backups/<id>/`, outside the
   active skills directory, and rolls back completed replacements on failure.
4. Leaves unrelated skills, MCP configuration, API keys, permissions and models unchanged.

Restart the host and verify actual skill discovery. Skill instructions are not a guarantee
that a model will invoke them. No engine, model, package, binary or target is downloaded or run
by this installer. Frida, SDKs, debuggers and signing tools remain separate prerequisites.

Re-run the same command to refresh the snapshot. To undo an update, close the host and restore
the affected skill directories from the printed backup. To remove a fresh installation, remove
only the 12 `rea-*` directories listed by this corpus; keep unrelated skills. The other skills
depend on the `rea-knowledge-base/references/` bundle, so do not delete that directory alone.

## Checks and verification boundaries

### Helper contracts

`apply-patch.py` requires a hash-bound manifest, matching preimages and a new output path.
The input is the rollback; existing outputs and edits to the original are refused. For PE
address translation, `vaddr-to-offset.py` expects a preferred-image VA by default; use `--rva`
for an RVA and remove any runtime ASLR slide first. Select a universal Mach-O slice with
`--slice INDEX`. Candidate scanning does not establish instruction boundaries or execution.

The Android helper requires SDK Build Tools supporting `zipalign -P 16`. Keystore and key
passwords are separate `ANDROID_STORE_PASS` / `ANDROID_KEY_PASS` environment inputs, forwarded
through apksigner environment references rather than printed command-line passwords.
The C template's optional changes are controlled by `REA_LICENSE_PREFIX`, `REA_MACHINE_ID_FILE`
and `REA_FIXED_TIME`; unset options preserve the corresponding original operation. Frida
scripts still require selecting real target modules, methods and ABI; they are not universal
app patches.

```sh
npm run test:rea
```

This requires Python 3.10+ and Node.js 20+. The ordinary `npm test` remains a Node-only suite.
The REA command tests synthetic patch inputs, address maps, scanner boundaries, installation
relocation/rollback and Frida API contracts using mocks, then checks all entries and Markdown
resources and runs the metadata normalizer in `--check` mode. A compiler-dependent syntax
check is skipped when no C compiler is present.

All 49 entries currently say `verified: false`. Passing the checks does not prove that a live
app accepts a modification, a vendor signature is valid, a runtime hook works on a particular
OS, or server-side entitlement changes. Native Windows/Linux, device signing and live engine
coverage need separate evidence. The [review](rea-review.md) records what this pass fixes and
what still deserves targeted validation.

Use only explicitly scoped artifacts and environments. Retain originals, hashes, selected
architecture, original/new bytes, tool versions and cleanup notes; redact license keys and
tokens before sharing reports.
