# Harness features

[Back to project overview](../README.md) · [Installation](installation.md) · [Screenshots](screenshots/README.md)

These features belong to the native Harness plugin. The OpenCode adapter copies the source prompt, adds tool-use guidance, and copies offline knowledge; it does not provide the Harness UI or campaign tools. Its optional MCP registration connects Context7 and REA separately.

## Plugin UI and prompt configuration

The plugin adds a "Fujiang Pojia" status toggle and a settings entry next to the input box, which enable or disable prompt injection. The settings panel provides:

- **Vulnerability reports**: persist vulnerability records written by the AI, browsable by critical, high, medium, low, and informational severity.
- **Custom prompt**: edit the prompt configuration.
- **Skill library**: download, enable, or disable REA and AboutSecurity.
- **Knowledge base**: browse and use the built-in CVE / PoC entries.
- **Pentest workflow**: manage tasks, assets, verification steps, stages, and follow-up suggestions.

The status entry uses the official `conversation.input.overlay` extension point so it does not disturb the input area's original layout. With custom prompt injection enabled, the plugin replaces the opening of the official `harness:identity` section with an empty section; disabling it restores the official opening while your own prompt text stays as it is.

## Skill library download and AI invocation

The skill library covers two upstream projects:

- **REA reverse-engineering toolkit**: [morluto/rea](https://github.com/morluto/rea).
- **AboutSecurity security-assessment skills**: [wgpsec/AboutSecurity](https://github.com/wgpsec/AboutSecurity).

AboutSecurity downloads the current `master` branch archive from GitHub, extracts only the `skills/` directory, and registers the discovered skills once enabled. The download shows progress and can be cancelled; enabling and disabling adds or removes the skill provider, and deletion only touches files the plugin downloaded. Skill counts may change as upstream evolves.

This repository downloads skill libraries and the REA installer on demand from upstream links and ships no full copy of them; third-party projects keep their own license terms.

REA requires a compatible Node.js version: `^22.23.4 || ^24.22.1 || >=26.12.1`. When the plugin is installed through npm, lifecycle scripts are disabled, so that install path does not build Frida's optional native bindings. Whether a given tool works also depends on the runtime and analysis engine being available. AboutSecurity consists mainly of Markdown skill documents and needs no extra native runtime components.

Once skills are registered, the AI can discover them in the available-skills catalog and read the relevant content on demand. Whether a skill is actually invoked depends on the session, model, tool configuration, and task context; a successful download does not mean every tool has been verified end to end.

## Automated workflow and fingerprint matching

Context7 and REA integration details, connection status, authentication, offline opt-out, and host differences are documented in [tool integrations](tool-integrations.md). The shared instructions request the appropriate tool automatically but do not guarantee model behavior or imply that an engine is installed.

The plugin provides local fingerprint matching and a task ledger. Matching and ledger writes happen on the local machine; skill downloads, online model calls, and actual target verification may generate network requests.

| Endpoint | Purpose |
| --- | --- |
| `POST /api/dsh-prompt-custom/match` | Feed in a port, service banner, or product name and get ranked knowledge-base candidates with the match reasons. Weights: port 40, product 30, CVE 20, keywords 20, severity 5. |
| `/api/dsh-prompt-custom/campaigns` | Manage scope, asset fingerprints, execution steps, attempt records, and task stages. The ledger lives in `$DSH_HOME/vuln-report/campaigns.json`. `GET ?id=` returns a task plus its next-step suggestions. |

The workflow is organized into these stages:

**Recon → Fingerprint → Vulnerability matching → Feasibility verification → Exploitation → Lateral movement → Reporting**

Each task can be bound to one session, and a session holds at most one task. Through `campaign:context` the plugin gives the bound AI the task, stage, asset count, and follow-up suggestions, and can call `agent.followup(...)` to keep pushing. The task API offers `bind`, `unbind`, `kick`, and similar operations.

In the current implementation the user creates tasks in the plugin panel; the AI uses the existing task to record assets, steps, and results. Native tool endpoints include `kb_match`, `campaign_upsert`, `finding_upsert`, and `pipeline_next`; skill lookup goes through `skill_search` and `skill_read`. Native tool registration depends on a resolvable DSH tool service, and the local HTTP endpoints expose the same functionality.

A task records its objective, progress, and completion flag. Automatic continuation runs at most 8 rounds by default and provides stall detection and next-step suggestions. Progress and stage help organize the work; they do not prove a vulnerability. Vulnerability reports should still be backed by verification results and evidence.

## Built-in CVE / PoC knowledge base

The knowledge base lives in `plugin/knowledge/` and ships with the plugin, so enabling it needs no download. The content is registered as eleven category skills through `skills.registerProvider`; the AI can discover them in the `available_skills` catalog and load them on demand.

| Category skill | Main coverage |
| --- | --- |
| `kb-java-deser` | Java deserialization and related component issues, including Log4Shell, Spring4Shell, Struts2, WebLogic, Shiro, Fastjson, and Java ECDSA signature verification. |
| `kb-java-web` | Java and developer-collaboration platforms, including Confluence, GitLab, Jenkins, TeamCity, Solr, Tomcat, and Struts2. |
| `kb-edge-device` | Edge-device issues, including PAN-OS, Ivanti, Pulse, Citrix, FortiOS, and F5. |
| `kb-exchange-ad` | Exchange and Active Directory issues, including ProxyLogon, ProxyShell, ProxyNotShell, Zerologon, AD CS, PrintNightmare, MS17-010, BlueKeep, and Outlook. |
| `kb-web-cms` | Websites and content-management systems, including Drupal, PHP, Laravel, ThinkPHP, vBulletin, Apache, and Joomla. |
| `kb-linux-priv` | Linux privilege escalation, including PwnKit, Dirty Pipe, Baron Samedit, filesystem context, nf_tables, Looney Tunables, and overlayfs. |
| `kb-cloud-container` | Cloud and container issues, including runc, cgroups, Docker API, Kubernetes, Redis, PostgreSQL, and Nacos. |
| `kb-gray-market` | Business-site and API risks, including source and configuration leaks, broken object-level authorization, account tiers, payment callbacks, concurrency and idempotency, uploads, public buckets, export paths, SQL injection, and SSRF. |
| `kb-triage` | From fingerprinting to CVE candidate selection, verification-evidence write-ups, and report templates. |
| `kb-red-team` | Authorized scope, web/API and identity assessment, cloud/Kubernetes controls, CI/CD, secrets, segmentation, reporting and retesting. |
| `kb-blue-team` | SOC investigation, identity/cloud/network telemetry, incident response, patching, recovery, detection engineering and evidence handling. |

Knowledge entries are compilations of public material and should not be treated as conclusions already verified against your target. Entries carry metadata such as `verified: false` and `sources:` to mark verification status and provenance; exploitation steps must be re-checked against the target version and preconditions.

Each entry is a Markdown file whose metadata includes `title`, `cve`, `severity`, `cvss`, `product`, `versions`, `ports`, `keywords`, and more, with sections for fingerprint, preconditions, PoC, exploitation steps, remediation and mitigation, and references. Entries are re-read from disk when loaded, so knowledge-base updates take effect on later calls; category definitions live in `plugin/lib/knowledge-schema.js`, and changing categories requires reloading the plugin.

The knowledge base is enabled by default; the toggle state is stored in `$DSH_HOME/fujiang-skills/knowledge-state.json`. Disabling it stops feeding the related knowledge to the AI while the original files stay on disk; since the knowledge base ships with the package, no extra install or download is needed.

For the current entry format, validation rules, verification evidence, and dated risk metadata, see the [knowledge schema](../plugin/knowledge/SCHEMA.md) and [maintenance guide](../plugin/knowledge/CONTRIBUTING.md).
