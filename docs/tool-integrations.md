# Context7 and Reverse Engineer Anything

[Project overview](../README.md) · [Installation](installation.md) · [Harness features](features.md)

The integration adds actual MCP connections and a separate tool-use instruction section. It does not replace or rewrite `prompt-custom.json`, change the activation word, add a content filter, or guarantee a model will call a tool. A registered server, a connected tool, a working analysis engine, and a verified finding are distinct states.

## How tools are selected

- Context7 is requested automatically for library, framework, SDK, API, setup, configuration, and version-specific documentation. The agent resolves a library ID, then queries the relevant documentation. Relevant results can be reused within a task.
- REA is requested for supplied binaries, packages, Electron/ASAR applications, firmware, decompilation, and requested runtime reverse-engineering evidence. A complete source repository does not need a token REA call just to satisfy an instruction.
- The agent uses the tools actually exposed by the host. It reports missing connections, rate limits, and engines rather than inventing tool results or repeatedly running setup.
- Context7 receives a minimal public documentation question, not credentials, private source, or target details. Reading a document does not grant it instruction authority.

The shared section is defined in [`plugin/lib/tool-integrations.js`](../plugin/lib/tool-integrations.js). In Harness it belongs to the same disposable per-agent scope as custom prompt injection, so disabling the prompt removes that section. In OpenCode the installer appends it after the byte-preserved source prompt text in `agents/fujiang.md`; reinstallation updates the generated agent.

## DeepSeek Harness

Context7 attempts a Streamable HTTP connection to `https://mcp.context7.com/mcp` when Harness provides its tool service. It uses the official `@deepseek-ai/dsh-mcp-client` bridge, loaded through the host loader or module resolution. There is no automatic npm installation or new credential file. If the bridge package is unavailable in that host, the connection is reported unavailable; this does not establish a working MCP session.

Connection work runs asynchronously rather than blocking custom-prompt installation. Startup failure is nonfatal, tools are counted from the live registry, and disposal closes the bridge. Reconnection uses the MCP client's bounded retry policy. Starting Harness now attempts an external Context7 connection by default; the offline knowledge base itself is still local.

Optional environment variables must be present in the actual Harness process, not just an unrelated terminal:

| Variable | Purpose |
| --- | --- |
| `CONTEXT7_API_KEY` | Optional authentication, sent as an `Authorization: Bearer ...` header; never returned in plugin status |
| `FUJIANG_CONTEXT7=0` | Disable the Context7 connection for offline operation |

Without a key, service access is subject to Context7's current authentication and quota policy. No pricing or unlimited-use promise is made here. The plugin does not print raw connection errors because those may contain request credentials.

Inspect `GET /api/dsh-prompt-custom/config` on the existing Harness loopback server. Its `toolIntegrations.context7` includes `enabled`, `phase`, live `tools`, and a non-secret error code. `ready` means matching tool definitions are present, not that an end-to-end query passed. `toolIntegrations.rea` reflects the existing REA skill-library state.

REA remains a real, separately installed integration: open the Harness skill library, download **Reverse Engineering**, and enable it. The owned installation registers the `fujiang_rea` MCP server and REA's bundled skill; a persisted enabled state is restored on restart. No REA download, engine installation, or target execution is forced simply by loading this plugin.

## OpenCode

Normal installation remains offline and does not edit OpenCode JSON/JSONC configuration. To additionally register the servers, use the explicit option:

```sh
sh ./scripts/installers/install-opencode.sh --project '/path/to/project' --with-tools --dry-run
sh ./scripts/installers/install-opencode.sh --project '/path/to/project' --with-tools
```

```powershell
.\scripts\installers\install-opencode.ps1 -Project 'D:\Projects\My Project' -WithTools -DryRun
.\scripts\installers\install-opencode.ps1 -Project 'D:\Projects\My Project' -WithTools
```

For global installation, omit the project option. For isolation, prefer a dedicated project or `--config-dir` and configure OpenCode to read that same location. No global host configuration is changed while developing or testing this repository.

`--with-tools` merges `mcp.servers` into the selected directory's `opencode.json`, preserves unrelated JSON values, and uses the installer's staging, backups, rollback, and symlink protections. Existing conflicting `fujiang_context7` / `fujiang_rea` entries, malformed JSON, or a same-directory `opencode.jsonc` stop installation before any agent/skill/config replacement. JSON formatting may change; JSONC comments are never stripped automatically. Existing servers under other names are not detected as duplicates across every inherited configuration; review `opencode mcp list` for the effective host state.

The generated registration uses the current OpenCode 2 nested server schema. For a manual JSONC merge, the keyless form is:

```json
{
  "mcp": {
    "servers": {
      "fujiang_context7": {
        "type": "remote",
        "url": "https://mcp.context7.com/mcp",
        "oauth": false
      },
      "fujiang_rea": {
        "type": "local",
        "command": ["npx", "-y", "rea-agents@6.9.0", "--mcp"],
        "environment": { "REA_MCP_OUTPUT_SCHEMA_PROFILE": "off" },
        "timeout": { "startup": 120000, "execution": 60000 }
      }
    }
  }
}
```

If `CONTEXT7_API_KEY` is set in the installer process, the Context7 configuration additionally contains `"headers": { "Authorization": "Bearer {env:CONTEXT7_API_KEY}" }`. Only the environment reference is saved, not the key. Export the variable in the OpenCode process too. To change authentication after installation, update that header deliberately; a conflicting existing server is not silently overwritten by the installer. Do not put a real key in a command line, repository, or checked-in example.

Starting OpenCode with this registration can download and execute the **pinned REA 6.9.0** npm package via `npx`; the installer itself never runs it. Review third-party package trust before enabling it. REA 6.9.0 declares Node.js `^22.23.4 || ^24.22.1 || >=26.12.1`, stricter than this repository's Node.js 20+ offline-install requirement. Make sure OpenCode's inherited PATH supplies compatible Node.js and npm. Native analysis may additionally require an appropriate existing engine; this installer does not install Hopper, Ghidra, IDA, Java, JADX, or Frida bindings.

Restart OpenCode, inspect `opencode mcp list` and the active session's tool list, and select `fujiang` with your DeepSeek model. Registration applies to the selected OpenCode configuration scope, not exclusively to one provider; the added instructions apply to the generated `fujiang` agent. Existing host permissions and approvals still govern tool calls; no blanket permission grants or default-model changes are added. This adapter does not automatically copy REA's full upstream skill into OpenCode: it configures its MCP connection and provides the shared selection guidance. Follow the installed server's actual tools and schemas.

In isolated checks with the local OpenCode 2.2.7 binary, `debug config --standalone` loaded the generated document, but `mcp list --standalone` returned `No MCP servers configured`, including with a harmless local fixture server. This does not establish that the active session has connected. The underlying startup/listing cause has not been established; do not treat document discovery as MCP readiness or repeatedly reinstall/overwrite configuration to hide this result. Confirm actual session tools after restarting the host before relying on either integration.

### Removal

Close the host. Restore backed-up `opencode.json` if this was an update, or remove only `mcp.servers.fujiang_context7` and `mcp.servers.fujiang_rea` from a fresh configuration. Preserve unrelated settings and servers. Remove the generated agent/knowledge files only if the whole adapter is being uninstalled. REA's npm cache and any separately installed engines are not deleted by removing a server entry.

## Verification limits

Offline tests cover configuration preservation, conflicts, JSONC refusal, symlink rejection, backups, idempotency, environment-only authentication, live-registry status, failure cleanup, and disposal races. Optional native OpenCode tests use isolated temporary HOME/config/data directories and no model request. They verify agent discovery and MCP document discovery with servers disabled, not live session MCP readiness or REA engine execution. Cross-platform CI configuration is not evidence of a completed Windows run.

A separate credential-free HTTP check on 2026-11-13 received HTTP 200 for Context7 `initialize` and `tools/list`, advertising `resolve-library-id` and `query-docs`. No documentation query, model request, private data, or target was sent by that check. This confirms endpoint availability at that time, not the host connection, future quotas, or REA engine readiness.

Primary references checked on 2026-11-13:

- [Context7 upstream](https://github.com/upstash/context7) and [client setup](https://context7.com/docs/resources/all-clients).
- [OpenCode MCP servers](https://opencode.ai/docs/mcp-servers/), [configuration](https://opencode.ai/docs/config/), and [published JSON schema](https://opencode.ai/config.json).
- [REA upstream](https://github.com/morluto/rea) and [REA 6.9.0 npm metadata](https://registry.npmjs.org/rea-agents/6.9.0).
- [Harness MCP bridge 0.2.1-rc.5 metadata](https://registry.npmjs.org/@deepseek-ai%2fdsh-mcp-client/0.2.1-rc.5); its published TypeScript declarations define `transport: 'streamable-http'`, `headers`, lifecycle, and tool namespaces.
