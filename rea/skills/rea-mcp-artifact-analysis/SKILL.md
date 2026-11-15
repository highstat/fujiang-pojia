---
name: rea-mcp-artifact-analysis
description: "Use advertised REA MCP artifact tools to obtain evidence from supplied binaries or packages."
---

# rea-mcp-artifact-analysis

## Resources

- [references/tool-matrix.md](../../references/tool-matrix.md)
- [knowledge/native-core/elf-pe-macho-layout.md](../../knowledge/native-core/elf-pe-macho-layout.md)
- [knowledge/native-core/call-graph-and-xref-recovery.md](../../knowledge/native-core/call-graph-and-xref-recovery.md)

Resolve paths from this skill file, not the current working directory. The installer packages references locally. Read only resources relevant to the task.

## Workflow

This skill installs neither the MCP server nor its engines. Use the connected server's actual tool catalog and input schemas. Route native, managed, Android and ASAR artifacts accordingly. Use retained IDs, paging and export only when advertised; preserve inline evidence otherwise. Do not guess tool names or repeat setup before every task. Report the observed connection or provider blocker.

Use supplied or explicitly scoped targets. Example commands do not authorize unrelated actions. Record tool versions, artifact hashes, observations, limitations and verification actually performed. A successful parser, schema check or byte edit does not verify an entire procedure.
