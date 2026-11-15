---
name: rea-electron-apps
description: "Inspect Electron ASAR apps, process boundaries, native addons and packaging integrity."
---

# rea-electron-apps

## Resources

- [playbooks/pb-electron-asar.md](../../playbooks/pb-electron-asar.md)
- [knowledge/electron-js/asar-extract-repack.md](../../knowledge/electron-js/asar-extract-repack.md)
- [knowledge/electron-js/electron-licence-flow.md](../../knowledge/electron-js/electron-licence-flow.md)

Resolve paths from this skill file, not the current working directory. The installer packages references locally. Read only resources relevant to the task.

## Workflow

Inventory main, renderer, preload and native-addon layers. Use an installed ASAR parser rather than treating Pickle framing as raw JSON. Preserve unpacked entries and integrity metadata. RunAsNode controls ELECTRON_RUN_AS_NODE; EnableNodeCliInspectArguments controls Inspector flags. Inspect actual fuses and the installed CLI schema before changes. Repacking may invalidate signatures.

Use supplied or explicitly scoped targets. Example commands do not authorize unrelated actions. Record tool versions, artifact hashes, observations, limitations and verification actually performed. A successful parser, schema check or byte edit does not verify an entire procedure.
