---
name: rea-windows-apps
description: "Analyze Windows applications, distinguishing native PE, managed IL and NativeAOT."
---

# rea-windows-apps

## Resources

- [playbooks/pb-windows-native.md](../../playbooks/pb-windows-native.md)
- [playbooks/pb-windows-dotnet.md](../../playbooks/pb-windows-dotnet.md)
- [knowledge/windows-dotnet/strong-name-and-authenticode.md](../../knowledge/windows-dotnet/strong-name-and-authenticode.md)
- [knowledge/windows-native/windows-integrity-and-tamper-checks.md](../../knowledge/windows-native/windows-integrity-and-tamper-checks.md)

Resolve paths from this skill file, not the current working directory. The installer packages references locally. Read only resources relevant to the task.

## Workflow

Identify native PE versus managed IL before choosing tools. Missing IL alone does not prove NativeAOT. Inspect wrappers without executing unknown installers. Trace UI, services and backend decisions separately. Preserve evaluation-stack balance during IL edits. Strong names, Authenticode and OS trust are separate; do not globally disable enforcement as a routine repair.

Use supplied or explicitly scoped targets. Example commands do not authorize unrelated actions. Record tool versions, artifact hashes, observations, limitations and verification actually performed. A successful parser, schema check or byte edit does not verify an entire procedure.
