---
name: rea-native-static
description: "Analyze native PE, ELF and Mach-O artifacts, cross-references and candidate patches."
---

# rea-native-static

## Resources

- [knowledge/native-core/elf-pe-macho-layout.md](../../knowledge/native-core/elf-pe-macho-layout.md)
- [knowledge/native-core/call-graph-and-xref-recovery.md](../../knowledge/native-core/call-graph-and-xref-recovery.md)
- [knowledge/native-core/conditional-branch-patching.md](../../knowledge/native-core/conditional-branch-patching.md)
- [knowledge/native-core/checksum-and-integrity-repair.md](../../knowledge/native-core/checksum-and-integrity-repair.md)

Resolve paths from this skill file, not the current working directory. The installer packages references locally. Read only resources relevant to the task.

## Workflow

Select the exact architecture slice. Distinguish virtual addresses, RVAs and file offsets. Trace the failed operation to its decision and confirm instruction boundaries. Inverting a condition swaps outcomes; it does not always force success. Choose return sequences for the actual ABI: an 8-bit C++ bool is not a 32-bit Windows BOOL. Preserve original bytes and hashes.

Use supplied or explicitly scoped targets. Example commands do not authorize unrelated actions. Record tool versions, artifact hashes, observations, limitations and verification actually performed. A successful parser, schema check or byte edit does not verify an entire procedure.
