---
name: rea-linux-apps
description: "Analyze Linux ELF applications, dynamic linking, interposition and file-backed addresses."
---

# rea-linux-apps

## Resources

- [playbooks/pb-linux-elf.md](../../playbooks/pb-linux-elf.md)
- [knowledge/linux-elf/elf-interposition-ld-preload.md](../../knowledge/linux-elf/elf-interposition-ld-preload.md)
- [knowledge/linux-elf/elf-patch-elf-toolchain.md](../../knowledge/linux-elf/elf-patch-elf-toolchain.md)
- [knowledge/linux-elf/linux-desktop-licence-flow.md](../../knowledge/linux-elf/linux-desktop-licence-flow.md)

Resolve paths from this skill file, not the current working directory. The installer packages references locally. Read only resources relevant to the task.

## Workflow

Determine CPU, endianness, interpreter and dynamic dependencies. Avoid ldd on untrusted binaries; inspect readelf records instead. Addresses beyond p_filesz but inside p_memsz have no file bytes. Prove symbol resolution and ABI compatibility. Do not assume versioned references always require .symver; use the correct version script when exporting version definitions.

Use supplied or explicitly scoped targets. Example commands do not authorize unrelated actions. Record tool versions, artifact hashes, observations, limitations and verification actually performed. A successful parser, schema check or byte edit does not verify an entire procedure.
