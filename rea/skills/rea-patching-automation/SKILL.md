---
name: rea-patching-automation
description: "Create hash-bound, reversible application patch manifests and validate file-offset mappings."
---

# rea-patching-automation

## Resources

- [scripts/apply-patch.py](../../scripts/apply-patch.py)
- [scripts/vaddr-to-offset.py](../../scripts/vaddr-to-offset.py)
- [scripts/find-patch-sites.py](../../scripts/find-patch-sites.py)
- [templates/patch-manifest.schema.json](../../templates/patch-manifest.schema.json)
- [templates/patch-report.md](../../templates/patch-report.md)

Resolve paths from this skill file, not the current working directory. The installer packages references locally. Read only resources relevant to the task.

## Workflow

Use the shipped helper rather than duplicating its implementation. Require an original SHA-256, non-overlapping in-bounds equal-length edits and matching bytes. Write to a new output path; the original is rollback. Raw-byte candidates are not disassembled instructions. Use structural editors for length changes. Re-sign after modification and verify behavior separately from byte matching.

Use supplied or explicitly scoped targets. Example commands do not authorize unrelated actions. Record tool versions, artifact hashes, observations, limitations and verification actually performed. A successful parser, schema check or byte edit does not verify an entire procedure.
