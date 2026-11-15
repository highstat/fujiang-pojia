---
name: rea-anti-analysis-bypass
description: "Diagnose anti-debug, integrity, packing and obfuscation interference in scoped application analysis."
---

# rea-anti-analysis-bypass

## Resources

- [playbooks/pb-anti-analysis.md](../../playbooks/pb-anti-analysis.md)
- [knowledge/anti-analysis/debugger-detection-techniques.md](../../knowledge/anti-analysis/debugger-detection-techniques.md)
- [knowledge/anti-analysis/integrity-self-checks.md](../../knowledge/anti-analysis/integrity-self-checks.md)
- [knowledge/anti-analysis/control-flow-flattening.md](../../knowledge/anti-analysis/control-flow-flattening.md)

Resolve paths from this skill file, not the current working directory. The installer packages references locally. Read only resources relevant to the task.

## Workflow

Start from an observed symptom, not blanket hooks. Modify only an identified check while preserving unrelated API behavior. Respect out-parameter sizes, return status semantics and calling conventions. Clock hooks affect scheduling and expiry logic. Unpack when necessary, retain the original and distinguish reconstructed data from original-source recovery.

Use supplied or explicitly scoped targets. Example commands do not authorize unrelated actions. Record tool versions, artifact hashes, observations, limitations and verification actually performed. A successful parser, schema check or byte edit does not verify an entire procedure.
