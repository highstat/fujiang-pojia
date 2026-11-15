---
name: rea-android-apps
description: "Analyze Android APK code and native libraries; rebuild, align and sign scoped modifications."
---

# rea-android-apps

## Resources

- [playbooks/pb-android-apk.md](../../playbooks/pb-android-apk.md)
- [playbooks/pb-android-gadget.md](../../playbooks/pb-android-gadget.md)
- [knowledge/android/dex-smali-licence-patching.md](../../knowledge/android/dex-smali-licence-patching.md)
- [knowledge/android/android-native-library-licence.md](../../knowledge/android/android-native-library-licence.md)

Resolve paths from this skill file, not the current working directory. The installer packages references locally. Read only resources relevant to the task.

## Workflow

Inventory package identity, splits, DEX files, native ABIs and signing certificates. Use the smali assembler for branch offsets and DEX checksums. Rebuild, align, sign, then verify signature and alignment. Preserve lib/<ABI>/ paths. Back up test data before uninstalling or clearing state. Client edits cannot create a valid server-side entitlement.

Use supplied or explicitly scoped targets. Example commands do not authorize unrelated actions. Record tool versions, artifact hashes, observations, limitations and verification actually performed. A successful parser, schema check or byte edit does not verify an entire procedure.
