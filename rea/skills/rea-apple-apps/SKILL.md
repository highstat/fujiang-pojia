---
name: rea-apple-apps
description: "Analyze macOS and iOS app artifacts, architecture-aware Mach-O patches and signing requirements."
---

# rea-apple-apps

## Resources

- [playbooks/pb-macos-bundle.md](../../playbooks/pb-macos-bundle.md)
- [playbooks/pb-ios-ipa.md](../../playbooks/pb-ios-ipa.md)
- [knowledge/macos/codesign-and-entitlements.md](../../knowledge/macos/codesign-and-entitlements.md)
- [knowledge/ios/fairplay-decrypted-binary-handling.md](../../knowledge/ios/fairplay-decrypted-binary-handling.md)

Resolve paths from this skill file, not the current working directory. The installer packages references locally. Read only resources relevant to the task.

## Workflow

Separate macOS, iOS device and simulator builds. Select the correct slice and preserve arm64e/PAC distinctions. Confirm four-byte AArch64 instruction boundaries. Sign nested code deepest first using each component's required entitlements. Ad-hoc signing is not notarization, Gatekeeper trust or installation authorization on ordinary iOS devices. A core dump is not a rebuilt decrypted IPA.

Use supplied or explicitly scoped targets. Example commands do not authorize unrelated actions. Record tool versions, artifact hashes, observations, limitations and verification actually performed. A successful parser, schema check or byte edit does not verify an entire procedure.
