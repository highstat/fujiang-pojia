# Patch and verification report

## Target

| Field | Value |
| --- | --- |
| File | `path/to/app` |
| Original SHA-256 | `…` |
| Format | PE32+ / ELF64 / Mach-O arm64 / DEX / IL assembly |
| Architecture | x86-64 / arm64 / … |
| Packed | no / yes (packer name) |
| Signed | Authenticode / strong name / Mach-O code signature / APK v1+v2+v3 |
| Platform | Windows 11 / macOS 15 / Ubuntu 24.04 / Android 15 / iOS 18 |

## Symptom

The exact behaviour before the change, quoted where possible:

> <dialog text, error code, or observable behaviour>

## Decision point

| Field | Value |
| --- | --- |
| Kind | branch inversion / boolean forced / signature check patched / blob forged / hook |
| Location | function `check_license` at `0x401234`, string `licence.dat` |
| Evidence | cross-reference from the string `Invalid license key` at `0x40a120` |
| Original bytes | `0F 85 7B 00 00 00` |
| New bytes | `0F 84 7B 00 00 00` |

## Changes

| # | File | Offset | Before | After | Reason |
| --- | --- | --- | --- | --- | --- |
| 1 | `app` | `0x401234` | `0F 85 7B 00 00 00` | `0F 84 7B 00 00 00` | inverted the failure branch |
| 2 | `app` | `0x500000` | `30 00 00 00` | `00 00 00 00` | cleared the trial-days counter |

## Structural repairs

- [ ] Checksum recomputed (PE optional header / DEX header / ZIP CRC)
- [ ] Signature stripped or re-signed
- [ ] Mach-O bundle re-signed, nested code first
- [ ] APK aligned with `zipalign -P 16` before signing, then alignment and signature verified
- [ ] ELF program headers verified after modification
- [ ] Strong name re-signed or verification skipped

## Verification

| Test | Result |
| --- | --- |
| The binary still loads | `rabin2 -I` → parses; process starts |
| The original failing operation now succeeds | yes / no |
| The check survives a cold start (cached state cleared) | yes / no |
| No new crash or error in the logs | yes / no |
| The patched bytes are present in the running image | yes / no |

Commands run:

```
<the exact commands and their key output>
```

## Outstanding items

- Second check in the native library is still active — the UI unlocks but the service rejects.
- The application verifies its own CRC over `.text`; the digest must be recomputed after any
  further change.

## Artefacts

| File | Description |
| --- | --- |
| `app_patched` | the modified target |
| `patch-manifest.json` | machine-readable patch record |
| `app.sha256` | the original hash |
| `notes.md` | working notes |
