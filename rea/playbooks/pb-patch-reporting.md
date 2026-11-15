# Playbook: producing the patch report

**Target**: any completed patching session.
**Outcome**: a report that another engineer can audit, reproduce and roll back without redoing
the analysis.

## Why the report matters

A patch without a record is a patch without a rollback. Six months later, nobody remembers why
byte `0x401234` was changed, and a version bump silently reintroduces the licence check.

The report carries three things: the evidence that led to the change, the change itself in a
form that can be re-applied, and the verification that proves the outcome.

## 1. Collect the evidence

From the working notes (`templates/working-notes.md`):

| Item | Source |
| --- | --- |
| Original hash | `sha256sum` at triage, before any modification |
| Format and architecture | `file`, `rabin2 -I`, `readelf -hW`, `otool -hv` |
| Symptom | the exact dialog text, error code or observable behaviour |
| Decision point | the function, address and instruction that carries the decision |
| Evidence for the decision point | the cross-reference from the error string, or the runtime trace |

Keep observations and inferences separate. "The string `Invalid license key` is at `0x40a120`"
is an observation. "The check lives at `0x401234`" is an inference until a cross-reference
confirms it.

## 2. Record the change

Every modified byte, in the manifest format:

```json
{
  "target": "app.exe",
  "target_sha256": "9f2c…",
  "format": "PE32+",
  "architecture": "x86-64",
  "notes": "Inverted the failure branch of the serial comparison.",
  "patches": [
    {
      "id": "licence-branch-invert",
      "reason": "JNE at the serial comparison inverted so the valid path is taken",
      "match": "0F 85 7B 00 00 00",
      "replace": "0F 84 7B 00 00 00",
      "offset": 4198400,
      "virtual_address": "0x401234",
      "section": ".text"
    }
  ]
}
```

The manifest is executable: `scripts/apply-patch.py` re-applies it and refuses to write when the
expected bytes are not present.

```sh
python3 scripts/apply-patch.py manifest.json original.bin patched.bin
python3 scripts/apply-patch.py manifest.json patched.bin check --check
```

## 3. Record the structural repairs

A modified artefact usually needs more than the byte change. Tick each item that applies:

- [ ] PE optional-header checksum recomputed
- [ ] Authenticode signature stripped or re-signed
- [ ] Mach-O bundle re-signed, nested code first
- [ ] Mach-O entitlements preserved (`--preserve-metadata=entitlements,requirements,flags,runtime`)
- [ ] APK aligned with `zipalign -P 16` before signing, then alignment and signature verified
- [ ] DEX header checksum and Adler-32 recomputed
- [ ] ELF program headers verified after modification
- [ ] .NET strong name re-signed or verification skipped
- [ ] Electron integrity fuse disabled and the app re-signed

## 4. Record the verification

The verification table is the part that distinguishes a report from an assertion.

| Test | Command | Expected | Observed |
| --- | --- | --- | --- |
| The structure is intact | `rabin2 -I patched` | parses, same entry point | |
| The original operation succeeds | | the feature unlocks | |
| It survives a cold start | clear state, restart | still unlocked | |
| No new error | check the logs | no crash, no new warning | |
| The bytes are in the running image | re-read the patched file | the recorded bytes | |
| The signature is valid | `codesign -v` / `apksigner verify` | passes | |

A patch that passes the first test but fails the second was tested with a warm cache. Say so.

## 5. Write the report

Use `templates/patch-report.md`. Fill every section; delete none. A section that does not apply
gets "not applicable" rather than being removed, so the next reader knows it was considered.

## 6. Package the artefacts

```
deliverables/
├── patched/                 the modified artefact and its container
├── manifest.json            the machine-readable patch record
├── original.sha256          the hash of the unmodified target
├── evidence/                screenshots, logs, traces, dumps
└── report.md                the report
```

## 7. Handover notes

Write what the next engineer needs and cannot derive:

- **Why this patch and not another.** "The signature check is compiled into the native library,
  so patching the managed layer would have broken the strong name."
- **What was tried and rejected.** "Patching the UI branch had no effect: the feature is gated
  by the service, which validates the blob independently."
- **What breaks on an update.** "The offset is build-specific; the pattern `0F 85 7B 00 00 00`
  is the stable anchor."
- **What was left undone.** "The service-side entitlement check is untouched; the UI unlocks
  but batch operations are still rejected."

## Pitfalls

- **Reporting the intent instead of the result.** "Patched the check" is not a verification.
  "The serial is accepted after clearing `HKCU\Software\Vendor` and restarting" is.
- **Omitting the original hash.** Without it the report cannot establish which build was
  analysed.
- **Listing only the changed bytes.** The structural repairs are part of the change.
- **Claiming more than was tested.** If the cold start was not tested, say the verification was
  performed from a warm state.

## Related

- `templates/patch-report.md`
- `templates/working-notes.md`
- `templates/patch-manifest.schema.json`
- `skills/rea-patching-automation/SKILL.md`
