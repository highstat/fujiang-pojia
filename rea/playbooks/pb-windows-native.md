# Playbook: Windows native PE licence bypass

**Target**: a native Win32/MSVC application that refuses a feature or refuses to start until a
licence is accepted.
**Outcome**: the application runs with the feature unlocked, from a cold start, with no debugger
or instrumentation attached.

## 0. Preparation

```sh
mkdir -p work && cd work
cp "/path/to/app.exe" app.exe
sha256sum app.exe | tee app.sha256
file app.exe
rabin2 -I app.exe
rabin2 -S app.exe
rabin2 -i app.exe > imports.txt
rabin2 -z app.exe > strings.txt
```

Record the format, the architecture, whether the binary is signed, and the sections.

## 1. Identify the symptom precisely

| Symptom | Where the check probably is |
| --- | --- |
| A dialog at startup saying the licence is invalid | the startup path, before `main` |
| The app runs but one feature is greyed out | a feature-enable path, gated by a boolean |
| The app exits immediately | an early `exit()`/`ExitProcess` after a failed check |
| A nag dialog appears periodically | a timer or a call into the licensing service |

Capture the exact message text. It is the anchor for the rest of the work.

## 2. Locate the decision point

Three routes, cheapest first.

### Route A — the error string

```sh
r2 -q -c 'izz~invalid' app.exe          # find the string
r2 -q -c 'izzj~invalid' app.exe | python3 -m json.tool | head -40
```

Then take the cross-reference to its use site and read the function that owns it:

```sh
r2 -q -c 'aaa; axt @@ str.*' app.exe
r2 -q -c 'aaa; s <use_site>; pdf' app.exe
```

The use site is inside the branch that produced the dialog. Read upwards: the compare and the
conditional jump are within a few instructions.

### Route B — the licensing API

```sh
grep -iE 'verify|license|crypt' imports.txt
```

`CryptVerifySignature`, `BCryptVerifySignature`, `WinVerifyTrust`, `CertVerifyCertificateChainPolicy`
— the caller supplies the licence blob and receives a boolean. That caller is the decision point.

### Route C — runtime observation

Under x64dbg, break on the dialog API and read the call stack:

```
bp MessageBoxW ".echo --- messagebox; r; .args; k; gc"
```

The frame that called `MessageBoxW` is the branch that failed. Note the address, then dump the
disassembly around it.

## 3. Classify the check

| Shape | What you see | Route |
| --- | --- | --- |
| Comparison | `cmp`/`test` followed by `je`/`jne` | invert the branch |
| Boolean function | a function whose result is tested by the caller | force the return value |
| Verification API | a call to a crypto verification function | patch the call result |
| Server call | an HTTP request whose response sets a flag | protocol route — see `rea-license-crypto` |

## 4. Apply the patch

### Inverting a branch

Find the exact bytes at the address and write the inverted form.

x86/x64 near conditional jump, `0F 8x rel32`:

```
0F 85 7B 00 00 00   JNE +0x7B   ->   0F 84 7B 00 00 00   JE +0x7B
```

x86/x64 short conditional jump, `7x rel8`:

```
74 1E   JE  +0x1E   ->   75 1E   JNE +0x1E
```

arm64 `B.cond`:

```
40 00 00 54   b.eq +0x08   ->   41 00 00 54   b.ne +0x08
```

Patch with radare2 — it converts the virtual address to the file offset:

```sh
r2 -q -w -c 's 0x401234; p8 6; wx 0f847b000000; p8 6; q' app.exe
```

### Forcing a boolean return

x86 and x64, `mov al, 1 ; ret`:

```
B0 01 C3
```

x64 note: the System V ABI returns `bool` in `AL`. `mov eax, 1` also works, but `B0 01 C3`
is unambiguous and shorter.

arm64:

```
20 00 80 52 C0 03 5F D6      mov w0, #1 ; ret
```

### Neutralising a call

```
E8 44 33 22 11   ->   90 90 90 90 90
```

### Recording the patch

Append to the manifest (`skills/rea-patching-automation/SKILL.md`):

```json
{
  "id": "licence-branch-invert",
  "reason": "JNE after the serial comparison inverted",
  "match": "0F 85 7B 00 00 00",
  "replace": "0F 84 7B 00 00 00",
  "offset": 4198400,
  "virtual_address": "0x401234"
}
```

## 5. Repair the artefact

A patched PE fails Authenticode. Handle it:

```sh
# inspect the current signature
osslsigncode verify app.exe

# strip it
python3 - <<'PY'
import lief
pe = lief.PE.parse("app.exe")
pe.signatures.clear()
pe.write("app_patched.exe")
PY

# recompute the optional header checksum
python3 - <<'PY'
import pefile
pe = pefile.PE("app_patched.exe")
pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()
pe.write("app_patched.exe")
PY
```

If the target validates its own checksum at runtime, patch the validation instead — see
`knowledge/windows-native/windows-integrity-and-tamper-checks.md`.

## 6. Verify

```sh
rabin2 -I app_patched.exe          # the structure still parses
wine app_patched.exe 2>&1 | head   # or run natively on Windows
```

Then:

1. Repeat the exact operation that failed before the patch.
2. Clear the licence state — the registry value, `%APPDATA%\<Vendor>`, `%LOCALAPPDATA%\<Vendor>` —
   and restart. A patch that only works from a warm state is not a patch.
3. Confirm the patched bytes are in the running image: re-open the patched file in radare2 and
   check the bytes at the recorded offset.

## 7. If the patch did not take effect

| Cause | Check |
| --- | --- |
| Wrong offset | compare the virtual address with the file offset; use `r2` `?v` |
| Wrong branch | there may be two checks — one in the UI, one in the service |
| The check is elsewhere | search for a second use of the same error string |
| Integrity check | the app verifies its own code — see the anti-analysis playbook |
| Packed binary | unpack first, then patch the unpacked image |
| Exception-based flow | the check runs in an SEH handler — see `knowledge/windows-native/native-exception-based-control-flow.md` |

## Deliverable

`app_patched.exe`, the patch manifest, the original hash, and a short note stating which check
was patched and how it was verified.
