---
id: "strong-name-and-authenticode"
title: "Strong name and Authenticode"
domain: "windows-dotnet"
kind: "format"
platforms: "windows, macos, linux"
arch: "-"
difficulty: "intermediate"
tools: "sn,ildasm,ilasm,signtool,osslsigncode,dnSpyEx"
verified: false
updated: "2026-11-15"
summary: "Separates the .NET strong name from the Windows Authenticode signature, shows exactly which bytes each one covers, and gives the commands that restore or remove each signature after an edit."
---

## Summary

Two signatures exist on a .NET binary and they are confused constantly. A **strong name** is a
hash in the assembly metadata that gives the assembly an identity; it is not a security
guarantee, because the private key is usually in the repository. **Authenticode** is a PKCS#7
signature over the PE image produced by the Windows trust chain; it is what SmartScreen, UAC
and MSIX rely on.

Editing IL breaks the strong name. Editing any covered byte breaks Authenticode. This entry
gives the commands that repair the first, remove or renew the second, and the exact byte
regions each signature covers.

Cross-reference: [il-licence-check-editing](il-licence-check-editing.md) for the edits that
trigger the problem, and [dotnet-obfuscator-deobfuscation](dotnet-obfuscator-deobfuscation.md)
for the case where the tool that writes the assembly is not the original build.

## Recognition

Symptoms after an edit:

- `System.IO.FileLoadException` with the message "Strong name signature validation failed"
  (or "The located assembly's manifest definition does not match the assembly reference"),
  thrown while a strong-named host loads the edited assembly.
- `System.BadImageFormatException` or `FileNotFoundException` where the file is present —
  usually a public key mismatch, not a hash mismatch.
- Windows Defender SmartScreen shows "Windows protected your PC" or "The publisher could not be
  verified".
- UAC shows an "Unknown publisher" dialog for an EXE that used to be signed.
- `signtool verify /pa target.exe` fails with `0x80096010` (`CERT_E_UNTRUSTEDROOT`) or
  `0x80096004` (the digest does not match).
- `Get-AuthenticodeSignature` reports `HashMismatch` or `NotSigned` for a file that was signed
  in the build pipeline.

## Method

Working directory for every command below: the directory that contains the target binary.

### 1. Tell the two apart

| Property | Strong name | Authenticode |
| --- | --- | --- |
| Where it lives | assembly metadata (public key) plus a signature blob referenced by the COR header | PE certificate table, data directory index 4 |
| What it covers | a defined subset of the metadata and headers | the whole PE image except three regions |
| Key | an RSA key pair, the private half usually in the repository | a code-signing certificate from a CA (or a self-signed one) |
| Enforced by | the .NET Framework loader (not on .NET Core / .NET 5+) | Windows (UAC, SmartScreen, MSIX, WDAC) |
| Detected by | `sn -vf`, `ildasm` | `signtool verify /pa`, `Get-AuthenticodeSignature` |
| Broken by | any metadata edit | any covered byte edit |

### 2. Inspect the strong name

```bat
sn -T target.exe
sn -tp target.exe
```

`sn -T` prints the public key token, for example
`Public key token is b03f5f7f11d50a3a`. `sn -tp` prints the full public key and the token.

Dump the metadata to see the assembly attributes:

```bat
ildasm /text /nobar /tokens /out=target.il target.exe
```

In the dump, the assembly identity appears as:

```text
.assembly extern target
{
  .publickeytoken = (B0 3F 5F 7F 11 D5 0A 3A )   // PublicKeyToken
  .ver 1:0:0:0
}
```

An assembly-level `[assembly: AssemblyKeyFile("...")]` or
`[assembly: AssemblySignatureKeyAttribute("...")]` attribute indicates a delay-signed
assembly: the public key is present, the signature is not.

The signature blob itself is located through the CLI header. Data directory index 14 points at
the `IMAGE_COR20_HEADER`, 72 bytes:

| Offset | Size | Field |
| --- | --- | --- |
| `0x00` | 4 | `cb` |
| `0x04` | 2 | `MajorRuntimeVersion` |
| `0x06` | 2 | `MinorRuntimeVersion` |
| `0x08` | 8 | `MetaData` (RVA + size) |
| `0x10` | 4 | `Flags` |
| `0x14` | 4 | `EntryPointToken` / `EntryPointRVA` |
| `0x18` | 8 | `Resources` |
| `0x20` | 8 | `StrongNameSignature` (RVA + size) |
| `0x28` | 8 | `CodeManagerTable` |
| `0x30` | 8 | `VTableFixups` |
| `0x38` | 8 | `ExportAddressTableJumps` |
| `0x40` | 8 | `ManagedNativeHeader` |

`StrongNameSignature` points at the public key blob followed by the RSA signature over the
strong-name hash. The hash covers a specific set of regions (the PE headers up to the
metadata, the metadata tables and streams, and the assembly's public key), not the whole file,
which is why it cannot be recomputed by hand — only by `sn`.

### 3. Re-sign with the original key

```bat
sn -R target.exe original.snk
sn -vf target.exe
```

`sn -vf` prints `Assembly 'target.exe' is valid` when the recomputed hash matches the key.
A delay-signed assembly becomes fully signed by the same command.

Extract the key pair components:

```bat
sn -p fullkeypair.snk publickey.snk     :: public key out of a full key pair
sn -e publickey.blob publickey.snk       :: full public key out of a public key blob
sn -tp target.exe                        :: token and full public key of an assembly
```

If the private key is gone, the assembly can only be re-signed with a *new* key, which changes
its identity. Removing the strong name entirely is the alternative:

```bat
ilasm /dll /nologo target.il /out:target.unsigned.dll
```

and, in the C# project, the attributes to drop are:

```csharp
[assembly: AssemblyKeyFile("key.snk")]
[assembly: AssemblySignatureKeyAttribute("PublicKey=<hex>")]
```

In dnSpyEx, open the assembly attributes in the Assembly Explorer, remove the strong-name
attribute and clear the public key field, then save.

### 4. Skip verification instead of re-signing

To keep the original public key and skip the hash check, register the assembly for
verification skip:

```bat
sn -Vr target.exe
sn -Vr *
sn -Vu target.exe          :: unregister
```

The machine-wide registration requires an elevated command prompt; without elevation the
command writes to the user policy store where the policy allows it. This is a .NET Framework
mechanism and has no effect on .NET Core or .NET 5 and later.

The reference-time equivalent, in the project that references the edited assembly:

```xml
<PropertyGroup>
  <SkipVerification>true</SkipVerification>
</PropertyGroup>
```

which maps to the compiler switch `/skipverification+`. The property belongs to the *referencing*
project; setting it in the edited assembly's own project file has no effect at load time.

### 5. Repair the Authenticode signature

Re-sign the PE with a code-signing certificate:

```bat
signtool sign /fd SHA256 /td SHA256 /f cert.pfx /p <password> ^
  /tr http://timestamp.example.com /td SHA256 target.exe

signtool verify /pa /v target.exe
```

`-fd` selects the digest algorithm, `-td` the timestamp digest algorithm, `-tr` an RFC 3161
timestamp server (without a timestamp the signature stops validating when the certificate
expires).

OpenSSL alternative, which also handles the PKCS#7 structure without a Windows-only tool:

```bash
osslsigncode sign -in target.exe -out target.signed.exe \
  -pkcs12 cert.pfx -pass pass:<password> \
  -h sha256 -ts http://timestamp.example.com

osslsigncode verify -in target.signed.exe
```

Windows-only verification and removal:

```powershell
Get-AuthenticodeSignature .\target.exe | Format-List Status,StatusMessage,SignerCertificate
Unblock-File .\target.exe          :: drops the Mark-of-the-Web stream
signtool remove /s target.exe     :: removes the signature from the file
```

`signtool remove /s` zeroes the certificate table data directory entry and truncates the
certificate blob. If anything follows the certificate table in the file (an overlay, an
appended payload), that data is lost; check the layout first with the procedure in
[windows-integrity-and-tamper-checks](../windows-native/windows-integrity-and-tamper-checks.md).

### 6. Understand what Authenticode covers

The Authenticode hash is computed over the whole PE image except three regions:

1. The `CheckSum` field in the optional header (optional header + `0x40`, 4 bytes).
2. The certificate table entry in the data directory (8 bytes at optional header + `0x80` for
   PE32, + `0x98` for PE32+).
3. The certificate table itself.

Everything else — headers, sections, resources, the CLI header, the metadata — is covered.
The practical consequences:

- Recomputing the PE checksum does **not** break Authenticode, because the checksum field is
  excluded.
- Editing one byte in `.text` breaks it.
- The certificate table is a sequence of `WIN_CERTIFICATE` structures, each with an 8-byte
  header (`dwLength`, `wRevision`, `wCertificateType`, where `wCertificateType` is `0x0002` for
  PKCS#7) and the signature blob, each entry aligned to 8 bytes. A dual-signed file holds two
  such entries.

### 7. Recompute the PE checksum after an edit

Windows only enforces the PE checksum for kernel-mode drivers and some system binaries, but
tools and installers check it. The recomputation script is in
[windows-integrity-and-tamper-checks](../windows-native/windows-integrity-and-tamper-checks.md);
the OS-authoritative version is:

```c
#include <windows.h>
#include <imagehlp.h>

DWORD sum = 0;
CheckSumMappedFile(L"target.exe", NULL, NULL, &sum);
```

## Variations

- **.NET Core, .NET 5 and later**: the runtime does not validate strong names at load time.
  An edited strong-named assembly loads normally; only a public key mismatch between the
  assembly and its references breaks the resolution. `sn.exe` still comes from the .NET
  Framework SDK; a community re-signer exists for the modern runtimes.
- **Delay signing**: the assembly carries only the public key. `sn -R` with the private key
  completes the signature. The delay-signed assembly fails verification until then.
- **Signed NuGet packages**: the `.nupkg` carries its own NuGet signature over the package
  contents, separate from both mechanisms here. Editing an assembly inside a package breaks
  the NuGet signature too.
- **Single-file bundles**: the bundle contains the host with an Authenticode signature; the
  embedded assemblies are covered by that signature, and the bundle has its own digest
  (`DOTNET_BUNDLE_EXTRACT_BASE_DIR` relates to extraction, not signing).
- **MSIX / MSIX packages**: the package signature covers the whole ZIP, so an edit inside
  breaks the package signature before any code-level check runs.
- **Cross-signed and dual-signed assemblies**: two `WIN_CERTIFICATE` entries; removing one
  changes the trust path. `signtool sign /as` appends a second signature.
- **Internal Microsoft assemblies**: some carry a "Microsoft public key" and are not
  re-signable; the only option is to strip the strong name and patch the references.
- **Mono and Unity**: Unity's Mono builds use `Assembly-CSharp` without a strong name; the
  Authenticode question does not arise for the game assemblies themselves.
- **Signed installers**: the licence check may live inside an embedded payload whose
  Authenticode signature is separate from the installer's; strip each payload individually.

## Verification

1. **Strong name.** After re-signing:

   ```bat
   sn -vf target.exe
   ```

   Expect `Assembly 'target.exe' is valid`. The failure forms are "not strongly named" (the
   signature was removed), "strong name validation failed" (hash mismatch: wrong key or a
   further edit after signing) and a public key mismatch (a different identity).

2. **Authenticode.** After signing or stripping:

   ```bat
   signtool verify /pa /v target.exe
   powershell -Command "Get-AuthenticodeSignature .\target.exe | Select-Object Status"
   ```

   Expect `Valid` for a signed file and `NotSigned` for a deliberately stripped one.
   `HashMismatch` means the file was edited after signing.

3. **Positive test.** Launch the edited binary from a fresh process and exercise the licensed
   path. The program must start without a trust warning on a machine that would normally show
   one, or with the expected warning if the signature was intentionally removed.

4. **Negative test.** Restore the original file and confirm the original trust state returns:
   the signed file verifies again, and the edited file fails `signtool verify`. If both verify,
   the edit did not touch a covered region — usually the edit landed in the excluded
   checksum field.

5. **Load test from a strong-named host.** A host that references the assembly by strong name
   must still load it:

   ```bat
   host.exe
   ```

   A `FileLoadException` here with a valid `sn -vf` result means the reference in the host
   points at a different copy of the assembly than the one that was re-signed.

6. **Dual-environment check.** Run the binary on a machine with enforced WDAC/AppLocker policy
   and confirm the trust decision is unchanged; a locally stripped signature changes the
   decision only if the policy requires a valid publisher.

## Pitfalls

- **`sn -R` without the key file does not re-sign.** The command is `sn -R assembly key.snk`;
  without the key it fails with "unable to import key".
- **The strong-name hash is not a file hash.** It covers a defined set of regions, so a
  recomputation script for file hashes is wrong for it.
- **Changing the public key changes the identity.** Referencing assemblies then fail with
  "The located assembly's manifest definition does not match the assembly reference", which
  looks like a missing dependency rather than a signature error.
- **`sn -Vr` is machine-wide and needs elevation.** It also silences the check for every
  assembly on the machine, which hides real tampering elsewhere.
- **`SkipVerification` is a property of the referencing project**, not of the edited
  assembly.
- **Stripping the Authenticode signature does not remove the Mark-of-the-Web.** A file
  downloaded from the internet keeps its `Zone.Identifier` stream and still shows a warning;
  use `Unblock-File`.
- **The certificate table is normally last in the file, but not always.** Truncating at the
  certificate table offset destroys anything appended after it.
- **Re-signing after every edit is easy to forget.** A second edit after `sn -R` invalidates
  the strong name again, and a second edit after `signtool sign` invalidates Authenticode
  again. Order the operations: edit, then checksum, then strong name, then Authenticode.
- **`signtool sign` replaces the existing signature** unless `/as` is used to append.
- **SmartScreen reputation is separate from the signature.** A valid signature on a
  zero-reputation binary still warns; an ad-hoc signature (`signtool sign /a`) is valid but
  untrusted.
- **`osslsigncode` writes a different PE layout** in some versions (it can move the
  certificate table), so re-verify with `signtool verify` after using it.

## References

- Strong naming: <https://learn.microsoft.com/dotnet/standard/assembly/strong-name-signing>
- `sn.exe` tool: <https://learn.microsoft.com/dotnet/standard/tools/sn-tool>
- `AssemblySignatureKeyAttribute`:
  <https://learn.microsoft.com/dotnet/api/system.reflection.assemblysignaturekeyattribute>
- `SkipVerification` property:
  <https://learn.microsoft.com/dotnet/api/system.reflection.assembly.skipverification>
- Authenticode overview: <https://learn.microsoft.com/openspecs/office_file_formats/ms-oshared/9177d4b2-d2d2-4ef1-9d0b-11046b71b2fe>
- `signtool` reference: <https://learn.microsoft.com/windows-hardware/drivers/devtest/signtool>
- `ildasm` reference: <https://learn.microsoft.com/dotnet/standard/assembly/ildasm-command>
- ECMA-335 Partition II, metadata format:
  <https://ecma-international.org/publications-and-standards/standards/ecma-335/>
- osslsigncode: <https://github.com/mtrojnar/osslsigncode>
- Cross-reference: [il-licence-check-editing](il-licence-check-editing.md)
