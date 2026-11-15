---
id: "function-identification-fingerprints"
title: "Function identification fingerprints"
domain: "native-core"
kind: "pattern"
platforms: "-"
arch: "x86, x86-64, arm64"
difficulty: "advanced"
tools: "radare2, rabin2, Ghidra, Frida, python3"
verified: false
updated: "2026-11-15"
summary: "Names well-known library and OS functions from their code shape, import graph and cryptographic constants when the binary carries no symbols, and confirms each guess by differential testing."
---

## Summary

Stripped binaries still contain well-known code. `strcmp`, `memcmp`, `strlen`, `malloc`, the
`printf` family, `BCryptVerifySignature`, `SecKeyVerifySignature`, `CCCryptorCreate` and the
standard crypto tables all have recognisable shapes. Identifying them is what makes a licence
check analysable: the moment one of these is recognised, its arguments name the semantic
question ("is this the expected serial?") and the check becomes readable.

This entry gives the fingerprints, the search commands that find each one, and the differential
test that turns a guess into a fact.

## Recognition

- An imported symbol with a familiar name in the import table — the strongest fingerprint, and
  the anchor for every other one. The *callers* of that import inherit the name.
- A small function with a loop and no calls: a hand-written `strcmp`-alike.
- A function that takes a pointer, a length and a key: a cipher or a MAC.
- A 256-byte table of bytes in a read-only section whose first entries are `63 7c 77 7b`: an AES
  S-box.
- A 64-entry table of 32-bit words whose first entry is `0x428a2f98`: SHA-256 round constants.

## Method

### Step 1 — Start from the import table

An imported function names itself. Everything else is inference.

```
rabin2 -i target.exe                     # imports
rabin2 -ij target.exe | python3 -m json.tool | head -40
r2 -q -c 'ii' target.exe
r2 -q -c 'iiq' target.exe                # quiet
```

Then find who calls it:

```
r2 -q -c 'aaa; axt @@ sym.imp.*' target.exe
r2 -q -c 'aaa; axt @@ sym.imp.strcmp' target.exe
```

For a static ELF with no PLT calls, the relocation table names the external symbols:

```
readelf -rW target.elf | grep -E 'strcmp|memcmp|strlen'
r2 -q -c 'ir' target.elf | head -40
```

### Step 2 — C runtime shapes

The exact bytes vary by libc and by compiler, so treat the following as *shapes* and confirm by
differential testing.

**`strcmp`** — compares 8 bytes at a time using a byte-swap trick, so the loop body contains a
`bswap` or a 64-bit compare, and ends with a byte-wise tail loop.

```
48 8b 02          mov  rax, [rdx]
48 3b 06          cmp  rax, [rsi]
75 06             jne  +6
48 83 c2 08       add  rdx, 8
48 83 c6 08       add  rsi, 8
eb f5             jmp  loop
```

Signature: two pointer arguments, no length argument, returns an integer, and the caller usually
uses the result only as zero/non-zero. A `strcmp` that takes a third argument is `strncmp`.

**`memcmp`** — same shape but with a length in the third argument (`rcx` / `edx` on x86-32) and
a `rep`/SIMD compare inside the loop. The length argument is the discriminator.

**`strlen`** — a loop that searches for a zero byte. Modern implementations use `bsf`/`tzcnt`
or a word-at-a-time `pcmpeqb` mask:

```
48 0f b6 c3          movzx rax, byte [rbx]
48 85 c0             test rax, rax
74 02                je   +2
48 0f b6 5b 01       movzx rbx, byte [rbx+1]
```

```
66 0f 1f 44 00 00    movdqa xmm0, [rdx+rax]
66 0f 38 00 c8      pcmpeqb xmm1, xmm0
```

Signature: one pointer argument, returns a length. No length argument.

**`memcpy` / `memmove` / `memset`** — SIMD prologue. The canonical `memcpy` prologue for glibc
on x86-64 starts with `endbr64` and loads 32 bytes at a time:

```
f3 0f 1e fa          endbr64
66 0f 1f 44 00 00    movdqa xmm0, [rax]
f3 0f 6f 03          movdqu xmm1, [rbx]
0f 6f 01             movdqa xmm0, xmm0
```

`memset` is distinguished by a `rep stos` or an AVX `vmovdqu` store loop with a constant fill
register.

**`malloc` / `calloc` / `realloc` / `free`** — `malloc` takes one size argument and returns a
pointer; the distinguishing feature is that it forwards to an arena and that `calloc` takes two
arguments and zeroes the memory. `free` starts with a null check and then reads the chunk header
at `[rdi+8]` (glibc stores the size there) or calls into the arena.

```
48 85 ff             test rdi, rdi
74 0a                je   +0xa
48 8b 5f 08          mov  rbx, [rdi+8]
```

**`printf` family** — the fingerprint is at the *call site*, not in the callee. On x86-64
System V, the number of vector registers used is passed in `AL`:

```
ba 01 00 00 00       mov  edx, 1        ; 1 vector register
48 c7 c7 00 00 00 00 00  mov rdi, 0x0
e8 xx xx xx xx       call printf
```

On x86-32 cdecl, the vector count goes in `edx`. `sprintf`/`snprintf` take the buffer as the
first argument, which makes the output pointer the easiest thing to trace back to.

**`atoi` / `strtol` / `strtoll`** — parse a decimal string; look for the multiply-by-10 and
add-digit loop.

Search for these shapes with radare2's byte search:

```
r2 -q -c '/x f30f1efa; /x 660f1f440000' target.exe
r2 -q -c '/x 4885ff; /x 488b5f08' target.exe
```

### Step 3 — Win32 fingerprints

**`RegQueryValueEx`** — the shape is: open the key (`RegOpenKeyEx`), query the value
(`RegQueryValueEx` with `lpType = NULL`, `lpData` pointing at a stack buffer), then compare the
returned length and bytes. The distinguishing artefacts are the registry path strings
(`SOFTWARE\Vendor\Product`) and the buffer-size local.

```
r2 -q -c 'ii~Reg' target.exe
r2 -q -c 'izz~SOFTWARE\\Vendor' target.exe
```

**`GetVolumeInformation`** — called to bind a licence to a machine. The fingerprint is the
serial-number buffer: a 4-byte volume serial compared against a stored value, often followed by
a string comparison of the volume label. The call takes six arguments (root path, volume name
buffer, serial number pointer, max component length, flags, filesystem name buffer).

```
r2 -q -c 'ii~GetVolumeInformation' target.exe
r2 -q -c 'ii~GetVolumeInformationA; ii~GetVolumeInformationW' target.exe
```

Both the ANSI and the wide variant appear; the wide one takes the same arguments.

**`CryptVerifySignature` (CryptoAPI, `wintrust.dll` / `crypt32.dll`)** — the older API. The
fingerprint is the sequence: `CryptMsgGetParam` to get the signer, `CryptQueryObject` for the
public key, `CryptVerifySignature` with `pbSignature` pointing at a detached signature blob
(base64-decoded) and `hHash` pointing at the hashed message.

```
r2 -q -c 'ii~Crypt' target.exe
```

**`BCryptVerifySignature` (`bcrypt.dll`)** — the modern API. The fingerprint is a fixed call
sequence that is hard to fake:

```
BCryptOpenAlgorithmProvider  (BCRYPT_SHA256_ALGORITHM / "SHA256")
BCryptCreateHash
BCryptHashData                (the signed bytes)
BCryptFinishHash              (the digest)
BCryptVerifySignature         (digest, signature blob, public key blob)
```

Search the import table for the `BCrypt*` family; the presence of `BCryptOpenAlgorithmProvider`
plus `BCryptVerifySignature` in the same module is the fingerprint.

**`WinVerifyTrust`** — used for Authenticode validation of the executable itself; it appears
when a binary validates a sibling file.

### Step 4 — Apple fingerprints

**`SecKeyVerifySignature`** — Security.framework. The call sequence is
`SecKeyCreateWithData` (build a `SecKey` from a raw public key blob) then
`SecKeyVerifySignature` with a `SecKeyVerifySignatureContext` whose `.algorithm` is
`kSecKeyAlgorithmECDSASignatureX962SHA256` (or `rsaSignatureMessagePKCS1v15SHA256`) and whose
`.message` is the signed bytes.

The constant `0x0100` / `0x0103` in the algorithm enum is the giveaway.

```
r2 -q -c 'ii~SecKey' target.macho
r2 -q -c 'ii~SecKeyVerifySignature' target.macho
```

**`CCCryptorCreate`** — CommonCrypto, used for symmetric decryption of a licence blob. The
fingerprint is the algorithm constant: `kCCAlgorithmAES = 0`, `kCCAlgorithmDES = 1`,
`kCCAlgorithm3DES = 2`, `kCCAlgorithmRC4 = 5`, `kCCAlgorithmBlowfish = 8`. The mode is
`kCCModeECB = 1`, `kCCModeCBC = 0`.

```
r2 -q -c 'ii~CCCrypt' target.macho
```

**`SecStaticRandomCreate` / `SecRandomCopyBytes`** — used for a nonce in a licence envelope.

**`kSecAttrApplicationIdentifier` / `SecTaskCopyValueForEntitlement`** — used for App Store
receipt validation and to bind a licence to the app's bundle identifier.

### Step 5 — POSIX fingerprints

**`gethostname`** — fills a buffer of 64 bytes. The fingerprint is the constant `0x40` (64)
being passed as the buffer size, or `uname` being called instead.

**`getifaddrs`** — walks a linked list of `struct ifaddrs`. The fingerprint is the `freeifaddrs`
call after the traversal, and the use of `ifa_addr->sa_family` with `AF_INET` (2).

```
r2 -q -c 'ii~ifaddrs' target.elf
```

**`getenv`** — linear scan of `environ` comparing keys; the fingerprint is the `strcmp`-in-a-loop
shape and the `environ` global reference.

**`time` / `clock_gettime`** — used for licence expiry; the fingerprint is the 8-byte
`time_t` comparison against a stored timestamp.

**`dlopen` / `dlsym`** — dynamic plugin loading; `dlsym` takes a string literal as its second
argument, so the string's cross-reference is a strong anchor.

### Step 6 — Crypto constants

Crypto tables are unambiguous and survive all obfuscation that does not decrypt them.

**AES S-box** — first 16 bytes:

```
63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76
```

AES inverse S-box first 16 bytes:

```
52 09 6a d5 30 36 a5 38 bf 40 a3 9e 81 f3 d7 fb
```

AES round constants:

```
01 02 04 08 10 20 40 80 1b 36 6c d8 ab 4d 9a
```

**SHA-256 round constants** (K), first eight as 32-bit big-endian words:

```
428a2f98 71374491 b5c0fbcf e9b5dba5 3956c25b 59f111f1 923f82a4 ab1c5ed5
```

SHA-256 initial hash values (H0..H7):

```
6a09e667 bb67ae85 3c6ef372 a54ff53a 510e527f 9b05688c 1f83d9ab 5be0cd19
```

SHA-256 K constants in little-endian byte order start `98 2f 8a 42 91 44 37 71`.

**SHA-1 initial values:**

```
67452301 efcdab89 98badcfe 10325476 c3d2e1f0
```

**MD5 T table**, first four:

```
d76aa478 e8c7b756 242070db c1bdceee
```

**CRC-32 (reflected, IEEE 802.3)** — polynomial `0xEDB88320`; the first table entries are:

```
00000000 77073096 ee0e612c 990951ba 076dc419 706af48f e963a535 9e6495a3
```

The polynomial itself often appears as an immediate: `b8 20 b8 ed` (little-endian `0xedb88320`)
in the `mov eax, 0xedb88320` form.

**Blowfish P-array** starts:

```
243f6a88 85a308d3 13198a2e 03707344
```

**CRC-32C (Castagnoli)** — polynomial `0x82f63b78`.

**RSA / modular exponentiation.** There is no constant table, so the fingerprint is structural:

- OpenSSL's `BN_mod_exp` calls `BN_MONT_CTX_set` and then `bn_mul_mont`, whose inner loop
  performs a multiply-accumulate over a fixed window; `bn_mul_mont` contains a 64-bit multiply
  followed by a carry propagate.
- A hand-rolled modexp is a loop of "square and multiply": a loop body containing a multiply
  (`mul`/`imul`/`umulh`), a conditional shift, and a branch on the exponent bit.
- A Python-embedded RSA is often a PyInstaller payload rather than native code — check
  `pyi-archive_viewer` before hunting for `BN_mod_exp`.

Search for the tables:

```
r2 -q -c '/x 637c777bf26b6fc5' target.exe      # AES S-box
r2 -q -c '/x 428a2f9871374491' target.elf      # SHA-256 K (big-endian words)
r2 -q -c '/x 982f8a4291443771' target.elf      # SHA-256 K (little-endian words)
r2 -q -c '/x b820b8ed' target.exe               # CRC-32 polynomial immediate
```

A scanner for all of them at once:

```
python3 - <<'PY'
import pathlib, sys

data = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "target.exe").read_bytes()

SIGS = {
    "AES S-box":            bytes.fromhex("637c777bf26b6fc53001672bfed7ab76"),
    "AES inv S-box":        bytes.fromhex("52096ad53036a538bf40a39e81f3d7fb"),
    "AES rcon":             bytes.fromhex("01020408102040801b366cd8ab4d9a"),
    "SHA-256 K (BE)":       bytes.fromhex("428a2f9871374491b5c0fbcf"),
    "SHA-256 K (LE)":       bytes.fromhex("982f8a4291443771cffb0cb5"),
    "SHA-256 H (BE)":       bytes.fromhex("6a09e667bb67ae853c6ef372"),
    "SHA-1 H":              bytes.fromhex("01234567" "89abcdef" "fedcba98" "76543210"),
    "MD5 T":                bytes.fromhex("d76aa478e8c7b756242070db"),
    "CRC-32 table":         bytes.fromhex("00000000963007772c610eee"),
    "CRC-32 polynomial":    bytes.fromhex("b820b8ed"),
    "Blowfish P":           bytes.fromhex("886a3f24d308a885"),
}

for name, sig in SIGS.items():
    off = data.find(sig)
    if off >= 0:
        print(f"0x{off:08x}  {name}")
    else:
        print(f"           {name}: not found")
PY
```

### Step 7 — Confirm by differential testing

A fingerprint is a hypothesis. Differential testing turns it into a fact: call the candidate
with two controlled inputs and observe whether the output matches the expected semantics.

**In-process, with Frida 17.x:**

```
const base = Process.getModuleByName("target.exe").base;
// candidate at RVA 0x1234
const fn = new NativeFunction(base.add(0x1234), 'int', ['pointer', 'pointer']);
const a = Memory.allocUtf8String("hello");
const b = Memory.allocUtf8String("hellp");
console.log(fn(a, b));   // 0 means strcmp-like
```

**Interpose instead of guess.** The strongest differential test is to replace the real function
with a logging wrapper and observe the arguments the program passes:

```
const strcmp = Module.getGlobalExportByName("strcmp");
Interceptor.attach(strcmp, {
  onEnter(args) {
    console.log("strcmp", args[0].readCString(), args[1].readCString());
  },
  onLeave(retval) {
    console.log("  ->", retval.toInt32());
  }
});
```

Seeing `strcmp("expected_serial", user_input)` confirms both the identity of the function and
the semantic role of the check.

**Offline, with a harness.** Extract the candidate function into a small C or Python harness and
compare its behaviour against a reference implementation over a set of inputs:

```
python3 - <<'PY'
import ctypes, ctypes.util, sys
libc = ctypes.CDLL(ctypes.util.find_library("c"))
libc.strcmp.restype = ctypes.c_int
libc.strcmp.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
cases = [("a", "a"), ("a", "b"), ("", "a"), ("abc", "abd"), (b"\x00x", b"\x00y")]
for x, y in cases:
    print(x, y, libc.strcmp(x, y))
PY
```

Run the same matrix against the candidate implementation and require identical results. One
differential case is suggestive; a matrix covering equal, less, greater, empty and
embedded-NUL inputs is conclusive.

**For the crypto constants**, confirmation is mathematical rather than behavioural: extract the
S-box and verify it against the published table, or hash a known vector with the candidate
routine and compare the digest to a reference value (e.g. SHA-256 of the empty string is
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`).

## Variations

### Static versus dynamic

Static identification is possible whenever the code is present in the file and the tables are
not obfuscated. Dynamic identification is the fallback for packed binaries, encrypted strings
and JIT-compiled code.

### Windows x64 calling convention

Win64 passes the first four arguments in `rcx`, `rdx`, `r8`, `r9`, requires 32 bytes of shadow
space, and returns in `rax`. When calling a candidate from a harness, allocate the shadow space
or the callee will overwrite the caller's stack.

### Go and Rust internals

Go's runtime has its own `runtime.memequal`, `runtime.cmpstring` and `runtime.mapassign` — these
are not the libc versions and their semantics differ (Go's `cmpstring` returns the byte
difference, not just the sign). Rust's `core::slice::cmp` is inlined and has no import to
anchor on.

### Managed code

.NET P/Invoke stubs appear as `pinvokeimpl` methods with an `DllImport` or `LibraryImport`
attribute; the native symbol name is in the metadata, not the code. Java JNI methods are named
`Java_...` in the symbol table when it survives.

### ARM64 specifics

On ARM64 the compiler emits `ldp x29, x30, [sp, #-N]!` prologues and `ret` (`0xD65F03C0`)
epilogues, and frequently calls through a PLT with `bl` to `0x...`. The PLT stub shape on
arm64 is `adrp x16, page; ldr x17, [x16, off]; br x17`, which is a distinct fingerprint for
"call to an external function".

## Verification

1. Every claimed identification must be corroborated by at least one of: an import-table entry, a
   cross-reference from a known string, a matching constant table, or a differential test.

2. For a differential test, record the input matrix and the observed outputs alongside the
   reference outputs. A mismatch voids the identification.

3. Confirm the constant tables by checksum. The AES S-box appears in exactly one place in a
   binary; finding two copies means one is data and one is a decoy, or the binary contains two
   independent crypto implementations.

4. Confirm the crypto routine end to end: hash a known input with the candidate and compare the
   digest against a reference. A correct constant table with a broken loop still produces wrong
   output.

5. Negative test — confirm the identification is not a false positive by showing that a
   *different* candidate function does **not** satisfy the semantics. `memcmp` and `strcmp` are
   the classic confusion: `memcmp` takes three arguments, and a candidate with three arguments
   cannot be `strcmp`.

6. Record the identification with the evidence, not just the name: `function RVA 0x1234 =
   strcmp (evidence: 2 args, no length, differential test rows 1-5)`.

## Pitfalls

- Assuming the import table is complete. Some binaries resolve symbols at runtime with
  `GetProcAddress` or `dlsym`; the imported name list is then short and misleading.
- Trusting a function name from a PDB whose GUID does not match the binary.
- Confusing `strcmp` with `strncmp` or with `strcasecmp`; the argument count is the only reliable
  discriminator.
- Confusing `malloc` with `calloc`; `calloc` has two arguments and zeroes the memory.
- Assuming a crypto table implies the algorithm is used. A binary may embed a table it never
  calls — check for a cross-reference from the table to the code.
- Reading an AES S-box at the wrong alignment, e.g. offset by one byte into the table.
- Assuming big-endian SHA-256 constants; some libraries store them little-endian. Search for
  both forms.
- Treating an `__int128` multiplication inside a modexp as proof of RSA; Montgomery multiplication
  looks identical and is used by many algorithms.
- Using differential testing on a function with side effects — calling a licence validator may
  write a log, increment a counter, or consume a one-time token. Test a copy, in a sandbox.
- Accepting a hypothesis from the decompiler's naming heuristics alone; Ghidra and IDA will
  happily print `FUN_00101234` or `sub_140001234` and occasionally guess wrong.

## References

- FIPS 197, Advanced Encryption Standard (S-box and rcon tables): <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf>
- FIPS 180-4, Secure Hash Standard (SHA-1/SHA-256 constants): <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf>
- RFC 1321, MD5 (T table): <https://www.rfc-editor.org/rfc/rfc1321>
- IEEE 802.3 / RFC 3309, CRC-32 polynomial `0xEDB88320`: <https://www.rfc-editor.org/rfc/rfc3309>
- Microsoft BCrypt documentation: <https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcryptverifysignature>
- Apple Security framework, `SecKeyVerifySignature`: <https://developer.apple.com/documentation/security/1398306-seckeyverifysignature>
- Apple CommonCrypto, `CCCryptorCreate`: <https://developer.apple.com/documentation/commoncrypto/cccryptorcreate>
- glibc source, `string/` directory: <https://sourceware.org/git/?p=glibc.git>
- OpenSSL `crypto/bn/bn_exp.c` and `bn_mont.c`: <https://github.com/openssl/openssl>
- Frida JavaScript API, `Interceptor` and `NativeFunction`: <https://frida.re/docs/javascript-api/>
