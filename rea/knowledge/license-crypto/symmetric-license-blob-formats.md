---
id: "symmetric-license-blob-formats"
title: "Symmetric licence blob formats"
domain: "license-crypto"
kind: "format"
platforms: "windows, macos, linux, android, ios"
arch: "x86, x86-64, arm64"
difficulty: "advanced"
tools: "Frida, radare2, Python, openssl"
verified: false
updated: "2026-11-15"
summary: "How applications encrypt a licence payload with a shared key instead of signing it, where that key hides, how to recognise the cipher from the blob and the API calls, and how to dump the key at runtime to decrypt the payload offline."
---

## Summary

Where an asymmetric licence is signed (see
[Asymmetric licence signature verification](asymmetric-license-signature-verification.md)),
a symmetric licence is *encrypted*: the application holds the same key the vendor used, so
the payload is unreadable on disk but the key is recoverable from the binary or from the
running process.

The chain that has to be reconstructed is always the same three links:

1. **Container** — how the ciphertext is wrapped (raw bytes, base64 in JSON, a length-prefixed
   struct, a Windows registry `REG_BINARY` value).
2. **Cipher and mode** — AES-CBC, AES-ECB, AES-CTR, ChaCha20, RC4, or a custom XOR stream.
3. **Key and IV provenance** — a constant in `.rodata`, a key derived from a hardcoded
   password, a key derived from machine data, or a key wrapped with DPAPI.

Recovering the plaintext is straightforward once all three are known, and the key is
recoverable at runtime even when it is never present in the file as plaintext.

## Recognition

**Blob-level signals.**

- Size is a multiple of the block size (16 for AES, 8 for DES/RC2/3DES). A licence blob of
  48, 64, 80 or 96 bytes is almost certainly block-cipher output.
- ECB mode leaves repeated 16-byte blocks. Count them:

  ```bash
  python3 - <<'PY'
  data = open("licence.bin","rb").read()
  blocks = [data[i:i+16] for i in range(0, len(data), 16)]
  uniq = len(set(blocks))
  print("blocks:", len(blocks), "unique:", uniq)
  if uniq < len(blocks):
      print("ECB-like repetition at:", sorted(set(i for i,b in enumerate(blocks) if blocks.count(b) > 1)))
  PY
  ```

  A high-entropy payload where the first 16 bytes repeat at the end is ECB with a shared
  prefix block (a common layout: `IV || ciphertext` where the "IV" is actually an encrypted
  header).
- The file is printable base64 with `=` padding and a length that is a multiple of 4 — that
  is a base64-wrapped ciphertext. Decode once and look at the raw size.
- A JSON envelope with fields like `{"data":"...","key":"...","iv":"..."}` — the `iv` field
  is often present, which confirms the mode.

**Binary-level signals.**

```bash
rabin2 -i target.exe | grep -iE 'CryptDecrypt|BCryptDecrypt|BCryptImportKey|CryptImportKey|CryptUnprotectData|AES_set_decrypt_key|EVP_CipherInit|CreateDecryptor'
rabin2 -i target.exe | grep -iE 'CCCrypt|CCCryptorCreate|CCHmac'
```

High-entropy strings of an exact cipher-key length are the classic embedded key. Look for
strings of 16, 24 or 32 bytes that are not printable ASCII:

```bash
r2 -q -c 'izz~..' target.exe | awk '{ if (length($0) >= 20) print }'
r2 -q -c '/x 3a5f8c' target.exe          # hunt a candidate key by a known 4-byte prefix
```

A DPAPI-wrapped key is recognisable by the DPAPI blob header and by the import of
`CryptUnprotectData`:

```bash
r2 -q -c 'aaa; axt @ sym.imp.CryptUnprotectData' target.exe
```

Key derivation shows up as `PKCS5_PBKDF2_HMAC`, `EVP_PBE_scrypt`, `bcrypt`, `EVP_BytesToKey`,
or a hand-rolled loop over a literal password string.

## Method

### Step 1 — Find the decrypt call

```bash
r2 -q -c 'aaa; axt @ sym.imp.CryptDecrypt' target.exe
r2 -q -c 'aaa; axt @ sym.imp.BCryptDecrypt' target.exe
r2 -q -c 'aaa; axt @ sym.imp.EVP_CipherUpdate' target.exe
r2 -q -c 'aaa; axt @ sym.imp.AES_set_decrypt_key' target.exe
```

Read the caller to learn the layout: how many bytes are read, where the key pointer comes
from, where the IV comes from, and whether the output length is the input length.

```bash
r2 -q -c 'aaa; s 0x140002300; pdf' target.exe
```

### Step 2 — Dump the key and IV at runtime

The key is available at the moment the cipher is initialised, even when it was assembled
from pieces or unwrapped from DPAPI.

```javascript
// dump_key.js — Frida 17.x
//   frida -f target.exe -l dump_key.js
function hex(p, len) {
  const b = new Uint8Array(p.readByteArray(len));
  let out = "";
  for (let i = 0; i < b.length; i++) out += ("0" + b[i].toString(16)).slice(-2) + " ";
  return out.trim();
}

function hook(name, moduleName, exportName) {
  let mod;
  try {
    mod = Process.getModuleByName(moduleName);
  } catch (e) {
    console.log("[!] not loaded: " + moduleName);
    return;
  }
  const fn = mod.getExportByName(exportName);
  Interceptor.attach(fn, {
    onEnter(args) {
      console.log("[" + name + "] called");
      for (let i = 0; i < 6; i++) {
        try {
          console.log("   arg" + i + " = " + args[i]);
        } catch (e) {}
      }
    }
  });
  console.log("[+] " + moduleName + "!" + exportName);
}

// --- macOS / iOS CommonCrypto ---
// int CCCryptorCreate(CCOperation op, CCAlgorithm alg, CCOptions options,
//                      const void *key, size_t keyLength, const void *iv,
//                      CCCryptorRef *cryptorRef)
const cso = Process.getModuleByName("libSystem.B.dylib");
Interceptor.attach(cso.getExportByName("CCCryptorCreate"), {
  onEnter(args) {
    const op = args[0].toInt32();
    const alg = args[1].toInt32();
    const options = args[2].toInt32();
    const key = args[3];
    const keyLen = args[4].toUInt32();
    const iv = args[5];
    console.log("[CCCryptorCreate] op=" + op + " (0=encrypt,1=decrypt) alg=" + alg +
                " options=0x" + options.toString(16) + " keyLen=" + keyLen);
    console.log("   key = " + hex(key, keyLen));
    if (!iv.isNull()) console.log("   iv  = " + hex(iv, 16));
  }
});

// --- OpenSSL (Linux, macOS, Windows) ---
// int AES_set_decrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key)
try {
  const lc = Process.getModuleByName("libcrypto.so.3");
  Interceptor.attach(lc.getExportByName("AES_set_decrypt_key"), {
    onEnter(args) {
      const bits = args[1].toInt32();
      console.log("[AES_set_decrypt_key] bits=" + bits + " key = " + hex(args[0], bits / 8));
    }
  });
  console.log("[+] libcrypto.so.3!AES_set_decrypt_key");
} catch (e) {
  console.log("[!] libcrypto.so.3 not loaded");
}

// --- Windows BCrypt ---
// NTSTATUS BCryptImportKey(BCRYPT_KEY_HANDLE hAlgorithm, ..., PUCHAR pbKeyData, ULONG cbKeyData, ...)
try {
  const bc = Process.getModuleByName("bcrypt.dll");
  Interceptor.attach(bc.getExportByName("BCryptImportKey"), {
    onEnter(args) {
      const data = args[5];
      const len = args[6].toUInt32();
      console.log("[BCryptImportKey] len=" + len + " data = " + hex(data, len));
    }
  });
  Interceptor.attach(bc.getExportByName("BCryptDecrypt"), {
    onEnter(args) {
      // NTSTATUS BCryptDecrypt(hKey, pbInput, cbInput, pPaddingInfo, pbIV, cbIV, pbOutput, cbOutput, pcbResult, dwFlags)
      const inLen = args[1].toUInt32();
      const iv = args[4];
      console.log("[BCryptDecrypt] cbInput=" + inLen + " iv = " +
                  (iv.isNull() ? "null" : hex(iv, 16)));
    }
  });
  console.log("[+] bcrypt.dll hooks installed");
} catch (e) {
  console.log("[!] bcrypt.dll not loaded");
}

// --- Windows Crypt32 ---
// BOOL CryptDecrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen)
try {
  const c32 = Process.getModuleByName("crypt32.dll");
  Interceptor.attach(c32.getExportByName("CryptDecrypt"), {
    onEnter(args) {
      const dataLenPtr = args[5];
      const dataLen = dataLenPtr.readU32();
      console.log("[CryptDecrypt] len=" + dataLen + " data = " + hex(args[4], dataLen));
    }
  });
  console.log("[+] crypt32.dll!CryptDecrypt");
} catch (e) {
  console.log("[!] crypt32.dll not loaded");
}

// --- Windows DPAPI: the key material is unwrapped here ---
try {
  const k32 = Process.getModuleByName("kernel32.dll");
  Interceptor.attach(k32.getExportByName("CryptUnprotectData"), {
    onEnter(args) {
      this.outPtr = args[1];
    },
    onLeave() {
      const blob = this.outPtr.readPointer();
      const desc = blob.readPointer();
      const len = blob.add(8).readU32();
      console.log("[CryptUnprotectData] plaintext len=" + len + " = " + hex(desc, len));
    }
  });
  console.log("[+] kernel32.dll!CryptUnprotectData");
} catch (e) {
  console.log("[!] CryptUnprotectData not available");
}
```

Expected output for a target that decrypts a licence blob:

```
[CCCryptorCreate] op=1 (0=encrypt,1=decrypt) alg=0 options=0x1 keyLen=16
   key = 8f 21 c4 0d 77 aa 19 5e 3b 6c 90 d2 41 88 07 f3
   iv  = 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff 00
```

Note `options=0x1` is `kCCOptionPKCS7Padding` and `0x2` is `kCCOptionECBMode`.

### Step 3 — Identify the mode from the parameters

| API | Parameter that reveals the mode |
| --- | --- |
| `CCCryptorCreate` | `options`: bit 0 = PKCS#7 padding, bit 1 = ECB mode; `iv == NULL` means ECB |
| `CryptDecrypt` | `dwFlags`: `CRYPT_NO_SALT` / `CRYPT_DECRYPT`, plus `hHash` for a hash handle |
| `BCryptDecrypt` | `pbIV != NULL` means CBC/CTR; `pbIV == NULL` means ECB |
| `EVP_CipherInit_ex` | `enc == 0` decrypt, `enc == 1` encrypt; `type` selects the cipher; IV in `iv` |
| `AES_set_decrypt_key` + `AES_cbc_encrypt` | the ECB/CBC choice is in the *next* call |

For AES, `alg` in `CCCryptorCreate` is `0` for AES-128, and `kCCAlgorithmAES128` with
`keyLength` of 16/24/32 selects AES-128/192/256.

### Step 4 — Re-implement the transform offline

#### XOR stream with a repeating key

```python
# xor_decrypt.py
def xor_stream(data: bytes, key: bytes) -> bytes:
    out = bytearray(len(data))
    for i, b in enumerate(data):
        out[i] = b ^ key[i % len(key)]
    return bytes(out)

if __name__ == "__main__":
    import sys
    blob = open(sys.argv[1], "rb").read()
    key = bytes.fromhex(sys.argv[2].replace(" ", ""))
    plain = xor_stream(blob, key)
    open(sys.argv[3], "wb").write(plain)
    print(plain[:256])
```

#### RC4

```python
# rc4.py
def rc4(data: bytes, key: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out = bytearray(len(data))
    i = j = 0
    for n, b in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out[n] = b ^ S[(S[i] + S[j]) & 0xFF]
    return bytes(out)

if __name__ == "__main__":
    import sys
    blob = open(sys.argv[1], "rb").read()
    key = bytes.fromhex(sys.argv[2].replace(" ", ""))
    plain = rc4(blob, key)
    open(sys.argv[3], "wb").write(plain)
    print(plain[:256])
```

#### AES-CBC / AES-ECB with a known key and IV

```python
# aes_decrypt.py — pip install pycryptodome
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def decrypt(blob: bytes, key: bytes, iv: bytes | None = None) -> bytes:
    if iv is None:
        cipher = AES.new(key, AES.MODE_ECB)
    else:
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    out = cipher.decrypt(blob)
    try:
        return unpad(out, AES.block_size)
    except ValueError:
        return out          # no PKCS#7 padding

if __name__ == "__main__":
    import sys
    blob = open(sys.argv[1], "rb").read()
    key = bytes.fromhex(sys.argv[2].replace(" ", ""))
    iv = bytes.fromhex(sys.argv[3].replace(" ", " ")) if len(sys.argv) > 3 else None
    print(decrypt(blob, key, iv)[:512])
```

#### ChaCha20

```python
# chacha20_decrypt.py — pip install pycryptodome
from Crypto.Cipher import ChaCha20

def decrypt(blob: bytes, key: bytes, nonce: bytes) -> bytes:
    # OpenSSL EVP_chacha20 uses a 16-byte nonce: 4-byte little-endian counter || 12-byte nonce
    if len(nonce) == 16:
        counter = int.from_bytes(nonce[:4], "little")
        nonce = nonce[4:]
    else:
        counter = 1
    cipher = ChaCha20.new(key=key, nonce=nonce, counter=counter)
    return cipher.decrypt(blob)
```

### Step 5 — Identify the key provenance

Three provenances, distinguishable by what the code does before the cipher call:

| Provenance | Evidence | Recovery |
| --- | --- | --- |
| Constant in the binary | `lea rdx, [rip+disp]` straight into the cipher call | dump the bytes at that address |
| Derived from a hardcoded password | a literal string near a KDF call, or a hand-rolled KDF loop | recover the literal, re-run the KDF |
| Derived from machine data | the KDF input includes a hostname, MAC, or volume serial | hook the collector to fix the input |

Hand-rolled KDFs are common and simple:

```asm
0x140002410  movzx eax, byte [rcx+rax]   ; salt[i]
0x140002414  imul edx, edx, 0x1b          ; multiply
0x140002417  add  edx, eax
0x140002419  rol  edx, 0x0d
0x14000241d  inc  rax
0x140002420  cmp  rax, rdx_len
0x140002424  jne  0x140002410
```

For a hardcoded password, the KDF input is usually a string literal found by
`izz~password` or by scanning for the salt constant.

### Step 6 — Rebuild the container

Once the plaintext is recovered, determine how the app expects to receive it: raw file, a
JSON envelope, a registry value, or an HTTP response body. Re-encrypt and place it where the
app reads it:

```bash
# re-encrypt with openssl (AES-256-CBC, base64 output)
openssl enc -aes-256-cbc -K 8f21c40d77aa195e3b6c90d2418807f3 \
        -iv 112233445566778899aabbccddeeff00 -in plaintext.bin -out licence.enc
```

For a Windows registry blob:

```bash
reg add "HKCU\Software\Vendor\App" /v LicenseBlob /t REG_BINARY /d licence.enc /f
```

For a macOS preference value:

```bash
plutil -replace LicenseBlob -data "$(base64 -i licence.enc)" ~/Library/Preferences/com.vendor.app.plist
```

## Variations

**DPAPI-wrapped key.** The key blob is encrypted with a machine/user key; the app calls
`CryptUnprotectData` to unwrap it. Hook that call (see the Frida script above) to obtain the
plaintext key, then decrypt the licence offline. The blob can also be unwrapped by a small
program that calls `CryptUnprotectData` with the same scope.

**Key derived from machine data.** The KDF mixes in a fingerprint. Fix the fingerprint at
runtime (see [Hardware fingerprint binding](hardware-fingerprint-binding.md)) and the derived
key becomes reproducible.

**Second-stage cipher.** Some blobs are encrypted twice, or the outer layer is a custom
obfuscation (byte shuffle + XOR) over an AES layer. Recover the outer transform first, then
apply the cipher.

**Compression before encryption.** `zlib` magic `78 9c` at the start of the plaintext means
the payload was deflated before encryption. Decompress after decrypting.

**Custom stream cipher.** A tight loop with `add`/`xor`/`rol` over the keystream is a
hand-rolled stream cipher. Transcribe it exactly — including the byte order of any word
operations — and re-implement in Python.

**Managed runtimes.** .NET uses `RijndaelManaged`/`Aes.Create()`; Java uses
`javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding")`; both are visible in decompiled
code (dnSpyEx 6.6.0, jadx 1.5.6) and the key is a `byte[]` literal or a `RNGCryptoServiceProvider`
seed. In Java, hook `javax.crypto.Cipher.doFinal` with the Frida Java bridge to see the key
in the `SecretKeySpec`.

**Android.** The key is frequently in `libnative.so` or in `assets/`; `Cipher.getInstance`
appears in the DEX. Use jadx 1.5.6 to find the `SecretKeySpec` construction.

**Custom alphabet container.** The ciphertext may be base32/base64-encoded inside a JSON
field before storage. Decode the container first, then decrypt.

## Verification

1. **Plaintext plausibility.** The decrypted output must be structured: printable text, a
   JSON object, or a `key=value` list. Random bytes mean the key, mode, or IV is wrong.
2. **Structure match.** The plaintext field names match the fields the binary parses. Confirm
   the field list against the strings in the binary:
   `r2 -q -c 'izz~expire' target.exe`.
3. **Round trip.** Re-encrypt the plaintext with the recovered key and IV, drop the file where
   the app reads it, and confirm the app reports a valid licence.
4. **Negative test — the transform is real.** Flip one bit in the ciphertext and decrypt
   again. The plaintext must change in the corresponding region. If the output is identical,
   the "decryption" was a no-op and the real check is elsewhere.
5. **Negative test — the wrong key is rejected.** Decrypt with a single byte changed in the
   key and confirm the plaintext becomes garbage. This rules out a coincidental match.
6. **ECB check.** If the mode is ECB, decrypting two independent blobs that share a prefix
   must produce identical first blocks. If not, the mode is not ECB.
7. **Restart test.** Restart the app and confirm the licence file is still accepted and not
   silently re-validated against a server.

## Pitfalls

- **Key schedule confused with the raw key.** `AES_set_decrypt_key` fills an `AES_KEY`
  structure; the *user* key is the first `bits/8` bytes of that structure, and the expanded
  round keys follow. Dump the argument, not the expanded structure.
- **Wrong byte order in the key.** Some stores use big-endian words inside a 16-byte blob.
  If the plaintext is garbage, try byte-swapping the key in 4-byte words.
- **IV from the file vs IV from the binary.** In CBC, the IV is often the first 16 bytes of
  the licence file, *not* a constant. Read the call site: `pbIV` pointing into the input
  buffer means the blob is `IV || ciphertext`.
- **PKCS#7 padding removal failing.** A `unpad` exception usually means the wrong key or
  the wrong mode, not a missing padding step. Do not swallow the exception silently; it is
  the only signal that the decryption is wrong.
- **Base64 nesting.** The file may be base64 of base64 of ciphertext. Decode until the size
  stops being a multiple of 4 and the entropy stops dropping.
- **Key in a resource, not the executable.** Helper DLLs, `.rsrc` entries, and files next to
  the binary are all common. `rabin2 -zz` on the DLL, not just the EXE.
- **Hooking too late.** The key may be imported and used during `main` before the agent
  attaches. Spawn the process with `frida -f ...` and hook the library load
  callback (`Process.attachModuleObserver`) so the hook is installed the moment the library
  appears.
- **Altered ciphertext accepted by the app.** If the app only checks a length or a magic
  header inside the encrypted region, the licence may not be cryptographically bound to the
  payload at all. Confirm by changing a payload byte and re-testing.
- **Signing after editing.** Replacing the licence file may invalidate an outer signature
  (Authenticode, codesign, APK v2/v3). Re-sign as described in
  [Asymmetric licence signature verification](asymmetric-license-signature-verification.md).

## References

- CommonCrypto `CCCryptorCreate` / `CCCrypt` — <https://developer.apple.com/documentation/commoncrypto>
- Windows `CryptDecrypt`, `BCryptDecrypt`, `CryptUnprotectData` —
  <https://learn.microsoft.com/windows/win32/api/wincrypt/> ,
  <https://learn.microsoft.com/windows/win32/api/bcrypt/>
- OpenSSL 3.x `EVP_CipherInit_ex` — <https://docs.openssl.org/3.0/man3/EVP_EncryptInit_ex/>
- NIST SP 800-38A (CBC, ECB, CTR modes) — <https://csrc.nist.gov/publications/detail/sp/800-38a/final>
- RFC 8439 (ChaCha20 and Poly1305) — <https://www.rfc-editor.org/rfc/rfc8439>
- Frida 17.x `Interceptor` and `Process.attachModuleObserver` —
  <https://frida.re/docs/javascript-api/>
- pycryptodome API — <https://pycryptodome.readthedocs.io/>
- Sibling entries: [Asymmetric licence signature verification](asymmetric-license-signature-verification.md),
  [Offline activation and machine binding](offline-activation-and-machine-binding.md),
  [Hardware fingerprint binding](hardware-fingerprint-binding.md)
