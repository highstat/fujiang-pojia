# Playbook: signed licence blob forgery

**Target**: an application that accepts a licence file or blob whose authenticity it checks with
a public key, or that decrypts a licence payload with a symmetric key.
**Outcome**: a reconstructed format and a tested artifact for the declared scope. An asymmetric
signature cannot be forged from its public key alone; key substitution or verifier patching
changes the application. A locally changed client does not establish backend entitlement.

## 0. Preparation

```sh
mkdir -p work && cd work
cp /path/to/app app
sha256sum app
cp /path/to/license.dat license.dat      # a real licence file, if one exists
xxd license.dat | head -20
```

## 1. Determine the shape of the licence

| Observation | Shape |
| --- | --- |
| The file is base64 or hex text | an encoded container |
| The file is exactly 16/32/64 bytes of high-entropy data | a symmetric ciphertext, or a signature |
| The file starts with a version byte or a magic | a structured container |
| The file is a JWT (three base64 segments separated by dots) | a signed token |
| The app reads a licence file from a known path | a local file check |

```sh
file license.dat
python3 - <<'PY'
import base64, json, pathlib
raw = pathlib.Path('license.dat').read_bytes()
try:
    text = raw.decode('ascii').strip()
    if text.count('.') == 2:
        head, payload, sig = text.split('.')
        print('jwt header  :', base64.urlsafe_b64decode(head + '=' * (-len(head) % 4)))
        print('jwt payload :', base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))
    else:
        dec = base64.b64decode(text + '=' * (-len(text) % 4), validate=True)
        print('base64 ->', dec[:64].hex(' '))
except Exception as e:
    print('not base64:', e)
PY
```

## 2A. Asymmetric route — find the verification

```sh
strings -a app | grep -iE 'BEGIN PUBLIC KEY|BEGIN RSA PUBLIC|-----BEGIN'
r2 -q -c 'izz~PUBLIC KEY' app
```

Look for the verification call:

| API | Platform |
| --- | --- |
| `CryptVerifySignature`, `BCryptVerifySignature` | Windows |
| `SecKeyVerifySignature`, `SecCertificateVerify` | macOS / iOS |
| `EVP_DigestVerify`, `EVP_DigestVerifyFinal`, `RSA_verify` | OpenSSL |
| `Signature.verify` | Java / Android |
| `RSA.VerifyData`, `ECDsa.VerifyData` | .NET |

A DER public key starts with `30 82` and contains the modulus. Extract it:

```sh
r2 -q -c '/x 3082' app | head
```

```python
# carve the DER blob out of the binary
data = open('app', 'rb').read()
i = data.find(bytes.fromhex('3082'))
if i != -1:
    length = int.from_bytes(data[i+2:i+4], 'big') + 4
    open('pubkey.der', 'wb').write(data[i:i+length])
    print('extracted', length, 'bytes at', hex(i))
```

## 3A. Forging — route A: swap the key

```sh
openssl genrsa -out priv.pem 2048
openssl rsa -in priv.pem -pubout -out pub.pem
openssl pkcs8 -topk8 -inform PEM -outform DER -nocrypt -in priv.pem -out priv.der
```

Sign a payload:

```sh
printf 'product=suite3\nexpiry=2030-01-01\nfeatures=pro,batch\nmachine=any\n' > payload.txt
openssl dgst -sha256 -sign priv.pem -out payload.sig payload.txt
```

Assemble the licence in the format the app expects. A common container is
`base64(payload) + "." + base64(signature)`:

```python
import base64, pathlib
payload = pathlib.Path('payload.txt').read_bytes()
sig = pathlib.Path('payload.sig').read_bytes()
blob = base64.b64encode(payload) + b'.' + base64.b64encode(sig)
pathlib.Path('license.dat').write_bytes(blob)
```

Replace the embedded public key with yours. The key blob length must be handled:

- If the new key is shorter, pad it — but only if the parser tolerates trailing bytes.
- If it is longer, the container must grow — do this with LIEF so the structure is rebuilt, or
  find a key of the same length (generate an RSA key with a matching modulus size).

```python
import lief
from pathlib import Path

binary = lief.ELF.parse('app')
old = Path('old_pub.der').read_bytes()
new = Path('pub.der').read_bytes()
assert len(new) <= len(old), 'new key is longer — use LIEF to rebuild the section'

data = bytearray(Path('app').read_bytes())
i = data.find(old)
assert i != -1, 'public key not found'
data[i:i+len(new)] = new
Path('app_keyswapped').write_bytes(bytes(data))
print('replaced at', hex(i))
```

Route A keeps the application unmodified in every other respect — the verification path still
runs and still succeeds. Route B is smaller and survives key rotation.

## 3B. Forging — route B: patch the verification

Find the branch that consumes the verification result and invert it, or force the boolean.

x86/x64:

```
0F 95 C0        setne al    ->   B0 01 C3      mov al,1 ; ret
0F 94 C0        sete  al    ->   B0 01 C3      mov al,1 ; ret
```

arm64:

```
00 00 80 52 C0 03 5F D6    mov w0,#0 ; ret   ->   20 00 80 52 C0 03 5F D6
```

Runtime alternative, no file modification:

```js
const fn = Process.getModuleByName('libcrypto.so').getExportByName('EVP_DigestVerifyFinal');
Interceptor.attach(fn, { onLeave(r) { r.replace(1); } });
```

## 2B. Symmetric route — recover the key

Recognise the decryption call and hook it:

```js
// Windows
const bc = Process.getModuleByName('bcrypt.dll');
Interceptor.attach(bc.getExportByName('BCryptDecrypt'), {
  onEnter(args) {
    console.log('key handle', args[0], 'iv', hexdump(args[4], { length: 16 }));
  }
});

// macOS / iOS
const cc = Process.getModuleByName('libcommonCrypto.dylib');
Interceptor.attach(cc.getExportByName('CCCryptorCreate'), {
  onEnter(args) {
    console.log('key', hexdump(args[3], { length: args[4].toInt32() }));
    console.log('iv ', hexdump(args[5], { length: 16 }));
  }
});
```

Once the key and IV are known, decrypt and re-encrypt offline:

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = bytes.fromhex('...')
iv  = bytes.fromhex('...')
cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
dec = cipher.decryptor()
plain = dec.update(ciphertext) + dec.finalize()
print(plain)
```

Re-encrypt after editing the plaintext (remove the PKCS#7 padding correctly, then re-pad):

```python
pad = 16 - len(plaintext) % 16
plaintext_padded = plaintext + bytes([pad]) * pad
cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
enc = cipher.encryptor()
blob = enc.update(plaintext_padded) + enc.finalize()
```

For XOR/RC4 style schemes, the reconstruction is a one-liner:

```python
def xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
```

## 4. Verify

1. Place the forged licence where the app reads it.
2. Launch the app and confirm the feature is unlocked.
3. Clear the cached licence state and repeat — a cached "licensed" flag otherwise masks a
   failed forgery.
4. Confirm the app accepted the *forged* blob, not a cached one: modify one byte in the
   payload and check that the app now rejects it. If it still accepts, the check is not reading
   the blob.

## 5. Pitfalls

- **Payload structure.** The app may parse fields by name or by offset. Match the original
  payload's structure exactly, including field order.
- **Expiry.** A forged payload with a past expiry fails the date check even when the signature
  is good.
- **Feature list.** The signature may cover only part of the payload; adding a feature to an
  unsigned part is not enough if the app verifies a digest over the whole structure.
- **Key length.** A shorter RSA key needs padding; a longer one needs a structural rebuild.
- **The blob is signed over its canonical form.** Re-serialising JSON changes the byte
  sequence — sign the exact bytes you will deliver.
- **The app verifies the payload against a digest stored in the same file.** Recompute it.

## Deliverable

The forged licence, the extracted public key and its offset, the generated private key (or the
patch manifest for route B), and the acceptance output.
