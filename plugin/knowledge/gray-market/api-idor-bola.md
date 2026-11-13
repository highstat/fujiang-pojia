---
id: "api-idor-bola"
title: "API authorization bypass / BOLA (read others' orders, transactions, and withdrawals)"
kind: "business-logic"
cve: null
related-cves: null
cve-note: "None (business logic)"
severity: "high"
cvss: 8.1
severity-basis: "cvss"
severity-note: null
product: "Custom API (common on gambling/agent/payment-running platforms)"
versions: "Any"
ports: "80, 443"
keywords: "idor, bola, broken access control, horizontal privilege escalation, orderNo, uid, agent backend"
entry: "API endpoints accepting user-controlled object identifiers"
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

Endpoints look like this (visible in captured traffic):

```
/api/user/info?uid=10086 /api/order/detail?orderNo=20241105001
/api/wallet/bill?userId=... /api/agent/member/list?agentId=...
/api/withdraw/detail?id=... /api/bet/record?memberId=...
```

Response bodies contain sequential IDs, phone numbers, balances, and transaction numbers — these fields provide entry points to "other users' data". Authorization checks on these sites are often implemented in the frontend (hidden menus/disabled buttons), while the backend checks only whether the user is logged in.

## Prerequisites

- **Two** regular accounts (A and B; registration barriers are low on these sites, and trial/demo accounts are common) — one account cannot prove an authorization bypass; see the "two-account comparison" below.
- Ability to capture your own requests (use an intercepting proxy + certificate for an App; inspect H5 directly).

## PoC

```http
# Request account B's resource using account A's token
GET /api/order/detail?orderNo=20241105001234 HTTP/1.1
Host: target
Authorization: Bearer <token for A>
```

Three result levels: another user's complete data is returned (confirmed) → 200 with fields removed (partially confirmed) → 403/404 (not confirmed). A **two-account comparison** is the only reliable evidence.

## Exploitation Steps

1. Place one order with each account, A and B; capture both requests and confirm that only the id parameter differs.
2. A's token + B's id → check whether B's phone number/balance/transactions are readable; if confirmed, move to high-impact endpoints: withdrawal approval, commission rates, and agent hierarchy.
3. Enumeration: `orderNo` is often "date + sequence" or 6-10 digits; sample with a low-rate script (these sites use device fingerprints + IP rate limits; do not use concurrency).
4. Vertical privilege escalation: access `/api/admin/*` and `/api/agent/*` with a regular account token; many sites only hide menus in the frontend.
5. Evidence: each account's request + response and timestamps; do not bulk-export member data.

## Remediation and Mitigation

### Remediation and Mitigation (Hardening)

- Use the `uid` from the session/JWT on the server, ignoring the request's `uid`; enforce resource-level authorization (owner check).
- Use UUIDs/signed opaque IDs for order numbers; prevent sequential enumeration.
- Consistently return 404/403 for unauthorized access; avoid exposing existence through "200 + empty object".
- Validate the ancestor chain for agent hierarchies on the server; do not accept client-supplied `agentId`.

## References

- OWASP API Security Top 10: API1 BOLA, API5 BFLA.
