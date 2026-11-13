---
id: "payment-notify-forgery"
title: "Payment-callback forgery and amount tampering (financial impact)"
kind: "business-logic"
cve: null
related-cves: null
cve-note: "None (business logic)"
severity: "critical"
cvss: 9.1
severity-basis: "cvss"
severity-note: null
product: "Custom deposit/payout callbacks (common on gambling, money-mule payment-processing, and digital-code sales sites)"
versions: "Any"
ports: "80, 443"
keywords: "notify, callback, callback forgery, amount tampering, replay, signature verification, money-mule payment processing"
entry: "Payment-provider notification and callback endpoints"
verified: false
verified-on: null
verification-evidence: null
source-url: null
vendor-advisory: null
cwe: null
patch-date: null
sources: "Compiled from public sources (business logic / implementation / configuration flaws; no CVE; see references below)"
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

- Order-creation endpoints return `payUrl` / `orderNo` / `amount` / `sign`;
- Callback addresses resemble `/notify/alipay`, `/pay/callback`, `/api/recharge/notify`, `/api/daifu/notify`;
- Parameters include `amount`, `money`, `total_fee`, `trade_status`, and `state` together.

## Prerequisites

- Ability to register an account and create a minimum-value order (to observe the callback format and order state machine).
- Access to a callback sample: often from exposed API documentation (`/doc.html`, `/swagger-ui.html`), leaked logs, or `notify_url` in frontend source.

## PoC

### PoC (test the three flaws separately)

```http
### A. No callback signature verification — directly forge success
POST /api/recharge/notify HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

orderNo=<your-own-order-number>&amount=0.01&state=success&sign=whatever

### B. Amount taken from the incoming request — order amount tampering
POST /api/recharge/create HTTP/1.1
Content-Type: application/json

{"amount":10000,"payAmount":0.01,"channel":"alipay"}

### C. Replayable state machine — the same callback credits funds repeatedly
(Replay request A unchanged 3 times and observe whether the balance accumulates)
```

## Exploitation Steps

1. Create a minimum-value order → capture order and callback requests, identifying the signature algorithm (`md5(key+amount)`? `RSA`? None at all?).
2. Try A/B/C in sequence; use a fixed confirmation criterion: **order-status change + balance change**; both must occur.
3. If signatures exist but the key is leaked (`.env`, frontend JS, callback logs), recompute the signature locally.
4. One level deeper: enumerable `orderNo` → forge "paid" for other users' orders (disruptive to operations; describe the affected scope in the report rather than repeating it at scale).
5. Record order number, amount, raw requests/responses, and before/after balances; explicitly estimate the "upper bound of financial impact" as the per-order amount × possible replays.

## Remediation and Mitigation

### Remediation and Mitigation (Hardening)

- Trust amounts only from the server-side order table; use callback `amount` only for comparison and reject mismatches.
- Require signature verification (RSA2 / merchant key) and an allowlist of callback-source IPs (Alipay/WeChat/bank egress ranges).
- Idempotency: unique `orderNo` index + state machine (pending→paid only once); return success for duplicate callbacks without crediting funds.
- Reconciliation job: compare daily against channel transaction records and alert on discrepancies.

## References

- OWASP Top 10 A04 (Insecure Design); Alipay/WeChat Pay callback-signature verification documentation.
