---
id: "cors-misconfig-credential"
title: "CORS misconfiguration (read other users' API data with credentials)"
kind: "configuration"
cve: null
related-cves: null
cve-note: "None (configuration flaw)"
severity: "high"
cvss: 8.1
severity-basis: "cvss"
severity-note: null
product: "Custom API (reflected Origin + ACAC:true)"
versions: "Any"
ports: "80, 443"
keywords: "cors, cross-origin, credentialed, origin, disclosure"
entry: "Reflected Origin with Allow-Credentials: true"
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

```bash
curl -s -D- -o /dev/null 'https://target/api/user/info' -H 'Origin: https://evil.example' | grep -i 'access-control'
```

## Prerequisites

- The API uses Cookie authentication; CORS reflects arbitrary Origin values and allows credentials.

## PoC

```bash
# 1) Check the result
curl -s -D- -o /dev/null 'https://target/api/user/info' -H 'Origin: https://evil.example' \
  | grep -iE 'access-control-allow-(origin|credentials)'
# ACAO: https://evil.example + ACAC: true returned = confirmed

# 2) Retry with a null Origin (some gateways block only non-null origins)
curl -s -D- -o /dev/null 'https://target/api/user/info' -H 'Origin: null' | grep -i access-control

# 3) Verify exploitability: induce the victim to open a page that reads the API
#    Attacker page: fetch('https://target/api/user/info',{credentials:'include'})
```

## Exploitation Steps

1. First inspect response headers (read-only);
2. Confirm reflected Origin + `ACAC:true`;
3. Create a PoC page (opening it locally is sufficient) to prove user data can be read;
4. Evidence: the two response headers + fields read by the page.

## Remediation and Mitigation

- Allowlist Origins; disable `ACAC:true` on sensitive endpoints; CSRF token / SameSite.

## References

- OWASP CORS configuration guidance; CWE-942.
