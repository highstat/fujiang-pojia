---
id: "sms-bomb-and-enum"
title: "SMS bombing and account enumeration (verification-code attack surface)"
kind: "business-logic"
cve: null
related-cves: null
cve-note: "None (business logic)"
severity: "medium"
cvss: 5.3
severity-basis: "cvss"
severity-note: null
product: "Custom registration/login/recovery endpoints"
versions: "Any"
ports: "80, 443"
keywords: "sms, bombing, enumeration, verification-code brute force, rate limiting, user enumeration"
entry: "SMS verification-code and account lookup endpoints"
verified: false
verified-on: null
verification-evidence: null
source-url: null
vendor-advisory: null
cwe: null
patch-date: null
sources: "Compiled from public sources (business logic / implementation / configuration flaws; no CVE; see references below)"
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

- `/api/sms/send`, `/api/user/register`, `/api/user/findpwd`, `/api/login` (image CAPTCHA/SMS verification code);
- Response-message differences: `This phone number is already registered` / `User does not exist` / `Verification code sent`.

## Prerequisites

- No account required (sending endpoints are usually callable anonymously).

## PoC

```http
### 1) Rate-limit testing: repeated sends to the same number
POST /api/sms/send HTTP/1.1
Content-Type: application/json

{"phone":"13800138000","type":"register"}

### 2) Bypass rate limits (three common methods)
- Change X-Forwarded-For / X-Real-IP (effective when the server counts by IP)
- Vary the phone-number format: +86, spaces, leading 0, Unicode digits
- Change type: register / login / findpwd / bind may have independent counters

### 3) Enumeration: message differences in the registration endpoint
POST /api/user/register {"phone":"13800138000"}  → "Already registered"
POST /api/user/register {"phone":"13800138001"}  → "Available for registration"

### 4) Verification-code brute force: 4 digits, no attempt limit, no expiry
POST /api/login {"phone":"...","code":"0000"}  → Iterate through 9999
```

## Exploitation Steps

1. Test three rate-limit dimensions: interval per number, total per IP, and per device (`deviceId` helps).
2. Test codes: length, validity period, failed-attempt limit, and phone-number binding (use A's code for B).
3. Enumeration: use message/status-code differences to determine number existence in batches (rate-limit + deduplicate; sampling is sufficient proof).
4. Chain: enumerate registered numbers → weak passwords/credential stuffing (six-digit numeric passwords are common on these sites) → verification-code brute force as a fallback.
5. Retain only 2–3 requests as evidence; do not include a phone-number database in the report.

## Remediation and Mitigation

### Remediation and Mitigation (Hardening)

- Require image/behavioral verification (slider) first; rate-limit across "phone number + IP + device + type" and silently discard over-limit requests.
- Six-digit codes, 5-minute validity, 5-attempt limit, single use; bind to the phone number and session.
- Use consistent registration/recovery/login messages ("A verification code will be sent if the number exists") without revealing existence.
- Apply SMS-provider-side rate limits and cost alerts (SMS fees are the direct loss from bombing).

## References

- OWASP WSTG-IDNT-04 (account enumeration); OWASP Authentication Cheat Sheet.
