---
name: "kb-gray-market"
description: "CVE/PoC knowledge base · Turnkey gambling platforms / illicit and gray-market sites: source and backup disclosure, reversible frontend signing, API authorization bypass (BOLA), unauthenticated admin APIs, unauthorized impersonation, agent hierarchy authorization bypass, member-privacy enumeration, Mass Assignment, payment callback forgery, withdrawal-approval authorization bypass, balance concurrency and negative amounts, bet-odds tampering, missing bonus idempotency, third-party game callback forgery, predictable draw algorithms, unauthenticated support IM/WS, stored XSS targeting admin backends, SMS verification-code disclosure/reuse/brute forcing, password-reset token authorization bypass, web shells via upload, SMS bombing, unauthenticated reporting APIs, RuoYi backends, Actuator, JWT, public OSS buckets, arbitrary file read via exports, business API SQLi, SSRF. Each entry includes directly executable requests and confirmation criteria; compiled from public sources, verified=false."
verified: false
sources: "Compiled from public sources (business logic / implementation flaws; no CVE; see each entry's \"References\")"
---

# Gambling / Illicit and Gray-Market Sites (59 entries)
> Entries are compiled from public sources (see each entry's "References"); `Exploitation Steps` are hypotheses awaiting validation. Verify against the target version before reporting and set `verified` to true.

These targets (turnkey gambling platforms, agent backends, payment-running/payout services, digital-code vending, SMS-receiving services) share a trait: **they buy the same complete system, reskin it, and launch**, so fingerprints and flaws are consistent; they rarely depend on "new CVEs", and almost always involve:

1. Deployment leftovers (backups, `.git`, `.env`, sourcemaps, swagger, Druid, Actuator);
2. Authorization implemented only in the frontend (API bypasses exposing others' orders/transactions/withdrawals/member profiles);
3. Weak financial logic (unsigned callbacks, amounts trusted from requests, replayable state machines, concurrency, missing idempotency, predictable draws);
4. Frontend as the trust boundary (signing algorithms and keys in JS, vendor keys bundled into H5 packages);
5. Uploads and verification codes (avatar/KYC web shells, SMS bombing, account enumeration).

## Entries

| File | Vulnerability | Severity | Entry Point |
|---|---|---|---|
| `admin-api-unauthenticated.md` | Unauthenticated admin API (menus hidden only in the frontend) | critical | Access /api/admin/* directly with a regular token |
| `admin-ip-whitelist-bypass.md` | Admin IP allowlist bypass (spoofing an internal source with X-Forwarded-For) | high | 403 page + access restricted to 127.0.0.1/internal ranges |
| `admin-reset-any-user.md` | Broken access control in the admin "reset any user's password" endpoint (direct member/admin takeover) | critical | /api/admin/user/resetPassword /api/agent/resetPwd |
| `agent-hierarchy-privilege.md` | Agent hierarchy authorization bypass (read site-wide downlines / change commission rates) | critical | Change agentId to read another agent's downline; change rate to raise commission |
| `api-idor-bola.md` | API authorization bypass / BOLA (read others' orders, transactions, and withdrawals) | high | API endpoints accepting user-controlled object identifiers |
| `api-replay-nonce-missing.md` | Missing API nonce / timestamp → request replay (deposits, rewards, bets) | high | Missing nonce validation on deposit/reward/betting endpoints |
| `bet-history-idor.md` | Bulk unauthorized access to bet / transaction endpoints (site-wide member data) | high | /api/bet/list?uid= /api/report/bet |
| `bet-odds-tampering.md` | Tampering with betting/settlement odds and multipliers (financial impact) | critical | Modify odds/multiple in the betting body |
| `callback-url-ssrf.md` | Controllable payment / callback URL → internal SSRF (including cloud metadata) | high | Payment configuration/callback URL/agent promotional-link checks |
| `client-side-signature-forgery.md` | Reversible frontend signing / encryption (forge requests to bypass risk controls) | high | Extract the algorithm and key from app.js and recalculate sign |
| `cors-misconfig-credential.md` | CORS misconfiguration (read other users' API data with credentials) | high | Reflected Origin with Allow-Credentials: true |
| `coupon-code-enumeration.md` | Enumerable coupon / bonus codes (bulk redemption and cash-out) | high | /api/coupon/redeem /api/promo/exchange |
| `cs-chat-export-unauth.md` | Unauthenticated support-chat exports (site-wide conversations and identity documents) | high | /api/cs/history/export /api/im/sessions |
| `csrf-transfer.md` | CSRF (tokenless withdrawals/password changes/card linking) | high | Critical operations lack CSRF tokens and SameSite is unset |
| `daily-reward-farming.md` | Bulk farming of check-in / task rewards (missing idempotency and rate controls) | high | /api/activity/sign, /api/task/claim |
| `db-admin-tool-exposed.md` | Exposed phpMyAdmin / Adminer (direct database access with weak passwords) | critical | /phpmyadmin/  /pma/  /adminer.php |
| `druid-monitor-unauth.md` | Unauthenticated Druid monitoring → session disclosure/admin takeover (essential for RuoYi-based systems) | critical | /druid/index.html  /druid/websession.html |
| `export-file-read.md` | Arbitrary file read through export / download endpoints | high | /api/report/export?file=../../../../etc/passwd |
| `finance-export-pii.md` | Unauthorized financial exports (bulk bank-card + identity-number export) | critical | /api/finance/export  /api/withdraw/export |
| `game-vendor-api-forgery.md` | Third-party game / live-casino API key disclosure and callback forgery | critical | Obtain vendor key from the frontend and forge /api/game/callback to credit funds |
| `host-header-poisoning.md` | Host header poisoning (hijacked password-reset links → arbitrary account takeover) | critical | Host / X-Forwarded-Host in POST /api/user/findpwd |
| `impersonate-switch-user.md` | Authorization bypass in admin "switch user/impersonation" endpoints (arbitrary account takeover) | critical | /api/admin/user/loginAs?uid=1 |
| `im-websocket-unauth.md` | Unauthenticated support IM / WebSocket (subscribe to others' conversations) | high | Subscribe to room directly via ws://host/ws without a token |
| `invite-referral-selfdealing.md` | Self-referral rebate loops (alternate-account networks farming rebates) | high | /api/user/invite or inviteCode during registration |
| `jwt-none-and-weak-key.md` | JWT implementation flaws (alg:none / weak keys / predictability / kid injection) | high | JWT authentication and signing-key validation |
| `lottery-prng-predictable.md` | Predictable draw results (weak PRNG / client-side algorithm / fixed seed) | critical | Historical draw statistics + reproduction of the frontend JS algorithm |
| `mass-assignment-role.md` | Mass Assignment (inject role / vip / balance / agentId through registration/profile endpoints) | high | Add role=admin to the registration body |
| `member-data-enumeration.md` | Bulk member-privacy queries / account enumeration (phone numbers, bank cards) | high | /api/member/info?phone= returns other users' profiles one by one |
| `multi-tenant-cross-site.md` | Multi-tenant authorization bypass in turnkey platforms (enumerate tenantId/siteId across dozens of sites) | critical | tenantId / siteId / merchantId in request bodies or Headers |
| `notification-template-ssti.md` | Notification-template injection (unescaped subject/body templates → SSTI / stored XSS) | critical | Admin template editor / member-defined notification titles |
| `oauth-redirect-uri.md` | OAuth redirect_uri hijacking / missing state (account takeover) | high | Tamperable /oauth/authorize?redirect_uri= |
| `object-storage-datastore-exposure.md` | Exposed object and data stores (OSS / S3 / MinIO / MySQL / MongoDB) | high | Public object storage or exposed datastore services |
| `operator-backend-weak-login.md` | Weak operator-backend passwords + CAPTCHA reuse (most common entry point on gambling sites) | critical | Login endpoints for /admin /manage /agent |
| `order-status-tamper.md` | Order state-machine tampering (unpaid to paid / crediting canceled orders again) | critical | /api/order/status  /api/recharge/confirm |
| `origin-ip-leak-waf-bypass.md` | Origin IP disclosure → bypass WAF for direct access (essential on gambling sites) | critical | Origin disclosed through subdomains/email headers/certificate history/SSRF |
| `panel-bt-1panel.md` | BT Panel / 1Panel weak passwords and unauthenticated access (most common backend on illicit/gray-market sites) | critical | :8888/<random-entry-path> or :8888/login |
| `password-reset-token-abuse.md` | Predictable password-reset tokens / no user binding (change arbitrary users' passwords) | critical | token = md5(uid) / token exposed in response / uid not validated |
| `payment-channel-swap.md` | Payment-channel / merchant-ID tampering (deposits sent to the attacker's account) | critical | channelId / merchantId / notifyUrl in /api/pay/create |
| `payment-notify-forgery.md` | Payment callback forgery and amount tampering (financial impact) | critical | Payment-provider notification and callback endpoints |
| `promotion-abuse.md` | Unlimited promotion / bonus / rebate claims (missing idempotency) | high | Repeated or concurrent claims through /api/promotion/receive |
| `race-condition-balance.md` | Balance concurrency and negative values (race conditions / amount signs) | critical | 20 concurrent copies of the same request / amount=-100 |
| `redis-session-forgery.md` | Unauthenticated Redis → steal backend session / token for direct backend access | critical | login/session/token keys in Redis |
| `repo-config-backup-leak.md` | Source / backup / configuration disclosure | high | Public repository metadata, configuration, and backup files |
| `report-api-unauth.md` | Unauthenticated reporting/finance endpoints (site-wide transactions and agent commissions) | high | /api/report/* without authentication or with an ordinary token |
| `ruoyi-admin-unauth.md` | RuoYi-based backend default passwords / Druid / scheduled-task RCE | critical | RuoYi administration and monitoring web endpoints |
| `scheduled-task-injection.md` | Backend scheduled-task / job injection (Quartz, XXL-JOB, RuoYi) | critical | Writable task execution content / cron expressions |
| `sms-bomb-and-enum.md` | SMS bombing and account enumeration (verification-code surface) | medium | SMS verification-code and account lookup endpoints |
| `sms-code-reuse-and-bruteforce.md` | SMS verification-code disclosure / reuse / brute forcing (arbitrary account takeover) | critical | Code in response / same-code reuse / four-digit brute force |
| `sourcemap-js-secret-leak.md` | sourcemap / frontend JS discloses endpoints and keys (primary entry point for SPA turnkey sites) | high | /static/js/*.js.map and AK/secret values packaged in bundles |
| `spring-actuator-exposure.md` | Unauthenticated Spring Boot Actuator (heapdump / Jolokia / Gateway) | critical | Spring Boot Actuator management endpoints |
| `sql-injection-business-api.md` | SQL injection in business APIs (reports / orders / agent queries) | critical | orderNo=1' AND SLEEP(5)-- |
| `ssrf-to-internal.md` | SSRF (image fetching / callback validation / promotional-link checks) targeting internal networks and cloud metadata | high | url=http://169.254.169.254/latest/meta-data/ |
| `stored-xss-to-admin.md` | Stored XSS in member profiles targeting backend review (admin session hijacking) | high | Insert <img onerror> into nicknames/notes/tickets |
| `support-ticket-attachment-idor.md` | Unauthorized support-ticket attachment downloads (identity photos / KYC materials) | high | /api/support/attachment?fileId= |
| `swagger-knife4j-unauth.md` | Exposed Swagger / Knife4j API documentation → direct access to unauthenticated endpoints | high | /v2/api-docs  /doc.html  /swagger-ui/index.html |
| `upload-getshell.md` | Web shells via uploads (avatars / KYC documents / support attachments) | critical | Application file-upload and uploaded-file serving endpoints |
| `vip-level-escalation.md` | VIP/level endpoint parameter tampering (free higher-tier benefits) | high | /api/user/level or vipLevel/levelId in profile updates |
| `withdraw-approval-idor.md` | Withdrawal-approval authorization bypass (read others' bank cards / change approval status) | critical | Choose one of two forms (Query/JSON), based on captured requests |
| `withdraw-bankcard-swap.md` | Unauthorized withdrawal-card replacement (route others' withdrawals to your own card) | critical | bankId / cardNo / memberId in /api/withdraw/apply |

## Testing Order (Do Not Start by Grinding Through Uploads)

```
1. Locate the origin (real IP behind the CDN)                 → kb-triage/fingerprint-workflow.md
2. Deployment leftovers (.git / backups / .env / sourcemaps) → obtain site-wide logic and keys in one step
3. Frontend signatures and vendor keys (reversible ⇒ everything afterward can be forged) → client-side-signature-forgery / game-vendor-api-forgery
4. API authorization bypass (BOLA / agent hierarchy / member privacy) → api-idor-bola / agent-hierarchy-privilege / member-data-enumeration
5. Financial surface (callbacks / withdrawal approval / concurrency / bonuses / draws) → payment-notify-forgery / withdraw-approval-idor / race-condition-balance / promotion-abuse / lottery-prng-predictable
6. Foothold and privilege escalation (uploads / JWT / backend leftovers) → upload-getshell / jwt-none-and-weak-key / ruoyi-admin-unauth / spring-actuator-exposure
7. Data surface (public buckets / exposed DBs / exports / SQLi / SSRF) → object-storage-datastore-exposure / export-file-read / sql-injection-business-api / ssrf-to-internal
```

## Hard Rules

- Entries are **compiled from public sources**, not live-test reports; `Exploitation Steps` are hypotheses awaiting validation. Verify against the target version before reporting and set `verified` to true.
- Use only your own accounts and test orders for financial testing; retain only 1-2 records as evidence of authorization bypass; do not include member databases, identity documents, or card numbers in reports.
- These sites commonly use device fingerprints and IP rate limits and have poor log retention; rate-limit enumeration/brute-force actions and choose off-peak windows. Concurrency testing is a **single burst** (for example, one burst of 20 concurrent requests), not sustained load testing.
- **Grade financial findings explicitly**: changing a status ≠ actual payout. Actual withdrawals also depend on secondary review, payout risk controls, and channel reconciliation — these are not covered by this material and must be marked "unverified" in reports.
