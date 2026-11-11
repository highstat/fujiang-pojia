---
name: kb-web-cms
description: CVE/PoC knowledge base · PHP/Python/Node sites and CMS platforms: Drupalgeddon2(2018-7600), PHP-FPM(2019-11043), PHP-CGI Windows(2024-4577), ThinkPHP 5.x, vBulletin(2019-16759), Apache httpd(2021-41773), Joomla(2023-23752), PHPUnit eval-stdin(2017-9841). Each entry includes a corresponding PoC; compiled from public sources, verified=false.
verified: false
sources: Compiled from public sources (CVE advisories / public analyses / business logic issues; see each entry's references)
---

# Web / CMS (19 entries)
> Entries are compiled from public sources (see "References" at the end of each entry); `Exploitation Steps` are hypotheses awaiting verification. Before reporting, verify them against the target version and set `verified` to true.

This section contains **framework/CMS vulnerabilities with CVE identifiers** (business logic issues in turnkey gambling platforms are covered in `kb-gray-market`):

- Test known CVEs by version; identify the component and version first, then compare against affected ranges.
- Applicable to both white-box and black-box testing: `fingerprint → version → entry`. Prefer "fileless" results (command output/callbacks) to reduce cleanup.

## Entries

| File | Vulnerability | Severity | Entry Point |
|---|---|---|---|
| `command-injection.md` | Command injection (semicolons / backticks / $() and blind out-of-band exfiltration) | critical | Parameters concatenated into system/exec/popen |
| `cve-2017-9841-phpunit.md` | PHPUnit eval-stdin remote code execution | critical | POST /vendor/phpunit/.../eval-stdin.php |
| `cve-2018-7600-drupalgeddon2.md` | Drupal Form API remote code execution (Drupalgeddon2) | critical | - |
| `cve-2019-11043-phpfpm-underflow.md` | PHP-FPM path info underflow RCE | critical | - |
| `cve-2019-16759-vbulletin.md` | vBulletin widget configuration code execution | critical | - |
| `cve-2021-3129-laravel-ignition.md` | Laravel Ignition debug-mode arbitrary file read → RCE (CVE-2021-3129) | critical | solution parameter in POST /_ignition/execute-solution |
| `cve-2021-41773-apache-path-traversal.md` | Apache HTTP Server path traversal / CGI RCE | critical | /cgi-bin/.%2e/%2e%2e/bin/sh |
| `cve-2023-23752-joomla-config-leak.md` | Joomla unauthenticated configuration disclosure (API) | medium | /api/index.php/v1/config/application?public=true |
| `cve-2023-6553-backup-migration-rce.md` | WordPress Backup Migration unauthenticated RCE (CVE-2023-6553) | critical | Parameter injection into include in backup-heart.php |
| `cve-2024-25600-bricks-rce.md` | WordPress Bricks unauthenticated RCE (CVE-2024-25600) | critical | queryEditor injection in /wp-json/bricks/v1/render_element |
| `cve-2024-27956-wp-automatic-sqli.md` | WordPress WP-Automatic unauthenticated SQL injection (CVE-2024-27956) | critical | q parameter in /wp-content/plugins/wp-automatic/csv.php |
| `cve-2024-4577-phpcgi-windows.md` | PHP-CGI Windows argument injection (best-fit encoding) | critical | - |
| `lfi-to-rce.md` | Local file inclusion → RCE (log inclusion / pearcmd / PHP filter chain) | critical | Inclusion parameters such as ?page=  ?file=  ?lang= |
| `nginx-alias-traversal.md` | Nginx alias path traversal (arbitrary file read/source code disclosure) | high | /static../  /files..;/  alias without a trailing / |
| `php-object-injection.md` | PHP deserialization (POP chain → RCE / phar trigger) | critical | unserialize($_COOKIE) / phar:// file operations |
| `sqli-union-error.md` | General SQL injection techniques (error-based / UNION / stacked queries) | critical | Numeric/string parameters |
| `ssti-rce.md` | SSTI template injection → RCE (Jinja2 / Twig / Freemarker) | critical | User input concatenated into template strings |
| `thinkphp5-rce.md` | ThinkPHP 5.x method injection / routing RCE | critical | - |
| `xxe-file-read.md` | XXE external entity injection (file read / SSRF / OOB exfiltration) | high | Endpoints using Content-Type: application/xml |

## How to Use This Page

1. **Locate the actual origin before testing vulnerabilities**: these sites commonly use a CDN/cloud WAF, and the `www.` record points to a protection node. Certificate transparency (crt.sh), favicon `icon_hash`, historical DNS, subdomains, email `Received` headers, and SPF/MX can reveal the origin IP. Connecting directly to the origin before testing makes a substantial difference to success rates and reliability.
2. **Priorities for custom-built sites**: source code/backup disclosure (obtain the entire site's logic in one step) → broken endpoint authorization (read all member/order data) → payment callbacks (financial impact) → uploads (file deployment) → SMS (assist account takeover). Do not start by forcing an upload exploit; check for `.git` first.
3. **Evidence and impact**: verify payment issues only with your own test orders, and clearly record "order number + amount + status change" in the report; for authorization bypasses, retrieve only 1-2 records rather than downloading the member database as a trophy.
