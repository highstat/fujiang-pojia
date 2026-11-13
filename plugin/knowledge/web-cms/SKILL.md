---
name: "kb-web-cms"
description: "Web applications, CMS, application libraries and transfer services; affected-version evidence, authorization boundaries, safe assessment and remediation."
verified: false
sources: "Compiled from public sources (CVE advisories / public analyses / business logic issues; see each entry's references)"
---

# Web / CMS (28 entries)
> Public-source notes and assessment cards. Candidate matches are not proof of exploitation; laboratory verification requires dated, redacted evidence.

This section contains **framework/CMS vulnerabilities with CVE identifiers** (business logic issues in turnkey gambling platforms are covered in `kb-gray-market`):

- Test known CVEs by version; identify the component and version first, then compare against affected ranges.
- Applicable to both white-box and black-box testing: `fingerprint → version → entry`. Prefer "fileless" results (command output/callbacks) to reduce cleanup.

## Entries

| File | Vulnerability | Severity | Entry Point |
|---|---|---|---|
| `command-injection.md` | Command injection (semicolons / backticks / $() and blind out-of-band exfiltration) | critical | Parameters concatenated into system/exec/popen |
| `cve-2017-9841-phpunit.md` | PHPUnit eval-stdin remote code execution | critical | POST /vendor/phpunit/.../eval-stdin.php |
| `cve-2018-7600-drupalgeddon2.md` | Drupal Form API remote code execution (Drupalgeddon2) | critical | Drupal Form API request handling |
| `cve-2019-11043-phpfpm-underflow.md` | PHP-FPM path info underflow RCE | critical | Nginx-to-PHP-FPM PATH_INFO handling |
| `cve-2019-16759-vbulletin.md` | vBulletin widget configuration code execution | critical | vBulletin widget configuration endpoint |
| `cve-2021-3129-laravel-ignition.md` | Laravel Ignition debug-mode arbitrary file read → RCE (CVE-2021-3129) | critical | solution parameter in POST /_ignition/execute-solution |
| `cve-2021-41773-apache-path-traversal.md` | Apache HTTP Server path traversal / CGI RCE | critical | /cgi-bin/.%2e/%2e%2e/bin/sh |
| `cve-2023-23752-joomla-config-leak.md` | Joomla unauthenticated configuration disclosure (API) | medium | /api/index.php/v1/config/application?public=true |
| `cve-2023-6553-backup-migration-rce.md` | WordPress Backup Migration unauthenticated RCE (CVE-2023-6553) | critical | Parameter injection into include in backup-heart.php |
| `cve-2024-25600-bricks-rce.md` | WordPress Bricks unauthenticated RCE (CVE-2024-25600) | critical | queryEditor injection in /wp-json/bricks/v1/render_element |
| `cve-2024-27956-wp-automatic-sqli.md` | WordPress WP-Automatic unauthenticated SQL injection (CVE-2024-27956) | critical | q parameter in /wp-content/plugins/wp-automatic/csv.php |
| `cve-2024-4577-phpcgi-windows.md` | PHP-CGI Windows argument injection (best-fit encoding) | critical | Windows PHP-CGI HTTP argument handling |
| `lfi-to-rce.md` | Local file inclusion → RCE (log inclusion / pearcmd / PHP filter chain) | critical | Inclusion parameters such as ?page=  ?file=  ?lang= |
| `nginx-alias-traversal.md` | Nginx alias path traversal (arbitrary file read/source code disclosure) | high | /static../  /files..;/  alias without a trailing / |
| `php-object-injection.md` | PHP deserialization (POP chain → RCE / phar trigger) | critical | unserialize($_COOKIE) / phar:// file operations |
| `sqli-union-error.md` | General SQL injection techniques (error-based / UNION / stacked queries) | critical | Numeric/string parameters |
| `ssti-rce.md` | SSTI template injection → RCE (Jinja2 / Twig / Freemarker) | critical | User input concatenated into template strings |
| `thinkphp5-rce.md` | ThinkPHP 5.x method injection / routing RCE | critical | ThinkPHP 5.x routing and method handling |
| `xxe-file-read.md` | XXE external entity injection (file read / SSRF / OOB exfiltration) | high | Endpoints using Content-Type: application/xml |
| `cve-2023-0669-fortra-goanywhere-mft.md` | Fortra GoAnywhere MFT: Administration interface (CVE-2023-0669) | high | Administration interface |
| `cve-2023-34362-progress-moveit-transfer.md` | Progress MOVEit Transfer: Web application database queries (CVE-2023-34362) | critical | Web application database queries |
| `cve-2024-2961-gnu-glibc-iconv.md` | GNU glibc iconv: Character-set conversion in an application (CVE-2024-2961) | high | Character-set conversion in an application |
| `cve-2024-34102-adobe-commerce-magento.md` | Adobe Commerce Magento: XML processing (CVE-2024-34102) | critical | XML processing |
| `cve-2024-45409-ruby-saml.md` | Ruby SAML: SAML response verification (CVE-2024-45409) | critical | SAML response verification |
| `cve-2024-56326-jinja.md` | Jinja: Sandboxed template filters (CVE-2024-56326) | medium | Sandboxed template filters |
| `cve-2024-5806-progress-moveit-transfer.md` | Progress MOVEit Transfer: SFTP authentication (CVE-2024-5806) | critical | SFTP authentication |
| `cve-2025-29927-next-js.md` | Next.js: Middleware authorization (CVE-2025-29927) | critical | Middleware authorization |
| `cve-2025-55182-react-server-components.md` | React Server Components: Server function request decoding (CVE-2025-55182) | critical | Server function request decoding |

## How to Use This Page

1. **Locate the actual origin before testing vulnerabilities**: these sites commonly use a CDN/cloud WAF, and the `www.` record points to a protection node. Certificate transparency (crt.sh), favicon `icon_hash`, historical DNS, subdomains, email `Received` headers, and SPF/MX can reveal the origin IP. Connecting directly to the origin before testing makes a substantial difference to success rates and reliability.
2. **Priorities for custom-built sites**: source code/backup disclosure (obtain the entire site's logic in one step) → broken endpoint authorization (read all member/order data) → payment callbacks (financial impact) → uploads (file deployment) → SMS (assist account takeover). Do not start by forcing an upload exploit; check for `.git` first.
3. **Evidence and impact**: verify payment issues only with your own test orders, and clearly record "order number + amount + status change" in the report; for authorization bypasses, retrieve only 1-2 records rather than downloading the member database as a trophy.
